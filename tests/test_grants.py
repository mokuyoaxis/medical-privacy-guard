"""Regression tests for scoped, expiring approval grants (v0.5).

ASK was the one verdict with no working end-to-end path: the guard withheld the
payload and told the caller a scoped grant was required, with nothing able to
say what a grant is. ``core/grant.py`` closes that, and these tests pin the four
properties the design lists:

- a grant cannot be replayed;
- it does not outlive its scope;
- it cannot be issued by the payload it authorizes;
- it is not a blanket allow.

The most important test here is the release semantics: **an approved disclosure
is still a minimized disclosure**. A grant carries the residual risk of a value
the transformer cannot rewrite; it does not switch the transformation off.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest

from core.grant import (
    ApprovalRequest,
    Grant,
    GrantIssuer,
    GrantRegistry,
    check_grant,
    content_hash,
)
from core.model import Payload, Purpose, Recipient, TrustLevel, Verdict
from medical_privacy_guard import Guard

KEY = b"test-grant-key"
ISSUER = "deployment-approval-svc"
APPROVED = Recipient(kind="api", trust_level=TrustLevel.EXTERNAL_APPROVED)
PURPOSE = Purpose.RESEARCH

#: A document with one transformable identifier and one that cannot be
#: rewritten: a JSON number has no string replacement that keeps its type.
MIXED = {"name": "张三", "mrn": 1234567}


@pytest.fixture
def guard():
    return Guard(grant_key=KEY)


@pytest.fixture
def issuer():
    return GrantIssuer(KEY, issuer=ISSUER)


def _ask(guard, document=None):
    return guard.sanitize(
        Payload(kind="json", content=dict(document or MIXED)), APPROVED, PURPOSE
    )


# -- the request -------------------------------------------------------------


def test_an_ask_produces_a_request_but_no_payload(guard):
    result = _ask(guard)
    assert result.decision_before.verdict is Verdict.ASK
    assert result.sanitized_payload is None
    assert result.approval_request is not None
    assert isinstance(result.approval_request, ApprovalRequest)


def test_the_request_carries_no_raw_value(guard):
    request = _ask(guard).approval_request
    blob = request.to_json()
    for secret in ("张三", "1234567"):
        assert secret not in blob, secret


def test_without_a_key_there_is_no_request_to_issue():
    """Nothing to bind a grant to, so no point describing an unanswerable ASK."""
    result = Guard(grant_key=None).sanitize(
        Payload(kind="json", content=dict(MIXED)), APPROVED, PURPOSE
    )
    assert result.decision_before.verdict is Verdict.ASK
    assert result.approval_request is None
    assert result.sanitized_payload is None


# -- binding -----------------------------------------------------------------


def test_the_fingerprint_binds_the_content(guard):
    """One changed byte and every previously issued grant stops matching."""
    first = _ask(guard).approval_request.fingerprint
    other = {"name": "张三", "mrn": 7654321}
    second = guard.sanitize(Payload(kind="json", content=other), APPROVED, PURPOSE)
    assert first != second.approval_request.fingerprint


def test_the_fingerprint_binds_recipient_purpose_and_policy(guard):
    base = _ask(guard).approval_request.fingerprint
    different_purpose = guard.sanitize(
        Payload(kind="json", content=dict(MIXED)), APPROVED, Purpose.PUBLICATION
    )
    assert base != different_purpose.approval_request.fingerprint

    different_recipient = guard.sanitize(
        Payload(kind="json", content=dict(MIXED)),
        Recipient(kind="api", trust_level=TrustLevel.EXTERNAL_UNKNOWN),
        PURPOSE,
    )
    assert base != different_recipient.approval_request.fingerprint


def test_content_hash_is_stable_but_not_the_content():
    assert content_hash("json", {"a": 1}) == content_hash("json", {"a": 1})
    assert content_hash("json", {"a": 1}) != content_hash("json", {"a": 2})


# -- the four properties -----------------------------------------------------


def test_a_grant_cannot_be_replayed(guard, issuer):
    """One-time use: the second submission is refused."""
    grant = issuer.issue(_ask(guard).approval_request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    first = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED, PURPOSE, grant=grant)
    assert first.sanitized_payload is not None
    second = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED, PURPOSE, grant=grant)
    assert second.sanitized_payload is None
    assert "already been used" in second.decision_before.explanation


def test_a_grant_cannot_be_replayed_by_another_guard(guard, issuer):
    grant = issuer.issue(_ask(guard).approval_request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    first = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                           PURPOSE, grant=grant)
    assert first.sanitized_payload is not None

    second = Guard(grant_key=KEY).sanitize(
        Payload(kind="json", content=dict(MIXED)), APPROVED, PURPOSE, grant=grant
    )
    assert second.decision_before.verdict is Verdict.ASK
    assert second.sanitized_payload is None
    assert "already been used" in second.decision_before.explanation


@pytest.mark.parametrize("uses_allowed", [1, 3])
def test_concurrent_guards_share_the_use_budget(guard, issuer, uses_allowed):
    grant = issuer.issue(_ask(guard).approval_request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",),
                         uses_allowed=uses_allowed)
    callers = 8
    start = Barrier(callers)

    def release(_):
        other = Guard(grant_key=KEY)
        start.wait(timeout=10)
        return other.sanitize(Payload(kind="json", content=dict(MIXED)),
                              APPROVED, PURPOSE, grant=grant)

    with ThreadPoolExecutor(max_workers=callers) as executor:
        results = list(executor.map(release, range(callers)))
    released = [r for r in results if r.sanitized_payload is not None]
    assert len(released) == uses_allowed
    assert all(r.decision_before.verdict is Verdict.ASK for r in results)
    for result in released:
        assert result.verification is not None and result.verification.passed
        assert json.loads(result.sanitized_payload.content)["name"] != "张三"


@pytest.mark.parametrize("uses_allowed", [1, 3])
def test_registry_consumption_is_atomic(guard, issuer, uses_allowed):
    grant = issuer.issue(_ask(guard).approval_request, ttl_seconds=300,
                         uses_allowed=uses_allowed)

    class YieldingCounter(dict):
        def get(self, key, default=0):
            used = super().get(key, default)
            # Allow another thread to run between the read and the update.
            time.sleep(0.02)
            return used

    registry = GrantRegistry()
    store = YieldingCounter()
    callers = 8
    start = Barrier(callers)

    def consume(_):
        start.wait(timeout=10)
        return registry.consume(grant, store=store)

    with ThreadPoolExecutor(max_workers=callers) as executor:
        results = list(executor.map(consume, range(callers)))
    assert sum(results) == uses_allowed
    assert store[grant.grant_id] == uses_allowed


def test_an_explicit_registry_can_be_shared(issuer):
    registry = GrantRegistry()
    first_guard = Guard(grant_key=KEY, registry=registry)
    second_guard = Guard(grant_key=KEY, registry=registry)
    grant = issuer.issue(_ask(first_guard).approval_request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    first = first_guard.sanitize(Payload(kind="json", content=dict(MIXED)),
                                 APPROVED, PURPOSE, grant=grant)
    second = second_guard.sanitize(Payload(kind="json", content=dict(MIXED)),
                                   APPROVED, PURPOSE, grant=grant)
    assert first.sanitized_payload is not None
    assert second.sanitized_payload is None


def test_a_grant_does_not_outlive_its_scope(guard, issuer):
    """An approval that never expires would be a blanket allow."""
    import core.grant as grant_module

    request = _ask(guard).approval_request
    moment = grant_module._now()
    stale = issuer.issue(request, ttl_seconds=60, now=moment)
    assert check_grant(stale, request, key=KEY, now=moment + timedelta(seconds=61)) == (
        "grant has expired"
    )
    # And it is still valid one second before the deadline, so the boundary is
    # the expiry, not the presence of one.
    assert check_grant(stale, request, key=KEY,
                       now=moment + timedelta(seconds=59)) is None


def test_a_grant_issued_for_the_future_is_refused(guard, issuer):
    request = _ask(guard).approval_request
    import core.grant as grant_module

    future = issuer.issue(request, ttl_seconds=300,
                          now=grant_module._now() + timedelta(hours=1))
    assert check_grant(future, request, key=KEY) == "grant is not yet valid"


def test_a_grant_signed_by_another_key_is_refused(guard, issuer):
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    assert check_grant(grant, request, key=b"a-different-key") == (
        "grant signature does not verify"
    )


def test_an_edited_grant_is_refused(guard, issuer):
    """The signature covers expiry and allowed uses, so they cannot be widened."""
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=60, uses_allowed=1)
    widened = Grant(**{**grant.__dict__, "uses_allowed": 99})
    assert check_grant(widened, request, key=KEY) == "grant signature does not verify"


def test_an_unsigned_grant_is_refused(guard):
    request = _ask(guard).approval_request
    grant = Grant(grant_id="g", request_fingerprint=request.fingerprint, issuer="x",
                  issued_at="2026-01-01T00:00:00.000000Z",
                  expires_at="2027-01-01T00:00:00.000000Z")
    assert check_grant(grant, request, key=KEY) == "grant is not signed"


def test_a_grant_must_accept_the_types_it_carries(guard, issuer):
    """A grant for one type does not launder the others."""
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300)  # accepted nothing
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=grant)
    assert result.sanitized_payload is None
    assert "does not accept the risk of" in result.decision_before.explanation


def test_no_key_means_no_grant(guard, issuer):
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300)
    assert check_grant(grant, request, key=b"") == "no grant key is configured"


# -- release semantics -------------------------------------------------------


def test_an_approved_release_is_still_a_minimized_release(guard, issuer):
    """The crux: approval does not undo the detectors that did fire."""
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=grant)
    assert result.sanitized_payload is not None
    released = json.loads(result.sanitized_payload.content)
    assert released["name"] != "张三"
    assert "[PERSON_NAME_" in released["name"]
    # The number could not be rewritten; the grant carries it.
    assert released["mrn"] == 1234567


def test_a_granted_release_is_verified(guard, issuer):
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=grant)
    assert result.verification is not None and result.verification.passed


def test_the_verdict_stays_ask_after_approval(guard, issuer):
    """The audit must show a person accepted a risk, not that policy relaxed."""
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=grant)
    assert result.decision_before.verdict is Verdict.ASK


def test_a_grant_does_not_exempt_a_transformable_value(guard, issuer):
    """Narrowness is the safety property: only unrewritable values are covered."""
    request = _ask(guard).approval_request
    # PERSON_NAME *can* be tokenized, so accepting it must not exempt it.
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("PERSON_NAME", "MEDICAL_RECORD_NUMBER"))
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=grant)
    assert result.sanitized_payload is not None
    released = json.loads(result.sanitized_payload.content)
    assert released["name"] != "张三"


# -- audit -------------------------------------------------------------------


def test_a_granted_release_is_recorded_as_grant_approved(guard, issuer, tmp_path):
    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED, PURPOSE,
                   grant=grant, audit_dir=str(tmp_path))
    events = [json.loads(line) for line in
              (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    assert events
    assert any(e.get("grant_id") == grant.grant_id for e in events)
    assert any(e.get("grant_issuer") == ISSUER for e in events)
    blob = json.dumps(events, ensure_ascii=False)
    for secret in ("张三", "1234567"):
        assert secret not in blob


# -- issuer guardrails -------------------------------------------------------


def test_an_issuer_requires_a_key():
    with pytest.raises(Exception):
        GrantIssuer(b"", issuer="x")


def test_an_approval_must_expire(issuer):
    """A grant that never expires is a blanket allow."""
    guard = Guard(grant_key=KEY)
    req = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED, PURPOSE).approval_request
    with pytest.raises(Exception):
        issuer.issue(req, ttl_seconds=0)
    with pytest.raises(Exception):
        issuer.issue(req, ttl_seconds=-5)


# -- adapter integration -----------------------------------------------------


def test_release_or_raise_still_refuses_an_unapproved_ask(guard):
    """The ordinary ASK path is unchanged: nothing leaves without a grant."""
    from adapters import release_or_raise
    from core.errors import HumanApprovalRequired

    with pytest.raises(HumanApprovalRequired):
        release_or_raise(_ask(guard))


def test_release_or_raise_releases_a_granted_ask(guard, issuer):
    """A granted ASK yields the minimized payload, not the original."""
    from adapters import release_or_raise

    request = _ask(guard).approval_request
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=grant)
    payload = release_or_raise(result)
    released = json.loads(payload.content)
    assert released["name"] != "张三"
    assert released["mrn"] == 1234567


RARE_NOTE = "本例为罕见变异型病例，建议多学科会诊。"


def test_a_narrative_with_nothing_to_transform_is_still_releasable(guard, issuer):
    """An empty plan must not mean refusal.

    A rare-condition note carries no identifier: there is nothing to minimize,
    but sending it is exactly what the human was asked to approve. Refusing
    after approval would make the grant useless for the case that most needs it.
    """
    first = guard.sanitize(RARE_NOTE, APPROVED, Purpose.RESEARCH)
    assert first.decision_before.verdict is Verdict.ASK
    assert first.sanitized_payload is None

    grant = issuer.issue(first.approval_request, ttl_seconds=300)
    second = guard.sanitize(RARE_NOTE, APPROVED, Purpose.RESEARCH, grant=grant)
    assert second.sanitized_payload is not None
    assert second.sanitized_payload.content == RARE_NOTE


def test_an_ungranted_narrative_stays_withheld(guard):
    """No grant, no release — even when there is nothing to transform."""
    result = guard.sanitize(RARE_NOTE, APPROVED, Purpose.RESEARCH)
    assert result.sanitized_payload is None
    assert result.approval_request is not None


@pytest.mark.parametrize("kind, content", [
    ("text", RARE_NOTE),
    ("json", {"note": RARE_NOTE}),
    ("csv", "note\n" + RARE_NOTE + "\n"),
    ("fhir", {"resourceType": "Condition", "note": [{"text": RARE_NOTE}]}),
])
def test_approved_context_is_releasable_in_every_format(guard, issuer, kind, content):
    payload = Payload(kind=kind, content=content)
    request = guard.sanitize(payload, APPROVED, PURPOSE).approval_request
    grant = issuer.issue(request, ttl_seconds=300)
    result = guard.sanitize(payload, APPROVED, PURPOSE, grant=grant)
    assert result.decision_before.verdict is Verdict.ASK
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None


@pytest.mark.parametrize("document, accepted, unchanged_key, rewritten_key", [
    ({"phone": 13800000000, "name": "张三"}, "PHONE", "phone", "name"),
    ({"name": "张三", "phone": 13800000000}, "PHONE", "phone", "name"),
    ({"mrn": 1234567, "medical_record_number": "ZY2026001"},
     "MEDICAL_RECORD_NUMBER", "mrn", "medical_record_number"),
    ({"phone": 13800000000, "mobile": "13900000000"}, "PHONE", "phone", "mobile"),
    ({"id_card": 110101199003078888, "name": "张三"},
     "GOVERNMENT_ID", "id_card", "name"),
])
def test_approved_read_only_values_survive_and_writable_values_transform(
    guard, issuer, document, accepted, unchanged_key, rewritten_key
):
    payload = Payload(kind="json", content=document)
    grant = issuer.issue(_ask(guard, document).approval_request, ttl_seconds=300,
                         accepted_types=(accepted,))
    result = guard.sanitize(payload, APPROVED, PURPOSE, grant=grant)
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None
    released = json.loads(result.sanitized_payload.content)
    assert released[unchanged_key] == document[unchanged_key]
    assert type(released[unchanged_key]) is type(document[unchanged_key])
    assert released[rewritten_key] != document[rewritten_key]


@pytest.mark.parametrize("kind, content", [
    ("text", RARE_NOTE),
    ("json", MIXED),
])
def test_rejected_grants_do_not_enter_authorized_audit_fields(
    guard, issuer, tmp_path, kind, content
):
    payload = Payload(kind=kind, content=content)
    request = guard.sanitize(payload, APPROVED, PURPOSE).approval_request
    grant = issuer.issue(request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    rejected = replace(grant, issuer="SYNTH-UNVERIFIED-ISSUER", signature="invalid")
    result = guard.sanitize(payload, APPROVED, PURPOSE, grant=rejected,
                            audit_dir=str(tmp_path))
    assert result.sanitized_payload is None
    event = json.loads((tmp_path / "events.jsonl").read_text())
    assert event["grant_id"] == "" and event["grant_issuer"] == ""
    assert rejected.issuer not in json.dumps(event)


@pytest.mark.parametrize("raw", [
    'null', '[]', '1', '"a grant"',
    '{"grant_id": 1, "request_fingerprint": "x", "issuer": "x", '
    '"issued_at": "x", "expires_at": "x"}',
])
def test_grant_decoding_rejects_invalid_shapes(raw):
    from core.errors import GrantError

    with pytest.raises(GrantError):
        Grant.from_json(raw)


@pytest.mark.parametrize("field, value", [
    ("uses_allowed", 1.5), ("uses_allowed", True), ("uses_allowed", "1"),
    ("uses_allowed", 0), ("accepted_types", "PHONE"),
    ("accepted_types", [1]), ("issuer", {"name": "synthetic"}),
])
def test_grant_decoding_does_not_coerce_fields(guard, issuer, field, value):
    from core.errors import GrantError

    data = json.loads(issuer.issue(_ask(guard).approval_request, ttl_seconds=300).to_json())
    data[field] = value
    with pytest.raises(GrantError):
        Grant.from_json(json.dumps(data))


def test_grant_json_round_trip_preserves_signature(guard, issuer):
    grant = issuer.issue(_ask(guard).approval_request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",), uses_allowed=3)
    parsed = Grant.from_json(grant.to_json())
    assert parsed == grant
    assert parsed.signature_is_valid(KEY)


def test_read_only_approval_does_not_cover_a_failed_writable_transformation(
    guard, issuer, monkeypatch
):
    document = {"phone": 13800000000, "mobile": "13900000000"}
    grant = issuer.issue(_ask(guard, document).approval_request, ttl_seconds=300,
                         accepted_types=("PHONE",))
    monkeypatch.setattr("transformers.text.TextTransformer.apply",
                        lambda self, fact, op, tokens: fact.value)
    result = guard.sanitize(Payload(kind="json", content=document), APPROVED,
                            PURPOSE, grant=grant)
    assert result.sanitized_payload is None
    assert result.verification is not None and not result.verification.passed


@pytest.mark.parametrize("signature", ["", "invalid", "不合法"])
def test_invalid_signatures_remain_ask_without_spending_a_use(guard, issuer, signature):
    grant = issuer.issue(_ask(guard).approval_request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=replace(grant, signature=signature))
    assert result.decision_before.verdict is Verdict.ASK
    assert result.sanitized_payload is None
    result = guard.sanitize(Payload(kind="json", content=dict(MIXED)), APPROVED,
                            PURPOSE, grant=grant)
    assert result.sanitized_payload is not None


@pytest.mark.parametrize("field, value", [
    ("ttl_seconds", True), ("ttl_seconds", 1.5), ("ttl_seconds", "1"),
    ("uses_allowed", True), ("uses_allowed", 1.5), ("uses_allowed", "1"),
])
def test_issuer_rejects_non_integer_budgets(guard, issuer, field, value):
    from core.errors import GrantError

    kwargs = {"ttl_seconds": 300, field: value}
    with pytest.raises(GrantError):
        issuer.issue(_ask(guard).approval_request, **kwargs)


@pytest.mark.parametrize("text", ["普通随访", "电话13800000000"])
def test_a_grant_not_needed_by_the_decision_is_not_audited_as_accepted(
    guard, issuer, tmp_path, text
):
    grant = issuer.issue(_ask(guard).approval_request, ttl_seconds=300,
                         accepted_types=("MEDICAL_RECORD_NUMBER",))
    result = guard.sanitize(text, APPROVED, PURPOSE, grant=grant, audit_dir=str(tmp_path))
    assert result.sanitized_payload is not None
    event = json.loads((tmp_path / "events.jsonl").read_text())
    assert event["grant_id"] == "" and event["grant_issuer"] == ""


@pytest.mark.parametrize("offset", [-5, 8])
def test_issuance_preserves_the_instant_across_timezones(guard, issuer, offset):
    request = _ask(guard).approval_request
    moment = datetime.now(timezone(timedelta(hours=offset)))
    grant = issuer.issue(request, ttl_seconds=60, now=moment)
    assert check_grant(grant, request, key=KEY, now=moment) is None
    assert check_grant(grant, request, key=KEY,
                       now=moment + timedelta(seconds=61)) == "grant has expired"


def test_a_naive_clock_has_an_explicit_failure(guard, issuer):
    from core.errors import GrantError

    request = _ask(guard).approval_request
    moment = datetime.now(timezone.utc).replace(tzinfo=None)
    with pytest.raises(GrantError, match="timezone-aware"):
        issuer.issue(request, ttl_seconds=60, now=moment)
    grant = issuer.issue(request, ttl_seconds=60)
    assert check_grant(grant, request, key=KEY, now=moment) == (
        "grant evaluation time must be timezone-aware"
    )
