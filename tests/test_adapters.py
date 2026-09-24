"""Adapter release semantics.

The contract these tests pin: an adapter may send exactly what the guard
approved and nothing else. Every verdict maps to one caller behaviour, and the
mapping is written once in ``adapters/egress.py`` so a vendor module cannot
quietly invent its own.
"""

from __future__ import annotations

import pytest

from adapters import release_or_raise, verification_details
from core.errors import (
    DisclosureBlocked,
    GuardError,
    HumanApprovalRequired,
    VerificationError,
    VerificationFailed,
)
from core.model import (
    Decision,
    Payload,
    Purpose,
    ReasonCode,
    Recipient,
    RiskLevel,
    RiskSummary,
    SanitizationResult,
    TrustLevel,
    Verdict,
    VerificationResult,
)
from medical_privacy_guard import Guard


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


def _synthetic(verdict, *, payload=None, verification=None, reason_codes=()):
    """A SanitizationResult assembled directly, for states the guard cannot reach."""
    return SanitizationResult(
        decision_before=Decision(
            verdict=verdict,
            reason_codes=tuple(reason_codes),
            explanation="synthetic",
            risk=RiskSummary(level=RiskLevel.HIGH, score=50, factors=()),
            plan=None,
            policy_version="test/1",
        ),
        sanitized_payload=payload,
        verification=verification,
        decision_after=None,
    )


def _json(guard, document, recipient, purpose=Purpose.EXTERNAL_AI_ASSISTANCE):
    return guard.sanitize(Payload(kind="json", content=document), recipient, purpose)


# -- one behaviour per verdict ----------------------------------------------


class TestVerdictMapping:
    def test_allow_returns_the_payload_unchanged(self, guard, approved):
        result = _json(guard, {"note": "普通随访"}, approved)
        assert result.decision_before.verdict is Verdict.ALLOW
        payload = release_or_raise(result)
        assert payload.content == {"note": "普通随访"}

    def test_sanitize_returns_the_verified_replacement(self, guard, approved):
        result = _json(guard, {"name": "张三"}, approved)
        assert result.decision_before.verdict is Verdict.SANITIZE
        payload = release_or_raise(result)
        assert "张三" not in str(payload.content)
        assert "[PERSON_NAME_001]" in str(payload.content)

    def test_block_raises_and_carries_the_decision(self, guard):
        result = _json(guard, {"id_card": "110101199003078888"}, "external-unknown")
        assert result.decision_before.verdict is Verdict.BLOCK
        with pytest.raises(DisclosureBlocked) as excinfo:
            release_or_raise(result)
        assert excinfo.value.decision.verdict is Verdict.BLOCK

    def test_ask_raises_rather_than_approving(self, guard, approved):
        """ASK is not consent: an unwritable identifier must not be released."""
        result = _json(guard, {"mrn": 1234567}, approved)
        assert result.decision_before.verdict is Verdict.ASK
        with pytest.raises(HumanApprovalRequired):
            release_or_raise(result)

    def test_every_verdict_is_covered(self, guard, approved):
        """No verdict may fall through to a return."""
        seen = set()
        for document, recipient in (
            ({"note": "普通随访"}, approved),
            ({"name": "张三"}, approved),
            ({"mrn": 1234567}, approved),
            ({"id_card": "110101199003078888"}, "external-unknown"),
        ):
            result = _json(guard, document, recipient)
            seen.add(result.decision_before.verdict)
            try:
                release_or_raise(result)
                assert result.decision_before.verdict in {Verdict.ALLOW, Verdict.SANITIZE}
            except GuardError:
                assert result.decision_before.verdict in {Verdict.ASK, Verdict.BLOCK}
        assert seen == {Verdict.ALLOW, Verdict.SANITIZE, Verdict.ASK, Verdict.BLOCK}


# -- fail closed on an unverified sanitize ----------------------------------


class TestVerificationFailure:
    def test_a_sanitize_with_no_payload_fails_closed(self):
        """Never fall back to the input when there is nothing verified to send."""
        result = _synthetic(Verdict.SANITIZE, payload=None, verification=None)
        with pytest.raises(VerificationFailed):
            release_or_raise(result)

    def test_an_unverified_payload_is_withheld(self):
        payload = Payload(kind="text", content="患者：[PERSON_NAME_001]")
        verification = VerificationResult(
            passed=False,
            reason_codes=(ReasonCode.VERIFICATION_FAILED,),
            details="PERSON_NAME span is followed by unexplained text ('由急诊科')",
        )
        result = _synthetic(Verdict.SANITIZE, payload=payload, verification=verification)
        with pytest.raises(VerificationFailed):
            release_or_raise(result)

    def test_diagnostic_detail_stays_out_of_the_message(self):
        """``details`` can quote the payload, so it must not reach a log sink."""
        payload = Payload(kind="text", content="x")
        verification = VerificationResult(
            passed=False,
            reason_codes=(ReasonCode.VERIFICATION_FAILED,),
            details="PERSON_NAME span is followed by unexplained text ('由急诊科')",
        )
        result = _synthetic(Verdict.SANITIZE, payload=payload, verification=verification)
        with pytest.raises(VerificationFailed) as excinfo:
            release_or_raise(result)
        assert "由急诊科" not in str(excinfo.value)
        assert excinfo.value.details is not None
        assert "由急诊科" in verification_details(result)


# -- the exception family ---------------------------------------------------


class TestExceptionFamily:
    def test_every_exception_is_catchable_as_a_guard_error(self, guard):
        for document, recipient in (
            ({"mrn": 1234567}, "external-approved"),
            ({"id_card": "110101199003078888"}, "external-unknown"),
        ):
            result = _json(guard, document, recipient)
            with pytest.raises(GuardError):
                release_or_raise(result)

    def test_a_verification_failure_is_also_a_verification_error(self):
        assert issubclass(VerificationFailed, VerificationError)
        result = _synthetic(Verdict.SANITIZE, payload=None)
        with pytest.raises(VerificationError):
            release_or_raise(result)

    def test_messages_quote_reason_codes_but_no_values(self, guard):
        result = _json(guard, {"id_card": "110101199003078888"}, "external-unknown")
        with pytest.raises(DisclosureBlocked) as excinfo:
            release_or_raise(result)
        message = str(excinfo.value)
        assert "110101199003078888" not in message
        assert "GOVERNMENT_ID_PRESENT" in message

    def test_ask_message_does_not_leak_the_number(self, guard, approved):
        result = _json(guard, {"mrn": 1234567}, approved)
        with pytest.raises(HumanApprovalRequired) as excinfo:
            release_or_raise(result)
        assert "1234567" not in str(excinfo.value)
        assert "UNTRANSFORMABLE_IDENTIFIER" in str(excinfo.value)
