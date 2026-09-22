"""Unit tests for the public Python API (Phase 1 Step 7).

Coverage:
- Guard construction (default + custom profile path)
- evaluate: string/object coercion, verdicts, public facts
- sanitize: full pipeline, BLOCK/ALLOW/SANITIZE outcomes
- audit integration
- fail-closed on unsupported payload kinds
"""

import pytest

from core.errors import PolicyError
from core.model import (
    EnvironmentContext,
    Payload,
    Purpose,
    Recipient,
    SanitizationResult,
    TrustLevel,
    Verdict,
)
from medical_privacy_guard import Guard


def make_guard(**kwargs):
    return Guard(**kwargs)


# -- construction ------------------------------------------------------------


class TestConstruction:
    def test_default_profile(self):
        guard = Guard()
        assert guard.profile.policy_version == "external-ai-strict/1"

    def test_research_profile(self):
        guard = Guard(profile="research")
        assert guard.profile.policy_version == "research/1"

    def test_custom_profile_path(self, tmp_path):
        from shutil import copyfile

        src = "policies/external-ai-strict.yaml"
        custom = tmp_path / "custom.yaml"
        copyfile(src, custom)
        guard = Guard(profile_path=str(custom))
        assert guard.profile.policy_version == "external-ai-strict/1"

    def test_unknown_profile_raises(self):
        with pytest.raises(PolicyError):
            Guard(profile="nope")


# -- evaluate ----------------------------------------------------------------


class TestEvaluate:
    @pytest.fixture()
    def guard(self):
        return Guard()

    def test_clean_text_allows(self, guard):
        result = guard.evaluate("普通随访记录", "local", Purpose.TREATMENT)
        assert result.decision.verdict is Verdict.ALLOW
        assert result.facts == ()

    def test_phone_sanitizes(self, guard):
        result = guard.evaluate("电话13800000000", "external-unknown", "EXTERNAL_AI_ASSISTANCE")
        assert result.decision.verdict is Verdict.SANITIZE
        assert len(result.facts) == 1
        assert result.facts[0].type == "PHONE"

    def test_recipient_string_mapping(self, guard):
        # Unknown descriptor defaults to EXTERNAL_UNKNOWN; empty payload + any
        # recipient → ALLOW (no sensitive content).
        r1 = guard.evaluate("", "external-ai", "EXTERNAL_AI_ASSISTANCE")
        assert r1.decision.verdict is Verdict.ALLOW
        # Direct trust-level string maps exactly.
        result = guard.evaluate("电话13800000000", "external_unknown", "EXTERNAL_AI_ASSISTANCE")
        assert result.decision.verdict is Verdict.SANITIZE

    def test_purpose_string_mapping(self, guard):
        result = guard.evaluate("电话13800000000", "external_unknown", "treatment")
        assert result.decision.verdict is Verdict.SANITIZE

    def test_unknown_purpose_falls_back_unknown(self, guard):
        # Unknown purpose strings require scoped human context rather than
        # guessing intent or silently allowing disclosure.
        result = guard.evaluate(
            "电话13800000000", "external_unknown", "not-a-purpose"
        )
        assert result.decision.verdict is Verdict.ASK

    def test_public_facts_exclude_values(self, guard):
        result = guard.evaluate("电话13800000000", "external-unknown", "EXTERNAL_AI_ASSISTANCE")
        public = result.public_facts
        assert len(public) == 1
        assert not hasattr(public[0], "value")

    def test_payload_object_accepted(self, guard):
        result = guard.evaluate(
            Payload(kind="text", content="电话13800000000"),
            Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_UNKNOWN),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.decision.verdict is Verdict.SANITIZE

    def test_environment_accepted(self, guard):
        result = guard.evaluate(
            "电话13800000000",
            "external-unknown",
            "EXTERNAL_AI_ASSISTANCE",
            environment=EnvironmentContext(host="localhost"),
        )
        assert result.decision.verdict is Verdict.SANITIZE

    def test_invalid_types_raise(self, guard):
        with pytest.raises(TypeError):
            guard.evaluate(123, "external-unknown", "EXTERNAL_AI_ASSISTANCE")
        with pytest.raises(TypeError):
            guard.evaluate("x", 42, "EXTERNAL_AI_ASSISTANCE")


# -- sanitize ----------------------------------------------------------------


class TestSanitize:
    @pytest.fixture()
    def guard(self):
        return Guard()

    def test_sanitize_phone(self, guard):
        result = guard.sanitize(
            "联系电话 13800000000", "external-unknown", "EXTERNAL_AI_ASSISTANCE"
        )
        assert isinstance(result, SanitizationResult)
        assert result.decision_before.verdict is Verdict.SANITIZE
        assert result.verification is not None and result.verification.passed
        assert result.sanitized_payload is not None
        assert "13800000000" not in result.sanitized_payload.content
        assert "[REDACTED]" in result.sanitized_payload.content
        assert result.decision_after is not None

    def test_sanitize_allow_returns_payload_unchanged(self, guard):
        result = guard.sanitize("普通记录", "local", Purpose.TREATMENT)
        assert result.decision_before.verdict is Verdict.ALLOW
        assert result.sanitized_payload is not None
        assert result.sanitized_payload.content == "普通记录"
        assert result.verification is None

    def test_sanitize_block_returns_none(self, guard):
        result = guard.sanitize(
            "证件 11010519491231002X", "external-unknown", "EXTERNAL_AI_ASSISTANCE"
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None
        assert result.verification is None

    def test_sanitize_research_date_shift(self):
        guard = Guard(profile="research")
        result = guard.sanitize(
            "出院 2026-08-29", "external_approved", "research"
        )
        assert result.decision_before.verdict is Verdict.SANITIZE
        assert result.verification is not None and result.verification.passed
        assert "2026-08-29" not in result.sanitized_payload.content

    def test_sanitize_writes_audit(self, tmp_path):
        guard = Guard()
        audit_dir = tmp_path / "audit"
        result = guard.sanitize(
            "电话13800000000",
            "external-unknown",
            "EXTERNAL_AI_ASSISTANCE",
            audit_dir=str(audit_dir),
        )
        assert result.sanitized_payload is not None
        log = audit_dir / "events.jsonl"
        assert log.is_file()
        stream = log.read_text(encoding="utf-8")
        assert "13800000000" not in stream

    def test_constructor_audit_dir_used(self, tmp_path):
        guard = Guard(audit_dir=str(tmp_path / "audit"))
        guard.sanitize("电话13800000000", "external-unknown", "EXTERNAL_AI_ASSISTANCE")
        assert (tmp_path / "audit" / "events.jsonl").is_file()


# -- fail closed -------------------------------------------------------------


class TestFailClosed:
    def test_unsupported_kind_blocks(self):
        """JSON is supported as of v0.3; kinds without a parser still block."""
        guard = Guard()
        result = guard.sanitize(
            Payload(kind="fhir", content={"patient": "张三"}),
            "external-unknown",
            "EXTERNAL_AI_ASSISTANCE",
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None

    def test_json_payload_is_supported(self):
        guard = Guard()
        result = guard.sanitize(
            Payload(kind="json", content={"patient": "张三"}),
            "external-approved",
            "EXTERNAL_AI_ASSISTANCE",
        )
        assert result.decision_before.verdict is Verdict.SANITIZE
        assert result.sanitized_payload is not None
        assert "张三" not in result.sanitized_payload.content

    @pytest.mark.parametrize("kind", ["fhir", "dicom", "binary"])
    def test_non_text_kind_with_string_content_still_blocks(self, kind):
        guard = Guard()
        evaluated = guard.evaluate(
            Payload(kind=kind, content="string content must not bypass kind checks"),
            "external-unknown",
            "EXTERNAL_AI_ASSISTANCE",
        )
        sanitized = guard.sanitize(
            Payload(kind=kind, content="string content must not bypass kind checks"),
            "external-unknown",
            "EXTERNAL_AI_ASSISTANCE",
        )
        assert evaluated.decision.verdict is Verdict.BLOCK
        assert sanitized.decision_before.verdict is Verdict.BLOCK
        assert sanitized.sanitized_payload is None

    def test_detect_requires_str(self):
        guard = Guard()
        with pytest.raises(TypeError):
            guard.detect(b"bytes not allowed")


@pytest.mark.parametrize("profile", ["external-ai-strict", "research"])
def test_noop_transform_never_releases(profile, monkeypatch, tmp_path):
    from transformers.base import TransformOutcome

    text = "性别：男。病史：脑梗死。就诊日期：2026-08-21"
    monkeypatch.setattr(
        "medical_privacy_guard.guard.apply_plan",
        lambda text, facts, plan: TransformOutcome(text=text),
    )
    result = Guard(profile=profile, audit_dir=str(tmp_path)).sanitize(
        text, "external_approved", "EXTERNAL_AI_ASSISTANCE"
    )
    assert result.verification is not None and not result.verification.passed
    assert result.sanitized_payload is None
    assert result.decision_after is None
    log = (tmp_path / "events.jsonl").read_text()
    assert '"FAIL"' in log
    assert "2026-08-21" not in log


@pytest.mark.parametrize("kind,content", [("fhir", {"patient": "张三"}), ("text", b"secret")])
def test_unsupported_payload_block_is_audited(kind, content, tmp_path):
    import json

    result = Guard(audit_dir=str(tmp_path)).sanitize(
        Payload(kind=kind, content=content), "external_unknown", "RESEARCH"
    )
    assert result.decision_before.verdict is Verdict.BLOCK
    assert result.sanitized_payload is None
    log = (tmp_path / "events.jsonl").read_text()
    assert "张三" not in log and "secret" not in log
    event = json.loads(log)
    assert event["decision"] == "BLOCK"
    assert event["entity_counts"] == {}
    assert "UNSUPPORTED_FORMAT" in event["reason_codes"]


def test_unsupported_payload_audit_failure_propagates(monkeypatch, tmp_path):
    from core.errors import AuditError

    def fail_record(self, event):
        raise AuditError("synthetic audit failure")

    monkeypatch.setattr("medical_privacy_guard.guard.AuditWriter.record", fail_record)
    with pytest.raises(AuditError):
        Guard(audit_dir=str(tmp_path)).sanitize(
            Payload(kind="json", content={"patient": "张三"}),
            "external_unknown", "RESEARCH",
        )
