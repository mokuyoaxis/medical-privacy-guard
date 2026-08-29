"""Unit tests for the verification loop (Phase 1 Step 4).

Coverage:
- V1: residual identifiers after transformation → VERIFICATION_FAILED
- V2: new sensitive types introduced by transformation → FAILED
- V4: policy re-run on sanitized output must be ALLOW
- happy path: detect → transform → verify → passed
- failure never returns the original payload (no fallback)
"""

import pytest

from core.model import (
    DetectedFact,
    Purpose,
    ReasonCode,
    Recipient,
    TrustLevel,
    Verdict,
)
from core.policy import PolicyEvaluator, load_builtin_profile
from core.verify import Verifier, verify_sanitized
from detectors import detect_all
from transformers import apply_plan


def external_recipient() -> Recipient:
    return Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_UNKNOWN)


@pytest.fixture()
def strict_verifier():
    return Verifier(load_builtin_profile("external-ai-strict"))


# -- happy path --------------------------------------------------------------


class TestHappyPath:
    def test_clean_payload_passes(self, strict_verifier):
        result = strict_verifier.verify(
            sanitized_text="普通随访内容，无敏感信息",
            original_facts=(),
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is True
        assert result.reason_codes == ()

    def test_phone_remove_verifies(self, strict_verifier):
        text = "联系电话 13800000000"
        facts = detect_all(text)
        decision = PolicyEvaluator(load_builtin_profile("external-ai-strict")).evaluate(
            facts, external_recipient(), Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert decision.verdict is Verdict.SANITIZE
        outcome = apply_plan(text, facts, decision.plan)
        assert outcome.text == "联系电话 [REDACTED]"

        result = strict_verifier.verify(
            sanitized_text=outcome.text,
            original_facts=facts,
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is True

    def test_date_generalize_verifies(self, strict_verifier):
        text = "就诊日期 2026-08-29"
        facts = detect_all(text)
        decision = PolicyEvaluator(load_builtin_profile("external-ai-strict")).evaluate(
            facts, external_recipient(), Purpose.TREATMENT
        )
        outcome = apply_plan(text, facts, decision.plan)
        assert outcome.text == "就诊日期 2026-08"

        result = strict_verifier.verify(
            sanitized_text=outcome.text,
            original_facts=facts,
            recipient=external_recipient(),
            purpose=Purpose.TREATMENT,
        )
        assert result.passed is True

    def test_date_shift_verifies_research(self):
        # DATE_SHIFT keeps full dates by design: a shifted date is the intended
        # output, so residual EXACT_DATE (transform-type) is not a failure.
        profile = load_builtin_profile("research")
        verifier = Verifier(profile)
        text = "出院 2026-08-29 随访 2026-09-15"
        facts = detect_all(text)
        recipient = Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_APPROVED)
        decision = PolicyEvaluator(profile).evaluate(facts, recipient, Purpose.RESEARCH)
        assert decision.verdict is Verdict.SANITIZE
        assert decision.plan.operations[0].op == "DATE_SHIFT"
        outcome = apply_plan(text, facts, decision.plan)
        assert "2026-08-29" not in outcome.text  # shifted away

        result = verifier.verify(
            sanitized_text=outcome.text,
            original_facts=facts,
            recipient=recipient,
            purpose=Purpose.RESEARCH,
        )
        assert result.passed is True


# -- V1 residual identifiers -------------------------------------------------


class TestV1Residual:
    def test_residual_phone_fails(self, strict_verifier):
        result = strict_verifier.verify(
            sanitized_text="还有 13800000000 没删",
            original_facts=(DetectedFact(type="PHONE", start=0, end=11, confidence=1.0, source="t", value="13800000000"),),
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is False
        assert ReasonCode.VERIFICATION_FAILED in result.reason_codes
        assert "PHONE" in result.details

    def test_residual_id_fails(self, strict_verifier):
        result = strict_verifier.verify(
            sanitized_text="证件 11010519491231002X",
            original_facts=(),
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is False
        assert ReasonCode.VERIFICATION_FAILED in result.reason_codes


# -- V2 new types ------------------------------------------------------------


class TestV2NewTypes:
    def test_new_type_introduced_fails(self, strict_verifier):
        # Input had only a date; output unexpectedly contains a phone.
        result = strict_verifier.verify(
            sanitized_text="13800000000 出现在输出里",
            original_facts=(DetectedFact(type="EXACT_DATE", start=0, end=10, confidence=1.0, source="t", value="2026-08-29"),),
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is False
        assert "PHONE" in result.details


# -- V4 policy re-run --------------------------------------------------------


class TestV4Policy:
    def test_policy_rerun_not_allow_fails(self, strict_verifier):
        # Sanitized output still contains enough sensitive material that the
        # policy re-run yields SANITIZE, not ALLOW.
        residual = (
            DetectedFact(type="PHONE", start=0, end=11, confidence=1.0, source="t", value="13800000000"),
        )
        result = strict_verifier.verify(
            sanitized_text="13800000000",
            original_facts=residual,
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is False
        assert ReasonCode.VERIFICATION_FAILED in result.reason_codes


# -- no fallback -------------------------------------------------------------


class TestNoFallback:
    def test_verify_failure_never_returns_payload(self, strict_verifier):
        text = "13800000000"
        result = strict_verifier.verify(
            sanitized_text=text,  # unchanged → residual
            original_facts=(DetectedFact(type="PHONE", start=0, end=11, confidence=1.0, source="t", value="13800000000"),),
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is False
        # The caller only receives the VerificationResult; the raw text is not
        # echoed anywhere in the result.
        assert "13800000000" not in result.details

    def test_convenience_wrapper(self):
        text = "电话 13800000000"
        facts = detect_all(text)
        profile = load_builtin_profile("external-ai-strict")
        decision = PolicyEvaluator(profile).evaluate(
            facts, external_recipient(), Purpose.EXTERNAL_AI_ASSISTANCE
        )
        outcome = apply_plan(text, facts, decision.plan)
        result = verify_sanitized(
            profile=profile,
            sanitized_text=outcome.text,
            original_facts=facts,
            recipient=external_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is True


# -- full pipeline -----------------------------------------------------------


class TestFullPipeline:
    def test_sanitize_then_verify_full_loop(self):
        text = "患者：张三，电话 13800000000"
        profile = load_builtin_profile("research")
        recipient = Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_APPROVED)
        purpose = Purpose.RESEARCH

        facts = detect_all(text)
        decision = PolicyEvaluator(profile).evaluate(facts, recipient, purpose)
        assert decision.verdict is Verdict.SANITIZE

        outcome = apply_plan(text, facts, decision.plan)
        assert "张三" not in outcome.text
        assert "13800000000" not in outcome.text

        result = verify_sanitized(
            profile=profile,
            sanitized_text=outcome.text,
            original_facts=facts,
            recipient=recipient,
            purpose=purpose,
        )
        assert result.passed is True
