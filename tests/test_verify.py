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


def approved_recipient() -> Recipient:
    """An institution-approved endpoint: medical content no longer forces ASK,
    so the policy re-run can reach SANITIZE on a note that still needs work."""
    return Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_APPROVED)


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
            original_text=text,
            plan=decision.plan,
            outcome=outcome,
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
            original_text=text,
            plan=decision.plan,
            outcome=outcome,
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
            original_text=text,
            plan=decision.plan,
            outcome=outcome,
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

    def test_context_only_residuals_do_not_block_release(self, strict_verifier):
        """SEX and MEDICAL_CONTENT have no span transformation, so a payload
        can never stop containing them. Treating them as unfinished work made
        every real clinical note fail verification and release nothing."""
        text = "性别：男。病史：脑梗死。就诊日期：2026-08-21"
        facts = detect_all(text)
        decision = PolicyEvaluator(strict_verifier.profile).evaluate(
            facts, approved_recipient(), Purpose.EXTERNAL_AI_ASSISTANCE
        )
        outcome = apply_plan(text, facts, decision.plan)
        result = strict_verifier.verify(
            sanitized_text=outcome.text,
            original_facts=facts,
            original_text=text,
            plan=decision.plan,
            outcome=outcome,
            recipient=approved_recipient(),
            purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.passed is True, result.details

    def test_exemption_does_not_cover_untransformed_identifiers(self, strict_verifier):
        """The exemption must be narrow: an erase-type residual still fails."""
        text = "性别：男。病史：脑梗死。电话 13800000000"
        result = strict_verifier.verify(
            sanitized_text=text,
            original_facts=detect_all(text),
            recipient=approved_recipient(),
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
            original_text=text,
            plan=decision.plan,
            outcome=outcome,
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
            original_text=text,
            plan=decision.plan,
            outcome=outcome,
            original_facts=facts,
            recipient=recipient,
            purpose=purpose,
        )
        assert result.passed is True


def execution_case(text, profile_name="external-ai-strict", days=None):
    from dataclasses import replace

    profile = load_builtin_profile(profile_name)
    facts = detect_all(text)
    decision = PolicyEvaluator(profile).evaluate(
        facts, approved_recipient(), Purpose.RESEARCH
    )
    plan = decision.plan
    if days is not None:
        plan = replace(plan, operations=tuple(
            replace(op, parameters={"shift_days": days}) if op.op == "DATE_SHIFT" else op
            for op in plan.operations
        ))
    return profile, facts, plan, apply_plan(text, facts, plan)


def verify_case(text, profile, facts, plan, outcome):
    return verify_sanitized(
        profile=profile, original_text=text, original_facts=facts, plan=plan,
        outcome=outcome, sanitized_text=outcome.text, recipient=approved_recipient(),
        purpose=Purpose.RESEARCH,
    )


@pytest.mark.parametrize("profile_name", ["external-ai-strict", "research"])
def test_transform_without_evidence_fails(profile_name):
    text = "性别：男。病史：脑梗死。就诊日期：2026-08-21"
    profile, facts, _, outcome = execution_case(text, profile_name)
    for candidate in (text, outcome.text):
        result = Verifier(profile).verify(
            sanitized_text=candidate, original_facts=facts,
            recipient=approved_recipient(), purpose=Purpose.RESEARCH,
        )
        assert not result.passed
        assert "2026-08-21" not in result.details


def test_legacy_erase_only_call_remains_supported():
    result = Verifier(load_builtin_profile("external-ai-strict")).verify(
        sanitized_text="电话[REDACTED]", original_facts=detect_all("电话13800000000"),
        recipient=approved_recipient(), purpose=Purpose.RESEARCH,
    )
    assert result.passed


@pytest.mark.parametrize("mutation", ["missing", "applied", "span", "op", "parameters", "context", "plan"])
def test_execution_contract_rejects_incomplete_or_tampered_evidence(mutation):
    from dataclasses import replace

    text = "日期2026-08-21；年龄67岁"
    profile, facts, plan, outcome = execution_case(text)
    first, *rest = outcome._evidence
    if mutation == "missing":
        outcome = replace(outcome, _evidence=tuple(rest))
    elif mutation == "applied":
        outcome = replace(outcome, applied=())
    elif mutation == "span":
        outcome = replace(outcome, _evidence=(replace(first, output_end=first.output_end + 1), *rest))
    elif mutation in {"op", "parameters"}:
        op = replace(first.operation, op="REMOVE") if mutation == "op" else replace(
            first.operation, parameters={"retain_day": True}
        )
        outcome = replace(outcome, _evidence=(replace(first, operation=op), *rest))
    elif mutation == "context":
        outcome = replace(outcome, text=outcome.text.replace("日期", "诊断"))
    else:
        plan = replace(plan, operations=plan.operations[:1])
    assert not verify_case(text, profile, facts, plan, outcome).passed


@pytest.mark.parametrize("text,bad_output", [
    ("2026-08-21", "2026-08-21"),
    ("2026-08-21", "2026-08-22"),
    ("2026-08-21", "2026-09"),
    ("年龄67岁", "70-79岁"),
    ("就诊于北京协和医院", "[OTHER_GENERALIZED]"),
    ("电话13800000000", "[PHONE_999]"),
])
def test_independent_postconditions_reject_bad_transformer(text, bad_output):
    from transformers.base import Transformer
    from transformers.registry import TransformerRegistry

    class BrokenTransformer(Transformer):
        handles = ("GENERALIZE", "REMOVE")

        def apply(self, fact, op, tokens):
            return bad_output

    profile, facts, plan, _ = execution_case(text)
    outcome = apply_plan(text, facts, plan, registry=TransformerRegistry((BrokenTransformer(),)))
    assert not verify_case(text, profile, facts, plan, outcome).passed


def test_date_shift_may_equal_another_original_date():
    text = "出院2026-01-01 随访2026-01-06"
    profile, facts, plan, outcome = execution_case(text, "research", days=5)
    assert outcome.text == "出院2026-01-06 随访2026-01-11"
    assert verify_case(text, profile, facts, plan, outcome).passed


@pytest.mark.parametrize("offsets", [(5, 6), (6, 6), (0, 0)])
def test_date_shift_rejects_wrong_or_inconsistent_offsets(offsets):
    from datetime import date, timedelta

    from transformers.base import Transformer
    from transformers.registry import TransformerRegistry

    class BrokenShift(Transformer):
        handles = ("DATE_SHIFT",)

        def apply(self, fact, op, tokens):
            days = offsets[0 if fact.start == 2 else 1]
            return str(date.fromisoformat(fact.value) + timedelta(days=days))

    text = "出院2026-01-01 随访2026-01-06"
    profile, facts, plan, _ = execution_case(text, "research", days=5)
    outcome = apply_plan(text, facts, plan, registry=TransformerRegistry((BrokenShift(),)))
    assert not verify_case(text, profile, facts, plan, outcome).passed


@pytest.mark.parametrize("value,shifted", [
    ("2026-8-9", "2026-08-14"), ("２０２６-８-９", "2026-08-14"),
    ("２０２６/０８/９", "2026/08/14"), ("20２６.8.０９", "2026-08-14"),
    ("８/9/20２６", "2026/08/14"), ("２０２６年８月９日", "2026年8月14日"),
])
def test_date_shift_formats_with_interleaved_operations_verify(value, shifted):
    text = f"患者：张伟；出院：{value}；电话：13800000000；随访：2026-8-14；年龄：67岁。"
    profile, facts, plan, outcome = execution_case(text, "research", days=5)
    assert outcome.text == (
        f"患者：[PERSON_NAME_001]；出院：{shifted}；电话：[REDACTED]；"
        "随访：2026-08-19；年龄：60-69岁。"
    )
    assert [record.start for record in outcome._evidence] == sorted(
        record.start for record in outcome._evidence
    )
    assert [op.target for op in outcome.applied] == [
        "AGE", "EXACT_DATE", "PHONE", "PERSON_NAME",
    ]
    assert verify_case(text, profile, facts, plan, outcome).passed


@pytest.mark.parametrize("mutation", ["applied_order", "evidence_order", "zero", "missing"])
def test_execution_order_and_offset_contract_cannot_be_bypassed(mutation):
    from dataclasses import replace

    text = "患者：张伟；出院2026-01-01；随访2026-01-06；年龄67岁"
    profile, facts, plan, outcome = execution_case(text, "research", days=5)
    if mutation == "applied_order":
        outcome = replace(outcome, applied=tuple(reversed(outcome.applied)))
    elif mutation == "evidence_order":
        outcome = replace(outcome, _evidence=tuple(reversed(outcome._evidence)))
    else:
        parameters = {"shift_days": 0} if mutation == "zero" else {}
        plan = replace(plan, operations=tuple(
            replace(op, parameters=parameters) if op.op == "DATE_SHIFT" else op
            for op in plan.operations
        ))
    result = verify_case(text, profile, facts, plan, outcome)
    assert not result.passed
    for fact in facts:
        assert fact.value not in result.details
