"""Unit tests for core model types.

These tests verify the Phase 0 invariants: types are immutable, reason codes
are stable, and the public/internal fact split correctly removes raw values.
"""

from dataclasses import FrozenInstanceError

import pytest

from core.errors import AuditError, GuardError, ParserError, PolicyError, VerificationError
from core.model import (
    Decision,
    DetectedFact,
    DisclosurePlan,
    DisclosureRequest,
    EnvironmentContext,
    EvaluationResult,
    Payload,
    PublicDetectedFact,
    Purpose,
    ReasonCode,
    Recipient,
    RiskFactor,
    RiskLevel,
    RiskSummary,
    TransformationOp,
    TrustLevel,
    Verdict,
    VerificationResult,
)


def test_verdict_enum_values():
    assert Verdict.ALLOW.value == "ALLOW"
    assert Verdict.SANITIZE.value == "SANITIZE"
    assert Verdict.ASK.value == "ASK"
    assert Verdict.BLOCK.value == "BLOCK"


def test_reason_codes_are_stable_strings():
    assert ReasonCode.GOVERNMENT_ID_PRESENT.value == "GOVERNMENT_ID_PRESENT"
    assert ReasonCode.EXTERNAL_RECIPIENT.value == "EXTERNAL_RECIPIENT"
    assert ReasonCode.VERIFICATION_FAILED.value == "VERIFICATION_FAILED"


def test_decision_is_frozen():
    risk = RiskSummary(
        level=RiskLevel.HIGH,
        score=72,
        factors=(RiskFactor("DIRECT_ID", "direct identifier present", 40),),
    )
    decision = Decision(
        verdict=Verdict.SANITIZE,
        reason_codes=(ReasonCode.DIRECT_IDENTIFIER_PRESENT,),
        explanation="Direct identifier present.",
        risk=risk,
        plan=None,
        policy_version="external-ai-strict/1",
    )
    with pytest.raises(FrozenInstanceError):
        decision.verdict = Verdict.BLOCK


def test_decision_explanation_must_not_include_raw_phi_by_convention():
    # This is a convention test: explanations are human-readable strings and the
    # implementation must never populate them with raw sensitive values.
    decision = Decision(
        verdict=Verdict.BLOCK,
        reason_codes=(ReasonCode.CONTACT_IDENTIFIER_PRESENT,),
        explanation="Phone number detected; raw value intentionally omitted.",
        risk=RiskSummary(
            level=RiskLevel.HIGH,
            score=40,
            factors=(RiskFactor("PHONE", "phone present", 20),),
        ),
        plan=None,
        policy_version="external-ai-strict/1",
    )
    assert "138" not in decision.explanation
    assert "张三" not in decision.explanation


def test_detected_fact_to_public_strips_value():
    fact = DetectedFact(
        type="PHONE",
        start=10,
        end=21,
        confidence=1.0,
        source="regex.cn_phone",
        value="13800000000",
    )
    public = fact.to_public()
    assert isinstance(public, PublicDetectedFact)
    assert public.type == "PHONE"
    assert public.start == 10
    assert public.end == 21
    assert not hasattr(public, "value")  # Public facts intentionally omit raw values.
    assert public.confidence == 1.0


def test_evaluation_result_public_facts_exclude_values():
    facts = (
        DetectedFact(
            type="PERSON_NAME",
            start=0,
            end=2,
            confidence=0.95,
            source="heuristic",
            value="张伟",
        ),
    )
    decision = Decision(
        verdict=Verdict.SANITIZE,
        reason_codes=(ReasonCode.DIRECT_IDENTIFIER_PRESENT,),
        explanation="Name detected.",
        risk=RiskSummary(
            level=RiskLevel.HIGH,
            score=40,
            factors=(RiskFactor("PERSON_NAME", "name present", 20),),
        ),
        plan=DisclosurePlan(
            operations=(
                TransformationOp(op="TOKENIZE", target="span-0", entity_type="PERSON_NAME"),
            )
        ),
        policy_version="external-ai-strict/1",
    )
    result = EvaluationResult(decision=decision, facts=facts)
    public = result.public_facts
    assert len(public) == 1
    assert not hasattr(public[0], "value")  # Public facts intentionally omit raw values.
    assert public[0].type == "PERSON_NAME"


def test_disclosure_request_is_frozen():
    request = DisclosureRequest(
        payload=Payload(kind="text", content="synthetic note"),
        recipient=Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_UNKNOWN),
        purpose=Purpose.EXTERNAL_AI_ASSISTANCE,
        environment=EnvironmentContext(host="localhost"),
        policy_profile="external-ai-strict",
    )
    with pytest.raises(FrozenInstanceError):
        request.policy_profile = "research"


def test_default_recipient_is_external_unknown():
    recipient = Recipient(kind="llm")
    assert recipient.trust_level is TrustLevel.EXTERNAL_UNKNOWN
    assert recipient.endpoint is None


def test_verification_result_passed():
    v = VerificationResult(passed=True, reason_codes=(), details="No residual identifiers.")
    assert v.passed is True


def test_errors_inherit_from_guard_error():
    assert issubclass(ParserError, GuardError)
    assert issubclass(PolicyError, GuardError)
    assert issubclass(VerificationError, GuardError)
    assert issubclass(AuditError, GuardError)
