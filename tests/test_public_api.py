"""Public API surface: stable exports and ergonomic result accessors."""

from __future__ import annotations

import json

from medical_privacy_guard import (
    Decision,
    EvaluationResult,
    Guard,
    Payload,
    SanitizationResult,
    Verdict,
    VerificationResult,
)

_PUBLIC_NAMES = (
    "Guard",
    "Verdict",
    "ReasonCode",
    "RiskLevel",
    "TrustLevel",
    "Purpose",
    "Payload",
    "Recipient",
    "EnvironmentContext",
    "Decision",
    "DetectedFact",
    "PublicDetectedFact",
    "RiskFactor",
    "RiskSummary",
    "DisclosurePlan",
    "TransformationOp",
    "EvaluationResult",
    "SanitizationResult",
    "VerificationResult",
    "GuardError",
    "DictionaryError",
    "ParserError",
    "PolicyError",
    "TransformerError",
    "AuditError",
    "GrantError",
    "DisclosureBlocked",
    "HumanApprovalRequired",
    "VerificationError",
    "VerificationFailed",
)


def test_public_exports_are_complete_and_unique():
    import medical_privacy_guard as mpg

    assert len(mpg.__all__) == len(set(mpg.__all__))
    for name in _PUBLIC_NAMES:
        assert name in mpg.__all__, name
        assert getattr(mpg, name) is not None, name


def test_evaluation_result_has_direct_accessors():
    result: EvaluationResult = Guard().evaluate(
        "电话13800000000",
        "external_unknown",
        "EXTERNAL_AI_ASSISTANCE",
    )
    assert isinstance(result, EvaluationResult)
    assert result.verdict is Verdict.SANITIZE
    summary = result.public_summary()
    assert summary["verdict"] == "SANITIZE"
    assert summary["fact_count"] == 1
    assert "13800000000" not in json.dumps(summary, ensure_ascii=False)


def test_sanitization_result_exposes_released_text_and_summary():
    result: SanitizationResult = Guard().sanitize(
        "电话13800000000",
        "external_unknown",
        "EXTERNAL_AI_ASSISTANCE",
    )
    assert isinstance(result, SanitizationResult)
    assert result.verdict is Verdict.SANITIZE
    assert result.released is True
    assert result.text is not None
    assert "13800000000" not in result.text
    summary = result.public_summary()
    assert summary["released"] is True
    assert summary["verification_passed"] is True
    assert "13800000000" not in json.dumps(summary, ensure_ascii=False)


def test_withheld_result_has_no_text():
    result = Guard().sanitize(
        Payload(kind="binary", content="not a supported payload"),
        "external_unknown",
        "EXTERNAL_AI_ASSISTANCE",
    )
    assert result.verdict is Verdict.BLOCK
    assert result.released is False
    assert result.text is None
    assert result.public_summary()["released"] is False


def test_verification_result_type_is_public():
    result = Guard().sanitize(
        "电话13800000000",
        "external_unknown",
        "EXTERNAL_AI_ASSISTANCE",
    )
    assert isinstance(result.verification, VerificationResult)
    assert isinstance(result.decision_before, Decision)
