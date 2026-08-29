"""Core types and errors for medical-privacy-guard."""

from .audit import AuditEvent, AuditWriter, build_audit_event
from .errors import (
    AuditError,
    GuardError,
    ParserError,
    PolicyError,
    VerificationError,
)
from .model import (
    DataProvenance,
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
    SanitizationResult,
    TransformationOp,
    TrustLevel,
    Verdict,
)
from .policy import PolicyEvaluator, PolicyProfile, load_builtin_profile
from .verify import Verifier, verify_sanitized

__all__ = [
    # audit
    "AuditEvent",
    "AuditWriter",
    "build_audit_event",
    # errors
    "AuditError",
    "GuardError",
    "ParserError",
    "PolicyError",
    "VerificationError",
    # model
    "DataProvenance",
    "Decision",
    "DetectedFact",
    "DisclosurePlan",
    "DisclosureRequest",
    "EnvironmentContext",
    "EvaluationResult",
    "Payload",
    "PublicDetectedFact",
    "Purpose",
    "ReasonCode",
    "Recipient",
    "RiskFactor",
    "RiskLevel",
    "RiskSummary",
    "SanitizationResult",
    "TransformationOp",
    "TrustLevel",
    "Verdict",
    # policy
    "PolicyEvaluator",
    "PolicyProfile",
    "load_builtin_profile",
    # verify
    "Verifier",
    "verify_sanitized",
]
