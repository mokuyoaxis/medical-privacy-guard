"""medical-privacy-guard: local-first privacy guardrails for medical data.

The supported public API is the ``Guard`` class, the result and decision types,
and the guard-specific exceptions re-exported here. Internal modules remain
available under ``medical_privacy_guard.core``, ``medical_privacy_guard.detectors``
and the other subpackages, but only this module's exports are promised as stable.

Example::

    from medical_privacy_guard import Guard

    guard = Guard(profile="external-ai-strict")
    result = guard.sanitize(
        text,
        recipient="external-ai",
        purpose="EXTERNAL_AI_ASSISTANCE",
    )
    if result.released:
        send(result.text)
"""

from .core.errors import (
    AuditError,
    DictionaryError,
    DisclosureBlocked,
    GrantError,
    GuardError,
    HumanApprovalRequired,
    ParserError,
    PolicyError,
    TransformerError,
    VerificationError,
    VerificationFailed,
)
from .core.model import (
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
    VerificationResult,
)
from .guard import Guard

__version__ = "0.6.0rc1"

__all__ = [
    "__version__",
    "Guard",
    # results and decisions
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
    "VerificationResult",
    # errors
    "AuditError",
    "DictionaryError",
    "DisclosureBlocked",
    "GrantError",
    "GuardError",
    "HumanApprovalRequired",
    "ParserError",
    "PolicyError",
    "TransformerError",
    "VerificationError",
    "VerificationFailed",
]
