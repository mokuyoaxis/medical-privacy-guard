"""Immutable core types for the medical-privacy-guard decision protocol.

All public data classes are frozen and hashable where practical. Types that may
contain raw sensitive values are marked as internal-only and must not be written
to audit logs or serialised to persistent storage without explicit handling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class Verdict(str, Enum):
    """The four possible outcomes of the privacy decision protocol."""

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    ASK = "ASK"
    BLOCK = "BLOCK"


class ReasonCode(str, Enum):
    """Stable, machine-readable reason codes for a Decision.

    Reason codes must never include raw sensitive values. They are intended for
    policy matching, adapter logic, test assertions, and audit metadata.
    """

    # Safe / benign
    NO_SENSITIVE_DATA_DETECTED = "NO_SENSITIVE_DATA_DETECTED"
    SYNTHETIC_DATA_CONFIRMED = "SYNTHETIC_DATA_CONFIRMED"

    # Direct identifiers
    DIRECT_IDENTIFIER_PRESENT = "DIRECT_IDENTIFIER_PRESENT"
    CONTACT_IDENTIFIER_PRESENT = "CONTACT_IDENTIFIER_PRESENT"
    NETWORK_IDENTIFIER_PRESENT = "NETWORK_IDENTIFIER_PRESENT"
    GOVERNMENT_ID_PRESENT = "GOVERNMENT_ID_PRESENT"
    MEDICAL_RECORD_IDENTIFIER_PRESENT = "MEDICAL_RECORD_IDENTIFIER_PRESENT"
    EXACT_DATE_PRESENT = "EXACT_DATE_PRESENT"
    PRECISE_LOCATION_PRESENT = "PRECISE_LOCATION_PRESENT"
    BIOMETRIC_DATA_PRESENT = "BIOMETRIC_DATA_PRESENT"
    GENETIC_DATA_PRESENT = "GENETIC_DATA_PRESENT"

    # Medical / quasi-identifier risk
    MEDICAL_CONTENT_PRESENT = "MEDICAL_CONTENT_PRESENT"
    QUASI_IDENTIFIER_COMBINATION = "QUASI_IDENTIFIER_COMBINATION"
    RARE_CONDITION_REIDENTIFICATION_RISK = "RARE_CONDITION_REIDENTIFICATION_RISK"

    # Recipient context
    EXTERNAL_RECIPIENT = "EXTERNAL_RECIPIENT"
    UNKNOWN_RECIPIENT = "UNKNOWN_RECIPIENT"
    UNTRUSTED_RECIPIENT = "UNTRUSTED_RECIPIENT"

    # Purpose / consent
    PURPOSE_NOT_DECLARED = "PURPOSE_NOT_DECLARED"
    PURPOSE_NOT_ALLOWED = "PURPOSE_NOT_ALLOWED"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    CONSENT_UNKNOWN = "CONSENT_UNKNOWN"

    # Transformation / verification
    TRANSFORMATION_AVAILABLE = "TRANSFORMATION_AVAILABLE"
    TRANSFORMATION_INCOMPLETE = "TRANSFORMATION_INCOMPLETE"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"

    # Format / policy errors
    PARSER_FAILURE = "PARSER_FAILURE"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    POLICY_CONFIGURATION_INVALID = "POLICY_CONFIGURATION_INVALID"
    RISK_THRESHOLD_EXCEEDED = "RISK_THRESHOLD_EXCEEDED"


class RiskLevel(str, Enum):
    """Engineering risk levels. Not a legal or statistical guarantee."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrustLevel(str, Enum):
    """Trust classification for a recipient."""

    LOCAL = "LOCAL"
    INTERNAL_TRUSTED = "INTERNAL_TRUSTED"
    EXTERNAL_APPROVED = "EXTERNAL_APPROVED"
    EXTERNAL_UNKNOWN = "EXTERNAL_UNKNOWN"
    EXTERNAL_BLOCKED = "EXTERNAL_BLOCKED"


class Purpose(str, Enum):
    """Declared purpose of the disclosure. Used as policy input only."""

    TREATMENT = "TREATMENT"
    RESEARCH = "RESEARCH"
    EDUCATION = "EDUCATION"
    OPERATIONS = "OPERATIONS"
    PUBLICATION = "PUBLICATION"
    EXTERNAL_AI_ASSISTANCE = "EXTERNAL_AI_ASSISTANCE"
    UNKNOWN = "UNKNOWN"


class DataProvenance(str, Enum):
    """Optional provenance hint for parser and risk selection."""

    EHR = "EHR"
    DICOM = "DICOM"
    FHIR = "FHIR"
    USER_PASTE = "USER_PASTE"
    FILE_UPLOAD = "FILE_UPLOAD"
    TOOL_OUTPUT = "TOOL_OUTPUT"


@dataclass(frozen=True)
class Payload:
    """A normalised payload ready for classification.

    v0.1 supports plain text content. JSON-like, FHIR and DICOM payloads are
    represented by this protocol type but fail closed until their format
    handlers are implemented.
    """

    kind: str  # e.g. "text", "json", "fhir", "dicom"
    content: Any  # str for text, Mapping for json, etc.
    provenance: DataProvenance | None = None


@dataclass(frozen=True)
class Recipient:
    """The intended recipient of a disclosure."""

    kind: str  # e.g. "llm", "mcp_tool", "http_api"
    name: str | None = None
    endpoint: str | None = None
    trust_level: TrustLevel = TrustLevel.EXTERNAL_UNKNOWN
    location: str | None = None  # e.g. "CN", "US-EU"
    data_retention: str | None = None


@dataclass(frozen=True)
class EnvironmentContext:
    """Additional runtime context that may affect policy."""

    host: str | None = None
    session_id: str | None = None
    provenance: DataProvenance | None = None
    extras: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectedFact:
    """A detector fact that may include a raw span/value.

    This type is INTERNAL-ONLY. It must not be persisted to audit logs or
    returned to adapters without first converting to PublicDetectedFact.
    """

    type: str
    start: int
    end: int
    confidence: float
    source: str
    value: str | None = None

    def to_public(self) -> PublicDetectedFact:
        """Return a privacy-safe representation for logging and audit."""
        return PublicDetectedFact(
            type=self.type,
            start=self.start,
            end=self.end,
            confidence=self.confidence,
            source=self.source,
        )


@dataclass(frozen=True)
class PublicDetectedFact:
    """Privacy-safe detector fact suitable for audit and adapter output.

    Does not contain the raw matched value.
    """

    type: str
    start: int
    end: int
    confidence: float
    source: str


@dataclass(frozen=True)
class RiskFactor:
    """A single re-identification risk factor."""

    code: str
    description: str
    score: int


@dataclass(frozen=True)
class RiskSummary:
    """Engineering risk summary. Not a legal or probabilistic guarantee."""

    level: RiskLevel
    score: int
    factors: tuple[RiskFactor, ...]


@dataclass(frozen=True)
class TransformationOp:
    """A single deterministic transformation operation."""

    op: str  # e.g. REMOVE, MASK, TOKENIZE, GENERALIZE, DATE_SHIFT
    target: str  # e.g. span identifier or field path
    entity_type: str | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DisclosurePlan:
    """The plan produced for a SANITIZE verdict.

    Must not contain raw sensitive values.
    """

    operations: tuple[TransformationOp, ...]
    verification_profile: str = "default"


@dataclass(frozen=True)
class Decision:
    """The outcome of policy evaluation."""

    verdict: Verdict
    reason_codes: tuple[ReasonCode, ...]
    explanation: str
    risk: RiskSummary
    plan: DisclosurePlan | None
    policy_version: str


@dataclass(frozen=True)
class DisclosureRequest:
    """The full request passed to the Guard for evaluation."""

    payload: Payload
    recipient: Recipient
    purpose: Purpose
    environment: EnvironmentContext
    policy_profile: str


@dataclass(frozen=True)
class EvaluationResult:
    """Result of evaluate(): a decision without modifying data."""

    decision: Decision
    facts: tuple[DetectedFact, ...]

    @property
    def public_facts(self) -> tuple[PublicDetectedFact, ...]:
        """Privacy-safe facts for audit and logging."""
        return tuple(f.to_public() for f in self.facts)


@dataclass(frozen=True)
class SanitizationResult:
    """Result of sanitize(): transform + verify."""

    decision_before: Decision
    sanitized_payload: Payload | None
    verification: VerificationResult | None
    decision_after: Decision | None


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of the post-transformation verification step."""

    passed: bool
    reason_codes: tuple[ReasonCode, ...]
    details: str
