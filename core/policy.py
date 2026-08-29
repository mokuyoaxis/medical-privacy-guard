"""Policy engine: loads policy profiles and evaluates facts into a Decision.

Design (see plan.md §13):
- PolicyProfile loads and validates a YAML/JSON profile (invalid config → PolicyError, fail closed).
- PolicyEvaluator turns DetectedFacts + Recipient + Purpose into a stable Decision.
- Hard rules always win over risk scores (hard constraints > score).
- Reason codes and explanations never contain raw sensitive values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .errors import PolicyError
from .model import (
    Decision,
    DetectedFact,
    DisclosurePlan,
    EnvironmentContext,
    Purpose,
    ReasonCode,
    Recipient,
    RiskFactor,
    RiskLevel,
    RiskSummary,
    TransformationOp,
    TrustLevel,
    Verdict,
)

# Fact type → ReasonCode (stable, machine-readable)
_FACT_REASON_CODES: Mapping[str, ReasonCode] = {
    "PHONE": ReasonCode.CONTACT_IDENTIFIER_PRESENT,
    "EMAIL": ReasonCode.CONTACT_IDENTIFIER_PRESENT,
    "URL": ReasonCode.NETWORK_IDENTIFIER_PRESENT,
    "IP_ADDRESS": ReasonCode.NETWORK_IDENTIFIER_PRESENT,
    "PERSON_NAME": ReasonCode.DIRECT_IDENTIFIER_PRESENT,
    "GOVERNMENT_ID": ReasonCode.GOVERNMENT_ID_PRESENT,
    "MEDICAL_RECORD_NUMBER": ReasonCode.MEDICAL_RECORD_IDENTIFIER_PRESENT,
    "EXACT_DATE": ReasonCode.EXACT_DATE_PRESENT,
    "PRECISE_LOCATION": ReasonCode.PRECISE_LOCATION_PRESENT,
    "BIOMETRIC": ReasonCode.BIOMETRIC_DATA_PRESENT,
    "GENETIC": ReasonCode.GENETIC_DATA_PRESENT,
    "MEDICAL_CONTENT": ReasonCode.MEDICAL_CONTENT_PRESENT,
    "RARE_CONDITION": ReasonCode.RARE_CONDITION_REIDENTIFICATION_RISK,
    "PARSER_FAILURE": ReasonCode.PARSER_FAILURE,
    "UNSUPPORTED_FORMAT": ReasonCode.UNSUPPORTED_FORMAT,
}

# Fact type → human-readable description used in explanations (no raw PHI)
_FACT_LABELS: Mapping[str, str] = {
    "PHONE": "phone number",
    "EMAIL": "email address",
    "URL": "URL",
    "IP_ADDRESS": "IP address",
    "PERSON_NAME": "person name",
    "GOVERNMENT_ID": "government ID",
    "MEDICAL_RECORD_NUMBER": "medical record number",
    "EXACT_DATE": "exact date",
    "PRECISE_LOCATION": "precise location",
    "BIOMETRIC": "biometric data",
    "GENETIC": "genetic data",
    "MEDICAL_CONTENT": "medical content",
    "RARE_CONDITION": "rare condition signal",
    "PARSER_FAILURE": "unparseable input",
    "UNSUPPORTED_FORMAT": "unsupported format",
}

# Fallback risk for fact types not declared in a profile (fail-closed).
_UNKNOWN_FACT_RISK = 25

_TOP_LEVEL_KEYS = frozenset(
    {"profile", "version", "rules", "recipient_risk", "purpose_risk", "thresholds", "verification"}
)
_RULE_KEYS = frozenset({"hard", "identifiers", "medical"})
_IDENTIFIER_SPEC_KEYS = frozenset({"action", "risk_score"})
_MEDICAL_SPEC_KEYS = frozenset({"risk_score"})
_HARD_RULE_KEYS = frozenset({"condition", "verdict", "reason_code", "reason_codes"})
_CONDITION_KEYS = frozenset({"facts_contain", "recipient_trust_level"})
_THRESHOLD_KEYS = frozenset({"allow_max", "sanitize_max"})
_VERIFICATION_KEYS = frozenset({"required", "fail_verdict"})
_IMPLEMENTED_ACTIONS = frozenset(
    {"REMOVE", "MASK", "TOKENIZE", "GENERALIZE", "DATE_SHIFT", "BLOCK"}
)


def _risk_level_for_score(score: int) -> RiskLevel:
    """Map an engineering risk score to a RiskLevel. Not a legal threshold."""
    if score <= 20:
        return RiskLevel.LOW
    if score <= 50:
        return RiskLevel.MEDIUM
    if score <= 80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


class PolicyProfile:
    """A validated policy profile loaded from a YAML/JSON file.

    Attributes:
        profile: profile name (must match the file's `profile` key).
        version: string version, used in Decision.policy_version.
        config: the raw validated config mapping.
        source: origin path or label, for diagnostics only.
    """

    def __init__(self, config: Mapping[str, Any], source: str = "<memory>") -> None:
        self.config = dict(config)
        self.source = source
        self.profile = self._require_str("profile")
        self.version = self._require_str("version")
        self._validate()

    # -- loading -----------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "PolicyProfile":
        """Load and validate a profile from a YAML/JSON file.

        Raises PolicyError on unreadable file, invalid YAML, or invalid schema.
        """
        p = Path(path)
        try:
            raw = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy profile {p}: {exc}") from exc
        try:
            config = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise PolicyError(f"invalid YAML in policy profile {p}: {exc}") from exc
        if not isinstance(config, dict):
            raise PolicyError(f"policy profile {p} must be a mapping, got {type(config).__name__}")
        return cls(config, source=str(p))

    # -- accessors ---------------------------------------------------------

    @property
    def policy_version(self) -> str:
        return f"{self.profile}/{self.version}"

    def threshold(self, key: str, default: int = 0) -> int:
        return int(self.config.get("thresholds", {}).get(key, default))

    def verification_required(self) -> bool:
        return bool(self.config.get("verification", {}).get("required", True))

    # -- schema validation (fail closed) -----------------------------------

    def _require(self, key: str) -> Any:
        if key not in self.config:
            raise PolicyError(f"policy profile {self.source}: missing required key '{key}'")
        return self.config[key]

    def _require_str(self, key: str) -> str:
        value = self._require(key)
        if not isinstance(value, str):
            raise PolicyError(
                f"policy profile {self.source}: key '{key}' must be a string, got {type(value).__name__}"
            )
        return value

    def _validate(self) -> None:
        self._reject_unknown(self.config, _TOP_LEVEL_KEYS, "policy profile")
        rules = self.config.get("rules")
        if not isinstance(rules, dict):
            raise PolicyError(f"policy profile {self.source}: 'rules' must be a mapping")
        self._reject_unknown(rules, _RULE_KEYS, "rules")
        if "identifiers" not in rules:
            raise PolicyError(f"policy profile {self.source}: 'rules.identifiers' is required")
        identifiers = rules["identifiers"]
        if not isinstance(identifiers, dict):
            raise PolicyError(f"policy profile {self.source}: 'rules.identifiers' must be a mapping")
        for fact_type, spec in identifiers.items():
            if not isinstance(fact_type, str) or not fact_type:
                raise PolicyError(
                    f"policy profile {self.source}: identifier names must be non-empty strings"
                )
            if not isinstance(spec, dict) or "action" not in spec:
                raise PolicyError(
                    f"policy profile {self.source}: identifier '{fact_type}' needs an 'action'"
                )
            self._reject_unknown(spec, _IDENTIFIER_SPEC_KEYS, f"identifier '{fact_type}'")
            action = spec["action"]
            if action not in _IMPLEMENTED_ACTIONS:
                raise PolicyError(
                    f"policy profile {self.source}: unsupported action '{action}' for '{fact_type}'"
                )
            self._validate_score(spec.get("risk_score"), f"identifier '{fact_type}'.risk_score")

        medical = rules.get("medical", {})
        if not isinstance(medical, dict):
            raise PolicyError(f"policy profile {self.source}: 'rules.medical' must be a mapping")
        for fact_type, spec in medical.items():
            if not isinstance(fact_type, str) or not isinstance(spec, dict):
                raise PolicyError(
                    f"policy profile {self.source}: medical rules must map names to mappings"
                )
            self._reject_unknown(spec, _MEDICAL_SPEC_KEYS, f"medical rule '{fact_type}'")
            self._validate_score(spec.get("risk_score"), f"medical rule '{fact_type}'.risk_score")

        self._validate_hard_rules(rules.get("hard", []))

        if "recipient_risk" not in self.config or "purpose_risk" not in self.config:
            raise PolicyError(
                f"policy profile {self.source}: 'recipient_risk' and 'purpose_risk' are required"
            )
        self._validate_score_map(
            self.config["recipient_risk"],
            {level.value for level in TrustLevel},
            "recipient_risk",
        )
        self._validate_score_map(
            self.config["purpose_risk"],
            {purpose.value for purpose in Purpose},
            "purpose_risk",
        )
        self._validate_thresholds(self.config.get("thresholds"))
        self._validate_verification(self.config.get("verification"))

    def _reject_unknown(
        self,
        mapping: Mapping[str, Any],
        allowed: frozenset[str],
        path: str,
    ) -> None:
        unknown = set(mapping) - allowed
        if unknown:
            raise PolicyError(
                f"policy profile {self.source}: unknown field(s) in {path}: "
                f"{', '.join(sorted(str(key) for key in unknown))}"
            )

    def _validate_score(self, value: Any, path: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
            raise PolicyError(
                f"policy profile {self.source}: {path} must be an integer from 0 to 100"
            )

    def _validate_score_map(
        self,
        value: Any,
        expected_keys: set[str],
        path: str,
    ) -> None:
        if not isinstance(value, dict):
            raise PolicyError(f"policy profile {self.source}: '{path}' must be a mapping")
        actual = set(value)
        if actual != expected_keys:
            missing = expected_keys - actual
            unknown = actual - expected_keys
            details = []
            if missing:
                details.append(f"missing {', '.join(sorted(missing))}")
            if unknown:
                details.append(f"unknown {', '.join(sorted(str(key) for key in unknown))}")
            raise PolicyError(
                f"policy profile {self.source}: invalid '{path}' keys ({'; '.join(details)})"
            )
        for key, score in value.items():
            self._validate_score(score, f"{path}.{key}")

    def _validate_hard_rules(self, value: Any) -> None:
        if not isinstance(value, list):
            raise PolicyError(f"policy profile {self.source}: 'rules.hard' must be a list")
        for index, rule in enumerate(value):
            path = f"rules.hard[{index}]"
            if not isinstance(rule, dict):
                raise PolicyError(f"policy profile {self.source}: {path} must be a mapping")
            self._reject_unknown(rule, _HARD_RULE_KEYS, path)
            condition = rule.get("condition")
            if not isinstance(condition, dict):
                raise PolicyError(
                    f"policy profile {self.source}: {path}.condition must be a mapping"
                )
            self._reject_unknown(condition, _CONDITION_KEYS, f"{path}.condition")
            if not condition:
                raise PolicyError(
                    f"policy profile {self.source}: {path}.condition cannot be empty"
                )
            facts = condition.get("facts_contain", [])
            trusts = condition.get("recipient_trust_level", [])
            if not isinstance(facts, list) or not all(isinstance(item, str) for item in facts):
                raise PolicyError(
                    f"policy profile {self.source}: {path}.condition.facts_contain must be a string list"
                )
            if not isinstance(trusts, list) or not all(isinstance(item, str) for item in trusts):
                raise PolicyError(
                    f"policy profile {self.source}: {path}.condition.recipient_trust_level must be a string list"
                )
            invalid_trusts = set(trusts) - {level.value for level in TrustLevel}
            if invalid_trusts:
                raise PolicyError(
                    f"policy profile {self.source}: {path} has unknown trust level(s): "
                    f"{', '.join(sorted(invalid_trusts))}"
                )
            try:
                Verdict(rule.get("verdict"))
            except (TypeError, ValueError) as exc:
                raise PolicyError(
                    f"policy profile {self.source}: {path}.verdict is invalid"
                ) from exc
            has_one = "reason_code" in rule
            has_many = "reason_codes" in rule
            if has_one == has_many:
                raise PolicyError(
                    f"policy profile {self.source}: {path} requires exactly one of reason_code/reason_codes"
                )
            codes = [rule["reason_code"]] if has_one else rule["reason_codes"]
            if not isinstance(codes, list) or not codes:
                raise PolicyError(
                    f"policy profile {self.source}: {path} reason codes must be a non-empty list"
                )
            try:
                tuple(ReasonCode(code) for code in codes)
            except (TypeError, ValueError) as exc:
                raise PolicyError(
                    f"policy profile {self.source}: {path} contains an invalid reason code"
                ) from exc

    def _validate_thresholds(self, value: Any) -> None:
        if not isinstance(value, dict):
            raise PolicyError(f"policy profile {self.source}: 'thresholds' must be a mapping")
        self._reject_unknown(value, _THRESHOLD_KEYS, "thresholds")
        if set(value) != _THRESHOLD_KEYS:
            missing = _THRESHOLD_KEYS - set(value)
            raise PolicyError(
                f"policy profile {self.source}: thresholds missing {', '.join(sorted(missing))}"
            )
        for key, score in value.items():
            self._validate_score(score, f"thresholds.{key}")
        if value["allow_max"] > value["sanitize_max"]:
            raise PolicyError(
                f"policy profile {self.source}: allow_max cannot exceed sanitize_max"
            )

    def _validate_verification(self, value: Any) -> None:
        if not isinstance(value, dict):
            raise PolicyError(f"policy profile {self.source}: 'verification' must be a mapping")
        self._reject_unknown(value, _VERIFICATION_KEYS, "verification")
        if value.get("required") is not True or value.get("fail_verdict") != Verdict.BLOCK.value:
            raise PolicyError(
                f"policy profile {self.source}: verification must require fail_verdict BLOCK"
            )

    def action_for(self, fact_type: str) -> str | None:
        """Return the configured action for a fact type, or None if not declared."""
        identifiers = self.config.get("rules", {}).get("identifiers", {})
        spec = identifiers.get(fact_type)
        return spec.get("action") if isinstance(spec, dict) else None

    def is_declared(self, fact_type: str) -> bool:
        """True if the fact type appears in identifiers or medical sections."""
        rules = self.config.get("rules", {})
        return fact_type in rules.get("identifiers", {}) or fact_type in rules.get("medical", {})

    def risk_for(self, fact_type: str) -> int:
        """Return the risk contribution for a fact type (unknown → _UNKNOWN_FACT_RISK)."""
        rules = self.config.get("rules", {})
        identifiers = rules.get("identifiers", {})
        medical = rules.get("medical", {})
        for section in (identifiers, medical):
            spec = section.get(fact_type)
            if isinstance(spec, dict) and "risk_score" in spec:
                return int(spec["risk_score"])
        return _UNKNOWN_FACT_RISK

    def hard_rules(self) -> Sequence[Mapping[str, Any]]:
        return list(self.config.get("rules", {}).get("hard", []) or [])


class PolicyEvaluator:
    """Evaluates DetectedFacts + context into a stable Decision for one profile."""

    def __init__(self, profile: PolicyProfile) -> None:
        self.profile = profile

    # -- public API --------------------------------------------------------

    def evaluate(
        self,
        facts: Sequence[DetectedFact],
        recipient: Recipient,
        purpose: Purpose,
        environment: EnvironmentContext | None = None,
    ) -> Decision:
        """Evaluate facts against the profile.

        Raises PolicyError only for configuration errors. Input-level problems
        (e.g. PARSER_FAILURE facts) surface as BLOCK decisions, per fail-closed.
        """
        del environment  # reserved for future context inputs
        fact_types = tuple(f.type for f in facts)

        risk = self._compute_risk(facts, recipient, purpose)

        hard = self._check_hard_rules(fact_types, recipient)
        if hard is not None:
            verdict, reason_codes = hard
            return self._decision(
                verdict=verdict,
                reason_codes=reason_codes,
                risk=risk,
                plan=None,
                explanation=f"Hard rule triggered: {', '.join(rc.value for rc in reason_codes)}.",
            )

        # No sensitive content: recipient/purpose risk is a *scenario* risk
        # that transformations cannot fix, so it must not turn an empty
        # payload into SANITIZE (which would have nothing to transform).
        # Absence of detected facts is provably safe content-wise; hard rules
        # above already handled blocked recipients.
        if not fact_types:
            return self._decision(
                verdict=Verdict.ALLOW,
                reason_codes=(ReasonCode.NO_SENSITIVE_DATA_DETECTED,),
                risk=risk,
                plan=None,
                explanation="No sensitive data detected; release as-is.",
            )

        # Block-worthy types (action == BLOCK) are never auto-sanitized.
        block_types = {
            ft
            for ft in fact_types
            if self.profile.action_for(ft) == "BLOCK"
        }
        if block_types:
            codes = tuple(dict.fromkeys(_FACT_REASON_CODES.get(t, ReasonCode.RISK_THRESHOLD_EXCEEDED) for t in block_types))
            return self._decision(
                verdict=Verdict.BLOCK,
                reason_codes=codes,
                risk=risk,
                plan=None,
                explanation=f"Detected non-transformable sensitive content ({', '.join(sorted(block_types))}); release blocked.",
            )

        # Unknown fact types cannot be transformed → fail closed.
        undeclared = {
            ft
            for ft in fact_types
            if not self.profile.is_declared(ft)
        }
        if undeclared:
            return self._decision(
                verdict=Verdict.BLOCK,
                reason_codes=(ReasonCode.TRANSFORMATION_INCOMPLETE,),
                risk=risk,
                plan=None,
                explanation=(
                    f"Detected fact type(s) not covered by profile {self.profile.profile} "
                    f"({', '.join(sorted(undeclared))}); cannot guarantee safe transformation."
                ),
            )

        # A declared purpose is required before disclosing detected sensitive
        # content.  This is the normal, non-mocked ASK path: the caller must
        # provide context instead of a risk score guessing intent.
        if purpose is Purpose.UNKNOWN:
            return self._decision(
                verdict=Verdict.ASK,
                reason_codes=(ReasonCode.PURPOSE_NOT_DECLARED, ReasonCode.CONSENT_UNKNOWN),
                risk=risk,
                plan=None,
                explanation="Sensitive content was detected but the disclosure purpose is unknown; human context is required.",
            )

        # Rare-condition signals are not safely fixed by span replacement.
        # External disclosure therefore needs scoped human review.
        if (
            "RARE_CONDITION" in fact_types
            and recipient.trust_level
            in (TrustLevel.EXTERNAL_UNKNOWN, TrustLevel.EXTERNAL_APPROVED)
        ):
            return self._decision(
                verdict=Verdict.ASK,
                reason_codes=(
                    ReasonCode.RARE_CONDITION_REIDENTIFICATION_RISK,
                    ReasonCode.CONSENT_REQUIRED,
                ),
                risk=risk,
                plan=None,
                explanation="A rare-condition re-identification signal requires scoped human review before external disclosure.",
            )

        # Medical content remains sensitive even after direct identifiers are
        # absent.  A declared purpose alone does not authorize disclosure to
        # an unknown external endpoint; require scoped human approval or an
        # explicitly approved recipient.
        if (
            "MEDICAL_CONTENT" in fact_types
            and recipient.trust_level is TrustLevel.EXTERNAL_UNKNOWN
        ):
            return self._decision(
                verdict=Verdict.ASK,
                reason_codes=(
                    ReasonCode.MEDICAL_CONTENT_PRESENT,
                    ReasonCode.UNKNOWN_RECIPIENT,
                    ReasonCode.CONSENT_REQUIRED,
                ),
                risk=risk,
                plan=None,
                explanation="Medical content targeting an unknown external recipient requires scoped human authorization.",
            )

        # Verdict is based on transformability, not on the raw pre-transform
        # risk score alone.  If every direct identifier has a deterministic
        # operation, prepare the plan and let verification decide release.
        # This keeps high-risk but repairable records on the safe automatic
        # path while hard rules above still take precedence.
        plan = self._build_plan(fact_types)
        if plan.operations:
            reason_codes = self._sanitize_reason_codes(fact_types, recipient)
            return self._decision(
                verdict=Verdict.SANITIZE,
                reason_codes=reason_codes,
                risk=risk,
                plan=plan,
                explanation=(
                    f"Sensitive content detected ({', '.join(sorted(set(fact_types)))}); "
                    "transformation plan prepared, verification required before release."
                ),
            )

        # MEDICAL_CONTENT is a contextual classification, not a span to erase:
        # under a declared purpose it may remain after direct identifiers have
        # been removed.  It is still surfaced in the decision and audit.
        if set(fact_types) == {"MEDICAL_CONTENT"}:
            return self._decision(
                verdict=Verdict.ALLOW,
                reason_codes=(ReasonCode.MEDICAL_CONTENT_PRESENT,),
                risk=risk,
                plan=None,
                explanation="Medical content is present, but no configured direct identifier remains under the declared purpose.",
            )

        return self._decision(
            verdict=Verdict.BLOCK,
            reason_codes=(ReasonCode.TRANSFORMATION_INCOMPLETE,),
            risk=risk,
            plan=None,
            explanation="Sensitive content remains without a verified transformation; release blocked.",
        )

    # -- internals ---------------------------------------------------------

    def _compute_risk(
        self,
        facts: Sequence[DetectedFact],
        recipient: Recipient,
        purpose: Purpose,
    ) -> RiskSummary:
        factors: list[RiskFactor] = []
        seen_types: set[str] = set()
        total = 0

        for fact in facts:
            ft = fact.type
            if ft in seen_types:
                continue
            seen_types.add(ft)
            score = self.profile.risk_for(ft)
            total += score
            label = _FACT_LABELS.get(ft, ft)
            factors.append(RiskFactor(code=ft, description=f"{label} present", score=score))

        recipient_score = self.profile.config.get("recipient_risk", {}).get(recipient.trust_level.value, 20)
        total += recipient_score
        factors.append(
            RiskFactor(
                code=recipient.trust_level.value,
                description=f"recipient trust level {recipient.trust_level.value}",
                score=recipient_score,
            )
        )

        purpose_score = self.profile.config.get("purpose_risk", {}).get(purpose.value, 20)
        total += purpose_score
        factors.append(
            RiskFactor(
                code=purpose.value,
                description=f"purpose {purpose.value}",
                score=purpose_score,
            )
        )

        return RiskSummary(
            level=_risk_level_for_score(total),
            score=total,
            factors=tuple(factors),
        )

    def _check_hard_rules(
        self, fact_types: Sequence[str], recipient: Recipient
    ) -> tuple[Verdict, tuple[ReasonCode, ...]] | None:
        present = set(fact_types)
        trust = recipient.trust_level.value
        for rule in self.profile.hard_rules():
            condition = rule.get("condition", {})
            required = set(condition.get("facts_contain", []))
            allowed_trust = set(condition.get("recipient_trust_level", []))
            # An empty facts_contain list matches ANY fact set (including none),
            # so rules like "EXTERNAL_BLOCKED recipient → BLOCK" work.
            if required and not required.issubset(present):
                continue
            if allowed_trust and trust not in allowed_trust:
                continue
            verdict = Verdict(rule["verdict"])
            raw_codes = rule.get("reason_codes") or [rule["reason_code"]]
            codes = tuple(dict.fromkeys(ReasonCode(rc) for rc in raw_codes))
            return verdict, codes
        return None

    def _sanitize_reason_codes(
        self, fact_types: Sequence[str], recipient: Recipient
    ) -> tuple[ReasonCode, ...]:
        codes: list[ReasonCode] = []
        for ft in dict.fromkeys(fact_types):
            rc = _FACT_REASON_CODES.get(ft)
            if rc is not None and rc not in codes:
                codes.append(rc)
        if recipient.trust_level in (TrustLevel.EXTERNAL_UNKNOWN, TrustLevel.EXTERNAL_APPROVED, TrustLevel.EXTERNAL_BLOCKED):
            if ReasonCode.EXTERNAL_RECIPIENT not in codes:
                codes.append(ReasonCode.EXTERNAL_RECIPIENT)
        return tuple(codes)

    def _build_plan(self, fact_types: Sequence[str]) -> DisclosurePlan:
        operations: list[TransformationOp] = []
        for ft in dict.fromkeys(fact_types):
            action = self.profile.action_for(ft)
            if action is None or action == "BLOCK":
                continue
            operations.append(
                TransformationOp(op=action, target=ft, entity_type=ft)
            )
        return DisclosurePlan(operations=tuple(operations))

    def _decision(
        self,
        *,
        verdict: Verdict,
        reason_codes: tuple[ReasonCode, ...],
        risk: RiskSummary,
        plan: DisclosurePlan | None,
        explanation: str,
    ) -> Decision:
        return Decision(
            verdict=verdict,
            reason_codes=reason_codes,
            explanation=explanation,
            risk=risk,
            plan=plan,
            policy_version=self.profile.policy_version,
        )


# -- builtin profile loading ------------------------------------------------

_POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"


def load_builtin_profile(name: str) -> PolicyProfile:
    """Load a profile from the bundled `policies/` directory.

    Raises PolicyError if the profile does not exist or is invalid.
    """
    path = _POLICIES_DIR / f"{name}.yaml"
    if not path.is_file():
        raise PolicyError(f"unknown policy profile '{name}': no such bundled profile")
    return PolicyProfile.load(path)
