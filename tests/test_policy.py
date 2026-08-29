"""Unit tests for the policy engine (Phase 1 Step 1).

Coverage goals:
- profiles load and validate (invalid config fails closed with PolicyError)
- deterministic decisions: identical input → identical Decision
- hard rules beat risk scores
- unknown fact types fail closed (TRANSFORMATION_INCOMPLETE)
- plan is only present for SANITIZE
- reason codes and explanations never contain raw PHI
- research profile differs from external-ai-strict where designed
"""

from copy import deepcopy

import pytest

from core.errors import PolicyError
from core.model import (
    DetectedFact,
    EnvironmentContext,
    Purpose,
    ReasonCode,
    Recipient,
    RiskLevel,
    TransformationOp,
    TrustLevel,
    Verdict,
)
from core.policy import (
    PolicyEvaluator,
    PolicyProfile,
    load_builtin_profile,
)


def fact(fact_type: str, value: str | None = "synthetic-value") -> DetectedFact:
    return DetectedFact(
        type=fact_type,
        start=0,
        end=len(value or ""),
        confidence=1.0,
        source="test",
        value=value,
    )


def external_unknown_recipient() -> Recipient:
    return Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_UNKNOWN)


def local_recipient() -> Recipient:
    return Recipient(kind="internal", trust_level=TrustLevel.LOCAL)


@pytest.fixture()
def strict():
    return PolicyEvaluator(load_builtin_profile("external-ai-strict"))


@pytest.fixture()
def research():
    return PolicyEvaluator(load_builtin_profile("research"))


# -- profile loading --------------------------------------------------------


class TestProfileLoading:
    def test_load_builtin_external_ai_strict(self):
        profile = load_builtin_profile("external-ai-strict")
        assert profile.profile == "external-ai-strict"
        assert profile.version == "1"
        assert profile.policy_version == "external-ai-strict/1"

    def test_load_builtin_research(self):
        profile = load_builtin_profile("research")
        assert profile.profile == "research"
        assert profile.policy_version == "research/1"

    def test_unknown_profile_raises(self):
        with pytest.raises(PolicyError):
            load_builtin_profile("does-not-exist")

    def test_invalid_yaml_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("profile: [unclosed", encoding="utf-8")
        with pytest.raises(PolicyError):
            PolicyProfile.load(bad)

    def test_missing_required_key_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "profile: p\nversion: '1'\nrules:\n  identifiers: {}\nrecipient_risk: {}\npurpose_risk: {}\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyError):
            PolicyProfile.load(bad)  # missing 'thresholds'

    def test_unknown_action_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "profile: p\nversion: '1'\n"
            "rules:\n  identifiers:\n    PHONE:\n      action: EXPLODE\n      risk_score: 1\n"
            "recipient_risk: {}\npurpose_risk: {}\nthresholds:\n  allow_max: 0\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyError):
            PolicyProfile.load(bad)

    def test_unknown_top_level_field_rejected(self):
        config = deepcopy(load_builtin_profile("external-ai-strict").config)
        config["surprise"] = "must not be ignored"
        with pytest.raises(PolicyError, match="unknown field"):
            PolicyProfile(config)

    def test_malformed_hard_rule_rejected(self):
        config = deepcopy(load_builtin_profile("external-ai-strict").config)
        config["rules"]["hard"][0]["condition"] = "not-a-mapping"
        with pytest.raises(PolicyError, match="condition must be a mapping"):
            PolicyProfile(config)

    def test_invalid_threshold_rejected(self):
        config = deepcopy(load_builtin_profile("external-ai-strict").config)
        config["thresholds"]["sanitize_max"] = "high"
        with pytest.raises(PolicyError, match="integer"):
            PolicyProfile(config)

    def test_unimplemented_planned_action_rejected_at_load(self):
        config = deepcopy(load_builtin_profile("external-ai-strict").config)
        config["rules"]["identifiers"]["PHONE"]["action"] = "HASH_PSEUDONYMIZE"
        with pytest.raises(PolicyError, match="unsupported action"):
            PolicyProfile(config)


# -- decision behavior ------------------------------------------------------


class TestDecisionBehavior:
    def test_empty_payload_allows(self, strict):
        decision = strict.evaluate((), local_recipient(), Purpose.TREATMENT)
        assert decision.verdict is Verdict.ALLOW
        assert decision.reason_codes == (ReasonCode.NO_SENSITIVE_DATA_DETECTED,)
        assert decision.plan is None

    def test_empty_payload_external_recipient_allows(self, strict):
        # Scenario risk (recipient/purpose) must not turn empty content into
        # SANITIZE: there is nothing to transform.
        decision = strict.evaluate(
            (), external_unknown_recipient(), Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert decision.verdict is Verdict.ALLOW
        assert decision.reason_codes == (ReasonCode.NO_SENSITIVE_DATA_DETECTED,)

    def test_blocked_recipient_always_blocks(self, strict):
        blocked = Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_BLOCKED)
        decision = strict.evaluate((), blocked, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert decision.verdict is Verdict.BLOCK
        assert ReasonCode.UNTRUSTED_RECIPIENT in decision.reason_codes

    def test_fact_only_parser_failure_hard_rule_blocks(self, strict):
        decision = strict.evaluate(
            (fact("PARSER_FAILURE"),),
            local_recipient(),
            Purpose.TREATMENT,
        )
        assert decision.verdict is Verdict.BLOCK
        assert ReasonCode.PARSER_FAILURE in decision.reason_codes

    def test_phone_external_unknown_sanitizes(self, strict):
        decision = strict.evaluate(
            (fact("PHONE", "13800000000"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.verdict is Verdict.SANITIZE
        assert ReasonCode.CONTACT_IDENTIFIER_PRESENT in decision.reason_codes
        assert ReasonCode.EXTERNAL_RECIPIENT in decision.reason_codes
        assert decision.plan is not None
        assert decision.plan.operations == (
            TransformationOp(op="REMOVE", target="PHONE", entity_type="PHONE"),
        )

    def test_government_id_external_unknown_blocks_by_hard_rule(self, strict):
        decision = strict.evaluate(
            (fact("GOVERNMENT_ID"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.verdict is Verdict.BLOCK
        assert ReasonCode.GOVERNMENT_ID_PRESENT in decision.reason_codes
        assert decision.plan is None

    def test_multiple_transformable_identifiers_sanitize_despite_raw_risk(self, strict):
        # Raw disclosure risk is high, but both identifiers have deterministic
        # transformations; verification, not a score shortcut, gates release.
        decision = strict.evaluate(
            (fact("PERSON_NAME"), fact("PHONE")),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.verdict is Verdict.SANITIZE
        assert decision.plan is not None
        assert len(decision.plan.operations) == 2

    def test_biometric_blocks(self, strict):
        decision = strict.evaluate(
            (fact("BIOMETRIC"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.verdict is Verdict.BLOCK
        assert ReasonCode.BIOMETRIC_DATA_PRESENT in decision.reason_codes

    def test_exact_date_generalized_in_strict(self, strict):
        decision = strict.evaluate(
            (fact("EXACT_DATE"),),
            external_unknown_recipient(),
            Purpose.TREATMENT,
        )
        assert decision.verdict is Verdict.SANITIZE
        assert decision.plan is not None
        assert decision.plan.operations[0].op == "GENERALIZE"

    def test_unknown_fact_type_fails_closed(self, strict):
        decision = strict.evaluate(
            (fact("SOME_WEIRD_ENTITY"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.verdict is Verdict.BLOCK
        assert ReasonCode.TRANSFORMATION_INCOMPLETE in decision.reason_codes

    def test_medical_content_alone_allows_for_declared_local_treatment(self, strict):
        decision = strict.evaluate(
            (fact("MEDICAL_CONTENT"),),
            local_recipient(),
            Purpose.TREATMENT,
        )
        assert decision.verdict is Verdict.ALLOW
        assert decision.plan is None
        assert ReasonCode.MEDICAL_CONTENT_PRESENT in decision.reason_codes

    def test_medical_content_external_unknown_requires_authorization(self, strict):
        decision = strict.evaluate(
            (fact("MEDICAL_CONTENT"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.verdict is Verdict.ASK
        assert ReasonCode.UNKNOWN_RECIPIENT in decision.reason_codes
        assert ReasonCode.CONSENT_REQUIRED in decision.reason_codes

    def test_plan_only_for_sanitize(self, strict):
        allow = strict.evaluate((), local_recipient(), Purpose.TREATMENT)
        block = strict.evaluate(
            (fact("GOVERNMENT_ID"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert allow.plan is None
        assert block.plan is None

    def test_research_allows_date_shift(self, research):
        decision = research.evaluate(
            (fact("EXACT_DATE"),),
            external_unknown_recipient(),
            Purpose.RESEARCH,
        )
        assert decision.verdict is Verdict.SANITIZE
        assert decision.plan is not None
        assert decision.plan.operations[0].op == "DATE_SHIFT"

    def test_research_government_id_external_approved_sanitizes(self, research):
        recipient = Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_APPROVED)
        decision = research.evaluate(
            (fact("GOVERNMENT_ID"),),
            recipient,
            Purpose.RESEARCH,
        )
        # research hard rule only blocks EXTERNAL_BLOCKED; score 40+5+0=45 <= 70
        assert decision.verdict is Verdict.SANITIZE
        assert decision.plan is not None
        assert decision.plan.operations[0].op == "REMOVE"

    def test_research_rare_condition_asks(self, research):
        decision = research.evaluate(
            (fact("RARE_CONDITION"),),
            external_unknown_recipient(),
            Purpose.RESEARCH,
        )
        assert decision.verdict is Verdict.ASK
        assert ReasonCode.RARE_CONDITION_REIDENTIFICATION_RISK in decision.reason_codes


# -- determinism and privacy -------------------------------------------------


class TestDeterminismAndPrivacy:
    def test_identical_inputs_yield_identical_decisions(self, strict):
        facts = (fact("PERSON_NAME"), fact("PHONE"))
        recipient = external_unknown_recipient()
        purpose = Purpose.EXTERNAL_AI_ASSISTANCE
        d1 = strict.evaluate(facts, recipient, purpose)
        d2 = strict.evaluate(facts, recipient, purpose)
        assert d1 == d2
        assert d1.reason_codes == d2.reason_codes
        assert d1.risk.score == d2.risk.score
        assert d1.plan == d2.plan

    def test_explanation_never_contains_raw_values(self, strict):
        decision = strict.evaluate(
            (fact("PHONE", "13800000000"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert "13800000000" not in decision.explanation
        assert "13800000000" not in " ".join(rc.value for rc in decision.reason_codes)

    def test_risk_summary_factors_exclude_raw_values(self, strict):
        decision = strict.evaluate(
            (fact("PERSON_NAME", "张伟"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        factor_text = " ".join(f.description for f in decision.risk.factors)
        assert "张伟" not in factor_text

    def test_decision_policy_version_stable(self, strict):
        decision = strict.evaluate(
            (fact("PHONE"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.policy_version == "external-ai-strict/1"

    def test_risk_level_is_engineering_not_legal(self, strict):
        decision = strict.evaluate(
            (fact("PHONE"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert isinstance(decision.risk.level, RiskLevel)

    def test_environment_context_is_accepted_but_ignored(self, strict):
        decision = strict.evaluate(
            (fact("PHONE"),),
            external_unknown_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
            environment=EnvironmentContext(host="localhost", session_id="s1"),
        )
        assert decision.verdict is Verdict.SANITIZE
