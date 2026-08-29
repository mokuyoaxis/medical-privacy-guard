"""Unit tests for transformers (Phase 1 Step 3).

Coverage:
- REMOVE / MASK / TOKENIZE behavior
- TOKENIZE stability within one payload
- GENERALIZE / DATE_SHIFT for dates
- right-to-left span replacement (offsets stay valid)
- payload-derived DATE_SHIFT seed determinism
- end-to-end: detector → policy plan → transform
- failure modes: unknown op, TOKENIZE without raw value
- outcome never contains raw values
"""

import pytest

from core.errors import TransformerError
from core.model import (
    DetectedFact,
    DisclosurePlan,
    Purpose,
    Recipient,
    TransformationOp,
    TrustLevel,
)
from core.policy import PolicyEvaluator, load_builtin_profile
from detectors import detect_all
from transformers import TokenRegistry, apply_plan
from transformers.registry import TransformerRegistry


def fact(fact_type: str, start: int, end: int, value: str) -> DetectedFact:
    return DetectedFact(
        type=fact_type,
        start=start,
        end=end,
        confidence=1.0,
        source="test",
        value=value,
    )


def plan(*ops: TransformationOp) -> DisclosurePlan:
    return DisclosurePlan(operations=ops)


# -- REMOVE / MASK / TOKENIZE ------------------------------------------------


class TestTextOps:
    def test_remove(self):
        outcome = apply_plan(
            "电话13800000000",
            (fact("PHONE", 2, 13, "13800000000"),),
            plan(TransformationOp(op="REMOVE", target="PHONE", entity_type="PHONE")),
        )
        assert outcome.text == "电话[REDACTED]"
        assert outcome.applied == (
            TransformationOp(op="REMOVE", target="PHONE", entity_type="PHONE"),
        )

    def test_mask_preserves_length(self):
        outcome = apply_plan(
            "13800000000",
            (fact("PHONE", 0, 11, "13800000000"),),
            plan(TransformationOp(op="MASK", target="PHONE", entity_type="PHONE")),
        )
        assert outcome.text == "***********"

    def test_tokenize_same_value_same_token(self):
        # "张伟 张伟 李四": spans are (0,2) (3,5) (6,8) in code points.
        facts = (
            fact("PERSON_NAME", 0, 2, "张伟"),
            fact("PERSON_NAME", 3, 5, "张伟"),
            fact("PERSON_NAME", 6, 8, "李四"),
        )
        outcome = apply_plan(
            "张伟 张伟 李四",
            facts,
            plan(TransformationOp(op="TOKENIZE", target="PERSON_NAME", entity_type="PERSON_NAME")),
        )
        assert outcome.text == "[PERSON_NAME_001] [PERSON_NAME_001] [PERSON_NAME_002]"

    def test_tokenize_uses_explicit_registry_across_calls(self):
        tokens = TokenRegistry()
        op = TransformationOp(op="TOKENIZE", target="PERSON_NAME", entity_type="PERSON_NAME")
        out1 = apply_plan("张伟", (fact("PERSON_NAME", 0, 2, "张伟"),), plan(op), tokens=tokens)
        out2 = apply_plan("张伟", (fact("PERSON_NAME", 0, 2, "张伟"),), plan(op), tokens=tokens)
        assert out1.text == out2.text == "[PERSON_NAME_001]"

    def test_tokenize_without_value_raises(self):
        no_value = DetectedFact(
            type="PERSON_NAME", start=0, end=2, confidence=1.0, source="t"
        )
        with pytest.raises(TransformerError):
            apply_plan(
                "XX",
                (no_value,),
                plan(TransformationOp(op="TOKENIZE", target="PERSON_NAME", entity_type="PERSON_NAME")),
            )


# -- dates -------------------------------------------------------------------


class TestDateOps:
    def test_generalize_iso(self):
        outcome = apply_plan(
            "2026-08-29",
            (fact("EXACT_DATE", 0, 10, "2026-08-29"),),
            plan(TransformationOp(op="GENERALIZE", target="EXACT_DATE", entity_type="EXACT_DATE")),
        )
        assert outcome.text == "2026-08"

    def test_generalize_slash(self):
        outcome = apply_plan(
            "2026/08/29",
            (fact("EXACT_DATE", 0, 10, "2026/08/29"),),
            plan(TransformationOp(op="GENERALIZE", target="EXACT_DATE", entity_type="EXACT_DATE")),
        )
        assert outcome.text == "2026/08"

    def test_generalize_chinese(self):
        outcome = apply_plan(
            "2026年8月29日",
            (fact("EXACT_DATE", 0, 10, "2026年8月29日"),),
            plan(TransformationOp(op="GENERALIZE", target="EXACT_DATE", entity_type="EXACT_DATE")),
        )
        assert outcome.text == "2026年8月"

    def test_generalize_us_style(self):
        outcome = apply_plan(
            "08/29/2026",
            (fact("EXACT_DATE", 0, 10, "08/29/2026"),),
            plan(TransformationOp(op="GENERALIZE", target="EXACT_DATE", entity_type="EXACT_DATE")),
        )
        assert outcome.text == "2026-08"

    def test_date_shift_explicit_days(self):
        outcome = apply_plan(
            "2026-01-01",
            (fact("EXACT_DATE", 0, 10, "2026-01-01"),),
            plan(
                TransformationOp(
                    op="DATE_SHIFT",
                    target="EXACT_DATE",
                    entity_type="EXACT_DATE",
                    parameters={"shift_days": 5},
                )
            ),
        )
        assert outcome.text == "2026-01-06"

    def test_date_shift_preserves_interval(self):
        facts = (
            fact("EXACT_DATE", 0, 10, "2026-01-01"),
            fact("EXACT_DATE", 11, 21, "2026-02-01"),
        )
        outcome = apply_plan(
            "2026-01-01 2026-02-01",
            facts,
            plan(
                TransformationOp(
                    op="DATE_SHIFT",
                    target="EXACT_DATE",
                    entity_type="EXACT_DATE",
                    parameters={"shift_days": 5},
                )
            ),
        )
        assert outcome.text == "2026-01-06 2026-02-06"

    def test_date_shift_payload_seed_deterministic(self):
        op = TransformationOp(op="DATE_SHIFT", target="EXACT_DATE", entity_type="EXACT_DATE")
        facts = (fact("EXACT_DATE", 0, 10, "2026-03-15"),)
        o1 = apply_plan("2026-03-15", facts, plan(op))
        o2 = apply_plan("2026-03-15", facts, plan(op))
        assert o1.text == o2.text
        # And it actually moved (seed is nonzero with overwhelming probability).
        assert o1.text != "2026-03-15"


# -- span integrity ----------------------------------------------------------


class TestSpanIntegrity:
    def test_multiple_spans_right_to_left(self):
        outcome = apply_plan(
            "13800000000 13911112222",
            (
                fact("PHONE", 0, 11, "13800000000"),
                fact("PHONE", 12, 23, "13911112222"),
            ),
            plan(TransformationOp(op="REMOVE", target="PHONE", entity_type="PHONE")),
        )
        assert outcome.text == "[REDACTED] [REDACTED]"

    def test_mixed_ops_in_one_plan(self):
        outcome = apply_plan(
            "张伟 13800000000",
            (
                fact("PERSON_NAME", 0, 2, "张伟"),
                fact("PHONE", 3, 14, "13800000000"),
            ),
            plan(
                TransformationOp(op="TOKENIZE", target="PERSON_NAME", entity_type="PERSON_NAME"),
                TransformationOp(op="REMOVE", target="PHONE", entity_type="PHONE"),
            ),
        )
        assert outcome.text == "[PERSON_NAME_001] [REDACTED]"


# -- failure modes -----------------------------------------------------------


class TestFailureModes:
    def test_unknown_op_raises(self):
        registry = TransformerRegistry()
        with pytest.raises(TransformerError):
            registry.get("EXPLODE")

    def test_outcome_never_contains_raw_values(self):
        outcome = apply_plan(
            "13800000000",
            (fact("PHONE", 0, 11, "13800000000"),),
            plan(TransformationOp(op="REMOVE", target="PHONE", entity_type="PHONE")),
        )
        assert "13800000000" not in outcome.text
        assert "13800000000" not in str(outcome.applied)


# -- end to end --------------------------------------------------------------


class TestEndToEnd:
    def test_detect_policy_transform_loop(self):
        text = "电话13800000000"
        facts = detect_all(text)
        assert len(facts) == 1 and facts[0].type == "PHONE"

        evaluator = PolicyEvaluator(load_builtin_profile("external-ai-strict"))
        decision = evaluator.evaluate(
            facts,
            Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_UNKNOWN),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert decision.verdict.value == "SANITIZE"
        assert decision.plan is not None

        outcome = apply_plan(text, facts, decision.plan)
        assert outcome.text == "电话[REDACTED]"
