"""Unit tests for transformers (Phase 1 Step 3).

Coverage:
- REMOVE / MASK / TOKENIZE behavior
- TOKENIZE stability within one payload
- GENERALIZE / DATE_SHIFT for dates
- right-to-left span replacement (offsets stay valid)
- payload-derived DATE_SHIFT seed determinism
- end-to-end: detector → policy plan → transform
- failure modes: unknown op, TOKENIZE without raw value
- outcome and evidence repr do not expose payload values
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


# -- idempotency -------------------------------------------------------------
#
# Verification re-detects the sanitized output. If a transformation's own
# output looks like fresh input, the pipeline never reaches a fixed point: the
# policy re-run keeps demanding work and nothing is ever released. Both the age
# bands and the type markers violated this.


class TestIdempotency:
    def test_age_bands_are_not_re_detected_as_ages(self):
        from transformers.generalize import _AGE_BANDS

        for _, _, label in _AGE_BANDS:
            text = f"年龄：{label}"
            found = [f.type for f in detect_all(text) if f.type == "AGE"]
            assert found == [], (label, found)

    def test_type_markers_do_not_re_detect_their_own_type(self):
        from transformers.generalize import _TYPE_MARKERS

        for fact_type, marker in sorted(_TYPE_MARKERS.items()):
            text = f"字段：{marker}"
            found = [f.type for f in detect_all(text)]
            assert fact_type not in found, (fact_type, marker, found)

    def test_sanitized_output_needs_no_further_transformation(self):
        text = (
            "患者：测试患者甲，性别：男，年龄：67岁\n"
            "联系地址：北京市朝阳区建国路88号院2号楼\n"
            "住院号：SYNTH-MRN-0001\n"
            "就诊日期：2026-08-21\n"
            "诊断：脑梗死\n"
        )
        evaluator = PolicyEvaluator(load_builtin_profile("external-ai-strict"))
        recipient = Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_APPROVED)

        facts = detect_all(text)
        decision = evaluator.evaluate(facts, recipient, Purpose.EXTERNAL_AI_ASSISTANCE)
        once = apply_plan(text, facts, decision.plan).text

        residual = detect_all(once)
        second = evaluator.evaluate(residual, recipient, Purpose.EXTERNAL_AI_ASSISTANCE)
        if second.plan is not None:
            twice = apply_plan(once, residual, second.plan).text
            assert twice == once, (once, twice)


@pytest.mark.parametrize("value,expected", [
    ("2026-8-9", "2026-08"), ("2026/8/9", "2026/08"),
    ("2026.8.9", "2026.08"), ("8/9/2026", "2026-08"),
    ("２０２６-８-９", "2026-08"), ("２０２６/０８/９", "2026/08"),
    ("20２６.8.０９", "2026.08"), ("８/9/20２６", "2026-08"),
    ("２０２６年８月９日", "2026年8月"),
])
def test_unpadded_numeric_dates_generalize(value, expected):
    outcome = apply_plan(value, (fact("EXACT_DATE", 0, len(value), value),), plan(
        TransformationOp(op="GENERALIZE", target="EXACT_DATE")
    ))
    assert outcome.text == expected


@pytest.mark.parametrize("value,action,parameters", [
    ("2026-02-30", "GENERALIZE", {}),
    ("2026年2月30日", "DATE_SHIFT", {"shift_days": 1}),
    ("9999-12-31", "DATE_SHIFT", {"shift_days": 1}),
    ("0001-01-01", "DATE_SHIFT", {"shift_days": -1}),
    ("2026-08-21", "DATE_SHIFT", {"shift_days": 0}),
    ("2026-08-21", "DATE_SHIFT", {"shift_days": "secret-offset"}),
    ("2026-08-21", "DATE_SHIFT", {"shift_days": True}),
    ("2026-08-21", "DATE_SHIFT", {"shift_days": 1.5}),
])
def test_invalid_dates_and_offsets_fail_without_raw_values(value, action, parameters):
    with pytest.raises(TransformerError) as error:
        apply_plan(value, (fact("EXACT_DATE", 0, len(value), value),), plan(
            TransformationOp(op=action, target="EXACT_DATE", parameters=parameters)
        ))
    assert value not in str(error.value)
    assert "secret-offset" not in str(error.value)


@pytest.mark.parametrize("value", ["secret-age", "999岁", "1234岁"])
def test_age_errors_do_not_echo_raw_value(value):
    with pytest.raises(TransformerError) as error:
        apply_plan(value, (fact("AGE", 0, len(value), value),), plan(
            TransformationOp(op="GENERALIZE", target="AGE")
        ))
    assert value not in str(error.value)


def test_zero_hash_offset_is_replaced_by_nonzero_shift(monkeypatch):
    class ZeroOffsetHash:
        def hexdigest(self):
            return f"{365:08x}" + "0" * 56

    monkeypatch.setattr("transformers.registry.hashlib.sha256", lambda value: ZeroOffsetHash())
    outcome = apply_plan("2026-01-01", (fact("EXACT_DATE", 0, 10, "2026-01-01"),), plan(
        TransformationOp(op="DATE_SHIFT", target="EXACT_DATE")
    ))
    assert outcome.text == "2027-01-01"
    assert outcome.applied[0].parameters["_seed"] == 365


def test_execution_evidence_spans_and_repr():
    text = "张伟 2026-08-21"
    outcome = apply_plan(text, (
        fact("PERSON_NAME", 0, 2, "张伟"), fact("EXACT_DATE", 3, 13, "2026-08-21"),
    ), plan(
        TransformationOp(op="TOKENIZE", target="PERSON_NAME"),
        TransformationOp(op="DATE_SHIFT", target="EXACT_DATE", parameters={"shift_days": 1}),
    ))
    for record in outcome._evidence:
        assert outcome.text[record.output_start:record.output_end] == record.replacement
        assert record.replacement not in repr(record)
    assert outcome.text not in repr(outcome)
    assert "2026-08-22" not in repr(outcome)


def test_explicit_empty_token_registry_retains_distinct_entities_across_calls():
    tokens = TokenRegistry()
    operation = TransformationOp(op="TOKENIZE", target="PERSON_NAME")
    for value, expected in [("张伟", "001"), ("李四", "002"), ("张伟", "001")]:
        outcome = apply_plan(value, (fact("PERSON_NAME", 0, 2, value),), plan(operation), tokens)
        assert outcome.text == f"[PERSON_NAME_{expected}]"
    assert len(tokens) == 2
