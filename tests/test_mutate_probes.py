"""Unit tests for the challenge-probe mutation framework.

The operators themselves are exercised end-to-end by the challenge corpus:
every generated probe that is filed under ``regression/`` runs in
``test_challenge_corpus.py``. These tests pin the framework's bookkeeping
rails, which are what keep generated annotations honest.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent / "tools" / "mutate_probes.py"
_spec = importlib.util.spec_from_file_location("mutate_probes", _TOOLS)
mutate_probes = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mutate_probes  # dataclasses resolve the module here
_spec.loader.exec_module(mutate_probes)

Operator = mutate_probes.Operator
Variant = mutate_probes.Variant
MutationRefused = mutate_probes.MutationRefused
generate_variants = mutate_probes.generate_variants
OPERATORS = mutate_probes.OPERATORS


def _meta(must_detect, must_not=None, verdict="SANITIZE"):
    return {
        "doc_id": "seed_001",
        "dimension": "coverage",
        "expected_verdict": verdict,
        "must_detect": must_detect,
        "must_not_detect": must_not or [],
        "probe_note": "seed",
    }


def test_fullwidth_bookkeeping_follows_the_value():
    meta = _meta([{"type": "PHONE", "text": "13800001234"}])
    produced = generate_variants("联系电话：13800001234。", meta, OPERATORS)
    fullwidth = [v for op, v in produced if op.name == "digits_fullwidth"]
    assert len(fullwidth) == 1
    assert fullwidth[0].must_detect == [{"type": "PHONE", "text": "１３８００００１２３４"}]
    assert "１３８００００１２３４" in fullwidth[0].text


def test_phone_regroup_both_directions():
    meta = _meta([{"type": "PHONE", "text": "13800001234"}])
    produced = generate_variants("电话：13800001234。", meta, OPERATORS)
    regrouped = [v.must_detect[0]["text"] for op, v in produced if op.name == "phone_regroup"]
    assert regrouped == ["138 0000 1234", "138-0000-1234"]

    meta = _meta([{"type": "PHONE", "text": "138 0000 1234"}])
    produced = generate_variants("电话：138 0000 1234。", meta, OPERATORS)
    regrouped = [v.must_detect[0]["text"] for op, v in produced if op.name == "phone_regroup"]
    assert regrouped == ["13800001234"]


def test_ambiguous_seed_is_refused():
    meta = _meta([{"type": "PERSON_NAME", "text": "李四"}])
    with pytest.raises(MutationRefused):
        generate_variants("李四与李四均到场。", meta, OPERATORS)


def test_variant_whose_value_vanishes_is_refused():
    def vanishing(text, meta):
        return [Variant("电话：已脱敏。", [{"type": "PHONE", "text": "13800001234"}], [], "bad")]

    meta = _meta([{"type": "PHONE", "text": "13800001234"}])
    with pytest.raises(MutationRefused):
        generate_variants("电话：13800001234。", meta, [Operator("vanishing", "format", vanishing)])


def test_empty_mutation_is_refused():
    def identity(text, meta):
        return [Variant(text, [dict(e) for e in meta["must_detect"]], [], "bad")]

    meta = _meta([{"type": "PHONE", "text": "13800001234"}])
    with pytest.raises(MutationRefused):
        generate_variants("电话：13800001234。", meta, [Operator("identity", "format", identity)])


def test_separator_is_not_invented_for_unlabelled_values():
    meta = _meta([{"type": "AGE", "text": "五十六岁"}, {"type": "SEX", "text": "女"}])
    produced = generate_variants("患者，女，五十六岁。", meta, OPERATORS)
    assert not [v for op, v in produced if op.name == "separator_swap"]


def test_label_drop_keeps_bookkeeping_on_the_value():
    meta = _meta([{"type": "PERSON_NAME", "text": "李四"}])
    produced = generate_variants("姓名：李四。", meta, OPERATORS)
    dropped = [v for op, v in produced if op.name == "label_drop"]
    assert len(dropped) == 1
    assert dropped[0].text == "李四。"
    assert dropped[0].must_detect == [{"type": "PERSON_NAME", "text": "李四"}]


def test_mutated_meta_records_provenance():
    meta = _meta([{"type": "PHONE", "text": "13800001234"}])
    produced = generate_variants("电话：13800001234。", meta, OPERATORS)
    operator, variant = produced[0]
    new_meta = mutate_probes.mutated_meta(meta, operator, variant, "seed_001__x_1")
    assert new_meta["mutated_from"] == "seed_001"
    assert new_meta["operator"] == operator.name
    assert new_meta["doc_id"] == "seed_001__x_1"
