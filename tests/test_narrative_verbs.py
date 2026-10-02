"""Regression tests for narrative names carried by a verb or a connective.

The gender-opener recall rule (``张伟，男，67岁``) covered one narrative shape.
Two more common ones had no rule at all, and because nothing matched they
short-circuited to ALLOW and were released verbatim under an approved recipient:

    今日查房，陈曦诉头晕较前好转。
    上午9时，潘婷主诉腹痛加重。

The rule set now keys on a following complaint verb (诉/主诉/自诉/自述) and, more
cautiously, on a following connective (因/由/以). The anchors are not equally
strong and are not treated as such: the connective form additionally requires
the name to sit at a clause boundary, because 高峰, 文明 and 白云 are ordinary
words with the shape of a surname plus a given-name character.

The negative cases below are the load-bearing half. A recall guard that fires on
ordinary clinical prose would re-create the over-redaction defects the negative
corpus was written to catch.
"""

from __future__ import annotations

import pytest

from core.model import Verdict
from detectors import detect_all
from detectors.recall_guard import NarrativeNameDetector
from medical_privacy_guard import Guard

APPROVED = "external_approved"
UNKNOWN = "external_unknown"
PURPOSE = "EXTERNAL_AI_ASSISTANCE"


def _release(text: str, recipient: str = APPROVED):
    return Guard().sanitize(text, recipient, PURPOSE)


def _narrative_names(text: str) -> list[str]:
    return [f.value for f in detect_all(text) if f.source == "regex.recall_narrative_name"]


# -- complaint verb -----------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("今日查房，陈曦诉头晕较前好转。", "陈曦"),
        ("上午9时，潘婷主诉腹痛加重，查体见右下腹压痛。", "潘婷"),
        ("陈曦诉头晕", "陈曦"),
        ("潘婷主诉腹痛", "潘婷"),
        ("李静自诉头痛3天。", "李静"),
        ("王强自述既往体健。", "王强"),
    ],
)
def test_complaint_verb_name_is_not_released(text, name):
    """A name in front of 诉/主诉 attributes a complaint to that person."""
    result = _release(text)
    assert result.decision_before.verdict is Verdict.SANITIZE, text
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None
    assert name not in result.sanitized_payload.content


# -- connective ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("陈曦因胸痛入院。", "陈曦"),
        ("汪洋由急诊科转入心血管内科。", "汪洋"),
        ("张伟以发热为主诉。", "张伟"),
    ],
)
def test_connective_name_is_not_released(text, name):
    """The name sits at a clause boundary, so the weaker anchor is enough."""
    result = _release(text)
    assert result.decision_before.verdict is Verdict.SANITIZE, text
    assert result.sanitized_payload is not None
    assert name not in result.sanitized_payload.content


@pytest.mark.parametrize(
    "text",
    [
        "就诊高峰因流感患者增多。",
        "本院就诊高峰由上午转移至下午。",
        "白蛋白因肝功能异常而降低。",
        "血压由高转低。",
        "上海由某医院转诊。",
        "患者自上海由某医院转来。",
        "重庆因暴雨停诊。",
    ],
)
def test_embedded_or_non_name_words_do_not_fire(text):
    """These are the near misses the connective anchor must not read as people.

    高峰 / 上海 / 白蛋白 are not [surname][given-name] pairs, or are not at a
    clause boundary, so no narrative fact is produced. This is the direction the
    negative corpus exists to protect.
    """
    assert NarrativeNameDetector().detect(text) == (), text


@pytest.mark.parametrize(
    "text",
    [
        "本病区",
        "男病房",
        "男护士",
        "男女比例1:1",
        "性别：男",
        "患者男，67岁",
        "共12名医生",
        "主任医师",
        "50岁以上人群",
        "三级甲等医院",
        "主诉：胸痛3天",
        "既往高血压病史",
    ],
)
def test_gender_and_connective_near_misses_do_not_fire(text):
    """The original over-redaction set still produces no narrative name."""
    assert NarrativeNameDetector().detect(text) == (), text


# -- known residual -----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "文明因交流而多彩。",
        "白云由窗户飘入。",
        "黄金以克计价。",
    ],
)
def test_clause_initial_common_word_is_a_known_residual(text):
    """Known residual, pinned so it is not mistaken for a regression.

    A common word shaped like a surname plus a given-name character, opening a
    clause and followed by 因/由/以, is still read as a person. The connective
    anchor cannot tell 文明因交流 from 陈曦因胸痛 without semantic knowledge, and
    the clause-boundary rule is the strongest constraint that kept the committed
    corpora at zero false positives. Recorded in docs/scope.md.
    """
    assert _narrative_names(text), text


def test_complaint_verb_needs_a_name_character():
    """``陈诉`` is a word, not a person: 诉 is not a given-name character."""
    assert _narrative_names("原告陈诉事实经过。") == []


def test_numeral_placeholder_names_are_not_covered_by_the_verb_rule():
    """Known boundary: 张三诉… is missed because 三 is not a name character.

    Numeral placeholders are covered in the labelled and adjacent forms
    (``患者张三``, ``姓名：张三``, ``张三，男``); the verb rule keeps the
    given-name inventory and therefore does not read 周一/周三 as people.
    """
    assert _narrative_names("张三诉头痛。") == []
    assert _narrative_names("周三由门诊转来。") == []
