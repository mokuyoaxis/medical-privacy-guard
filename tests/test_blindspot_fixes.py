"""Regression tests for the 2026-09-19 detection-blindspot remediation.

Two fixes are pinned here, both originally invisible to the benchmark because
the committed corpus writes every name after a field label and every medical
statement with an explicit label word.

1. Shared field separator (``detectors/field_syntax.py``). Every label-anchored
   detector used to spell out its own ``\\s*[:：]?\\s*``, so a field was detected
   with a colon and missed with an equals sign, and a bracketed value was missed
   entirely. The kinship rules were worse: ``父亲张伟`` was detected while
   ``父亲：张伟`` was not, because the rule used bare ``\\s*``.

2. Independent recall guard (``detectors/recall_guard.py``). The verifier re-runs
   the same detectors that produced the original facts, so a first-pass miss is
   invisible to it. Worse, a payload nothing matches short-circuits to ALLOW and
   never reaches verification. ``张伟，男，67岁`` — the standard note opener — was
   released with the name intact.

The negative cases matter as much as the positive ones: a recall guard that
fires on ordinary clinical prose would block the release path.
"""

from __future__ import annotations

import pytest

from core.model import Verdict
from detectors import detect_all
from detectors.recall_guard import NarrativeNameDetector
from medical_privacy_guard import Guard

APPROVED = "external_approved"
PURPOSE = "EXTERNAL_AI_ASSISTANCE"


def _release(text: str, recipient: str = APPROVED):
    return Guard().sanitize(text, recipient, PURPOSE)


# -- 1. shared separator ------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "value", "sep"),
    [
        ("父亲", "张伟", "："),
        ("父亲", "张伟", ":"),
        ("母亲", "李某某", "："),
        ("配偶", "王某", "="),
        ("家属", "张伟", "："),
        ("儿子", "刘强", "："),
    ],
)
def test_kinship_with_colon_like_separators_is_detected(label, value, sep):
    """A colon used to defeat the kinship rules entirely."""
    text = f"{label}{sep}{value}"
    assert any(f.type == "RELATIVE_NAME" for f in detect_all(text)), text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("父亲：张伟", "张伟"),
        ("家属：张伟", "张伟"),
        ("配偶：王某", "王某"),
        ("住院号：（1234567）", "1234567"),
        ("入院号：1234567", "1234567"),
        ("登记号：1234567", "1234567"),
        ("住院号：123", "123"),
        ("标本号=SP12345", "SP12345"),
        ("标本号：（A12345）", "A12345"),
        ("QQ号：123456789", "123456789"),
        ("微信号：1234abcd", "1234abcd"),
        ("住址北京市西城区牛街12号院3号楼502", "牛街12号院"),
    ],
)
def test_separator_variants_do_not_release_the_identifier(text, secret):
    result = _release(text, recipient="external_unknown")
    assert result.sanitized_payload is None or secret not in result.sanitized_payload.content, text


def test_bracketed_value_is_fully_transformed():
    """The bracket must be part of the match but not of the reported span."""
    fact = next(f for f in detect_all("住院号：（1234567）") if f.type == "MEDICAL_RECORD_NUMBER")
    assert fact.value == "1234567"
    text = "住院号：（1234567）"
    assert text[fact.start : fact.end] == "1234567"


def test_english_mrn_does_not_selff_match():
    """``medical record`` must not match with ``number`` as its value.

    That reading left the word ``number`` in the output as fresh PHI, so the
    field could never pass verification.
    """
    facts = [f for f in detect_all("medical record number: 1234567")
             if f.type == "MEDICAL_RECORD_NUMBER"]
    assert [f.value for f in facts] == ["1234567"]
    result = _release("medical record number: 1234567")
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None


# -- 2. independent recall guard ---------------------------------------------


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("张伟，男，67岁", "张伟"),
        ("李某某，女，45岁，因胸痛入院。", "李某某"),
        ("张伟，男，67岁，因脑梗死入院，既往高血压病史。", "张伟"),
        ("赵四，男性", "赵四"),
        ("张伟 男 67岁", "张伟"),
        ("张伟（67岁，男）", "张伟"),
    ],
)
def test_narrative_name_is_not_released(text, secret):
    """The standard note opener carries the name without any field label."""
    result = _release(text)
    assert result.decision_before.verdict is Verdict.SANITIZE, text
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None
    assert secret not in result.sanitized_payload.content


def test_labelled_name_still_winsthe_merge():
    """The labelled-field detector has the higher confidence, so it wins."""
    facts = [f for f in detect_all("姓名：张伟") if f.type == "PERSON_NAME"]
    assert len(facts) == 1
    assert facts[0].confidence == 0.95


@pytest.mark.parametrize(
    "text",
    [
        "本病区",
        "男病房",
        "男护士",
        "男女比例1:1",
        "性别：男",
        "患者男，67岁",
        "男性与女性受试者",
        "共12名医生",
        "纳入18岁以上成人",
        "主任医师",
        "女病房",
    ],
)
def test_recall_guard_does_not_fire_on_near_misses(text):
    """These are the pinned over-redaction near misses.

    Firing on any of them would regress the precision gate, which is the
    failure mode the negative corpus exists to catch.
    """
    assert NarrativeNameDetector().detect(text) == (), text


@pytest.mark.parametrize(
    "text",
    [
        "患者因反复头痛3个月加重1周入院。",
        "病程3个月。",
        "随访3个月后复查。",
    ],
)
def test_duration_is_not_read_as_month_age(text):
    """``头痛3个月`` is a duration; only age context counts as month age."""
    assert not any(f.source.startswith("recall_guard") for f in detect_all(text)), text
