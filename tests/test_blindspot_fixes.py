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


# -- 2026-09-19 remaining blindspots ------------------------------------------


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("患者在宣武医院住院。", "宣武医院"),
        ("患者2023年因胸痛在宣武医院住院。", "宣武医院"),
        ("其女儿在北京协和医院工作。", "北京协和医院"),
        ("患者既往在宣武医院就诊。", "宣武医院"),
        ("患者既往就诊于宣武医院。", "宣武医院"),
    ],
)
def test_hospital_name_after_function_words_is_not_released(text, secret):
    """A function word used to make the whole match be discarded.

    "患者曾在X医院住院" is one of the most natural clinical sentences, and the
    institution name was released verbatim. The reject set now cuts the match
    at the last reject character instead of dropping it entirely.
    """
    result = _release(text, recipient="external_unknown")
    assert result.sanitized_payload is None or secret not in result.sanitized_payload.content, text


@pytest.mark.parametrize(
    "text",
    [
        "该院为三级甲等医院。",
        "加强罕见病诊疗管理，该院为三级甲等医院。",
        "转诊至上级医院进一步诊治。",
        "上级医院",
        "当地医院",
        "三级甲等医院",
    ],
)
def test_generic_institution_references_stay_clean(text):
    """The reject set exists for these; cutting must not resurrect them."""
    assert not any(f.type == "HOSPITAL_NAME" for f in detect_all(text)), text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("患儿6个月", "6个月"),
        ("年龄：3个月", "3个月"),
        ("患儿6月龄", "6月龄"),
        ("3个月大", "3个月大"),
    ],
)
def test_month_age_is_generalized(text, secret):
    """Month age is the primary infant age form and is more re-identifying
    than a year band; 岁/周岁 never matched it."""
    result = _release(text)
    assert result.decision_before.verdict is Verdict.SANITIZE, text
    assert result.verification is not None and result.verification.passed
    assert secret not in result.sanitized_payload.content
    # Replacing only the digits would leave a dangling 个月.
    assert "个月岁" not in result.sanitized_payload.content


@pytest.mark.parametrize(
    "text",
    [
        "反复头痛3个月",
        "随访3个月后复查",
        "住院6天",
    ],
)
def test_duration_is_not_month_age(text):
    """A bare "3个月" is a duration far more often than an age."""
    assert not any(f.source.endswith(".month") for f in detect_all(text)), text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("户籍地：河北省保定市涞水县永阳镇东关村", "涞水县"),
        ("工作单位：北京市西城区牛街12号院3号楼502", "牛街12号院"),
        ("籍贯：河北省保定市", "保定市"),
    ],
)
def test_address_labels_carrying_a_full_address_are_detected(text, secret):
    """户籍地 / 工作单位 almost always contain a precise address."""
    result = _release(text, recipient="external_unknown")
    assert result.sanitized_payload is None or secret not in result.sanitized_payload.content, text


@pytest.mark.parametrize(
    "text",
    [
        "因脑梗死入院",
        "既往高血压病史",
        "主诉：胸痛3天",
        "急诊入院",
        "会诊意见：考虑脑梗死",
    ],
)
def test_unlabelled_medical_narrative_asks_an_unknown_recipient(text):
    """Medical content used to require a label word (诊断/疾病/病史…).

    Free narration slipped past the ASK path and was released as-is to an
    unknown endpoint. The signal list now includes encounter/action terms
    (入院, 出院, 主诉, 既往, 会诊, 急诊, 病程, 转科, 服药, 住院), which covers
    far more narration than before.
    """
    result = _release(text, recipient="external_unknown")
    assert result.decision_before.verdict is Verdict.ASK, text


def test_disease_names_without_an_action_term_are_still_missed():
    """Known residual gap, pinned so it is not mistaken for a regression.

    A bare diagnosis with no encounter or action word ("考虑脑梗死") produces
    no MEDICAL_CONTENT fact, because the baseline is a term list rather than
    medical NER. Closing this needs semantic detection, not more synonyms.
    """
    assert not any(f.type == "MEDICAL_CONTENT" for f in detect_all("考虑脑梗死"))
    assert not any(f.type == "MEDICAL_CONTENT" for f in detect_all("患者因急性心肌梗死就诊"))


@pytest.mark.parametrize(
    "text",
    [
        "普通随访记录，无敏感信息",
        "复查,按需",
        "本病区",
        "男病房",
    ],
)
def test_medical_content_expansion_does_not_over_block(text):
    """Ordinary follow-up wording must stay releasable.

    Adding 随访 / 复查 to the signal list broke these, which is why they are
    pinned: over-blocking silently strips clinical meaning.
    """
    assert not any(f.type == "MEDICAL_CONTENT" for f in detect_all(text)), text


# ---------------------------------------------------------------------------
# 2026-09-21: adjacent person-field over-capture.
#
# The adjacent form ("患者张三") has no delimiter to bound the value, and the
# shared pattern let the lazy name capture run to the end of the line. Any
# sentence ending in a clinical verb therefore lost that verb to the name:
# "患者张三入院" reported PERSON_NAME "张三入院", and "患者于协和医院住院治疗"
# reported PERSON_NAME "于协和医院住院" while never reporting the hospital at
# all — clinical meaning deleted by the sanitizer. The corpus could not see it
# because every committed name is followed by a label or punctuation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected_name"),
    [
        ("患者张三入院", "张三"),
        ("患者张三，男，67岁", "张三"),
        ("患者张三电话13800000000", "张三"),
        ("患者欧阳娜娜入院", "欧阳娜娜"),
        ("患者于谦入院", "于谦"),
        # The boundary list must also stop at clinical connectives, otherwise
        # "患者李四因胸痛入院" loses the name entirely instead of over-capturing.
        ("患者李四因胸痛入院", "李四"),
        ("患者张三于2023年入院", "张三"),
        ("患者张三诉头痛", "张三"),
        ("患者张三在协和就诊", "张三"),
        ("患者张三自诉头晕", "张三"),
        ("患者张三伴发热", "张三"),
        ("患者张三拟行手术", "张三"),
    ],
)
def test_adjacent_person_name_stops_at_the_given_name(text, expected_name):
    """The adjacent form must capture the name, not the following clinical verb."""
    names = [f.value for f in detect_all(text) if f.type == "PERSON_NAME"]
    assert names == [expected_name], text


@pytest.mark.parametrize(
    "text",
    [
        "患者于协和医院住院治疗",
        "患者于北京医院住院治疗",
    ],
)
def test_adjacent_form_does_not_absorb_a_hospital_into_a_name(text):
    """A surname character opening a hospital name must not start a person fact."""
    facts = detect_all(text)
    assert not any(f.type == "PERSON_NAME" for f in facts), text
    assert any(f.type == "HOSPITAL_NAME" for f in facts), text
