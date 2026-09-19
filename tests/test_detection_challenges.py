"""Hand-authored synthetic challenges, independent of the generated note corpus."""

import pytest

from core.model import Verdict
from detectors import CnPhoneDetector, DateDetector
from medical_privacy_guard import Guard


@pytest.mark.parametrize(("phone", "visit", "month"), [
    ("138 0000 0000", "2026-8-9", "2026-08"),
    ("139-1111-2222", "2026/8/9", "2026/08"),
    ("158  2222  3333", "2026.8.9", "2026.08"),
    ("186\u00a03333\u00a04444", "8/9/2026", "2026-08"),
    ("１７８４４４４５５５５", "２０２６-８-９", "2026-08"),
    ("１８９　５５５５　６６６６", "２０２６年８月９日", "2026年8月"),
    ("１３７－６６６６－７７７７", "２０２６/０８/９", "2026/08"),
    ("1３6-７77７-888８", "20２６.8.０９", "2026.08"),
    ("151-8888 9999", "2026年08月09日", "2026年8月"),
])
def test_formatted_identifiers_sanitize_without_residue(phone, visit, month):
    text = f"联系：{phone}；复诊：{visit}；剂量 2.5 mg，血压 138/80 mmHg。"
    guard = Guard()
    facts = guard.detect(text)
    assert [(f.type, f.value) for f in facts] == [("PHONE", phone), ("EXACT_DATE", visit)]
    for fact in facts:
        assert text[fact.start : fact.end] == fact.value
    result = guard.sanitize(text, "external-unknown", "EXTERNAL_AI_ASSISTANCE")
    assert result.decision_before.verdict is Verdict.SANITIZE
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None
    sanitized = result.sanitized_payload.content
    assert sanitized == f"联系：[REDACTED]；复诊：{month}；剂量 2.5 mg，血压 138/80 mmHg。"
    assert phone not in sanitized
    assert visit not in sanitized
    assert CnPhoneDetector().detect(sanitized) == ()
    assert DateDetector().detect(sanitized) == ()
    assert result.decision_after is not None
    assert result.decision_after.verdict is Verdict.ALLOW


@pytest.mark.parametrize("text", [
    "剂量 2-4 mg，频率 1/2/3 次，疗程 8-9 天。",
    "血压 138/80 mmHg；血糖 6.8 mmol/L；体温 36.9℃。",
    "读数 138 0000 00000；校验串 12026-8-9。",
    "测量范围 138-140；数值范围 2026-8-9-10。",
    "无效日期 2026-2-29；月度记录 ２０２６年８月。",
    "读数 １３８０００００００００；数值版本 ２０２６.８.９.１。",
    "剂量 138\n0000\n0000；疗程 8-9 天。",
])
def test_adjacent_clinical_and_numeric_negatives_are_not_rewritten(text):
    assert CnPhoneDetector().detect(text) == ()
    assert DateDetector().detect(text) == ()
    result = Guard().sanitize(text, "external-unknown", "EXTERNAL_AI_ASSISTANCE")
    assert result.decision_before.verdict is Verdict.ALLOW
    assert result.sanitized_payload is not None
    assert result.sanitized_payload.content == text


def test_multiple_mobiles_and_date_interval_keep_surrounding_text():
    text = "联系 138 0000 0000、139-1111-2222；随访 2026-8-9 至 2026-9-10。"
    result = Guard().sanitize(text, "external-unknown", "EXTERNAL_AI_ASSISTANCE")
    assert result.verification is not None and result.verification.passed
    assert result.sanitized_payload is not None
    assert result.sanitized_payload.content == (
        "联系 [REDACTED]、[REDACTED]；随访 2026-08 至 2026-09。"
    )
