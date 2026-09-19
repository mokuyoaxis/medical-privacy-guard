"""Unit tests for deterministic detectors (Phase 1 Step 2).

Coverage:
- CN phone: valid / invalid / boundary
- CN ID-18: GB 11643-1999 check digit, low-confidence invalid candidates
- email: valid / invalid
- dates: calendar-valid formats, invalid dates rejected
- person name: field-marker only, label excluded from span
- medical record number: field-marker only
- registry merge: order, deduplication, determinism
"""

import pytest

from core.model import DetectedFact
from detectors import (
    CnIdDetector,
    CnPhoneDetector,
    DateDetector,
    EmailDetector,
    IpAddressDetector,
    MedicalContentDetector,
    MedicalRecordDetector,
    PersonNameDetector,
    PreciseLocationDetector,
    UrlDetector,
    detect_all,
)
from detectors.registry import _merge

# -- CN phone ---------------------------------------------------------------


class TestCnPhone:
    @pytest.fixture()
    def detector(self):
        return CnPhoneDetector()

    def test_valid_mobile(self, detector):
        facts = detector.detect("电话13800000000联系")
        assert len(facts) == 1
        assert facts[0].type == "PHONE"
        assert facts[0].value == "13800000000"
        assert facts[0].confidence == 1.0

    def test_multiple_mobiles(self, detector):
        facts = detector.detect("13800000000 和 13911112222")
        assert len(facts) == 2
        assert [f.value for f in facts] == ["13800000000", "13911112222"]

    def test_invalid_prefix_not_matched(self, detector):
        # 128 is not a valid mainland mobile prefix
        assert detector.detect("12800000000") == ()

    def test_boundary_letters_do_not_break_match(self, detector):
        # Letters are not digits: the boundary is only about digit runs.
        facts = detector.detect("x13800000000y")
        assert len(facts) == 1
        assert facts[0].value == "13800000000"

    def test_adjacent_digits_not_matched(self, detector):
        assert detector.detect("12313800000000") == ()

    @pytest.mark.parametrize("value", [
        "138 0000 0000", "138-0000-0000", "138  0000  0000",
        "138\u00a00000\u00a00000", "１３８００００００００", "１３８　００００　００００",
        "１３８－００００－００００", "1３8-０00０-000０",
    ])
    def test_formatted_mobile_preserves_original_span(self, detector, value):
        text = f"联系：{value}；继续随访"
        facts = detector.detect(text)
        assert len(facts) == 1
        assert facts[0].value == value
        assert (facts[0].start, facts[0].end) == (3, 3 + len(value))
        assert text[facts[0].start : facts[0].end] == value

    @pytest.mark.parametrize("text", [
        "128 0000 0000", "１２８００００００００", "138 000 0000", "138 00000 0000",
        "138 0000 00000", "0138-0000-0000", "138-0000-00000",
        "138\n0000\n0000", "138\t0000\t0000",
        "١٣٨٠٠٠٠٠٠٠٠", "138 0000 000٠",
        "剂量 138 mg，流速 0000 mL/h，累计 0000 mL", "血压 138-140 mmHg",
    ])
    def test_formatted_mobile_near_misses(self, detector, text):
        assert detector.detect(text) == ()

    def test_adjacent_formatted_mobiles_remain_separate(self, detector):
        text = "138 0000 0000 139-1111-2222"
        assert [f.value for f in detector.detect(text)] == [
            "138 0000 0000", "139-1111-2222",
        ]

    def test_country_prefix_does_not_hide_mobile(self, detector):
        assert [f.value for f in detector.detect("+86-138-0000-0000")] == [
            "138-0000-0000",
        ]


# -- CN ID-18 ---------------------------------------------------------------


class TestCnId:
    @pytest.fixture()
    def detector(self):
        return CnIdDetector()

    def test_valid_check_digit(self, detector):
        # 11010519491231002X is the canonical GB 11643-1999 sample.
        facts = detector.detect("证件号11010519491231002X")
        assert len(facts) == 1
        assert facts[0].type == "GOVERNMENT_ID"
        assert facts[0].value == "11010519491231002X"
        assert facts[0].confidence == 1.0

    def test_invalid_check_digit_low_confidence(self, detector):
        # Flip last digit: check digit no longer matches → still reported,
        # fail-closed, but with low confidence.
        facts = detector.detect("110105194912310021")
        assert len(facts) == 1
        assert facts[0].type == "GOVERNMENT_ID"
        assert facts[0].confidence < 1.0

    def test_seventeen_digits_not_matched(self, detector):
        assert detector.detect("11010519491231002") == ()

    def test_non_digit_body_not_matched(self, detector):
        assert detector.detect("11010A19491231002X") == ()


# -- email ------------------------------------------------------------------


class TestEmail:
    @pytest.fixture()
    def detector(self):
        return EmailDetector()

    def test_simple_email(self, detector):
        facts = detector.detect("联系 contact@example.com 咨询")
        assert len(facts) == 1
        assert facts[0].type == "EMAIL"
        assert facts[0].value == "contact@example.com"

    def test_local_part_with_plus_and_dots(self, detector):
        facts = detector.detect("user.name+tag@sub.example.co.uk")
        assert len(facts) == 1
        assert facts[0].value == "user.name+tag@sub.example.co.uk"

    def test_not_email(self, detector):
        assert detector.detect("this is not an email at all") == ()

    def test_missing_tld(self, detector):
        assert detector.detect("user@localhost") == ()


# -- dates ------------------------------------------------------------------


class TestDates:
    @pytest.fixture()
    def detector(self):
        return DateDetector()

    def test_iso_date(self, detector):
        facts = detector.detect("就诊日期 2026-08-29 出院")
        assert len(facts) == 1
        assert facts[0].type == "EXACT_DATE"
        assert facts[0].value == "2026-08-29"

    def test_slash_date(self, detector):
        facts = detector.detect("2026/08/29")
        assert len(facts) == 1
        assert facts[0].value == "2026/08/29"

    def test_chinese_date_single_digits(self, detector):
        facts = detector.detect("2026年8月9日入院")
        assert len(facts) == 1
        assert facts[0].value == "2026年8月9日"

    def test_invalid_calendar_date_rejected(self, detector):
        assert detector.detect("2023-02-30") == ()

    def test_invalid_month_rejected(self, detector):
        assert detector.detect("2026-13-01") == ()

    def test_ambiguous_fragment_not_matched(self, detector):
        # No separators → not a full date pattern.
        assert detector.detect("20260829") == ()

    def test_old_date_19xx_accepted(self, detector):
        facts = detector.detect("1999-12-31")
        assert len(facts) == 1

    @pytest.mark.parametrize("value", [
        "2026-8-9", "2026-08-9", "2026-8-09", "2026/8/9", "2026.8.9",
        "8/9/2026", "08/9/2026", "2026年08月09日", "2024-2-29",
        "２０２６-８-９", "２０２６/０８/９", "２０２６.８.０９", "８/９/２０２６",
        "２０２６年０８月９日", "20２６-8-９",
    ])
    def test_numeric_variants_preserve_original_span(self, detector, value):
        text = f"入院：{value}；继续随访"
        facts = detector.detect(text)
        assert len(facts) == 1
        assert facts[0].value == value
        assert (facts[0].start, facts[0].end) == (3, 3 + len(value))
        assert text[facts[0].start : facts[0].end] == value

    @pytest.mark.parametrize("text", [
        "2026-2-29", "2026-4-31", "2026-0-9", "2026-8-0", "2026-008-9",
        "2026-8-009", "2026年02月30日", "２０２６-２-２９", "2026-8/9",
        "12026-8-9", "2026-8-9123", "２０２６-８-９１２３", "8/9/20261",
        "范围 2026-8-9-10", "范围 1-2026-8-9", "版本 2026.8.9.1",
        "剂量 2-4 mg，频率 1/2/3 次，疗程 8-9 天", "剂量 2026.8 mg",
        "血压 138/80 mmHg", "２０２６年８月", "20260809",
    ])
    def test_numeric_near_misses(self, detector, text):
        assert detector.detect(text) == ()

    def test_dates_either_side_of_range_marker(self, detector):
        text = "住院 2026-8-9 至 2026-8-12"
        assert [f.value for f in detector.detect(text)] == ["2026-8-9", "2026-8-12"]


# -- person name ------------------------------------------------------------


class TestPersonName:
    @pytest.fixture()
    def detector(self):
        return PersonNameDetector()

    def test_chinese_field(self, detector):
        text = "患者：张三"
        facts = detector.detect(text)
        assert len(facts) == 1
        assert facts[0].type == "PERSON_NAME"
        assert facts[0].value == "张三"
        # Label excluded: span covers only the name.
        assert text[facts[0].start : facts[0].end] == "张三"

    def test_chinese_field_without_colon(self, detector):
        facts = detector.detect("姓名 李四")
        assert len(facts) == 1
        assert facts[0].value == "李四"

    def test_four_char_name(self, detector):
        facts = detector.detect("患者姓名：欧阳娜娜")
        assert len(facts) == 1
        assert facts[0].value == "欧阳娜娜"

    def test_bare_name_not_matched(self, detector):
        assert detector.detect("张三今天来复诊") == ()

    def test_english_field(self, detector):
        text = "Patient: John Smith"
        facts = detector.detect(text)
        assert len(facts) == 1
        assert facts[0].value == "John Smith"
        assert text[facts[0].start : facts[0].end] == "John Smith"

    def test_long_synthetic_chinese_name_is_not_truncated(self, detector):
        facts = detector.detect("患者：测试患者甲\n")
        assert len(facts) == 1
        assert facts[0].value == "测试患者甲"

    def test_multi_part_english_name_is_not_truncated(self, detector):
        facts = detector.detect("Patient: John Michael Smith, stable")
        assert len(facts) == 1
        assert facts[0].value == "John Michael Smith"

    def test_patient_address_is_not_misclassified_as_name(self, detector):
        assert detector.detect("患者住址：北京市朝阳区建国路88号") == ()

    def test_name_before_adjacent_phone_field(self, detector):
        facts = detector.detect("患者：张三电话13800000000")
        assert len(facts) == 1
        assert facts[0].value == "张三"


# -- medical record ---------------------------------------------------------


class TestMedicalRecord:
    @pytest.fixture()
    def detector(self):
        return MedicalRecordDetector()

    def test_chinese_mrn(self, detector):
        text = "病历号：MRN12345"
        facts = detector.detect(text)
        assert len(facts) == 1
        assert facts[0].type == "MEDICAL_RECORD_NUMBER"
        assert facts[0].value == "MRN12345"
        assert text[facts[0].start : facts[0].end] == "MRN12345"

    def test_chinese_admission_no(self, detector):
        facts = detector.detect("住院号 20260001")
        assert len(facts) == 1
        assert facts[0].value == "20260001"

    def test_english_mrn(self, detector):
        text = "MRN: 88231"
        facts = detector.detect(text)
        assert len(facts) == 1
        assert facts[0].value == "88231"

    def test_bare_number_not_matched(self, detector):
        assert detector.detect("号码 88231 用于登记") == ()

    def test_long_hyphenated_mrn_is_not_prefix_matched(self, detector):
        facts = detector.detect("住院号：SYNTH-MRN-0001")
        assert len(facts) == 1
        assert facts[0].value == "SYNTH-MRN-0001"


# -- URL / IP / location / medical content ---------------------------------


class TestAdditionalPhase1Detectors:
    def test_url(self):
        facts = UrlDetector().detect("影像链接 https://hospital.example/patient/123")
        assert len(facts) == 1
        assert facts[0].type == "URL"

    def test_valid_ipv4(self):
        facts = IpAddressDetector().detect("server 10.0.0.8")
        assert len(facts) == 1
        assert facts[0].value == "10.0.0.8"

    def test_invalid_ipv4(self):
        assert IpAddressDetector().detect("999.1.2.3") == ()

    def test_explicit_address(self):
        facts = PreciseLocationDetector().detect("患者住址：北京市朝阳区建国路88号")
        assert len(facts) == 1
        assert facts[0].value == "北京市朝阳区建国路88号"

    def test_medical_content_baseline(self):
        facts = MedicalContentDetector().detect("诊断：HIV感染；当前用药多替拉韦")
        assert facts
        assert {f.type for f in facts} == {"MEDICAL_CONTENT"}


# -- registry merge ---------------------------------------------------------


class TestRegistry:
    def test_detect_all_composite_text(self):
        text = (
            "患者：张三，电话13800000000，2026-08-29就诊，"
            "病历号：MRN12345，联系邮箱zhang@example.com"
        )
        facts = detect_all(text)
        types = {f.type for f in facts}
        assert types == {
            "PERSON_NAME",
            "PHONE",
            "EXACT_DATE",
            "MEDICAL_RECORD_NUMBER",
            "EMAIL",
        }
        # Facts are sorted by start offset.
        starts = [f.start for f in facts]
        assert starts == sorted(starts)
        # No overlapping spans.
        for prev, curr in zip(facts, facts[1:]):
            assert curr.start >= prev.end

    def test_merge_keeps_highest_confidence_on_overlap(self):
        a = DetectedFact(type="X", start=0, end=10, confidence=0.5, source="a")
        b = DetectedFact(type="Y", start=2, end=8, confidence=0.9, source="b")
        merged = _merge([a, b])
        assert len(merged) == 1
        assert merged[0] is b

    def test_merge_deduplicates_identical(self):
        a = DetectedFact(type="X", start=0, end=5, confidence=1.0, source="a")
        b = DetectedFact(type="X", start=0, end=5, confidence=1.0, source="b")
        assert len(_merge([a, b])) == 1

    def test_detect_all_deterministic(self):
        text = "患者：张三 13800000000 contact@example.com"
        assert detect_all(text) == detect_all(text)

    def test_value_never_leaks_into_public_facts(self):
        facts = detect_all("电话13800000000")
        public = facts[0].to_public()
        assert not hasattr(public, "value")
