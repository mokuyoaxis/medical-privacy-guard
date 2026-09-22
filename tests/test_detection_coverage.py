"""Detection coverage added in v0.2.4.

Every form here was found by probing released output, not by the corpus. The
generator writes ages as digits, names behind a label, and never a residence
verb, so the benchmark reported a strict 1.0 while these forms passed through
unchanged.

The lesson from the first of them is why several tests here go end to end: a
detector that reports a fact the transformer cannot execute is worse than no
detector at all, because the request now raises instead of being released.
Detection, transformation and verification are checked together.
"""

from __future__ import annotations

from datetime import date

import pytest

from core.model import Purpose, Recipient, TrustLevel
from detectors import detect_all
from detectors.dates import parse_cn_date
from detectors.demographics import parse_cn_numeral
from medical_privacy_guard import Guard


def values_of(text: str, fact_type: str) -> list[str]:
    return [text[f.start : f.end] for f in detect_all(text) if f.type == fact_type]


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


# -- Chinese numeral ages ----------------------------------------------------


class TestChineseNumeralAge:
    @pytest.mark.parametrize(
        "token, value",
        [("十", 10), ("十五", 15), ("二十", 20), ("五十六", 56), ("九十九", 99), ("两", 2)],
    )
    def test_numeral_parses(self, token: str, value: int) -> None:
        assert parse_cn_numeral(token) == value

    @pytest.mark.parametrize("token", ["", "二十十", "百", "零十"])
    def test_unparseable_numeral_is_rejected(self, token: str) -> None:
        assert parse_cn_numeral(token) is None

    @pytest.mark.parametrize(
        "token", ["十岁", "十五岁", "二十岁", "五十六岁", "九十九岁", "两岁"]
    )
    def test_age_is_detected(self, token: str) -> None:
        assert values_of(f"患者{token}。", "AGE") == [token]

    def test_digits_and_numerals_reach_the_same_verdict(
        self, guard: Guard, approved: Recipient
    ) -> None:
        """The whole point: the same sentence must not flip on digit style."""
        for text in ("患者，女，56岁。", "患者，女，五十六岁。"):
            result = guard.sanitize(text, approved, Purpose.EXTERNAL_AI_ASSISTANCE)
            assert result.decision_before.verdict.value == "SANITIZE", text
            assert result.verification is not None and result.verification.passed
            assert result.sanitized_payload is not None
            assert "50-59岁" in result.sanitized_payload.content

    def test_population_threshold_is_still_ignored(self) -> None:
        assert values_of("该病多见于五十岁以上人群。", "AGE") == []

    def test_numeral_age_generalizes_end_to_end(
        self, guard: Guard, approved: Recipient
    ) -> None:
        """A detected fact the transformer cannot execute raises, so the
        transformation and the postcondition are pinned here too."""
        result = guard.sanitize("患儿两岁，发热3天。", approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.sanitized_payload is not None
        assert "1-9岁" in result.sanitized_payload.content


# -- comma-separated sex -----------------------------------------------------


class TestCommaSeparatedSex:
    def test_sex_after_a_comma_is_detected(self) -> None:
        assert values_of("患者，女，67岁。", "SEX") == ["女"]
        assert values_of("患者，女，五十六岁。", "SEX") == ["女"]

    def test_adjacent_form_still_works(self) -> None:
        assert values_of("患者女，67岁。", "SEX") == ["女"]

    def test_attributive_form_is_not_a_bare_sex(self) -> None:
        """患者，女性家属 names a relative, not the patient."""
        assert values_of("患者，女性家属陪同。", "SEX") == []


# -- bracketed name values ---------------------------------------------------


class TestBracketedNameValue:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("患者（张三）因胸痛入院。", "张三"),
            ("患者(张三)因胸痛入院。", "张三"),
            ("患者姓名（李四）。", "李四"),
            ("患者姓名：张三。", "张三"),
        ],
    )
    def test_name_is_captured(self, text: str, expected: str) -> None:
        assert values_of(text, "PERSON_NAME") == [expected]


# -- labelled bed numbers ----------------------------------------------------


class TestLabelledBedNumber:
    @pytest.mark.parametrize(
        "text, expected",
        [("床号 12，病区3。", "12"), ("床号：A03。", "A03"), ("床号12。", "12"), ("12床。", "12床")],
    )
    def test_bed_is_detected(self, text: str, expected: str) -> None:
        assert values_of(text, "BED_NUMBER") == [expected]

    def test_capacity_word_is_not_an_identifier(self) -> None:
        assert values_of("床位紧张，需协调。", "BED_NUMBER") == []


# -- unlabelled addresses ----------------------------------------------------


class TestUnlabelledAddress:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("患者住北京市朝阳区建国路1号。", "北京市朝阳区建国路1号"),
            ("患者住北京市朝阳区。", "北京市朝阳区"),
            ("患者现住上海市浦东新区。", "上海市浦东新区"),
            ("患者居住于广州市天河区。", "广州市天河区"),
        ],
    )
    def test_address_after_a_residence_verb(self, text: str, expected: str) -> None:
        assert values_of(text, "PRECISE_LOCATION") == [expected]

    @pytest.mark.parametrize(
        "text",
        ["患者住院治疗。", "患者住所不详。", "患者住房条件良好。", "患者在协和医院住院。"],
    )
    def test_residence_words_that_are_not_addresses(self, text: str) -> None:
        assert values_of(text, "PRECISE_LOCATION") == []

    def test_labelled_form_is_unchanged(self) -> None:
        assert values_of("住址：北京市朝阳区建国路1号。", "PRECISE_LOCATION") == [
            "北京市朝阳区建国路1号"
        ]

    def test_unlabelled_address_is_withheld_or_sanitized(
        self, guard: Guard, approved: Recipient
    ) -> None:
        result = guard.sanitize(
            "患者住北京市朝阳区建国路1号。", approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision_before.verdict.value == "SANITIZE"
        assert result.sanitized_payload is not None
        assert "建国路" not in result.sanitized_payload.content


# -- Chinese numeral dates ---------------------------------------------------


class TestChineseNumeralDates:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("二〇二六年九月二十一日", date(2026, 9, 21)),
            ("二零二六年十二月三十一日", date(2026, 12, 31)),
            ("二〇二六年一月一日", date(2026, 1, 1)),
            ("二〇二六年十月十日", date(2026, 10, 10)),
        ],
    )
    def test_parses(self, text: str, expected: date) -> None:
        assert parse_cn_date(text) == expected

    @pytest.mark.parametrize(
        "text", ["二〇二三年二月三十日", "二〇二六年十三月一日", "二〇二六年九月"]
    )
    def test_invalid_or_partial_dates_are_rejected(self, text: str) -> None:
        assert parse_cn_date(text) is None

    def test_detected_and_generalized(self, guard: Guard, approved: Recipient) -> None:
        result = guard.sanitize(
            "就诊日期：二〇二六年九月二十一日。", approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision_before.verdict.value == "SANITIZE"
        assert result.sanitized_payload is not None
        assert "2026年9月" in result.sanitized_payload.content
        assert result.verification is not None and result.verification.passed

    def test_digits_and_numerals_reach_the_same_output(
        self, guard: Guard, approved: Recipient
    ) -> None:
        outputs = set()
        for text in ("就诊日期：2026年9月21日。", "就诊日期：二〇二六年九月二十一日。"):
            result = guard.sanitize(text, approved, Purpose.EXTERNAL_AI_ASSISTANCE)
            assert result.sanitized_payload is not None, text
            outputs.add(result.sanitized_payload.content)
        assert len(outputs) == 1

    def test_impossible_date_is_not_a_fact(self) -> None:
        assert values_of("签署日期：二〇二三年二月三十日。", "EXACT_DATE") == []


# -- given names outside the inventory ---------------------------------------


class TestOutOfInventoryGivenNames:
    """The title already bounds the name, so the inventory only causes misses.

    郑沫医生 and 欧阳修远医生 were undetected because 沫 and 修 are outside the
    name-character inventory, while the same names behind a labelled field were
    captured whole.
    """

    @pytest.mark.parametrize(
        "text, fact_type, expected",
        [
            ("郑沫医生。", "DOCTOR_NAME", "郑沫"),
            ("欧阳修远医生。", "DOCTOR_NAME", "欧阳修远"),
            ("郑沫护士。", "NURSE_NAME", "郑沫"),
            ("王五医生。", "DOCTOR_NAME", "王五"),
        ],
    )
    def test_suffix_form_is_captured_whole(
        self, text: str, fact_type: str, expected: str
    ) -> None:
        assert values_of(text, fact_type) == [expected]

    @pytest.mark.parametrize(
        "text, fact_type",
        [
            ("本科室共12名医生。", "DOCTOR_NAME"),
            ("主任医师每周查房两次。", "DOCTOR_NAME"),
            ("责任护士每班交接。", "NURSE_NAME"),
        ],
    )
    def test_title_words_are_not_names(self, text: str, fact_type: str) -> None:
        assert values_of(text, fact_type) == []

    def test_a_full_title_is_not_absorbed(self) -> None:
        """患者李四住院医师 names a patient, not a doctor called 李四住院."""
        assert values_of("患者李四住院医师。", "DOCTOR_NAME") == []
