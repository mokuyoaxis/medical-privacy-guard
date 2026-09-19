"""Unit tests for the v0.2 clinical-narrative and institution detectors.

Each detector is covered with positive cases and, where the risk of
over-detection is real, explicit negative cases. The negative tests matter
more than the positive ones here: SEX, POSTAL_CODE and name detectors are the
ones most likely to fire on ordinary clinical prose, and a false positive
either redacts clinical meaning or pollutes the risk score.
"""

from __future__ import annotations

from detectors import detect_all


def types_in(text: str) -> set[str]:
    return {f.type for f in detect_all(text)}


def values_of(text: str, fact_type: str) -> list[str]:
    return [text[f.start : f.end] for f in detect_all(text) if f.type == fact_type]


# -- AGE --------------------------------------------------------------------


class TestAgeDetector:
    def test_detects_common_ages(self):
        assert values_of("患者男，67岁，因脑梗死入院。", "AGE") == ["67岁"]

    def test_detects_zhou_sui(self):
        assert values_of("患儿3周岁，发热2天。", "AGE") == ["3周岁"]

    def test_ignores_implausible_age(self):
        assert values_of("数值999岁，超出范围。", "AGE") == []

    def test_ignores_number_without_unit(self):
        assert values_of("住院6天，费用1200元。", "AGE") == []

    def test_ignores_age_inside_long_digit_run(self):
        assert values_of("编号1380000067岁", "AGE") == []

    def test_negative_population_threshold(self):
        """An age-like number over a population is not a patient's age.

        Rewriting it would garble the sentence while protecting nobody.
        """
        for text in ("该病多见于50岁以上人群。", "本研究纳入18岁以上成人。"):
            assert values_of(text, "AGE") == [], text

    def test_generalized_band_is_not_an_age(self):
        """The transformer writes 40-49岁 / 90岁及以上 / 不足1岁.

        Those band labels are the guard's own output. Reading the trailing
        number as a fresh age makes the policy re-run report SANITIZE forever,
        so the sanitized note can never be released.
        """
        for text in (
            "年龄：40-49岁",
            "年龄：90岁及以上",
            "年龄：不足1岁",
            "年龄：10-19岁",
        ):
            assert values_of(text, "AGE") == [], text

    def test_exact_age_after_a_band_is_still_detected(self):
        """The band exclusion must not blind the detector to a real age."""
        assert values_of("年龄：40-49岁，长子67岁。", "AGE") == ["67岁"]


# -- SEX: the highest false-positive risk ------------------------------------


class TestSexDetector:
    def test_field_form(self):
        assert values_of("性别：男，主诉头痛。", "SEX") == ["男"]

    def test_patient_enumeration_form(self):
        assert values_of("患者男，67岁。", "SEX") == ["男"]

    def test_structured_enumeration_form(self):
        assert values_of("女，45岁，因腹痛入院。", "SEX") == ["女"]

    def test_attributive_form(self):
        assert values_of("男性患者，因胸痛就诊。", "SEX") == ["男"]

    def test_negative_ward_context(self):
        """男病房 describes a room, not a patient."""
        assert values_of("男病房与女病房分区管理。", "SEX") == []

    def test_negative_ratio_context(self):
        assert values_of("男女比例约为1:1。", "SEX") == []

    def test_negative_ordinary_word(self):
        assert values_of("男友陪同前来，女朋友亦在。", "SEX") == []

    def test_negative_gender_word_without_context(self):
        assert values_of("该研究纳入男性与女性受试者。", "SEX") == []


# -- institution -------------------------------------------------------------


class TestHospitalNameDetector:
    def test_detects_hospital_suffix(self):
        assert values_of("就诊于示例医院神经内科。", "HOSPITAL_NAME") == ["示例医院"]

    def test_detects_affiliated_hospital(self):
        assert "第一附属医院" in values_of("转诊至第一附属医院。", "HOSPITAL_NAME")

    def test_negative_plain_word(self):
        assert values_of("医院管理规范要求。", "HOSPITAL_NAME") == []

    def test_negative_generic_reference(self):
        """A grade or generic qualifier names no institution."""
        for text in (
            "该院为三级甲等医院。",
            "转诊至上级医院进一步诊治。",
            "建议转当地医院继续治疗。",
        ):
            assert values_of(text, "HOSPITAL_NAME") == [], text


class TestDepartmentDetector:
    def test_detects_labelled_departments(self):
        text = "就诊科室：神经内科，申请科室：检验科。"
        assert set(values_of(text, "DEPARTMENT")) == {"神经内科", "检验科"}

    def test_detects_patient_location(self):
        assert values_of("患者收入心内科继续治疗。", "DEPARTMENT") == ["心内科"]

    def test_detects_department_clinic(self):
        assert values_of("神经内科门诊随诊。", "DEPARTMENT") == ["神经内科"]

    def test_negative_referral_target(self):
        """建议神经内科会诊 names a service, not the patient's department.

        Redacting it would strip the meaning of the referral while revealing
        nothing the diagnosis in the same note does not already imply.
        """
        assert values_of("建议神经内科会诊协助诊治。", "DEPARTMENT") == []

    def test_negative_ordinary_words(self):
        assert values_of("本科室学科建设良好，外科手术流程规范。", "DEPARTMENT") == []


class TestWardDetector:
    def test_detects_named_ward(self):
        assert values_of("神内二病区收治。", "WARD") == ["神内二病区"]

    def test_detects_numbered_ward(self):
        assert values_of("三病区交接班。", "WARD") == ["三病区"]

    def test_negative_generic_reference(self):
        """本病区 / 各病区 refer to a ward in the abstract, not to one ward."""
        for text in ("本病区实行分区管理。", "各病区落实交接班制度。", "该病区管理规范。"):
            assert values_of(text, "WARD") == [], text


class TestBedNumberDetector:
    def test_detects_numeric_bed(self):
        assert values_of("12床患者复查。", "BED_NUMBER") == ["12床"]

    def test_detects_alphanumeric_bed(self):
        assert values_of("A03床今日出院。", "BED_NUMBER") == ["A03床"]

    def test_negative_bed_position_word(self):
        """床位 is a concept, not an identifier."""
        assert values_of("床位紧张，需协调。", "BED_NUMBER") == []


# -- staff and relatives -----------------------------------------------------


class TestDoctorNameDetector:
    def test_suffix_form(self):
        assert values_of("张医生查房。", "DOCTOR_NAME") == ["张"]

    def test_title_form(self):
        assert values_of("主治医师王建国查看患者。", "DOCTOR_NAME") == ["王建国"]

    def test_negative_measure_word(self):
        """共12名医生 must not yield the name 名."""
        assert values_of("本科室共12名医生。", "DOCTOR_NAME") == []

    def test_negative_title_word_internals(self):
        """主任医师 contains 任医师, which must not be read as a name."""
        assert values_of("主任医师每周查房两次。", "DOCTOR_NAME") == []


class TestNurseNameDetector:
    def test_suffix_form(self):
        assert values_of("李护士测量血压。", "NURSE_NAME") == ["李"]

    def test_title_form(self):
        assert values_of("责任护士王芳执行医嘱。", "NURSE_NAME") == ["王芳"]

    def test_negative_title_word_internals(self):
        """责任护士 contains 任护士, which must not be read as a name."""
        assert values_of("责任护士每班交接。", "NURSE_NAME") == []


class TestRelativeNameDetector:
    def test_spouse_form(self):
        assert values_of("其妻王芳陪同就诊。", "RELATIVE_NAME") == ["王芳"]

    def test_parent_form(self):
        assert values_of("父亲张伟签字同意。", "RELATIVE_NAME") == ["张伟"]

    def test_does_not_swallow_following_verb(self):
        """其妻王芳陪同 must not capture 王芳陪."""
        assert values_of("其妻王芳陪同就诊。", "RELATIVE_NAME") == ["王芳"]

    def test_negative_without_name(self):
        assert values_of("家属表示理解，父亲同意。", "RELATIVE_NAME") == []


# -- accession, contact and geography ---------------------------------------


class TestIdentifierDetectors:
    def test_specimen_id(self):
        assert values_of("标本号：SP123456", "SPECIMEN_ID") == ["SP123456"]

    def test_accession_number(self):
        assert values_of("检查号 IM2026001", "ACCESSION_NUMBER") == ["IM2026001"]

    def test_landline(self):
        assert values_of("联系电话010-66668888。", "LANDLINE") == ["010-66668888"]

    def test_landline_does_not_match_mobile(self):
        assert values_of("手机13800012345。", "LANDLINE") == []

    def test_postal_code_requires_label(self):
        assert values_of("邮政编码：100053", "POSTAL_CODE") == ["100053"]

    def test_postal_code_ignores_bare_six_digits(self):
        """A bare 6-digit run is common in clinical text and is not a postal code."""
        assert values_of("剂量120000单位，参考范围3.5-5.5。", "POSTAL_CODE") == []

    def test_social_media_id(self):
        assert values_of("微信号：patient_001", "SOCIAL_MEDIA_ID") == ["patient_001"]


class TestRareContextDetector:
    def test_unique_claim(self):
        assert "本县唯一" in values_of("本例为本县唯一一例。", "RARE_CONTEXT")

    def test_rare_disease(self):
        for phrase in ("罕见变异型病例", "罕见变异", "罕见病例", "罕见疾病", "罕见病"):
            text = f"该患者为{phrase}，已按疑难病例上报。"
            assert values_of(text, "RARE_CONTEXT") == [phrase]
            fact = next(f for f in detect_all(text) if f.type == "RARE_CONTEXT")
            assert (fact.start, fact.end) == (4, 4 + len(phrase))

    def test_negative_ordinary_sentence(self):
        assert values_of("该病例已按常规流程处理。", "RARE_CONTEXT") == []

    def test_negative_policy_language(self):
        """罕见病 as a policy category names no patient."""
        for text in ("加强罕见病诊疗管理。", "完善罕见病病例登记。"):
            assert values_of(text, "RARE_CONTEXT") == [], text


# -- integration -------------------------------------------------------------


class TestCombinedDetection:
    def test_full_clinical_sentence(self):
        text = "神经内科门诊，患者张三，男，67岁，12床，神内二病区，电话13800012345。"
        found = types_in(text)
        for expected in ("DEPARTMENT", "PERSON_NAME", "SEX", "AGE", "BED_NUMBER", "WARD", "PHONE"):
            assert expected in found, expected

    def test_ordinary_prose_stays_clean(self):
        """A sentence with no identifiers yields no span-level facts.

        The baseline medical-content classifier only fires on explicit
        clinical labels, so free prose may legitimately produce nothing.
        """
        text = "今日查房，患者一般情况可，继续观察病情变化。"
        span_types = types_in(text) - {"MEDICAL_CONTENT"}
        assert span_types == set()

    def test_negative_prefix_institution(self):
        """就诊于…  must not swallow the verb into the institution name."""
        assert values_of("就诊于示例医院神经内科。", "HOSPITAL_NAME") == ["示例医院"]


# -- markers are inert -------------------------------------------------------


class TestPlaceholderInertness:
    """A sanitized payload is re-detected during verification.

    If a detector reads the guard's own marker as a fresh identifier, the
    policy re-run reports SANITIZE forever and no note can ever be released.
    """

    def test_location_marker_is_not_an_address(self):
        assert values_of("联系地址：[LOCATION_GENERALIZED]", "PRECISE_LOCATION") == []

    def test_token_marker_is_not_a_name(self):
        assert values_of("患者：[PERSON_NAME_001]，男性。", "PERSON_NAME") == []

    def test_redaction_marker_is_inert(self):
        assert types_in("电话：[REDACTED]，住院号：[REDACTED]") - {"MEDICAL_CONTENT"} == set()

    def test_every_emitted_marker_is_inert(self):
        """Drive every marker the transformer layer can emit through detection."""
        from transformers.generalize import _TYPE_MARKERS
        from transformers.text import _REDACTED

        markers = [_REDACTED, *sorted(_TYPE_MARKERS.values())]
        for marker in markers:
            text = (
                f"患者：[PERSON_NAME_001]，性别：男\n"
                f"联系地址：{marker}\n"
                f"科室：{marker}\n"
                f"病区：{marker}\n"
                f"医院：{marker}\n"
                f"住院号：[REDACTED]\n"
                f"电话：[REDACTED]\n"
                f"就诊日期：2026-08\n"
            )
            found = types_in(text)
            assert found <= {"MEDICAL_CONTENT", "SEX"}, (marker, found)

    def test_is_placeholder_recognises_markers_only(self):
        from core.model import is_placeholder

        assert is_placeholder("[LOCATION_GENERALIZED]")
        assert is_placeholder("[PERSON_NAME_001]")
        assert is_placeholder("  [REDACTED]  ")
        assert not is_placeholder("北京市朝阳区建国路88号")
        assert not is_placeholder("[未闭合")
        assert not is_placeholder("lowercase_marker")
