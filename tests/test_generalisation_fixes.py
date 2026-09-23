"""Regression tests for the v0.3.2 generalisation fixes.

Each of these was found by the hand-written simulation corpus
(``tests/fixtures/simulation/``) rather than by the template corpus, and none of
them had an assertion before this file existed — the simulation corpus measures
but deliberately does not gate, so without these the fixes could silently
regress.

Four of the six share one shape: a shared contract existed and one consumer had
never adopted it. The last test covers the fourth instance of that shape, which
appeared while fixing the third.
"""

from __future__ import annotations

import pytest

from core.model import Purpose, Recipient, TrustLevel
from detectors import detect_all
from medical_privacy_guard import Guard


def values_of(text: str, fact_type: str) -> list[str]:
    return [text[f.start : f.end] for f in detect_all(text) if f.type == fact_type]


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


class TestSeparatorContractAdoption:
    """field_syntax exists so every labelled field accepts the same spellings.

    A consumer that spells out its own separator silently diverges: the same
    value is caught in one field and missed in another, with nothing a caller
    could see.
    """

    @pytest.mark.parametrize("sep", ["：", ":", "=", " ", "\u3000", ""])
    def test_person_name_accepts_every_separator(self, sep: str) -> None:
        assert values_of(f"姓名{sep}张伟", "PERSON_NAME") == ["张伟"]

    @pytest.mark.parametrize("sep", ["：", ":", "=", " ", "\u3000", ""])
    def test_department_accepts_every_separator(self, sep: str) -> None:
        assert values_of(f"科室{sep}神经内科", "DEPARTMENT") == ["神经内科"]

    def test_department_accepts_a_bracketed_value(self) -> None:
        assert values_of("科室（神经内科）", "DEPARTMENT") == ["神经内科"]

    def test_person_name_still_accepts_brackets(self) -> None:
        assert values_of("患者（张三）入院。", "PERSON_NAME") == ["张三"]


class TestStaffSignatureAndAssistant:
    """Signature and assistant lines are standard in surgical notes."""

    @pytest.mark.parametrize(
        "text, expected",
        [
            ("医师签名：王强", "王强"),
            ("医生签名：王强", "王强"),
            ("签名：王强", "王强"),
            ("助手：邓超", "邓超"),
            ("一助：邓超", "邓超"),
            ("手术助手：邓超", "邓超"),
        ],
    )
    def test_staff_name_is_detected(self, text: str, expected: str) -> None:
        assert values_of(text, "DOCTOR_NAME") == [expected]

    def test_a_title_word_is_still_not_a_name(self) -> None:
        assert values_of("主任医师每周查房两次。", "DOCTOR_NAME") == []


class TestDepartmentMovementContext:
    """A department reached by a movement verb is the patient's own.

    ``由急诊科转入心血管内科`` matched neither the label rule (no label) nor the
    trailing-suffix rule (no 门诊/病房/病区/住院).
    """

    def test_department_after_a_movement_verb(self) -> None:
        text = "患者汪洋由急诊科转入心血管内科。"
        assert "急诊科" in values_of(text, "DEPARTMENT")
        assert "心血管内科" in values_of(text, "DEPARTMENT")

    def test_the_patient_name_is_also_captured(self) -> None:
        assert values_of("患者汪洋由急诊科转入心血管内科。", "PERSON_NAME") == ["汪洋"]

    def test_a_referral_in_passing_is_still_left_alone(self) -> None:
        """docs/scope.md keeps the verb form out of scope."""
        assert values_of("建议神经内科会诊。", "DEPARTMENT") == []


class TestNestedKinshipValue:
    """``家属：其妻白洁陪同`` repeats the kinship term after the label."""

    def test_nested_form_is_captured(self) -> None:
        assert values_of("家属：其妻白洁陪同。", "RELATIVE_NAME") == ["白洁"]

    def test_plain_labelled_form_still_works(self) -> None:
        assert values_of("家属：张小明陪同。", "RELATIVE_NAME") == ["张小明"]

    def test_adjacent_form_still_works(self) -> None:
        assert values_of("其妻王芳陪同就诊。", "RELATIVE_NAME") == ["王芳"]

    def test_kinship_words_without_a_name_are_not_facts(self) -> None:
        assert values_of("家属表示理解，父亲同意。", "RELATIVE_NAME") == []


class TestSharedNameBoundary:
    """The adjacent form and the verifier must agree on what may follow a name.

    They kept separate lists. Adding a word to the detector's list but not the
    verifier's turns a detection into a verification failure — a released note
    becomes a withheld one, which is worse than the original miss because the
    caller sees a failure rather than a gap.
    """

    def test_movement_verb_after_a_name_verifies(self, guard: Guard, approved: Recipient) -> None:
        result = guard.sanitize(
            "患者汪洋由急诊科转入心血管内科。", approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.sanitized_payload is not None
        assert result.verification is not None and result.verification.passed
        assert "汪洋" not in result.sanitized_payload.content

    @pytest.mark.parametrize(
        "text",
        [
            "患者李四入院。",
            "患者李四出院。",
            "患者李四就诊。",
            "患者李四住院治疗。",
            "患者李四由急诊科转入。",
            "患者李四因胸痛入院。",
            "患者李四于本院治疗。",
            "患者李四诉头痛。",
            "患者李四在院治疗。",
            "患者李四自述头晕。",
            "患者李四伴发热。",
            "患者李四拟手术。",
        ],
    )
    def test_shared_boundary_words_verify(
        self, guard: Guard, approved: Recipient, text: str
    ) -> None:
        """Every word the detector accepts must also satisfy the verifier.

        The two used to keep separate lists, so a word added to one and not the
        other turned a detection into a withheld release.
        """
        result = guard.sanitize(text, approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.verification is not None, text
        assert result.verification.passed, f"{text}: {result.verification.details}"

    def test_a_name_followed_by_prose_still_fails_closed(
        self, guard: Guard, approved: Recipient
    ) -> None:
        """The boundary check must still catch a genuinely truncated span."""
        from core.policy import load_builtin_profile
        from core.verify import Verifier, _CheckFailure

        verifier = Verifier(load_builtin_profile("external-ai-strict"))
        with pytest.raises(_CheckFailure):
            verifier._check_name_span_boundary("PERSON_NAME", "张", "患者张伟。", 3)
