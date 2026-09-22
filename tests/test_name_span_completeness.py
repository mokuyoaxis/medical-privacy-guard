"""A name span must cover the whole name, and release must be withheld if it does not.

Found while analysing v0.2.0: the staff and relative detectors bounded a
labelled name with the given-name character inventory. That inventory cannot be
complete, so a name whose given character is outside it was captured only up to
the surname and the remainder was released — ``责任护士：郑爽`` sanitized to
``责任护士：[NURSE_NAME_001]爽``. Verification reported success, because an
orphaned given-name character no longer matches a name pattern: re-detection
cannot see what the detector never saw.

Both halves of the fix are pinned here. The detectors capture the whole name,
and verification withholds release when a span stops inside one anyway.
"""

from __future__ import annotations

import pytest

from core.model import DetectedFact, Purpose, Recipient, TrustLevel
from core.policy import load_builtin_profile
from core.verify import Verifier, _CheckFailure
from detectors import detect_all
from medical_privacy_guard import Guard


def values_of(text: str, fact_type: str) -> list[str]:
    return [text[f.start : f.end] for f in detect_all(text) if f.type == fact_type]


@pytest.fixture(scope="module")
def verifier() -> Verifier:
    return Verifier(load_builtin_profile("external-ai-strict"))


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


# 爽, 鑫 and 曦 are ordinary given-name characters that were missing from the
# inventory; 王五 / 李四 are the placeholder names the adjacent form already
# handled through its numeral branch.
_LABELLED_NAMES = ["郑爽", "王鑫", "李曦", "王五", "李四", "欧阳修远", "张小明"]


class TestLabelledValueIsComplete:
    """A separator bounds the value, so no character inventory is involved."""

    @pytest.mark.parametrize("name", _LABELLED_NAMES)
    def test_nurse_title(self, name: str) -> None:
        assert values_of(f"责任护士：{name}。", "NURSE_NAME") == [name]

    @pytest.mark.parametrize("name", _LABELLED_NAMES)
    def test_doctor_title(self, name: str) -> None:
        assert values_of(f"主治医师：{name}查看患者。", "DOCTOR_NAME") == [name]

    @pytest.mark.parametrize("name", _LABELLED_NAMES)
    def test_relative_label(self, name: str) -> None:
        assert values_of(f"家属：{name}签字同意。", "RELATIVE_NAME") == [name]

    @pytest.mark.parametrize("name", ["郑爽", "王五", "王芳"])
    def test_relative_adjacent(self, name: str) -> None:
        assert values_of(f"其妻{name}陪同就诊。", "RELATIVE_NAME") == [name]


class TestStaffLabels:
    """医生：X and 主刀医生：X were absent from the title list entirely."""

    @pytest.mark.parametrize("label", ["医生", "主刀医生", "管床医生", "值班医生"])
    def test_doctor_label(self, label: str) -> None:
        assert values_of(f"{label}：李四。", "DOCTOR_NAME") == ["李四"]

    @pytest.mark.parametrize("label", ["护士", "护士长", "责任护士"])
    def test_nurse_label(self, label: str) -> None:
        assert values_of(f"{label}：王五。", "NURSE_NAME") == ["王五"]


class TestBracketedAndCompoundForms:
    """A labelled value may be bracketed; a compound surname may precede a title."""

    @pytest.mark.parametrize(
        "text, fact_type, expected",
        [
            ("家属：王芳（女儿）。", "RELATIVE_NAME", "王芳"),
            ("家属：王芳（女儿）签字同意。", "RELATIVE_NAME", "王芳"),
            ("主治医师：王建国（主任）。", "DOCTOR_NAME", "王建国"),
            ("责任护士：郑爽（夜班）。", "NURSE_NAME", "郑爽"),
            ("欧阳娜娜医生。", "DOCTOR_NAME", "欧阳娜娜"),
            ("欧阳娜娜护士。", "NURSE_NAME", "欧阳娜娜"),
        ],
    )
    def test_form(self, text: str, fact_type: str, expected: str) -> None:
        assert values_of(text, fact_type) == [expected]


class TestOverDetectionControls:
    """A label alone must not turn clinical prose into a person."""

    @pytest.mark.parametrize(
        "text, fact_type",
        [
            ("责任护士每班交接。", "NURSE_NAME"),
            ("家属表示理解，父亲同意。", "RELATIVE_NAME"),
            ("主任医师每周查房两次。", "DOCTOR_NAME"),
            ("本科室共12名医生。", "DOCTOR_NAME"),
            ("患者周转正常。", "PERSON_NAME"),
            ("本病区患者周转正常。", "PERSON_NAME"),
        ],
    )
    def test_no_fact(self, text: str, fact_type: str) -> None:
        assert values_of(text, fact_type) == []


class TestVerifierNameSpanBoundary:
    """The check reads the original text, because re-detection cannot see this."""

    @pytest.mark.parametrize(
        "kind, raw, original, end",
        [
            ("NURSE_NAME", "郑", "责任护士：郑爽。", 6),
            ("NURSE_NAME", "郑", "责任护士：郑沫。", 6),
            ("PERSON_NAME", "张三", "患者张三李四。", 4),
        ],
    )
    def test_rejects_a_span_that_stops_inside_a_name(
        self, verifier: Verifier, kind: str, raw: str, original: str, end: int
    ) -> None:
        with pytest.raises(_CheckFailure):
            verifier._check_name_span_boundary(kind, raw, original, end)

    @pytest.mark.parametrize(
        "kind, raw, original, end",
        [
            ("NURSE_NAME", "郑爽", "责任护士：郑爽。", 7),
            ("NURSE_NAME", "郑爽", "责任护士：郑爽陪同。", 7),
            ("NURSE_NAME", "李", "李护士测量血压。", 1),
            ("PERSON_NAME", "张三", "患者张三入院。", 4),
            ("PERSON_NAME", "张三", "患者张三", 4),
            ("DOCTOR_NAME", "王建国", "主治医师：王建国查看患者。", 8),
            ("RELATIVE_NAME", "张伟", "父亲：张伟签字同意。", 5),
            ("AGE", "67岁", "年龄67岁多。", 6),
        ],
    )
    def test_accepts_a_complete_name(
        self, verifier: Verifier, kind: str, raw: str, original: str, end: int
    ) -> None:
        verifier._check_name_span_boundary(kind, raw, original, end)


class TestTruncatedNameWithholdsRelease:
    """End to end: a partial span must never reach the released payload."""

    def test_a_truncating_detector_cannot_release(
        self, monkeypatch: pytest.MonkeyPatch, approved: Recipient
    ) -> None:
        import detectors
        import detectors.registry as registry
        from detectors.base import Detector

        class TruncatingDetector(Detector):
            """Reproduces the defect: a labelled value captured up to the surname."""

            name = "truncating_probe"
            fact_type = "NURSE_NAME"
            confidence = 0.9

            def detect(self, text: str) -> tuple[DetectedFact, ...]:
                label = "责任护士："
                index = text.find(label)
                if index < 0:
                    return ()
                start = index + len(label)
                return (
                    DetectedFact(
                        type=self.fact_type,
                        start=start,
                        end=start + 1,
                        confidence=self.confidence,
                        source=f"regex.{self.name}",
                        value=text[start : start + 1],
                    ),
                )

        patched = registry.DEFAULT_DETECTORS + (TruncatingDetector(),)
        monkeypatch.setattr(registry, "DEFAULT_DETECTORS", patched)
        monkeypatch.setattr(detectors, "DEFAULT_DETECTORS", patched)

        guard = Guard(profile="external-ai-strict")
        result = guard.sanitize(
            "患者因胸痛入院，责任护士：郑爽。",
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )

        assert result.sanitized_payload is None
        assert result.verification is not None
        assert result.verification.passed is False
