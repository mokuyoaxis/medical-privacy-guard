"""Characters that render as nothing must not change what the guard detects.

The name detectors end a captured value on punctuation, whitespace or a
boundary word. Unicode's format characters are none of those, so one U+200B
after a name -- or inside it -- made every name detector miss while
verification, which re-runs the same detectors, reported success. The payload
was released with the name intact. The same character can arrive as a JSON
escape, which leaves the file's own bytes free of any control character, so the
text-path admission check never sees it.

These tests pin the reading, not the implementation: they assert that a name the
guard is meant to find is found and removed, whatever invisible character was
used to hide it.
"""

from __future__ import annotations

import json

import pytest

from cli.main import EXIT_BLOCK, EXIT_OK, main
from core.model import (
    Decision,
    DetectedFact,
    Payload,
    Purpose,
    ReasonCode,
    Recipient,
    RiskLevel,
    RiskSummary,
    TrustLevel,
    Verdict,
)
from core.policy import load_builtin_profile
from medical_privacy_guard import Guard
from medical_privacy_guard.guard import _rebuilt_document_releasable

INVISIBLE_CHARACTERS: tuple[tuple[str, str], ...] = (
    ("zero-width space", "\u200b"),
    ("zero-width non-joiner", "\u200c"),
    ("zero-width joiner", "\u200d"),
    ("word joiner", "\u2060"),
    ("byte order mark", "\ufeff"),
    ("soft hyphen", "\u00ad"),
    ("variation selector", "\ufe0f"),
    ("tag character", "\U000e0001"),
    ("left-to-right isolate", "\u2066"),
)

#: The visible separator the end conditions also accept. It is not an invisible
#: character: it changes what the reader sees, and it is listed here only so the
#: boundary table cannot lose it silently.
VISIBLE_SEPARATOR = "\u2e2f"


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


@pytest.fixture(scope="module")
def profile():
    return load_builtin_profile("external-ai-strict")


class TestInvisibleCharactersCannotHideAName:
    @pytest.mark.parametrize("label, char", INVISIBLE_CHARACTERS)
    def test_a_name_after_the_value_is_detected(self, guard, label, char):
        facts = {f.type for f in guard.detect(f"患者姓名：张伟{char}")}
        assert "PERSON_NAME" in facts, f"{label} blinded the name detector"

    @pytest.mark.parametrize("label, char", INVISIBLE_CHARACTERS)
    def test_a_name_split_by_the_character_is_detected(self, guard, label, char):
        facts = {f.type for f in guard.detect(f"患者姓名：张{char}伟")}
        assert "PERSON_NAME" in facts, f"{label} split the name past the detector"

    @pytest.mark.parametrize("label, char", INVISIBLE_CHARACTERS)
    def test_a_labelled_payload_never_reaches_allow(self, guard, approved, label, char):
        result = guard.evaluate(
            f"患者姓名：张伟{char}", approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision.verdict is not Verdict.ALLOW, label

    @pytest.mark.parametrize("label, char", INVISIBLE_CHARACTERS)
    def test_the_released_text_does_not_carry_the_name(self, guard, approved, label, char):
        result = guard.sanitize(
            f"患者姓名：张伟{char}，联系电话13800000000",
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.verification is not None and result.verification.passed
        released = result.sanitized_payload.content
        assert "张伟" not in released, label
        assert "13800000000" not in released

    def test_a_visible_separator_still_ends_the_value(self, guard):
        facts = {f.type for f in guard.detect(f"患者姓名：张伟{VISIBLE_SEPARATOR}")}
        assert "PERSON_NAME" in facts

    def test_the_released_document_does_not_carry_the_name(self, guard, approved):
        """The same character, arriving as a JSON escape inside a leaf."""
        result = guard.sanitize(
            '{"name": "张伟\u200b", "phone": "13800000000"}',
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.verification is not None and result.verification.passed
        rebuilt = json.loads(result.sanitized_payload.content)
        assert "张伟" not in rebuilt["name"]
        assert rebuilt["phone"] == "[REDACTED]"

    def test_an_explicitly_declared_text_payload_is_normalised_too(self, guard, approved):
        """``Payload(kind="text")`` skips classification, not normalisation."""
        result = guard.sanitize(
            Payload(kind="text", content="患者姓名：张伟\u200b"),
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.verification is not None and result.verification.passed
        assert "张伟" not in result.sanitized_payload.content


class TestStructuredLeavesAreAdmitted:
    def test_a_nul_escape_is_withheld(self, guard, approved):
        """The file's bytes are clean ASCII; the NUL only appears after parsing."""
        result = guard.sanitize(
            '{"name": "张伟\u0000"}', approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None

    def test_a_control_character_in_a_leaf_is_withheld(self, guard, approved):
        result = guard.sanitize(
            {"name": "张伟\u0001"}, approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None

    def test_a_non_string_key_is_withheld(self, guard, approved):
        """A pointer built from ``str(key)`` cannot address a non-string key."""
        result = guard.sanitize(
            {1: "姓名：张伟", "ok": "姓名：李四"},
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None

    @pytest.mark.parametrize("value", [b"x", {1, 2}, object()])
    def test_a_value_json_cannot_carry_is_withheld(self, guard, approved, value):
        result = guard.sanitize(
            {"name": "姓名：张伟", "extra": value},
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None


class TestGuardStringEntryClassifies:
    def test_a_json_string_is_scanned_as_a_document(self, guard, approved):
        result = guard.evaluate('{"name": "张三"}', approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.decision.verdict is Verdict.SANITIZE
        assert any(f.type == "PERSON_NAME" for f in result.facts)

    def test_a_chinese_labelled_key_is_scanned_as_a_document(self, guard, approved):
        result = guard.evaluate(
            '{"患者姓名": "张伟"}', approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision.verdict is Verdict.SANITIZE

    def test_a_number_identifier_is_not_rewritten_in_place(self, guard, approved):
        """A JSON number cannot take a string replacement; review, not release."""
        result = guard.sanitize(
            '{"phone": 13800000000}', approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision_before.verdict is Verdict.ASK
        assert result.sanitized_payload is None

    def test_prose_is_still_prose(self, guard, approved):
        result = guard.evaluate("患者：张三", approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.decision.verdict is Verdict.SANITIZE

    def test_the_guard_agrees_with_the_adapter_route(self, guard, approved):
        from adapters import payload_for

        text = '{"name": "张三", "mrn": "1234567"}'
        direct = guard.evaluate(text, approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        adapted = guard.evaluate(payload_for(text), approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert direct.decision.verdict is adapted.decision.verdict
        assert {f.type for f in direct.facts} == {f.type for f in adapted.facts}


class TestEnglishKeysReachTheEnglishRules:
    """A key translated to a Chinese label must not disable the English rules.

    ``{"name": "John Smith"}`` was probed as ``姓名：John Smith``: the Chinese
    rules need ideographs to capture and the English rules look for
    ``name:``/``patient:``, so neither fired and the document was released with
    the name intact.
    """

    @pytest.mark.parametrize(
        "document, name_key",
        [
            ('{"name": "John Smith"}', "name"),
            ('{"patient_name": "John Smith"}', "patient_name"),
            ('{"name": "Mary-Jane"}', "name"),
            ('{"name": "张伟"}', "name"),
        ],
    )
    def test_an_english_keyed_name_is_detected(self, guard, approved, document, name_key):
        result = guard.sanitize(document, approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.verification is not None and result.verification.passed
        rebuilt = json.loads(result.sanitized_payload.content)
        assert "John" not in rebuilt[name_key]
        assert "Smith" not in rebuilt[name_key]
        assert "张伟" not in rebuilt[name_key]

    def test_the_interpunct_is_detected_in_its_other_encodings(self, guard, approved):
        """The same mark, written by a different IME, is the same mark."""
        for char in ("\u00b7", "\u30fb", "\u2027"):
            result = guard.sanitize(
                f'{{"name": "阿依古丽{char}买买提"}}',
                approved,
                Purpose.EXTERNAL_AI_ASSISTANCE,
            )
            assert result.verification is not None and result.verification.passed
            released = result.sanitized_payload.content
            assert "阿依古丽" not in released and "买买提" not in released

    def test_a_csv_column_reaches_the_english_rules(self, guard, approved):
        result = guard.sanitize(
            Payload(kind="csv", content="name,phone\nJohn Smith,13800000000\n"),
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.verification is not None and result.verification.passed
        assert "[PERSON_NAME_001]" in result.sanitized_payload.content

    def test_a_number_under_an_english_key_is_still_reviewed(self, guard, approved):
        result = guard.sanitize('{"mrn": 1234567}', approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.decision_before.verdict is Verdict.ASK
        assert result.sanitized_payload is None

    def test_both_probes_agree_on_one_fact(self, guard):
        """A value both spellings match is one fact, not two."""
        parsed = guard._parse_structured({"name": "张伟"}, "json")
        from medical_privacy_guard.guard import _detect_leaves, _flatten

        text, spans = _flatten(parsed.leaves)
        facts = _detect_leaves(parsed.leaves, spans, guard._detectors)
        names = [f for f in facts if f.type == "PERSON_NAME"]
        assert len(names) == 1
        assert (names[0].start, names[0].end) == (0, 2)


class TestCliAdmissionAgrees:
    def test_inspect_and_sanitize_agree_on_a_csv_file(self, tmp_path, capsys):
        """A content classifier has no meaning for a table.

        The CSV below starts with a cell that looks like a JSON container. A
        content check read that as a broken payload and refused the file, while
        ``sanitize`` read it as CSV and released it: two answers for one file.
        """
        path = tmp_path / "records.csv"
        path.write_text('{"a":1},b\n张三,13800000000\n', encoding="utf-8")
        argv = [
            "--recipient", "external_unknown",
            "--purpose", "external_ai_assistance",
        ]
        inspect_code = main(["inspect", str(path), *argv])
        capsys.readouterr()
        sanitize_code = main(["sanitize", str(path), *argv])
        captured = capsys.readouterr()

        assert inspect_code == EXIT_OK
        assert sanitize_code == EXIT_OK
        assert "13800000000" not in captured.out

    def test_an_unreadable_file_is_refused_by_both(self, tmp_path, capsys):
        path = tmp_path / "broken.json"
        path.write_text('{"a": 1} trailing', encoding="utf-8")
        argv = ["--recipient", "external_unknown", "--purpose", "external_ai_assistance"]
        assert main(["inspect", str(path), *argv]) == EXIT_BLOCK
        capsys.readouterr()
        assert main(["sanitize", str(path), *argv]) == EXIT_BLOCK


def _decision(verdict: Verdict) -> Decision:
    return Decision(
        verdict=verdict,
        reason_codes=(ReasonCode.NO_SENSITIVE_DATA_DETECTED,),
        explanation="test",
        risk=RiskSummary(level=RiskLevel.LOW, score=0, factors=()),
        plan=None,
        policy_version="external-ai-strict/1",
    )


def _fact(fact_type: str) -> DetectedFact:
    return DetectedFact(
        type=fact_type, start=0, end=1, confidence=0.9, source="test", value="x"
    )


class TestRebuiltDocumentIsRechecked:
    """Verification reads the flattened text; the released string is the rebuilt
    document. The gap between them is closed by re-deciding on the rebuild."""

    def test_allow_is_releasable(self, profile):
        assert _rebuilt_document_releasable(profile, _decision(Verdict.ALLOW), ())

    @pytest.mark.parametrize("verdict", [Verdict.BLOCK, Verdict.ASK])
    def test_a_withholding_verdict_is_never_releasable(self, profile, verdict):
        assert not _rebuilt_document_releasable(profile, _decision(verdict), ())

    def test_an_erase_type_residual_is_not_releasable(self, profile):
        assert not _rebuilt_document_releasable(
            profile, _decision(Verdict.SANITIZE), (_fact("PERSON_NAME"),)
        )

    def test_a_context_only_residual_is_releasable(self, profile):
        assert _rebuilt_document_releasable(
            profile, _decision(Verdict.SANITIZE), (_fact("SEX"),)
        )

    def test_a_rebuild_that_drops_a_replacement_is_withheld(
        self, guard, approved, monkeypatch
    ):
        """The end-to-end shape of the same defect: a rebuild that silently keeps
        the original value must not be released as a verified sanitization."""
        from medical_privacy_guard import guard as guard_module

        monkeypatch.setattr(
            guard_module, "rebuild", lambda document, replacements: document
        )
        result = guard.sanitize(
            {"name": "张三", "phone": "13800000000"},
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.sanitized_payload is None
        assert result.verification is not None and not result.verification.passed
