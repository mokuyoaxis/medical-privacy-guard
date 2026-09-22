"""Institution dictionary: a local vocabulary used for detection and verification.

The vocabulary is the only genuinely independent verification signal in the
project. Re-scanning with the same detectors only proves they agree with
themselves; a term from the deployment's own records can flag a word no rule
ever knew. These tests cover loading (both formats and the failure paths), the
four categories, over-redaction controls, the residual check, and the rule that
the vocabulary itself never reaches an audit record.

All fixtures are synthetic. See ``tests/fixtures/synthetic/README.md``: the
vocabulary names real institutions and real staff in production, so no real name
may be committed here.
"""

from __future__ import annotations

import json

import pytest

from core.dictionary import InstitutionDictionary, load_dictionary
from core.errors import DictionaryError
from core.model import Purpose, Recipient, TrustLevel
from detectors.dictionary import DictionaryDetector
from medical_privacy_guard import Guard

CSV_BODY = """category,name
institution,望江医院
department,神经内科
ward,神内二病区
staff,王建国
"""

JSON_BODY = {
    "institution": ["望江医院"],
    "department": ["神经内科"],
    "ward": ["神内二病区"],
    "staff": ["王建国"],
}


@pytest.fixture
def csv_path(tmp_path):
    path = tmp_path / "vocabulary.csv"
    path.write_text(CSV_BODY, encoding="utf-8")
    return path


@pytest.fixture
def json_path(tmp_path):
    path = tmp_path / "vocabulary.json"
    path.write_text(json.dumps(JSON_BODY, ensure_ascii=False), encoding="utf-8")
    return path


@pytest.fixture
def vocabulary(csv_path):
    return load_dictionary(csv_path)


@pytest.fixture
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


# -- loading -----------------------------------------------------------------


class TestLoading:
    def test_csv_and_json_agree(self, csv_path, json_path):
        from_csv = load_dictionary(csv_path)
        from_json = load_dictionary(json_path)
        assert from_csv.terms("institution") == from_json.terms("institution")
        assert from_csv.terms("staff") == from_json.terms("staff")
        assert len(from_csv) == len(from_json) == 4

    def test_terms_are_grouped_by_category(self, vocabulary):
        assert vocabulary.terms("ward") == frozenset({"神内二病区"})
        assert vocabulary.terms("staff") == frozenset({"王建国"})

    def test_unknown_category_raises(self, vocabulary):
        with pytest.raises(DictionaryError):
            vocabulary.terms("patient")

    def test_entries_are_longest_first(self, vocabulary):
        terms = [term for term, _ in vocabulary.entries()]
        assert terms == sorted(terms, key=lambda term: (-len(term), term))

    @pytest.mark.parametrize(
        "body, reason",
        [
            ("", "empty file"),
            ("name,category\nx,institution\n", "header order"),
            ("category,name\nplanet,Mars\n", "unknown category"),
            ("category,name\ninstitution,\n", "empty term"),
        ],
    )
    def test_csv_failures_are_explicit(self, tmp_path, body, reason):
        """A vocabulary the deployment believes is active but which loaded
        nothing is worse than no vocabulary at all."""
        path = tmp_path / "bad.csv"
        path.write_text(body, encoding="utf-8")
        with pytest.raises(DictionaryError):
            load_dictionary(path)

    def test_json_unknown_key_raises(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text('{"planet": ["Mars"]}', encoding="utf-8")
        with pytest.raises(DictionaryError):
            load_dictionary(path)

    def test_json_wrong_type_raises(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text('{"staff": "王建国"}', encoding="utf-8")
        with pytest.raises(DictionaryError):
            load_dictionary(path)

    def test_unsupported_suffix_raises(self, tmp_path):
        path = tmp_path / "vocabulary.txt"
        path.write_text(CSV_BODY, encoding="utf-8")
        with pytest.raises(DictionaryError):
            load_dictionary(path)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(DictionaryError):
            load_dictionary(tmp_path / "absent.csv")

    def test_empty_dictionary_reports_empty(self):
        assert InstitutionDictionary().is_empty()


# -- detection ---------------------------------------------------------------


class TestDictionaryDetection:
    @pytest.mark.parametrize(
        "text, fact_type, term",
        [
            ("患者在望江医院就诊。", "HOSPITAL_NAME", "望江医院"),
            ("患者在神经内科住院。", "DEPARTMENT", "神经内科"),
            ("患者转入神内二病区。", "WARD", "神内二病区"),
            ("患者由王建国医师接诊。", "DOCTOR_NAME", "王建国"),
        ],
    )
    def test_each_category_is_detected(self, vocabulary, text, fact_type, term):
        facts = DictionaryDetector(vocabulary).detect(text)
        assert [(f.type, text[f.start : f.end]) for f in facts] == [(fact_type, term)]

    def test_longer_term_wins_over_its_own_prefix(self, tmp_path):
        """神内二病区 must not also produce a fact for a shorter entry."""
        path = tmp_path / "v.csv"
        path.write_text(
            "category,name\nward,神内二病区\nward,神内\n", encoding="utf-8"
        )
        dictionary = load_dictionary(path)
        text = "患者转入神内二病区。"
        facts = DictionaryDetector(dictionary).detect(text)
        assert [text[f.start : f.end] for f in facts] == ["神内二病区"]

    def test_dictionary_and_rules_are_merged(self, csv_path):
        """Both sources run; the registry deduplicates overlapping spans."""
        guard = Guard(profile="external-ai-strict", dictionary_path=str(csv_path))
        facts = guard.detect("患者在望江医院神经内科住院。")
        kinds = {f.type for f in facts}
        assert {"HOSPITAL_NAME", "DEPARTMENT"} <= kinds


class TestOverRedactionControls:
    """A dictionary must not overturn docs/scope.md's deliberate non-detection."""

    @pytest.mark.parametrize(
        "text",
        ["建议神经内科会诊。", "转诊至望江医院。", "转往神内二病区。"],
    )
    def test_referral_targets_stay_clean(self, vocabulary, text):
        assert DictionaryDetector(vocabulary).detect(text) == ()

    def test_no_dictionary_means_no_dictionary_detector(self):
        guard = Guard(profile="external-ai-strict")
        assert not any(
            f.source.startswith("dictionary.") for f in guard.detect("患者在望江医院就诊。")
        )


# -- the independent verification signal -------------------------------------


class TestDictionaryResidualVerification:
    def test_a_dictionary_term_is_detected_and_verified_away(self, csv_path, approved):
        """End to end: a staff name only the vocabulary knows is removed."""
        guard = Guard(profile="external-ai-strict", dictionary_path=str(csv_path))
        result = guard.sanitize(
            "患者由王建国医师接诊。", approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.sanitized_payload is not None
        assert "王建国" not in result.sanitized_payload.content
        assert result.verification is not None and result.verification.passed

    def test_a_referral_target_is_not_a_residual(self, csv_path):
        """The detector ignores referral targets, and verification must agree.

        Otherwise the two disagree and no note containing a referral could ever
        be released.
        """
        from core.policy import load_builtin_profile
        from core.verify import Verifier

        verifier = Verifier(
            load_builtin_profile("external-ai-strict"),
            dictionary=load_dictionary(csv_path),
        )
        verifier._check_dictionary_residual("建议神经内科会诊。")

    def test_failure_names_the_category_not_the_term(self, csv_path):
        """The vocabulary is a sensitive asset: a failure may say which
        category survived, never which term."""
        from core.policy import load_builtin_profile
        from core.verify import Verifier, _CheckFailure

        verifier = Verifier(
            load_builtin_profile("external-ai-strict"),
            dictionary=load_dictionary(csv_path),
        )
        with pytest.raises(_CheckFailure) as excinfo:
            verifier._check_dictionary_residual("患者由王建国医师接诊。")
        assert "staff" in excinfo.value.detail
        assert "王建国" not in excinfo.value.detail

    def test_clean_text_has_no_dictionary_residual(self, csv_path):
        from core.policy import load_builtin_profile
        from core.verify import Verifier

        verifier = Verifier(
            load_builtin_profile("external-ai-strict"),
            dictionary=load_dictionary(csv_path),
        )
        verifier._check_dictionary_residual("患者由[DOCTOR_NAME_001]医师接诊。")

    def test_clean_output_passes(self, csv_path, approved):
        guard = Guard(profile="external-ai-strict", dictionary_path=str(csv_path))
        result = guard.sanitize(
            "患者在望江医院就诊。", approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.sanitized_payload is not None
        assert result.verification is not None and result.verification.passed


# -- the vocabulary is an asset ----------------------------------------------


class TestAuditDoesNotLeakVocabulary:
    def test_audit_records_counts_only(self, tmp_path, csv_path, approved):
        audit_dir = tmp_path / "audit"
        guard = Guard(
            profile="external-ai-strict",
            dictionary_path=str(csv_path),
            audit_dir=str(audit_dir),
        )
        guard.sanitize("患者在望江医院就诊。", approved, Purpose.EXTERNAL_AI_ASSISTANCE)

        stream = (audit_dir / "events.jsonl").read_text(encoding="utf-8")
        event = json.loads(stream.strip())
        assert event["dictionary_loaded"] is True
        assert event["dictionary_entries"] == 4
        for term in ("望江医院", "神经内科", "神内二病区", "王建国"):
            assert term not in stream, term

    def test_audit_without_dictionary_reports_zero(self, tmp_path, approved):
        audit_dir = tmp_path / "audit"
        guard = Guard(profile="external-ai-strict", audit_dir=str(audit_dir))
        guard.sanitize("患者在望江医院就诊。", approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        event = json.loads((audit_dir / "events.jsonl").read_text(encoding="utf-8").strip())
        assert event["dictionary_loaded"] is False
        assert event["dictionary_entries"] == 0


# -- the reserved extension point --------------------------------------------


class TestExternalDetectors:
    """Supplied detectors may only extend recall; they never decide."""

    def test_a_custom_detector_is_used(self, approved):
        from core.model import DetectedFact
        from detectors.base import Detector

        class MarkerDetector(Detector):
            name = "marker"

            def detect(self, text):
                index = text.find("标记")
                if index < 0:
                    return ()
                return (
                    DetectedFact(
                        type="PERSON_NAME",
                        start=index,
                        end=index + 2,
                        confidence=0.9,
                        source="custom.marker",
                        value="标记",
                    ),
                )

        guard = Guard(profile="external-ai-strict", detectors=(MarkerDetector(),))
        facts = guard.detect("患者标记入院。")
        assert any(f.source == "custom.marker" for f in facts)
        # Policy still owns the verdict, and verification still runs.
        result = guard.sanitize("患者标记入院。", approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.decision_before.verdict.value == "SANITIZE"
        assert result.verification is not None

    def test_default_detectors_are_untouched(self, approved):
        """Passing no detectors keeps the built-in set."""
        guard = Guard(profile="external-ai-strict")
        assert any(
            f.type == "PERSON_NAME" for f in guard.detect("患者张三入院。")
        )
