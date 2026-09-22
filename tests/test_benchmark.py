"""Tests for the benchmark harness.

Two layers are covered:

- unit-level alignment logic (type-aware, exact one-to-one span matching);
- end-to-end runs against the committed corpus, asserting the zero-tolerance
  safety gates (false allows, residual PHI, audit leaks) and the report schema.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from core.benchmark import (
    CorpusDocument,
    _count_audit_leaks,
    _survives_as_token,
    align_document,
    load_corpus,
    run_benchmark,
)
from core.errors import GuardError
from core.model import DetectedFact

CORPUS = Path(__file__).resolve().parent / "fixtures" / "synthetic_cn_notes"


def _fact(fact_type: str, start: int, end: int) -> DetectedFact:
    return DetectedFact(
        type=fact_type,
        start=start,
        end=end,
        confidence=1.0,
        source="test",
        value=None,
    )


# -- alignment --------------------------------------------------------------


class TestAlignDocument:
    def test_exact_match_is_true_positive(self):
        spans = [{"type": "PHONE", "start": 5, "end": 16}]
        tp, fn, fp = align_document([_fact("PHONE", 5, 16)], spans)
        assert (tp, fn, fp) == (1, 0, 0)

    def test_type_mismatch_is_not_a_match(self):
        spans = [{"type": "PHONE", "start": 0, "end": 11}]
        tp, fn, fp = align_document([_fact("PERSON_NAME", 0, 11)], spans)
        assert (tp, fn) == (0, 1)

    @pytest.mark.parametrize("start,end", [(3, 4), (4, 5), (3, 6), (2, 5)])
    def test_inexact_boundaries_are_not_true_positives(self, start, end):
        spans = [{"type": "PERSON_NAME", "start": 3, "end": 5}]
        assert align_document([_fact("PERSON_NAME", start, end)], spans) == (0, 1, 1)

    def test_one_fact_cannot_match_two_labels(self):
        spans = [{"type": "PERSON_NAME", "start": 0, "end": 5}] * 2
        assert align_document([_fact("PERSON_NAME", 0, 5)], spans) == (1, 1, 0)

    def test_duplicate_facts_count_as_false_positives(self):
        spans = [{"type": "PERSON_NAME", "start": 0, "end": 5}]
        assert align_document([_fact("PERSON_NAME", 0, 5)] * 2, spans) == (1, 0, 1)

    def test_adjacent_but_non_overlapping_is_a_miss(self):
        spans = [{"type": "PERSON_NAME", "start": 0, "end": 3}]
        tp, fn, _ = align_document([_fact("PERSON_NAME", 3, 6)], spans)
        assert (tp, fn) == (0, 1)

    def test_unlabelled_fact_of_scored_type_is_false_positive(self):
        spans = [{"type": "PHONE", "start": 0, "end": 11}]
        facts = [_fact("PHONE", 0, 11), _fact("PHONE", 20, 31)]
        tp, fn, fp = align_document(facts, spans)
        assert (tp, fn, fp) == (1, 0, 1)

    def test_document_level_facts_are_not_scored(self):
        """MEDICAL_CONTENT has no labelled span and must not count as FP."""
        spans = [{"type": "PHONE", "start": 0, "end": 11}]
        facts = [_fact("PHONE", 0, 11), _fact("MEDICAL_CONTENT", 30, 32)]
        tp, fn, fp = align_document(facts, spans)
        assert (tp, fn, fp) == (1, 0, 0)

    def test_empty_annotations_yield_no_penalty(self):
        tp, fn, fp = align_document([_fact("MEDICAL_CONTENT", 0, 2)], [])
        assert (tp, fn, fp) == (0, 0, 0)


# -- corpus loading ---------------------------------------------------------


class TestLoadCorpus:
    def test_loads_committed_corpus(self):
        documents = load_corpus(CORPUS)
        assert len(documents) >= 140
        assert all(d.text for d in documents)

    def test_limit_is_applied(self):
        assert len(load_corpus(CORPUS, limit=5)) == 5

    def test_missing_directory_raises(self):
        with pytest.raises(GuardError):
            load_corpus(tmp_path_missing := Path("/nonexistent-corpus-path"))
        assert tmp_path_missing is not None

    def test_out_of_range_span_raises(self, tmp_path):
        (tmp_path / "doc_001.txt").write_text("短文本", encoding="utf-8")
        (tmp_path / "doc_001.spans.json").write_text(
            json.dumps(
                {
                    "doc_id": "doc_001",
                    "document_type": "outpatient_note",
                    "spans": [{"type": "PHONE", "start": 0, "end": 999}],
                    "expected_verdict": "SANITIZE",
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(GuardError):
            load_corpus(tmp_path)


# -- end-to-end -------------------------------------------------------------


@pytest.fixture(scope="module")
def report():
    return run_benchmark(CORPUS)


class TestBenchmarkGates:
    def test_no_false_allows(self, report):
        assert report.false_allow_count == 0

    def test_no_residual_phi(self, report):
        assert report.residual_phi_count == 0

    def test_no_audit_raw_leaks(self, report):
        assert report.audit_raw_leak_count == 0

    def test_no_errors(self, report):
        assert report.errors == 0

    def test_gates_passed(self, report):
        assert report.gates_passed() is True

    def test_no_verdict_mismatches(self, report):
        assert report.verdict_mismatch_count == 0

    def test_every_gate_passes(self, report):
        assert report.gate_failures() == ()
        assert report.passed() is True

    def test_high_recall_on_synthetic_corpus(self, report):
        # The corpus is generated to match detector capabilities, so recall is
        # expected to be 1.0 here; this asserts no silent regression.
        assert report.span_recall == 1.0
        assert report.span_precision == 1.0

    def test_every_labelled_span_is_accounted_for(self, report):
        assert report.true_positives + report.false_negatives == report.labelled_spans

    # The next two are the reason this suite exists in this shape: a run that
    # never reaches the sanitize path reports zero residual PHI and zero
    # verification failures while having measured nothing at all.

    def test_expected_release_paths_are_actually_exercised(self, report):
        assert report.sanitized_verified_documents == report.verification_runs == 135
        assert report.allowed_original_documents == 35
        assert report.ask_documents == 5
        assert report.blocked_documents == 0
        assert report.sanitized_documents == report.released_documents == 170
        assert report.lifecycle_failure_count == report.audit_failure_count == 0

    def test_vacuous_report_fails_the_safety_gate(self, report):
        vacuous = dataclasses.replace(
            report, sanitized_documents=0, verification_runs=0, residual_phi_count=0
        )
        assert vacuous.gates_passed() is False
        assert "sanitize_path_not_exercised" in vacuous.gate_failures()

    def test_gate_failures_name_each_broken_gate(self, report):
        broken = dataclasses.replace(
            report,
            residual_phi_count=1,
            false_allow_count=2,
            verdict_mismatch_count=3,
            false_positives=4,
        )
        assert set(broken.gate_failures()) == {
            "false_allow",
            "residual_phi",
            "verdict_mismatch",
            "false_positive",
        }


class TestResidualTokenMatching:
    """A value only counts as residual if it survives as a whole token."""

    def test_untouched_value_survives(self):
        assert _survives_as_token("13800000000", "电话13800000000。") is True

    def test_generalized_band_is_not_a_residual(self):
        # 89岁 is a fragment of the band 80-89岁, not a disclosure of 89.
        assert _survives_as_token("89岁", "年龄：80-89岁") is False
        assert _survives_as_token("90岁", "年龄：90岁及以上") is False
        assert _survives_as_token("1岁", "年龄：不足1岁") is False

    def test_qualified_age_is_not_a_residual(self):
        assert _survives_as_token("50岁", "多见于50岁以上人群") is False

    def test_fragment_of_a_longer_number_is_not_a_residual(self):
        assert _survives_as_token("12345", "编号13800012345") is False

    def test_band_does_not_mask_a_real_residual(self):
        # The same value must still be caught when it appears unqualified.
        assert _survives_as_token("89岁", "年龄：80-89岁，其母89岁。") is True


class TestBenchmarkReport:
    def test_schema_is_serializable(self, report):
        payload = json.loads(report.to_json())
        for key in (
            "documents",
            "span_recall",
            "span_precision",
            "false_allow_count",
            "residual_phi_count",
            "verification_failure_count",
            "audit_raw_leak_count",
            "audit_failure_count",
            "audit_missing_count",
            "audit_invalid_count",
            "audit_mismatch_count",
            "audit_read_error_count",
            "lifecycle_failure_count",
            "sanitized_verified_documents",
            "allowed_original_documents",
            "released_documents",
            "sanitized_documents_semantics",
            "ask_documents",
            "blocked_documents",
            "p95_latency_ms",
        ):
            assert key in payload, key

    def test_report_contains_no_raw_values(self, report):
        """The report must never carry corpus PHI, only counts and rates."""
        documents = load_corpus(CORPUS)
        serialized = report.to_json()
        for doc in documents:
            for span in doc.spans:
                value = doc.text[span["start"] : span["end"]]
                if len(value) < 2:
                    continue
                assert value not in serialized, (doc.doc_id, span["type"])

    def test_by_document_type_covers_all_types(self, report):
        assert set(report.by_document_type) == {
            "outpatient_note",
            "inpatient_progress",
            "discharge_summary",
            "imaging_report",
            "lab_report",
            "operation_note",
            "consultation_note",
        }

    def test_by_fact_type_reports_labelled_and_detected(self, report):
        for fact_type, stats in report.by_fact_type.items():
            assert stats["labelled"] == stats["detected"], fact_type
            assert stats["residual"] == 0, fact_type

    def test_limit_restricts_document_count(self):
        limited = run_benchmark(CORPUS, limit=10)
        assert limited.documents == 10
        assert limited.gates_passed() is True

    def test_audit_temporary_directory_honors_tmpdir(self, tmp_path, monkeypatch):
        import tempfile

        from medical_privacy_guard import Guard

        monkeypatch.setenv("TMPDIR", str(tmp_path))
        monkeypatch.setattr(tempfile, "tempdir", None)
        original = Guard.sanitize
        audit_paths = []

        def checked(guard, *args, **kwargs):
            audit_path = Path(kwargs["audit_dir"])
            assert audit_path.parent.parent == tmp_path
            audit_paths.append(audit_path)
            return original(guard, *args, **kwargs)

        monkeypatch.setattr(Guard, "sanitize", checked)
        run_benchmark(CORPUS, limit=1)
        assert len(audit_paths) == 1
        assert not audit_paths[0].parent.exists()


class TestBenchmarkProfile:
    def test_profile_label_includes_version(self, report):
        assert report.profile == "external-ai-strict/1"

    def test_research_profile_also_passes_gates(self):
        research = run_benchmark(CORPUS, profile="research")
        assert research.gates_passed() is True


def _write_corpus(directory, *, text="姓名：张三。", spans=None, verdict="SANITIZE", **meta):
    directory.mkdir(parents=True, exist_ok=True)
    annotation = {
        "doc_id": "test", "expected_verdict": verdict,
        "spans": spans if spans is not None else [{"type": "PERSON_NAME", "start": 3, "end": 5}],
        **meta,
    }
    (directory / "test.txt").write_text(text, encoding="utf-8")
    (directory / "test.spans.json").write_text(json.dumps(annotation), encoding="utf-8")


class TestCorpusValidation:
    @pytest.mark.parametrize("verdict", [None, "", "allow", "RELEASE", 1, []])
    def test_invalid_expectation_rejected(self, tmp_path, verdict):
        _write_corpus(tmp_path, verdict=verdict)
        with pytest.raises(GuardError):
            load_corpus(tmp_path)

    @pytest.mark.parametrize("doc_id", ["../escape", "/absolute", "..", ".", "a/b", "a\\b", ""])
    def test_untrusted_doc_id_cannot_become_path(self, tmp_path, doc_id):
        _write_corpus(tmp_path, doc_id=doc_id)
        with pytest.raises(GuardError):
            run_benchmark(tmp_path)
        assert not (tmp_path.parent / "escape").exists()

    @pytest.mark.parametrize("span", [None, {}, {"type": "PHONE", "start": True, "end": 4},
                                      {"type": "PHONE", "start": "0", "end": 4}])
    def test_malformed_span_rejected(self, tmp_path, span):
        _write_corpus(tmp_path, spans=[span])
        with pytest.raises(GuardError):
            load_corpus(tmp_path)

    def test_duplicate_document_ids_rejected(self, tmp_path):
        _write_corpus(tmp_path)
        (tmp_path / "other.txt").write_text("姓名：张三。", encoding="utf-8")
        (tmp_path / "other.spans.json").write_text(
            (tmp_path / "test.spans.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        with pytest.raises(GuardError):
            load_corpus(tmp_path)

    def test_missing_expectation_rejected(self, tmp_path):
        _write_corpus(tmp_path)
        (tmp_path / "test.spans.json").write_text('{"spans": []}', encoding="utf-8")
        with pytest.raises(GuardError):
            load_corpus(tmp_path)

    @pytest.mark.parametrize("limit", [0, -1, True, 1.5])
    def test_invalid_limit_rejected(self, limit):
        with pytest.raises(GuardError):
            load_corpus(CORPUS, limit=limit)


class TestFaultInjection:
    @pytest.mark.parametrize("fault,gate,count_field,count", [
        ("verification", "verification_failure", "verification_failure_count", 135),
        ("audit", "audit_failure", "audit_missing_count", 175),
    ])
    @pytest.mark.parametrize("json_output", [False, True])
    def test_cli_faults_exit_two(self, fault, gate, count_field, count, json_output):
        import subprocess
        import sys

        script = """
import sys
from unittest.mock import patch
from cli.main import main
from core.model import VerificationResult
fault = sys.argv.pop(1)
if fault == "verification":
    target = "medical_privacy_guard.guard.verify_sanitized"
    replacement = lambda **kwargs: VerificationResult(False, (), "injected failure")
else:
    target = "medical_privacy_guard.Guard._maybe_audit"
    replacement = lambda *args, **kwargs: None
with patch(target, replacement):
    sys.exit(main(sys.argv[1:]))
"""
        command = [sys.executable, "-c", script, fault, "benchmark", str(CORPUS)]
        if json_output:
            command.append("--json")
        result = subprocess.run(
            command, cwd=CORPUS.parents[2], capture_output=True, text=True, check=False,
        )
        assert result.returncode == 2, result.stderr
        assert not result.stderr
        if json_output:
            payload = json.loads(result.stdout)
            assert payload[count_field] == count
        else:
            assert "Result: FAIL" in result.stdout
            assert gate in result.stdout

    def test_all_135_verifications_fail_even_with_35_allow_releases(self, monkeypatch):
        from core.model import VerificationResult

        monkeypatch.setattr(
            "medical_privacy_guard.guard.verify_sanitized",
            lambda **kwargs: VerificationResult(False, (), "injected failure"),
        )
        failed = run_benchmark(CORPUS)
        assert failed.verification_runs == failed.verification_failure_count == 135
        assert failed.sanitized_verified_documents == 0
        assert failed.allowed_original_documents == failed.released_documents == 35
        assert failed.lifecycle_failure_count == 135
        assert failed.verdict_mismatch_count == failed.audit_failure_count == 0
        assert {"verification_failure", "lifecycle_failure"} <= set(failed.gate_failures())
        assert not failed.passed()
        assert not failed.gates_passed()

    def test_audit_noop_fails_all_documents(self, monkeypatch):
        monkeypatch.setattr("medical_privacy_guard.Guard._maybe_audit", lambda *a, **k: None)
        failed = run_benchmark(CORPUS)
        assert failed.audit_missing_count == failed.audit_failure_count == 175
        assert failed.audit_raw_leak_count == 0
        assert "audit_failure" in failed.gate_failures()
        assert not failed.passed()

    @pytest.mark.parametrize("damage,category", [
        ("empty", "missing"), ("duplicate", "invalid"), ("corrupt", "invalid"),
        ("extra_field", "invalid"), ("wrong_type", "invalid"),
        ("decision", "mismatch"), ("verification", "mismatch"),
        ("recipient_class", "mismatch"), ("purpose", "mismatch"),
        ("policy_version", "mismatch"), ("entity_counts", "mismatch"),
        ("reason_codes", "mismatch"), ("transformations", "mismatch"),
        ("timestamp", "invalid"), ("duplicate_key", "invalid"),
    ])
    def test_audit_damage_is_a_failure(self, tmp_path, monkeypatch, damage, category):
        from core.audit import AuditWriter

        _write_corpus(tmp_path)
        original = AuditWriter.record

        def damaged_record(writer, event):
            event_id = original(writer, event)
            line = writer.filename.read_text(encoding="utf-8")
            payload = json.loads(line)
            if damage == "empty":
                line = ""
            elif damage == "duplicate":
                line += line
            elif damage == "corrupt":
                line = "{broken"
            elif damage == "duplicate_key":
                line = line.rstrip().removesuffix("}") + ', "decision": "SANITIZE"}'
            else:
                if damage == "extra_field":
                    payload["raw_text"] = "unexpected metadata"
                elif damage == "wrong_type":
                    payload["risk_score"] = True
                elif damage == "entity_counts":
                    payload[damage] = {}
                elif damage in {"reason_codes", "transformations"}:
                    payload[damage] = []
                else:
                    payload[damage] = "WRONG"
                line = json.dumps(payload)
            writer.filename.write_text(line, encoding="utf-8")
            return event_id

        monkeypatch.setattr(AuditWriter, "record", damaged_record)
        failed = run_benchmark(tmp_path)
        assert failed.audit_failure_count == 1
        assert getattr(failed, f"audit_{category}_count") == 1
        assert not failed.passed()

    def test_unreadable_audit_is_not_silently_skipped(self, tmp_path, monkeypatch):
        _write_corpus(tmp_path)
        original = Path.read_text

        def unreadable(path, *args, **kwargs):
            if path.name == "events.jsonl":
                raise PermissionError("injected")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", unreadable)
        failed = run_benchmark(tmp_path)
        assert failed.audit_read_error_count == failed.audit_failure_count == 1
        assert not failed.passed()

    @pytest.mark.parametrize("verdict,change", [
        ("SANITIZE", "no_verification"), ("SANITIZE", "no_release"),
        ("ALLOW", "no_release"), ("ALLOW", "changed"),
        ("ASK", "release"), ("BLOCK", "release"),
    ])
    def test_expected_lifecycle_is_checked_per_document(self, tmp_path, monkeypatch, verdict, change):
        from core.model import Payload, Verdict
        from medical_privacy_guard import Guard

        _write_corpus(tmp_path, verdict=verdict)
        original = Guard.sanitize

        def changed(guard, *args, **kwargs):
            result = original(guard, *args, **kwargs)
            result = dataclasses.replace(
                result, decision_before=dataclasses.replace(result.decision_before, verdict=Verdict(verdict))
            )
            if change == "no_verification":
                return dataclasses.replace(result, verification=None)
            if change == "no_release":
                return dataclasses.replace(result, sanitized_payload=None)
            return dataclasses.replace(result, verification=None, sanitized_payload=Payload("text", "changed"))

        monkeypatch.setattr(Guard, "sanitize", changed)
        failed = run_benchmark(tmp_path)
        assert failed.lifecycle_failure_count == 1
        assert not failed.passed()

    def test_partial_identifier_residue_fails_even_when_full_value_is_absent(self, tmp_path, monkeypatch):
        from core.model import VerificationResult
        from detectors import detect_all

        _write_corpus(tmp_path)
        original = detect_all

        def partial(text, detectors=None):
            # Guard now passes its detector set explicitly so that a loaded
            # dictionary is seen by detection and verification alike.
            return tuple(
                dataclasses.replace(f, end=f.start + 1, value=text[f.start:f.start + 1])
                if f.type == "PERSON_NAME" else f for f in original(text, detectors)
            )

        monkeypatch.setattr("core.benchmark.detect_all", partial)
        monkeypatch.setattr("medical_privacy_guard.guard.detect_all", partial)
        monkeypatch.setattr(
            "medical_privacy_guard.guard.verify_sanitized",
            lambda **kwargs: VerificationResult(True, (), "injected pass"),
        )
        failed = run_benchmark(tmp_path)
        assert failed.true_positives == 0
        assert failed.false_negatives == failed.false_positives == 1
        assert failed.residual_phi_count == 1
        assert {"incomplete_span_coverage", "residual_phi"} <= set(failed.gate_failures())
        assert not failed.passed()

    def test_reused_event_ids_fail(self, monkeypatch):
        from core.audit import AuditWriter

        original = AuditWriter.record

        def replayed(writer, event):
            return original(writer, dataclasses.replace(event, event_id="same-event"))

        monkeypatch.setattr(AuditWriter, "record", replayed)
        failed = run_benchmark(CORPUS, limit=2)
        assert failed.audit_invalid_count == failed.audit_failure_count == 1
        assert not failed.passed()

    def test_each_corpus_document_has_expected_lifecycle(self, tmp_path):
        from core.benchmark import _evaluate_document
        from core.model import Purpose, Recipient, TrustLevel
        from medical_privacy_guard import Guard

        guard = Guard()
        recipient = Recipient("benchmark", trust_level=TrustLevel.EXTERNAL_APPROVED)
        for index, doc in enumerate(load_corpus(CORPUS)):
            outcome = _evaluate_document(
                guard, doc, recipient, Purpose.EXTERNAL_AI_ASSISTANCE,
                tmp_path / str(index), {},
            )
            assert not outcome.lifecycle_failed, doc.doc_id
            assert outcome.audit_failure is None, doc.doc_id
            if doc.expected_verdict == "SANITIZE":
                assert outcome.verification_ran and not outcome.verification_failed
                assert outcome.sanitized_verified and outcome.released
            elif doc.expected_verdict == "ALLOW":
                assert outcome.allowed_original and outcome.released
            else:
                assert not outcome.released


# -- the audit leak gate and random identifiers ------------------------------


class TestAuditLeakGateIgnoresRandomIdentifiers:
    """The leak gate is absolute, so a chance substring in a hash fails a run.

    Found while investigating an intermittent CI failure: the six-digit postal
    code 730908 occurs inside a 64-character ``event_hash``, and the gate
    reported a raw leak on a log that leaked nothing. ``event_id`` is a UUID and
    the chain hashes are digests, so neither carries payload; stripping them
    removes the false positive while a value in a semantic field is still
    caught.
    """

    @staticmethod
    def _document() -> CorpusDocument:
        return CorpusDocument(
            doc_id="probe",
            document_type="outpatient_note",
            department="general",
            text="邮编730908。",
            spans=({"type": "POSTAL_CODE", "start": 2, "end": 8},),
            expected_verdict="SANITIZE",
        )

    @pytest.mark.parametrize("field", ["event_id", "prev_hash", "event_hash"])
    def test_a_value_inside_a_random_field_is_not_a_leak(self, field: str) -> None:
        audit = json.dumps({field: "aa730908bb", "decision": "SANITIZE"})
        assert _count_audit_leaks([self._document()], audit) == 0

    @pytest.mark.parametrize("field", ["reason_codes", "transformations", "policy_version"])
    def test_a_value_in_a_semantic_field_is_still_a_leak(self, field: str) -> None:
        audit = json.dumps({field: "730908", "event_hash": "aabb"})
        assert _count_audit_leaks([self._document()], audit) == 1

    def test_a_value_beside_a_random_field_is_still_a_leak(self) -> None:
        """Stripping must not swallow the surrounding record."""
        audit = '{"event_hash": "aabb", "raw": "邮编730908"}'
        assert _count_audit_leaks([self._document()], audit) == 1

    def test_empty_audit_text_has_no_leaks(self) -> None:
        assert _count_audit_leaks([self._document()], "") == 0
