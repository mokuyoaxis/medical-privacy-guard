"""Tests for the static HTML report (core.report + the report command).

The report's safety property is structural: its inputs (audit events, the
grant registry) contain metadata only, so the page cannot leak clinical
text. These tests pin the aggregation, the escaping of every interpolated
string, and the CLI exit-code contract shared with audit-verify.
"""

import json
import os
import sqlite3
import stat
from datetime import datetime, timezone

import pytest

from medical_privacy_guard.cli.main import EXIT_BLOCK, EXIT_ERROR, EXIT_OK, main
from medical_privacy_guard.core.audit import (
    AuditEvent,
    AuditWriter,
    ChainVerification,
)
from medical_privacy_guard.core.dataset import analyze_dataset
from medical_privacy_guard.core.grant_sqlite import (
    SqliteGrantRegistry,
    initialize_grant_registry,
)
from medical_privacy_guard.core.report import (
    render_html,
    summarize_events,
    summarize_grants,
)

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)
FUTURE = "2999-01-01T00:00:00.000000Z"
PAST = "2000-01-01T00:00:00.000000Z"


def _event(**overrides) -> AuditEvent:
    fields = dict(
        event_id="evt-1",
        timestamp="2026-11-18T01:00:00.000000Z",
        decision="SANITIZE",
        reason_codes=("DIRECT_IDENTIFIER_PRESENT",),
        entity_counts={"PERSON_NAME": 1},
        risk_level="HIGH",
        risk_score=75,
        recipient_class="external_unknown",
        purpose="external_ai_assistance",
        policy_profile="external-ai-strict",
        policy_version="external-ai-strict/3",
        transformations=("REDACT_PERSON_NAME",),
        verification="PASS",
    )
    fields.update(overrides)
    return AuditEvent(**fields)


class TestSummarizeEvents:
    def test_aggregates_metadata(self):
        events = (
            _event(),
            _event(
                event_id="evt-2",
                timestamp="2026-11-18T02:00:00.000000Z",
                decision="BLOCK",
                entity_counts={"PERSON_NAME": 2, "PHONE_NUMBER": 1},
                risk_level="CRITICAL",
                grant_id="grant-a",
                grant_issuer="dr.wang",
                dictionary_loaded=True,
            ),
            _event(event_id="evt-3", decision="ASK", grant_id="grant-a",
                   grant_issuer="dr.wang"),
        )
        summary = summarize_events(events)
        assert summary.total == 3
        assert summary.first_timestamp == "2026-11-18T01:00:00.000000Z"
        assert summary.last_timestamp == "2026-11-18T02:00:00.000000Z"
        assert summary.decisions == {"SANITIZE": 1, "BLOCK": 1, "ASK": 1}
        assert summary.entity_types == {"PERSON_NAME": 4, "PHONE_NUMBER": 1}
        assert summary.grant_assisted == 2
        assert summary.grant_ids == 1
        assert summary.grant_issuers == {"dr.wang": 2}
        assert summary.dictionary_events == 1

    def test_empty_log(self):
        summary = summarize_events(())
        assert summary.total == 0
        assert summary.first_timestamp == ""


class TestSummarizeGrants:
    def test_status_classification(self):
        rows = (
            ("a" * 64, 3, 1, FUTURE, False),   # active
            ("b" * 64, 3, 1, PAST, False),     # expired
            ("c" * 64, 2, 2, FUTURE, False),   # exhausted
            ("d" * 64, 2, 0, FUTURE, True),    # revoked
        )
        summary = summarize_grants(rows, ("e" * 64,), now=NOW)
        assert summary.recorded == 4
        assert summary.active == 1
        assert summary.expired == 1
        assert summary.exhausted == 1
        assert summary.revoked == 2  # one row + one revocation-only key
        assert summary.revoked_only == 1
        assert summary.uses_consumed == 4
        assert summary.uses_allowed == 10


class TestRenderHtml:
    def _chain(self, verified=True) -> ChainVerification:
        return ChainVerification(
            total=3, chained=3, unchained=0,
            failures=() if verified else ("record 1: event_hash mismatch",),
        )

    def test_intact_chain_and_aggregates(self):
        page = render_html(
            audit=summarize_events((_event(),)),
            chain=self._chain(),
            sources=(("Audit log", "/tmp/audit/events.jsonl"),),
            now=NOW,
        )
        assert "Chain integrity: INTACT" in page
        assert "SANITIZE" in page
        assert "/tmp/audit/events.jsonl" in page

    def test_broken_chain_is_shown_not_hidden(self):
        page = render_html(
            audit=summarize_events((_event(),)), chain=self._chain(False), now=NOW
        )
        assert "Chain integrity: BROKEN" in page
        assert "event_hash mismatch" in page

    def test_interpolated_strings_are_escaped(self):
        page = render_html(
            audit=summarize_events((_event(grant_issuer="<script>x</script>",
                                           grant_id="g"),)),
            chain=self._chain(),
            now=NOW,
        )
        assert "<script>x</script>" not in page
        assert "&lt;script&gt;" in page

    def test_event_ids_never_render(self):
        page = render_html(
            audit=summarize_events((_event(event_id="secret-event-id"),)),
            chain=self._chain(),
            now=NOW,
        )
        assert "secret-event-id" not in page

    def test_grants_only_report(self):
        summary = summarize_grants((("a" * 64, 1, 1, FUTURE, False),), now=NOW)
        page = render_html(grants=summary, now=NOW)
        assert "Grant registry" in page
        assert "a" * 12 in page  # truncated key hash
        assert "a" * 64 not in page

    def test_no_source_is_an_error(self):
        with pytest.raises(ValueError):
            render_html(now=NOW)

    def test_chinese_rendering(self):
        summary = summarize_grants((("a" * 64, 3, 1, FUTURE, False),), now=NOW)
        page = render_html(
            audit=summarize_events((_event(),)),
            chain=self._chain(),
            grants=summary,
            now=NOW,
            lang="zh",
        )
        assert '<html lang="zh-CN">' in page
        assert "审计日志" in page
        assert "哈希链完整性校验：通过" in page
        assert "裁决分布" in page
        assert "授权登记册" in page
        assert "有效" in page  # localized grant status
        assert "SANITIZE" in page  # data labels stay canonical

    def test_unknown_language_is_an_error(self):
        with pytest.raises(ValueError):
            render_html(grants=summarize_grants((), now=NOW), now=NOW, lang="fr")


class TestRegistrySnapshot:
    def test_snapshot_reads_rows_and_revocation_only_keys(self, tmp_path):
        db = tmp_path / "grants.sqlite3"
        initialize_grant_registry(db)
        with sqlite3.connect(db) as connection:
            connection.execute(
                "INSERT INTO grant_uses VALUES (?, ?, ?, ?, ?)",
                ("a" * 64, "b" * 64, 3, 1, FUTURE),
            )
            connection.execute(
                "INSERT INTO grant_revocations VALUES (?)", ("a" * 64,)
            )
            connection.execute(
                "INSERT INTO grant_revocations VALUES (?)", ("c" * 64,)
            )
        rows, revoked_only = SqliteGrantRegistry(db).snapshot()
        assert rows == (("a" * 64, 3, 1, FUTURE, True),)
        assert revoked_only == ("c" * 64,)


class TestReportCommand:
    def _audit_dir(self, tmp_path) -> str:
        directory = tmp_path / "audit"
        writer = AuditWriter(directory)
        writer.record(_event())
        writer.record(_event(event_id="evt-2", decision="ALLOW",
                             entity_counts={}, risk_level="LOW"))
        return str(directory)

    def test_end_to_end(self, tmp_path):
        audit_dir = self._audit_dir(tmp_path)
        db = tmp_path / "grants.sqlite3"
        initialize_grant_registry(db)
        out = tmp_path / "report.html"
        code = main([
            "report", "--audit-dir", audit_dir, "--grant-db", str(db),
            "-o", str(out),
        ])
        assert code == EXIT_OK
        page = out.read_text(encoding="utf-8")
        assert "Chain integrity: INTACT" in page
        assert "Grant registry" in page
        assert stat.S_IMODE(os.stat(out).st_mode) == 0o600

    def test_broken_chain_exits_block_but_still_reports(self, tmp_path):
        audit_dir = self._audit_dir(tmp_path)
        log = tmp_path / "audit" / "events.jsonl"
        lines = log.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("SANITIZE", "ALLOW")
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out = tmp_path / "report.html"
        code = main(["report", "--audit-dir", audit_dir, "-o", str(out)])
        assert code == EXIT_BLOCK
        assert "BROKEN" in out.read_text(encoding="utf-8")

    def test_missing_audit_log_is_an_error(self, tmp_path):
        out = tmp_path / "report.html"
        code = main([
            "report", "--audit-dir", str(tmp_path / "nope"), "-o", str(out),
        ])
        assert code == EXIT_ERROR
        assert not out.exists()

    def test_no_source_is_an_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "medical_privacy_guard.cli.main.DEFAULT_GRANT_DB_PATH",
            tmp_path / "absent.sqlite3",
        )
        out = tmp_path / "report.html"
        code = main(["report", "-o", str(out)])
        assert code == EXIT_ERROR
        assert not out.exists()

    def test_chinese_report_via_cli(self, tmp_path):
        audit_dir = self._audit_dir(tmp_path)
        out = tmp_path / "report.html"
        code = main([
            "report", "--audit-dir", audit_dir, "--lang", "zh", "-o", str(out),
        ])
        assert code == EXIT_OK
        page = out.read_text(encoding="utf-8")
        assert "审计日志" in page
        assert "数据来源" in page

    def test_existing_output_is_refused(self, tmp_path):
        audit_dir = self._audit_dir(tmp_path)
        out = tmp_path / "report.html"
        out.write_text("old", encoding="utf-8")
        code = main(["report", "--audit-dir", audit_dir, "-o", str(out)])
        assert code == EXIT_ERROR
        assert out.read_text(encoding="utf-8") == "old"


def _golden_rows() -> list[dict]:
    """The design document's hand-computed example: 6 rows, (age, sex).

    Combinations: (40,F)x2, (40,M)x1, (41,F)x1, (41,M)x2 — 4 groups,
    sizes {2,1,1,2}, 2 singleton rows (33.3%), histogram ((1,2),(2,2)).
    """
    return [
        {"age": "40", "sex": "F"}, {"age": "40", "sex": "F"},
        {"age": "40", "sex": "M"}, {"age": "41", "sex": "F"},
        {"age": "41", "sex": "M"}, {"age": "41", "sex": "M"},
    ]


class TestRenderDataset:
    def test_dataset_only_report(self):
        page = render_html(
            dataset=analyze_dataset(_golden_rows(), ["age", "sex"]), now=NOW
        )
        assert "Re-identification risk (engineering measurement)" in page
        assert "does not authorize disclosure" in page
        assert "Quasi-identifiers: age, sex" in page
        assert "Singleton rows (unique combinations): 2 (33.3%)" in page
        assert "Rows in groups below the threshold: 2 (33.3%)" in page

    def test_dataset_section_comes_after_grants(self):
        summary = summarize_grants((("a" * 64, 1, 1, FUTURE, False),), now=NOW)
        page = render_html(
            grants=summary,
            dataset=analyze_dataset(_golden_rows(), ["age", "sex"]),
            now=NOW,
        )
        assert page.index("Grant registry") < page.index(
            "Re-identification risk"
        )

    def test_dataset_values_never_render(self):
        rows = [
            {"ward": "WARD-ALPHA-7", "age": "40"},
            {"ward": "WARD-ALPHA-7", "age": "40"},
            {"ward": "WARD-BETA-9", "age": "41"},
        ]
        page = render_html(
            dataset=analyze_dataset(rows, ["ward", "age"]), now=NOW
        )
        assert "WARD-ALPHA-7" not in page
        assert "WARD-BETA-9" not in page
        assert "ward, age" in page  # selected column names are user metadata

    def test_empty_dataset_does_not_divide_by_zero(self):
        page = render_html(dataset=analyze_dataset([], ["age"]), now=NOW)
        assert "The dataset held no rows." in page

    def test_dataset_chinese_rendering(self):
        page = render_html(
            dataset=analyze_dataset(_golden_rows(), ["age", "sex"]),
            now=NOW,
            lang="zh",
        )
        assert "再识别风险（工程度量）" in page
        assert "不构成披露授权" in page
        assert "单例行（唯一组合）: 2 (33.3%)" in page


class TestReportDatasetCommand:
    def _isolated(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "medical_privacy_guard.cli.main.DEFAULT_GRANT_DB_PATH",
            tmp_path / "absent.sqlite3",
        )

    def _csv(self, tmp_path) -> str:
        path = tmp_path / "cohort.csv"
        lines = ["age,sex"] + [
            f"{row['age']},{row['sex']}" for row in _golden_rows()
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def test_dataset_only_via_cli(self, tmp_path, monkeypatch):
        self._isolated(tmp_path, monkeypatch)
        out = tmp_path / "report.html"
        code = main([
            "report", "--dataset", self._csv(tmp_path),
            "--quasi-identifier", "age", "--quasi-identifier", "sex",
            "-o", str(out),
        ])
        assert code == EXIT_OK
        page = out.read_text(encoding="utf-8")
        assert "Re-identification risk" in page
        assert "33.3%" in page
        assert stat.S_IMODE(os.stat(out).st_mode) == 0o600

    def test_dataset_without_quasi_identifier_is_an_error(
        self, tmp_path, monkeypatch
    ):
        self._isolated(tmp_path, monkeypatch)
        out = tmp_path / "report.html"
        code = main([
            "report", "--dataset", self._csv(tmp_path), "-o", str(out),
        ])
        assert code == EXIT_ERROR
        assert not out.exists()

    def test_quasi_identifier_without_dataset_is_an_error(
        self, tmp_path, monkeypatch
    ):
        self._isolated(tmp_path, monkeypatch)
        out = tmp_path / "report.html"
        code = main([
            "report", "--quasi-identifier", "age", "-o", str(out),
        ])
        assert code == EXIT_ERROR
        assert not out.exists()

    def test_csv_and_json_inputs_agree(self, tmp_path, monkeypatch):
        self._isolated(tmp_path, monkeypatch)
        json_path = tmp_path / "cohort.json"
        rows = [
            {"age": int(row["age"]), "sex": row["sex"]}
            for row in _golden_rows()
        ]
        json_path.write_text(json.dumps(rows), encoding="utf-8")
        pages = []
        for name, source in (("csv", self._csv(tmp_path)), ("json", str(json_path))):
            out = tmp_path / f"report-{name}.html"
            code = main([
                "report", "--dataset", source,
                "--quasi-identifier", "age", "--quasi-identifier", "sex",
                "-o", str(out),
            ])
            assert code == EXIT_OK
            pages.append(out.read_text(encoding="utf-8"))
        for page in pages:
            assert "Singleton rows (unique combinations): 2 (33.3%)" in page
