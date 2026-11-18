"""Tests for the static HTML report (core.report + the report command).

The report's safety property is structural: its inputs (audit events, the
grant registry) contain metadata only, so the page cannot leak clinical
text. These tests pin the aggregation, the escaping of every interpolated
string, and the CLI exit-code contract shared with audit-verify.
"""

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
        assert "哈希链完整性：完整" in page
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
