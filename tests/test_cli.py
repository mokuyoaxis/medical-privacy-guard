"""Unit tests for the CLI (Phase 1 Step 6).

Coverage:
- inspect: human + JSON output, exit codes for ALLOW/SANITIZE/BLOCK
- sanitize: stdout and -o output, BLOCK refuses output, in-place overwrite
  protection, audit-dir integration, verification failure → exit 2
- error paths: missing file → exit 4
"""

import json
from pathlib import Path

import pytest

from cli.main import (
    EXIT_ASK,
    EXIT_BLOCK,
    EXIT_ERROR,
    EXIT_OK,
    main,
)
from core.model import VerificationResult

CLEAN = "普通随访记录，无敏感信息\n"
PHONE = "联系电话 13800000000\n"
ID_TEXT = "证件号码 11010519491231002X\n"
CORPUS = Path(__file__).resolve().parent / "fixtures" / "synthetic_cn_notes"


def write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


# -- inspect -----------------------------------------------------------------


class TestInspect:
    def test_clean_file_allows(self, tmp_path, capsys):
        rc = main(["inspect", write(tmp_path, "clean.txt", CLEAN)])
        out = capsys.readouterr().out
        assert rc == EXIT_OK
        assert "Decision: ALLOW" in out

    def test_phone_sanitize_verdict_exit_zero(self, tmp_path, capsys):
        rc = main(["inspect", write(tmp_path, "phone.txt", PHONE)])
        out = capsys.readouterr().out
        assert rc == EXIT_OK
        assert "Decision: SANITIZE" in out
        assert "Plan:" in out
        assert "REMOVE PHONE" in out

    def test_government_id_blocks(self, tmp_path, capsys):
        rc = main(["inspect", write(tmp_path, "id.txt", ID_TEXT)])
        out = capsys.readouterr().out
        assert rc == EXIT_BLOCK
        assert "Decision: BLOCK" in out

    def test_ask_verdict_exit_three(self, tmp_path, capsys):
        rc = main([
            "inspect",
            "--purpose",
            "unknown",
            write(tmp_path, "phone.txt", PHONE),
        ])
        assert rc == EXIT_ASK
        assert "PURPOSE_NOT_DECLARED" in capsys.readouterr().out

    def test_json_output(self, tmp_path, capsys):
        rc = main(["inspect", "--json", write(tmp_path, "phone.txt", PHONE)])
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert rc == EXIT_OK
        assert payload["decision"] == "SANITIZE"
        assert payload["counts"] == {"PHONE": 1}
        # Raw values never appear in the JSON stream.
        assert "13800000000" not in out
        assert payload["plan"]["operations"] == ["REMOVE_PHONE"]

    def test_json_facts_have_no_values(self, tmp_path, capsys):
        main(["inspect", "--json", write(tmp_path, "phone.txt", PHONE)])
        payload = json.loads(capsys.readouterr().out)
        for fact in payload["facts"]:
            assert "value" not in fact


# -- sanitize ----------------------------------------------------------------


class TestSanitize:
    def test_clean_file_passthrough(self, tmp_path, capsys):
        rc = main(["sanitize", write(tmp_path, "clean.txt", CLEAN)])
        assert rc == EXIT_OK
        assert capsys.readouterr().out == CLEAN

    def test_phone_redacted_to_stdout(self, tmp_path, capsys):
        rc = main(["sanitize", write(tmp_path, "phone.txt", PHONE)])
        assert rc == EXIT_OK
        assert capsys.readouterr().out == "联系电话 [REDACTED]\n"

    def test_output_file_written_input_untouched(self, tmp_path):
        src = write(tmp_path, "src.txt", PHONE)
        dst = str(tmp_path / "out.txt")
        rc = main(["sanitize", "-o", dst, src])
        assert rc == EXIT_OK
        assert (tmp_path / "out.txt").read_text(encoding="utf-8") == "联系电话 [REDACTED]\n"
        assert (tmp_path / "src.txt").read_text(encoding="utf-8") == PHONE

    def test_block_writes_no_output(self, tmp_path, capsys):
        src = write(tmp_path, "id.txt", ID_TEXT)
        dst = str(tmp_path / "out.txt")
        rc = main(["sanitize", "-o", dst, src])
        assert rc == EXIT_BLOCK
        assert not (tmp_path / "out.txt").exists()
        assert "BLOCK" in capsys.readouterr().err

    def test_verification_failure_exit_two(self, tmp_path, capsys, monkeypatch):
        import importlib

        guard_module = importlib.import_module("medical_privacy_guard.guard")

        def fake_verify(**kwargs):
            return VerificationResult(
                passed=False,
                reason_codes=(),
                details="residual identifiers after transformation: PHONE",
            )

        monkeypatch.setattr(guard_module, "verify_sanitized", fake_verify)
        src = write(tmp_path, "phone.txt", PHONE)
        dst = str(tmp_path / "out.txt")
        rc = main(["sanitize", "-o", dst, src])
        assert rc == EXIT_BLOCK
        assert not (tmp_path / "out.txt").exists()
        assert "VERIFICATION FAILED" in capsys.readouterr().err

    def test_audit_dir_written(self, tmp_path, capsys):
        src = write(tmp_path, "phone.txt", PHONE)
        audit_dir = tmp_path / "audit"
        rc = main(["sanitize", "--audit-dir", str(audit_dir), src])
        assert rc == EXIT_OK
        log = audit_dir / "events.jsonl"
        assert log.is_file()
        stream = log.read_text(encoding="utf-8")
        assert "13800000000" not in stream
        assert "SANITIZE" in stream

    def test_refuses_inplace_overwrite(self, tmp_path):
        src = write(tmp_path, "src.txt", PHONE)
        rc = main(["sanitize", "-o", src, src])
        assert rc == EXIT_ERROR


class TestInputFormats:
    @pytest.mark.parametrize("command", ["inspect", "sanitize"])
    @pytest.mark.parametrize("suffix", [
        ".json", ".JSON", ".jsonl", ".ndjson", ".csv", ".tsv", ".xlsx",
        ".xls", ".pdf", ".docx", ".fhir", ".xml", ".dcm", ".dicom", ".bin",
        ".json.txt", ".csv.gz",
    ])
    def test_known_unsupported_suffix_blocks(self, tmp_path, capsys, command, suffix):
        src = write(tmp_path, "SYNTH-CANARY" + suffix, "SYNTH-CANARY")
        dst = tmp_path / "out.txt"
        args = [command, src]
        if command == "sanitize":
            args += ["-o", str(dst), "--audit-dir", str(tmp_path / "audit")]
        else:
            args += ["--json"]
        assert main(args) == EXIT_BLOCK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "BLOCK" in captured.err
        assert "SYNTH-CANARY" not in captured.err
        assert not dst.exists()
        log = tmp_path / "audit" / "events.jsonl"
        if command == "sanitize":
            stream = log.read_text(encoding="utf-8")
            (event,) = [json.loads(line) for line in stream.splitlines()]
            assert event["decision"] == "BLOCK"
            assert event["reason_codes"] == ["UNSUPPORTED_FORMAT"]
            assert event["entity_counts"] == {}
            assert "SYNTH-CANARY" not in stream
            assert src not in stream
        else:
            assert not log.exists()

    @pytest.mark.parametrize("command", ["inspect", "sanitize"])
    @pytest.mark.parametrize("data", [
        b'{"patient": "\\u5f20\\u4e09", "note": "SYNTH-CANARY"}',
        b'\xef\xbb\xbf  [{"note": "SYNTH-CANARY"}]',
        b'{"note": "SYNTH-CANARY"}\n{"other": 1}',
        b'[] trailing SYNTH-CANARY',
        b'[' * 2000 + b'"SYNTH-CANARY"' + b']' * 2000,
        b'{"SYNTH-CANARY":' + b'9' * 5000 + b'}',
        b'\x00SYNTH-CANARY', b'\x01SYNTH-CANARY', b'\x7fSYNTH-CANARY',
        "\u0085SYNTH-CANARY".encode(), b'\xffSYNTH-CANARY',
        b'%PDF-1.7\nSYNTH-CANARY', b'{\\rtf1 SYNTH-CANARY}',
        b'<?xml version="1.0"?><Patient>SYNTH-CANARY</Patient>',
        b' ' * 128 + b'DICMSYNTH-CANARY', b'PK\x03\x04SYNTH-CANARY',
    ])
    def test_disguised_content_blocks(self, tmp_path, capsys, command, data):
        src = tmp_path / "SYNTH-CANARY.txt"
        src.write_bytes(data)
        dst = tmp_path / "out.txt"
        args = [command, str(src)]
        if command == "sanitize":
            args += ["-o", str(dst)]
        assert main(args) == EXIT_BLOCK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "BLOCK" in captured.err
        assert "SYNTH-CANARY" not in captured.err
        assert not dst.exists()
        assert src.read_bytes() == data

    @pytest.mark.parametrize("name,text", [
        ("note.txt", "[随访] 普通记录\n"),
        ("note", "{临床观察} 普通记录\n"),
        ("note.md", "普通记录,建议随访\n复查,按需\n"),
        ("note.data", "普通记录\t建议随访\n"),
    ])
    def test_plain_text_not_overblocked(self, tmp_path, capsys, name, text):
        assert main(["sanitize", write(tmp_path, name, text)]) == EXIT_OK
        assert capsys.readouterr().out == text

    def test_symlink_cannot_hide_unsupported_suffix(self, tmp_path, capsys):
        source = Path(write(tmp_path, "source.csv", "姓名,备注\n张三,随访\n"))
        alias = tmp_path / "note.txt"
        alias.symlink_to(source)
        assert main(["sanitize", str(alias)]) == EXIT_BLOCK
        assert capsys.readouterr().out == ""


class TestUnsupportedInputAudit:
    @pytest.mark.parametrize("data", [
        b'{"patient":"SYNTH-CONTENT-CANARY"}',
        b'\x00SYNTH-CONTENT-CANARY',
        b'\xffSYNTH-CONTENT-CANARY',
    ])
    def test_content_block_audits_only_empty_unsupported_payload(
        self, tmp_path, monkeypatch, capsys, data,
    ):
        from core.model import Payload
        from medical_privacy_guard import Guard

        src = tmp_path / "SYNTH-PATH-CANARY.txt"
        src.write_bytes(data)
        audit_dir = tmp_path / "audit"
        dst = tmp_path / "out.txt"
        original_sanitize = Guard.sanitize
        received = []

        def capture(self, payload, *args, **kwargs):
            received.append(payload)
            return original_sanitize(self, payload, *args, **kwargs)

        monkeypatch.setattr(Guard, "sanitize", capture)
        assert main(["sanitize", str(src), "-o", str(dst),
                     "--audit-dir", str(audit_dir)]) == EXIT_BLOCK
        assert received == [Payload(kind="unsupported", content="")]
        stream = (audit_dir / "events.jsonl").read_text(encoding="utf-8")
        (event,) = [json.loads(line) for line in stream.splitlines()]
        assert event["decision"] == "BLOCK"
        assert event["reason_codes"] == ["UNSUPPORTED_FORMAT"]
        assert event["entity_counts"] == {}
        assert event["transformations"] == []
        assert event["verification"] == "N/A"
        assert "SYNTH-CONTENT-CANARY" not in stream
        assert "SYNTH-PATH-CANARY" not in stream
        assert str(src) not in stream
        assert not dst.exists()
        assert src.read_bytes() == data
        assert capsys.readouterr().out == ""

    @pytest.mark.parametrize("failure", ["directory", "short", "zero", "fsync"])
    def test_format_block_audit_failure_is_error(self, tmp_path, monkeypatch, capsys, failure):
        import core.audit as audit

        src = write(tmp_path, "SYNTH-PATH-CANARY.json", "SYNTH-CONTENT-CANARY")
        audit_dir = tmp_path / "audit"
        dst = tmp_path / "out.txt"
        real_write = audit.os.write

        def fail_write(fd, data):
            return 0 if failure == "zero" else real_write(fd, data[:1])

        def fail_fsync(fd):
            raise OSError("synthetic fsync failure")

        if failure == "directory":
            audit_dir.write_text("KEEP", encoding="utf-8")
        elif failure == "fsync":
            monkeypatch.setattr(audit.os, "fsync", fail_fsync)
        else:
            monkeypatch.setattr(audit.os, "write", fail_write)
        assert main(["sanitize", src, "-o", str(dst),
                     "--audit-dir", str(audit_dir)]) == EXIT_ERROR
        assert not dst.exists()
        assert Path(src).read_text(encoding="utf-8") == "SYNTH-CONTENT-CANARY"
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "SYNTH-CONTENT-CANARY" not in captured.err
        assert "SYNTH-PATH-CANARY" not in captured.err

    @pytest.mark.parametrize("collision", ["input-output", "input-log", "output-log"])
    def test_format_block_collision_precedes_guard(self, tmp_path, monkeypatch, capsys, collision):
        from medical_privacy_guard import Guard

        src = Path(write(tmp_path, "source.json", "SYNTH-CONTENT-CANARY"))
        audit_dir = tmp_path / "audit"
        dst = tmp_path / "out.txt"
        if collision == "input-output":
            dst = src
        elif collision == "input-log":
            audit_dir = tmp_path
            src = Path(write(tmp_path, "events.jsonl", "SYNTH-CONTENT-CANARY"))
        else:
            dst = audit_dir / "events.jsonl"
        before = src.stat().st_mode

        def unexpected_guard(*args, **kwargs):
            pytest.fail("Guard must not run before path conflict rejection")

        monkeypatch.setattr(Guard, "sanitize", unexpected_guard)
        assert main(["sanitize", str(src), "-o", str(dst),
                     "--audit-dir", str(audit_dir)]) == EXIT_ERROR
        assert src.read_text(encoding="utf-8") == "SYNTH-CONTENT-CANARY"
        assert src.stat().st_mode == before
        if collision != "input-log":
            assert not audit_dir.exists()
        if collision != "input-output":
            assert not dst.exists()
        assert capsys.readouterr().out == ""


class TestPathSafety:
    @pytest.mark.parametrize("alias", ["same", "relative", "symlink", "hardlink"])
    @pytest.mark.parametrize("pair", ["input-output", "input-log", "output-log"])
    def test_aliases_rejected_before_audit(self, tmp_path, capsys, alias, pair):
        import os

        src = Path(write(tmp_path, "source.txt", PHONE))
        output = tmp_path / "output.txt"
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        log = audit_dir / "events.jsonl"
        if pair == "input-output":
            target = src
        else:
            log.write_text(PHONE if pair == "input-log" else "HISTORY\n", encoding="utf-8")
            target = log
        if alias == "same":
            linked = target
        elif alias == "relative":
            nested = target.parent / "nested"
            nested.mkdir()
            linked = nested / ".." / target.name
        else:
            linked = tmp_path / "alias.txt"
            if alias == "symlink":
                linked.symlink_to(target)
            else:
                os.link(target, linked)
        if pair == "input-output":
            output = linked
        elif pair == "input-log":
            src = linked
        else:
            output = linked
        before = {path: (path.read_bytes(), path.stat().st_mode)
                  for path in [src, output, log] if path.exists()}
        rc = main(["sanitize", str(src), "-o", str(output), "--audit-dir", str(audit_dir)])
        assert rc == EXIT_ERROR
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "13800000000" not in captured.err
        for path, (content, mode) in before.items():
            assert path.read_bytes() == content
            assert path.stat().st_mode == mode
        if pair == "input-output":
            assert not log.exists()
        if pair == "input-log":
            assert not output.exists()

    def test_future_log_output_collision_has_no_side_effect(self, tmp_path, capsys):
        src = write(tmp_path, "source.txt", PHONE)
        audit_dir = tmp_path / "new-audit"
        assert main(["sanitize", src, "--audit-dir", str(audit_dir),
                     "-o", str(audit_dir / "events.jsonl")]) == EXIT_ERROR
        assert not audit_dir.exists()
        assert capsys.readouterr().out == ""

    def test_input_log_collision_without_output(self, tmp_path, capsys):
        log = write(tmp_path, "events.jsonl", PHONE)
        before = Path(log).stat().st_mode
        assert main(["sanitize", log, "--audit-dir", str(tmp_path)]) == EXIT_ERROR
        assert Path(log).read_text(encoding="utf-8") == PHONE
        assert Path(log).stat().st_mode == before
        assert capsys.readouterr().out == ""

    def test_existing_output_refused_before_audit(self, tmp_path, capsys):
        src = write(tmp_path, "source.txt", PHONE)
        dst = write(tmp_path, "output.txt", "KEEP\n")
        audit_dir = tmp_path / "audit"
        assert main(["sanitize", src, "-o", dst, "--audit-dir", str(audit_dir)]) == EXIT_ERROR
        assert Path(dst).read_text(encoding="utf-8") == "KEEP\n"
        assert not audit_dir.exists()
        assert capsys.readouterr().out == ""

    def test_output_permissions_ignore_permissive_umask(self, tmp_path):
        import os
        import stat

        src = write(tmp_path, "source.txt", PHONE)
        dst = tmp_path / "output.txt"
        previous = os.umask(0)
        try:
            assert main(["sanitize", src, "-o", str(dst)]) == EXIT_OK
        finally:
            os.umask(previous)
        assert stat.S_IMODE(dst.stat().st_mode) == 0o600
        assert Path(src).read_text(encoding="utf-8") == PHONE

    def test_late_output_symlink_is_not_followed(self, tmp_path, monkeypatch, capsys):
        import importlib

        cli = importlib.import_module("cli.main")
        src = Path(write(tmp_path, "source.txt", PHONE))
        dst = tmp_path / "output.txt"
        real_open = cli.os.open

        def racing_open(path, flags, mode=0o777):
            if Path(path) == dst:
                dst.symlink_to(src)
            return real_open(path, flags, mode)

        monkeypatch.setattr(cli.os, "open", racing_open)
        assert main(["sanitize", str(src), "-o", str(dst)]) == EXIT_ERROR
        assert src.read_text(encoding="utf-8") == PHONE
        assert capsys.readouterr().out == ""

    @pytest.mark.parametrize("failure", ["short", "zero", "fsync"])
    def test_audit_failure_releases_nothing(self, tmp_path, monkeypatch, capsys, failure):
        import core.audit as audit

        src = write(tmp_path, "source.txt", PHONE)
        dst = tmp_path / "output.txt"
        real_write = audit.os.write

        def failing_write(fd, data):
            if failure == "zero":
                return 0
            return real_write(fd, data[:1])

        def failing_fsync(fd):
            raise OSError("synthetic fsync failure")

        if failure == "fsync":
            monkeypatch.setattr(audit.os, "fsync", failing_fsync)
        else:
            monkeypatch.setattr(audit.os, "write", failing_write)
        assert main(["sanitize", src, "-o", str(dst),
                     "--audit-dir", str(tmp_path / "audit")]) == EXIT_ERROR
        assert not dst.exists()
        assert Path(src).read_text(encoding="utf-8") == PHONE
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "13800000000" not in captured.err


# -- errors ------------------------------------------------------------------


class TestErrors:
    def test_missing_file_exit_four(self, tmp_path, capsys):
        rc = main(["inspect", str(tmp_path / "nope.txt")])
        assert rc == EXIT_ERROR
        assert "cannot read" in capsys.readouterr().err

    def test_unknown_profile_exit_four(self, tmp_path, capsys):
        rc = main(["inspect", "--profile", "nope", write(tmp_path, "c.txt", CLEAN)])
        assert rc == EXIT_ERROR
        assert "unknown policy profile" in capsys.readouterr().err

    def test_argparse_usage_error_exit_four(self, tmp_path, capsys):
        # Missing required <file> argument: argparse usage error must map to 4,
        # not collide with BLOCK's exit code 2.
        rc = main(["inspect"])
        assert rc == EXIT_ERROR
        assert "usage" in capsys.readouterr().err.lower()

    def test_unknown_command_exit_four(self, capsys):
        rc = main(["frobnicate", "x"])
        assert rc == EXIT_ERROR

    def test_help_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0

    def test_recipient_blocked_blocks(self, tmp_path, capsys):
        rc = main(["inspect", "--recipient", "external_blocked",
                   write(tmp_path, "clean.txt", CLEAN)])
        assert rc == EXIT_BLOCK


# -- benchmark ---------------------------------------------------------------


class TestBenchmarkCommand:
    def test_default_recipient_reaches_the_sanitize_path(self):
        """The CLI default must match the corpus's declared expectations.

        Under the conservative `external_unknown` default no clinical note is
        ever released, so every gate would be vacuous and the command would
        report a pass over zero measurements.
        """
        from cli.main import DEFAULT_BENCHMARK_RECIPIENT
        from core.benchmark import DEFAULT_RECIPIENT

        assert DEFAULT_BENCHMARK_RECIPIENT == DEFAULT_RECIPIENT
        assert DEFAULT_RECIPIENT != "external_unknown"

    def test_benchmark_reports_coverage_and_exits_ok(self, capsys):
        rc = main(["benchmark", str(CORPUS)])
        out = capsys.readouterr().out
        assert rc == EXIT_OK
        assert "Result: PASS" in out
        assert "documents released:  170" in out
        assert "unchanged ALLOW:     35" in out
        assert "verified SANITIZE:   135" in out
        assert "ASK / BLOCK:         5 / 0" in out
        assert "verifications run:   135" in out
        assert "lifecycle failures:  0" in out
        assert "audit failures:      0" in out
        assert "verdict mismatches:  0" in out

    def test_benchmark_json_exposes_the_new_gates(self, capsys):
        rc = main(["benchmark", str(CORPUS), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["released_documents"] == payload["sanitized_documents"] == 170
        assert payload["allowed_original_documents"] == 35
        assert payload["sanitized_verified_documents"] == 135
        assert payload["verification_runs"] == 135
        assert payload["ask_documents"] == 5
        assert payload["lifecycle_failure_count"] == 0
        assert payload["audit_failure_count"] == 0
        assert payload["verdict_mismatch_count"] == 0

    def test_conservative_recipient_fails_instead_of_passing_vacuously(self, capsys):
        """The old silent pass is now a loud failure."""
        rc = main(["benchmark", str(CORPUS), "--recipient", "external_unknown"])
        out = capsys.readouterr().out
        assert rc == EXIT_BLOCK
        assert "sanitize_path_not_exercised" in out
        assert "verdict_mismatch" in out


# -- audit-verify ------------------------------------------------------------


class TestAuditVerifyCommand:
    """The integrity chain is only useful if the CLI surfaces its verdict."""

    def _write_log(self, tmp_path, capsys, runs=1):
        note = write(tmp_path, "note.txt", "患者张三，电话13800000000。\n")
        audit_dir = tmp_path / "audit"
        for _ in range(runs):
            rc = main([
                "sanitize", note, "--recipient", "external_approved",
                "--audit-dir", str(audit_dir),
            ])
            assert rc == EXIT_OK
        capsys.readouterr()  # drop the sanitized payload; keep only our output
        return audit_dir

    def test_intact_chain_exits_ok(self, tmp_path, capsys):
        audit_dir = self._write_log(tmp_path, capsys, runs=3)
        rc = main(["audit-verify", str(audit_dir)])
        out = capsys.readouterr().out
        assert rc == EXIT_OK
        assert "Result: INTACT" in out
        assert "Records: 3 (chained 3, pre-chain 0)" in out

    def test_missing_log_is_an_error_not_a_pass(self, tmp_path, capsys):
        rc = main(["audit-verify", str(tmp_path / "absent")])
        assert rc == EXIT_ERROR
        assert "no audit log" in capsys.readouterr().err

    def test_edited_record_exits_block(self, tmp_path, capsys):
        audit_dir = self._write_log(tmp_path, capsys)
        log = audit_dir / "events.jsonl"
        payload = json.loads(log.read_text(encoding="utf-8").strip())
        payload["decision"] = "ALLOW"
        log.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        rc = main(["audit-verify", str(audit_dir)])
        out = capsys.readouterr().out
        assert rc == EXIT_BLOCK
        assert "Result: BROKEN" in out
        assert "event_hash does not match its contents" in out

    def test_json_report_is_machine_readable(self, tmp_path, capsys):
        audit_dir = self._write_log(tmp_path, capsys, runs=2)
        rc = main(["audit-verify", str(audit_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == EXIT_OK
        assert payload["verified"] is True
        assert payload["total"] == payload["chained"] == 2
        assert payload["unchained"] == 0
        assert payload["failures"] == []

    def test_unset_key_env_is_an_error(self, tmp_path, monkeypatch, capsys):
        """Asking for a keyed check and silently running unkeyed would pass a
        log the caller expects to be authenticated."""
        audit_dir = self._write_log(tmp_path, capsys)
        monkeypatch.delenv("MPG_TEST_ABSENT_KEY", raising=False)
        rc = main(["audit-verify", str(audit_dir), "--key-env", "MPG_TEST_ABSENT_KEY"])
        assert rc == EXIT_ERROR
        assert "MPG_TEST_ABSENT_KEY is not set" in capsys.readouterr().err

    def test_keyed_log_verifies_only_with_the_same_key(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("MEDICAL_PRIVACY_GUARD_AUDIT_KEY", "synthetic-cli-key")
        audit_dir = self._write_log(tmp_path, capsys)
        rc = main(
            ["audit-verify", str(audit_dir), "--key-env", "MEDICAL_PRIVACY_GUARD_AUDIT_KEY"]
        )
        assert rc == EXIT_OK
        assert "Result: INTACT" in capsys.readouterr().out

        monkeypatch.setenv("MEDICAL_PRIVACY_GUARD_AUDIT_KEY", "a-different-key")
        rc = main(
            ["audit-verify", str(audit_dir), "--key-env", "MEDICAL_PRIVACY_GUARD_AUDIT_KEY"]
        )
        assert rc == EXIT_BLOCK
        assert "Result: BROKEN" in capsys.readouterr().out

    def test_unkeyed_log_fails_a_keyed_check(self, tmp_path, monkeypatch, capsys):
        """An unkeyed chain must not satisfy a caller asking for authentication."""
        monkeypatch.delenv("MEDICAL_PRIVACY_GUARD_AUDIT_KEY", raising=False)
        audit_dir = self._write_log(tmp_path, capsys)
        monkeypatch.setenv("MEDICAL_PRIVACY_GUARD_AUDIT_KEY", "some-key")
        rc = main(
            ["audit-verify", str(audit_dir), "--key-env", "MEDICAL_PRIVACY_GUARD_AUDIT_KEY"]
        )
        assert rc == EXIT_BLOCK
