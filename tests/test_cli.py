"""Unit tests for the CLI (Phase 1 Step 6).

Coverage:
- inspect: human + JSON output, exit codes for ALLOW/SANITIZE/BLOCK
- sanitize: stdout and -o output, BLOCK refuses output, in-place overwrite
  protection, audit-dir integration, verification failure → exit 2
- error paths: missing file → exit 4
"""

import json

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
