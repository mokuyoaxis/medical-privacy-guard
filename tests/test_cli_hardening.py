"""Hardening coverage for cli/main.py branches the command tests do not
reach: REPL box commands and exits, approval-export key requirements,
dataset/report failure paths, the serve/dicom dispatchers, and the
defensive fallthroughs in main() itself.

Every fixture value is synthetic.
"""

from __future__ import annotations

import builtins
import json
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

import medical_privacy_guard.cli.main as cli_main
from medical_privacy_guard.cli.main import (
    EXIT_BLOCK,
    EXIT_ERROR,
    EXIT_OK,
    _json_decision,
    _write_output,
    main,
)
from medical_privacy_guard.core.errors import GuardError
from medical_privacy_guard.core.model import Verdict

DICOM_BASE = "tests/fixtures/dicom/ct_head_synthetic.dcm"
PHONE_TEXT = "患者复诊，联系电话13800000000"
HIV_TEXT = "诊断：HIV感染，建议复查"
GRANT_KEY_ENV = "MEDICAL_PRIVACY_GUARD_GRANT_KEY"


def _write(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _feed(monkeypatch, lines):
    iterator = iter(lines)

    def fake_input(prompt: str = "") -> str:
        print(prompt, end="")
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr(builtins, "input", fake_input)


# -- _json_decision -----------------------------------------------------------


def test_json_decision_includes_sanitized_and_verification_when_given():
    from medical_privacy_guard import Guard
    from medical_privacy_guard.core.model import Purpose, Recipient, TrustLevel

    result = Guard().evaluate(
        PHONE_TEXT,
        Recipient(kind="cli", trust_level=TrustLevel.EXTERNAL_UNKNOWN),
        Purpose.EXTERNAL_AI_ASSISTANCE,
    )
    payload = json.loads(
        _json_decision(
            result.decision,
            {"PHONE": 1},
            result.public_facts,
            sanitized="联系电话[REDACTED]",
            verification="passed",
        )
    )
    assert payload["sanitized"] == "联系电话[REDACTED]"
    assert payload["verification"] == "passed"


# -- approval-request export requires the grant key ----------------------------


def test_inspect_approval_export_requires_the_grant_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(GRANT_KEY_ENV, raising=False)
    source = _write(tmp_path, "note.txt", HIV_TEXT)
    code = main(["inspect", source, "--approval-request-out", str(tmp_path / "req.json")])
    assert code == EXIT_ERROR
    assert "requires the configured grant key" in capsys.readouterr().err


def test_sanitize_approval_export_requires_the_grant_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(GRANT_KEY_ENV, raising=False)
    source = _write(tmp_path, "note.txt", HIV_TEXT)
    code = main(["sanitize", source, "--approval-request-out", str(tmp_path / "req.json")])
    assert code == EXIT_ERROR
    assert "requires the configured grant key" in capsys.readouterr().err


def test_sanitize_checks_the_approval_path_against_the_output_path(tmp_path):
    source = _write(tmp_path, "note.txt", PHONE_TEXT)
    output = tmp_path / "clean.txt"
    code = main(
        [
            "sanitize",
            source,
            "-o",
            str(output),
            "--approval-request-out",
            str(tmp_path / "req.json"),
        ]
    )
    assert code == EXIT_OK
    assert output.exists()


# -- sanitize defensive verdict branches (stubbed Guard) ------------------------


def _stub_guard(monkeypatch, result):
    class _Guard:
        def __init__(self, **kwargs):
            pass

        def sanitize(self, *args, **kwargs):
            return result

    monkeypatch.setattr(cli_main, "Guard", _Guard)


def _stub_result(verdict, sanitized_payload, verification):
    return SimpleNamespace(
        decision_before=SimpleNamespace(verdict=verdict, explanation="stubbed"),
        sanitized_payload=sanitized_payload,
        verification=verification,
        approval_request=None,
    )


def test_sanitize_ask_with_an_unverified_payload_blocks(tmp_path, monkeypatch, capsys):
    _stub_guard(
        monkeypatch,
        _stub_result(Verdict.ASK, SimpleNamespace(content="x"), None),
    )
    source = _write(tmp_path, "note.txt", PHONE_TEXT)
    assert main(["sanitize", source]) == EXIT_BLOCK
    assert "no verified approved payload" in capsys.readouterr().err


def test_sanitize_without_a_verified_payload_blocks(tmp_path, monkeypatch, capsys):
    _stub_guard(monkeypatch, _stub_result(Verdict.ALLOW, None, None))
    source = _write(tmp_path, "note.txt", PHONE_TEXT)
    assert main(["sanitize", source]) == EXIT_BLOCK
    assert "no verified payload" in capsys.readouterr().err


# -- REPL box commands ----------------------------------------------------------


def test_repl_keyboard_interrupt_exits_cleanly(monkeypatch):
    def interrupting_input(prompt: str = "") -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", interrupting_input)
    assert main(["repl"]) == EXIT_OK


def test_repl_recipient_switch_is_applied(monkeypatch, capsys):
    _feed(monkeypatch, ["/recipient external_approved", "/quit"])
    assert main(["repl"]) == EXIT_OK
    assert "Recipient set to: EXTERNAL_APPROVED" in capsys.readouterr().out


def test_repl_unknown_recipient_is_reported(monkeypatch, capsys):
    _feed(monkeypatch, ["/recipient bogus", "/quit"])
    assert main(["repl"]) == EXIT_OK
    assert "Unknown recipient 'bogus'" in capsys.readouterr().out


def test_repl_unknown_purpose_is_reported(monkeypatch, capsys):
    _feed(monkeypatch, ["/purpose bogus", "/quit"])
    assert main(["repl"]) == EXIT_OK
    assert "Unknown purpose 'bogus'" in capsys.readouterr().out


def test_repl_file_command_without_a_path_shows_usage(monkeypatch, capsys):
    _feed(monkeypatch, ["/file", "/quit"])
    assert main(["repl"]) == EXIT_OK
    assert "Usage: /file <path>" in capsys.readouterr().out


def test_repl_file_command_reports_an_unreadable_file(monkeypatch, capsys):
    _feed(monkeypatch, ["/file /nonexistent/note.txt", "/quit"])
    assert main(["repl"]) == EXIT_OK
    assert "Cannot read /nonexistent/note.txt" in capsys.readouterr().out


def test_repl_file_command_reports_an_empty_file(tmp_path, monkeypatch, capsys):
    empty = _write(tmp_path, "empty.txt", "   ")
    _feed(monkeypatch, [f"/file {empty}", "/quit"])
    assert main(["repl"]) == EXIT_OK
    assert "is empty; nothing to evaluate." in capsys.readouterr().out


# -- dataset commands -----------------------------------------------------------


def _cohort(tmp_path: Path) -> str:
    return _write(
        tmp_path,
        "cohort.csv",
        "age,phone\n30,13800000000\n30,13900000000\n",
    )


def test_dataset_risk_requires_a_quasi_identifier(tmp_path, capsys):
    assert main(["dataset-risk", _cohort(tmp_path)]) == EXIT_ERROR
    assert "quasi-identifier" in capsys.readouterr().err


def test_dataset_sanitize_reports_input_combination_metrics(tmp_path):
    output_dir = tmp_path / "out"
    code = main(
        [
            "dataset-sanitize",
            _cohort(tmp_path),
            "--quasi-identifier",
            "age",
            "--output-dir",
            str(output_dir),
        ]
    )
    assert code == EXIT_OK
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "input_combination_metrics" in manifest


def test_dataset_sanitize_with_a_blocked_row_returns_block(tmp_path):
    cohort = _write(
        tmp_path,
        "ids.csv",
        "age,id_card\n30,110101199003078888\n",
    )
    code = main(
        [
            "dataset-sanitize",
            cohort,
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert code == EXIT_BLOCK


def test_dataset_sanitize_rejects_an_uncreatable_output_directory(tmp_path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    code = main(
        [
            "dataset-sanitize",
            _cohort(tmp_path),
            "--output-dir",
            str(blocker / "out"),
        ]
    )
    assert code == EXIT_ERROR
    assert "could not create the new private dataset output directory" in (
        capsys.readouterr().err
    )


def test_dataset_sanitize_rejects_an_unresolvable_audit_directory(
    tmp_path, monkeypatch, capsys
):
    # _check_paths resolves the audit path first and would mask the second
    # validation layer, so it is stubbed out to reach that layer directly.
    monkeypatch.setattr(cli_main, "_check_paths", lambda *args, **kwargs: None)
    loop = tmp_path / "loop"
    loop.symlink_to("loop", target_is_directory=True)
    code = main(
        [
            "dataset-sanitize",
            _cohort(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--audit-dir",
            str(loop / "audit"),
        ]
    )
    assert code == EXIT_ERROR
    assert "cannot validate dataset output and audit directories" in capsys.readouterr().err


# -- report command -------------------------------------------------------------


def test_report_rejects_an_explicit_missing_grant_db(tmp_path, capsys):
    code = main(
        [
            "report",
            "--grant-db",
            str(tmp_path / "absent.db"),
            "--output",
            str(tmp_path / "report.html"),
        ]
    )
    assert code == EXIT_ERROR
    assert "no grant registry at" in capsys.readouterr().err


def test_report_with_nothing_to_report_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli_main, "DEFAULT_GRANT_DB_PATH", tmp_path / "absent.db")
    code = main(["report", "--output", str(tmp_path / "report.html")])
    assert code == EXIT_ERROR
    assert "nothing to report" in capsys.readouterr().err


def test_report_falls_back_to_the_default_grant_db(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "grants.db"
    assert main(["grant-db-init", "--grant-db", str(db_path)]) == EXIT_OK
    monkeypatch.setattr(cli_main, "DEFAULT_GRANT_DB_PATH", db_path)
    output = tmp_path / "report.html"
    assert main(["report", "--output", str(output)]) == EXIT_OK
    assert output.exists()
    assert "Grants recorded:" in capsys.readouterr().out


# -- serve ----------------------------------------------------------------------


def test_serve_constructs_the_gateway_from_cli_settings(tmp_path, monkeypatch):
    captured = {}

    class _Gateway:
        def __init__(self, settings):
            captured["settings"] = settings

        def serve_forever(self):
            captured["served"] = True

    monkeypatch.setattr(cli_main, "HttpGateway", _Gateway)
    assert main(["serve", "--upstream", "http://127.0.0.1:4000"]) == EXIT_OK
    assert captured["served"] is True
    assert captured["settings"].upstream == "http://127.0.0.1:4000"


# -- dicom commands -------------------------------------------------------------


def test_dicom_inspect_text_output(tmp_path, capsys):
    assert main(["dicom-inspect", DICOM_BASE]) == EXIT_BLOCK
    out = capsys.readouterr().out
    assert "Metadata risk:" in out
    assert "Private tags:" in out


def test_dicom_inspect_missing_file_is_an_error(tmp_path, capsys):
    assert main(["dicom-inspect", str(tmp_path / "absent.dcm")]) == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


def test_dicom_inspect_json_output(capsys):
    assert main(["dicom-inspect", DICOM_BASE, "--json"]) == EXIT_BLOCK
    payload = json.loads(capsys.readouterr().out)
    assert payload["metadata_risk"] == "HIGH"
    assert payload["safe_to_release"] is False


def test_dicom_deidentify_single_file_text_output(tmp_path, capsys):
    output = tmp_path / "out.dcm"
    assert main(["dicom-deidentify", DICOM_BASE, "--out", str(output)]) == EXIT_OK
    assert output.exists()
    out = capsys.readouterr().out
    assert "De-identified:" in out
    assert "Pixel annotation risk: UNKNOWN" in out


def test_dicom_deidentify_json_output(tmp_path, capsys):
    output = tmp_path / "out.dcm"
    code = main(["dicom-deidentify", DICOM_BASE, "--out", str(output), "--json"])
    assert code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["output"] == str(output)


def test_dicom_deidentify_tree_text_output(tmp_path, capsys):
    import shutil

    source_root = tmp_path / "in"
    source_root.mkdir()
    shutil.copy(DICOM_BASE, source_root / "a.dcm")
    (source_root / "notes.txt").write_text("not dicom", encoding="utf-8")
    output_root = tmp_path / "out"
    assert main(["dicom-deidentify", str(source_root), "--out", str(output_root)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "De-identified 1 file(s)" in out
    assert "Skipped (not DICOM): notes.txt" in out
    assert (output_root / "a.dcm").exists()


def test_dicom_deidentify_with_an_audit_dir_writes_an_event(tmp_path):
    output = tmp_path / "out.dcm"
    audit_dir = tmp_path / "audit"
    code = main(
        [
            "dicom-deidentify",
            DICOM_BASE,
            "--out",
            str(output),
            "--audit-dir",
            str(audit_dir),
        ]
    )
    assert code == EXIT_OK
    assert (audit_dir / "events.jsonl").is_file()


def test_dicom_deidentify_missing_input_is_an_error(tmp_path, capsys):
    code = main(
        ["dicom-deidentify", str(tmp_path / "absent.dcm"), "--out", str(tmp_path / "o.dcm")]
    )
    assert code == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


# -- _write_output and main() fallthroughs ---------------------------------------


def test_write_output_raises_when_the_write_makes_no_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_main.os, "write", lambda fd, data: 0)
    with pytest.raises(GuardError):
        _write_output(str(tmp_path / "out.txt"), "input.txt", "data")


def test_main_reports_an_unknown_command(monkeypatch, capsys):
    class _Parser:
        def parse_args(self, argv):
            return Namespace(command="bogus", json=False)

        def print_usage(self, stream):
            print("usage: stub", file=stream)

    monkeypatch.setattr(cli_main, "_build_parser", lambda: _Parser())
    assert main([]) == EXIT_ERROR
    assert "unknown command: bogus" in capsys.readouterr().err


def test_main_reraises_system_exit_from_a_command(monkeypatch):
    def _boom(args):
        raise SystemExit(5)

    monkeypatch.setattr(cli_main, "_cmd_inspect", _boom)
    with pytest.raises(SystemExit) as excinfo:
        main(["inspect", "anything.txt"])
    assert excinfo.value.code == 5


def test_module_entrypoint_runs_as_a_script():
    completed = subprocess.run(
        [sys.executable, "-m", "medical_privacy_guard.cli.main"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == EXIT_OK
    assert "medical-privacy-guard" in completed.stdout


def test_module_main_guard_executes_in_process(monkeypatch):
    import runpy

    monkeypatch.setattr(sys, "argv", ["medical-privacy-guard"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("medical_privacy_guard.cli.main", run_name="__main__")
    assert excinfo.value.code == EXIT_OK
