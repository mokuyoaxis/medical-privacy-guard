"""Guidance: next-step lines after verdicts and the bare-run welcome."""

from __future__ import annotations

import builtins
import json

from medical_privacy_guard.cli.main import EXIT_ASK, EXIT_BLOCK, EXIT_OK, main

PHONE = "联系电话 13800000000\n"
ID_TEXT = "证件号码 11010519491231002X\n"


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_bare_run_prints_welcome_and_exits_zero(capsys):
    assert main([]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Start here:" in out
    assert "repl" in out
    assert "inspect <file>" in out


def test_sanitize_verdict_points_at_sanitize_command(tmp_path, capsys):
    main(["inspect", _write(tmp_path, "phone.txt", PHONE)])
    out = capsys.readouterr().out
    assert "Decision: SANITIZE" in out
    assert "Next: medical-privacy-guard sanitize <file> -o <output>" in out


def test_ask_verdict_points_at_grant_flow(tmp_path, capsys):
    rc = main(["inspect", "--purpose", "unknown", _write(tmp_path, "phone.txt", PHONE)])
    out = capsys.readouterr().out
    assert rc == EXIT_ASK
    assert "grant-issue request.json --approve" in out


def test_block_verdict_states_grants_do_not_override(tmp_path, capsys):
    rc = main(["inspect", _write(tmp_path, "id.txt", ID_TEXT)])
    out = capsys.readouterr().out
    assert rc == EXIT_BLOCK
    assert "cannot override" in out


def test_json_output_carries_no_guidance(tmp_path, capsys):
    main(["inspect", "--json", _write(tmp_path, "phone.txt", PHONE)])
    out = capsys.readouterr().out
    assert "Next:" not in out
    assert json.loads(out)["decision"] == "SANITIZE"


def test_repl_sanitize_omits_next_step_line(monkeypatch, capsys):
    lines = iter(["患者：测试患者甲，电话 13800000000", "/quit"])

    def fake_input(prompt: str = "") -> str:
        print(prompt, end="")
        return next(lines)

    monkeypatch.setattr(builtins, "input", fake_input)
    assert main(["repl"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Decision: SANITIZE" in out
    assert "Next:" not in out
