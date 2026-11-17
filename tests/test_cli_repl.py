"""Interactive repl: input box loop, verdicts, clean exits."""

from __future__ import annotations

import builtins

from medical_privacy_guard.cli.main import main


def _feed(monkeypatch, lines):
    iterator = iter(lines)

    def fake_input(prompt: str = "") -> str:
        print(prompt, end="")
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr(builtins, "input", fake_input)


def test_repl_evaluates_and_sanitizes_then_quits(monkeypatch, capsys):
    _feed(monkeypatch, ["患者：测试患者甲，电话 13800000000", "/quit"])
    assert main(["repl"]) == 0
    out = capsys.readouterr().out
    assert "╭" in out and "╰" in out
    assert "Decision: SANITIZE" in out
    assert "Sanitized:" in out
    assert "[REDACTED]" in out
    assert "13800000000" not in out.split("Sanitized:")[1]


def test_repl_eof_exits_cleanly(monkeypatch, capsys):
    _feed(monkeypatch, [])
    assert main(["repl"]) == 0
    assert "╭" in capsys.readouterr().out


def test_repl_skips_empty_lines(monkeypatch, capsys):
    _feed(monkeypatch, ["", "/quit"])
    assert main(["repl"]) == 0
    assert "Decision:" not in capsys.readouterr().out


def test_repl_help_lists_box_commands(monkeypatch, capsys):
    _feed(monkeypatch, ["/help", "/quit"])
    assert main(["repl"]) == 0
    out = capsys.readouterr().out
    assert "Box commands:" in out
    assert "/recipient <name>" in out
    assert "/file <path>" in out


def test_repl_purpose_switch_changes_verdict(monkeypatch, capsys):
    _feed(monkeypatch, ["/purpose unknown", "联系电话 13800000000", "/quit"])
    assert main(["repl"]) == 0
    out = capsys.readouterr().out
    assert "Purpose set to: UNKNOWN" in out
    assert "Decision: ASK" in out


def test_repl_recipient_switch_and_unknown_command(monkeypatch, capsys):
    _feed(monkeypatch, ["/recipient nope", "/bogus", "/quit"])
    assert main(["repl"]) == 0
    out = capsys.readouterr().out
    assert "Unknown recipient 'nope'" in out
    assert "Unknown command: /bogus" in out


def test_repl_file_command_evaluates_file(monkeypatch, capsys, tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("联系电话 13800000000\n", encoding="utf-8")
    _feed(monkeypatch, [f"/file {target}", "/quit"])
    assert main(["repl"]) == 0
    out = capsys.readouterr().out
    assert "Decision: SANITIZE" in out
    assert "Sanitized:" in out
