"""Pixel presentation: banner gating, risk bars, plain-output safety."""

from __future__ import annotations

import io

from medical_privacy_guard.cli import pixel
from medical_privacy_guard.core.model import RiskLevel, Verdict


class _Tty(io.StringIO):
    def isatty(self) -> bool:  # noqa: D102
        return True


def test_pixel_text_renders_mpg_in_seven_rows():
    rows = pixel.pixel_text("MPG")
    assert len(rows) == 7
    assert all("█" in row for row in rows)
    assert rows[0].startswith("██")
    assert rows[1].startswith("████")


def test_banner_uses_truecolor_gradient(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    tty = _Tty()
    pixel.print_banner(suppressed=False, stream=tty)
    assert "38;2;" in tty.getvalue()


def test_color_enabled_requires_tty_and_no_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    assert pixel.color_enabled(_Tty()) is True
    assert pixel.color_enabled(io.StringIO()) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert pixel.color_enabled(_Tty()) is False


def test_banner_suppressed_for_pipes_and_json():
    pipe = io.StringIO()
    pixel.print_banner(suppressed=False, stream=pipe)
    assert pipe.getvalue() == ""
    tty = _Tty()
    pixel.print_banner(suppressed=True, stream=tty)
    assert tty.getvalue() == ""


def test_banner_prints_pixel_mpg_on_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    tty = _Tty()
    pixel.print_banner(suppressed=False, stream=tty)
    out = tty.getvalue()
    assert "medical-privacy-guard" in out
    assert "█" in out


def test_risk_bar_fill_follows_level():
    assert pixel.risk_bar(RiskLevel.LOW, enabled=False) == "▓▓░░░░░░░░"
    assert pixel.risk_bar(RiskLevel.MEDIUM, enabled=False) == "▓▓▓▓▓░░░░░"
    assert pixel.risk_bar(RiskLevel.HIGH, enabled=False) == "▓▓▓▓▓▓▓▓░░"
    assert pixel.risk_bar(RiskLevel.CRITICAL, enabled=False) == "▓▓▓▓▓▓▓▓▓▓"


def test_paint_is_identity_when_disabled():
    assert pixel.paint("SANITIZE", pixel.verdict_code(Verdict.SANITIZE), False) == "SANITIZE"
    assert "\033[" in pixel.paint("SANITIZE", pixel.verdict_code(Verdict.SANITIZE), True)
