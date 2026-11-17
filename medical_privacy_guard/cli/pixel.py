"""Pixel-block presentation for interactive CLI use.

Pure standard library: Unicode block characters and ANSI colours, no
third-party dependency. The MPG banner uses a seven-row pixel font and
a blue-to-pink gradient, after the agent-guard logo. Decoration is for
humans at a terminal only: the banner is written to stderr, and both
the banner and the colours disappear when the stream is not a TTY,
when ``--json`` is in effect, or when ``NO_COLOR`` is set.
Machine-readable output is never altered.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

from medical_privacy_guard import __version__
from medical_privacy_guard.core.model import RiskLevel, Verdict

_PIXEL_FONT: dict[str, tuple[str, ...]] = {
    "M": (
        "█   █",
        "██ ██",
        "█ █ █",
        "█ █ █",
        "█   █",
        "█   █",
        "█   █",
    ),
    "P": (
        "████ ",
        "█   █",
        "█   █",
        "████ ",
        "█    ",
        "█    ",
        "█    ",
    ),
    "G": (
        " ████ ",
        "█    █",
        "█     ",
        "█  ███",
        "█    █",
        "█    █",
        " ████ ",
    ),
}

_ROWS = 7

# Banner gradient anchors (blue, violet, pink), after the agent-guard logo.
_GRADIENT = ((26, 109, 224), (147, 84, 222), (224, 49, 110))

_RESET = "\033[0m"

_VERDICT_CODES = {
    Verdict.ALLOW: "32",
    Verdict.SANITIZE: "36",
    Verdict.ASK: "33",
    Verdict.BLOCK: "31",
}

_LEVEL_CODES = {
    RiskLevel.LOW: "32",
    RiskLevel.MEDIUM: "33",
    RiskLevel.HIGH: "38;5;208",
    RiskLevel.CRITICAL: "31",
}

_LEVEL_FILL = {
    RiskLevel.LOW: 2,
    RiskLevel.MEDIUM: 5,
    RiskLevel.HIGH: 8,
    RiskLevel.CRITICAL: 10,
}

_BAR_WIDTH = 10


def pixel_text(text: str) -> list[str]:
    """Render text as seven rows of pixel blocks (font covers M, P, G).

    Each pixel is two characters wide: a terminal cell is about twice as
    tall as it is wide, so single-width blocks render stretched thin and
    hard to read. Doubled, a pixel is near-square, as in the SVG logos.
    """
    rows = [""] * _ROWS
    for ch in text:
        glyph = _PIXEL_FONT[ch]
        for index in range(_ROWS):
            cells = "".join("██" if px == "█" else "  " for px in glyph[index])
            rows[index] += cells + "    "
    return [row.rstrip() for row in rows]


def _gradient_code(column: int, total: int) -> str:
    """Truecolor ANSI code for a column's place in the banner gradient."""
    if total <= 1:
        position = 0.0
    else:
        position = column / (total - 1)
    if position < 0.5:
        start, end, local = _GRADIENT[0], _GRADIENT[1], position * 2
    else:
        start, end, local = _GRADIENT[1], _GRADIENT[2], (position - 0.5) * 2
    red, green, blue = (
        round(a + (b - a) * local) for a, b in zip(start, end, strict=True)
    )
    return f"38;2;{red};{green};{blue}"


def _painted_rows(text: str) -> list[str]:
    rows = pixel_text(text)
    width = max(len(row) for row in rows)
    painted = []
    for row in rows:
        cells = []
        padded = row.ljust(width)
        for start in range(0, width, 2):
            pair = padded[start:start + 2]
            if pair == "██":
                cells.append(f"\033[{_gradient_code(start // 2, width // 2)}m██{_RESET}")
            else:
                cells.append(pair)
        painted.append("".join(cells))
    return painted


def color_enabled(stream: TextIO) -> bool:
    """True when ANSI colour may be written to this stream."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and bool(stream.isatty())


def paint(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}{_RESET}"


def verdict_code(verdict: Verdict) -> str:
    return _VERDICT_CODES[verdict]


def level_code(level: RiskLevel) -> str:
    return _LEVEL_CODES[level]


def risk_bar(level: RiskLevel, enabled: bool) -> str:
    """A ten-block bar whose fill and colour follow the risk level."""
    filled = _LEVEL_FILL[level]
    bar = "▓" * filled + "░" * (_BAR_WIDTH - filled)
    return paint(bar, _LEVEL_CODES[level], enabled)


def print_banner(suppressed: bool, stream: TextIO | None = None) -> None:
    """Print the MPG pixel banner to stderr, for interactive runs only.

    ``suppressed`` is the caller's machine-output flag (``--json``);
    pipes and non-terminals suppress the banner as well.
    """
    stream = stream if stream is not None else sys.stderr
    if suppressed or not color_enabled(stream):
        return
    rows = _painted_rows("MPG")
    for index, row in enumerate(rows):
        if index == 2:
            print(f"{row}   medical-privacy-guard v{__version__}", file=stream)
        else:
            print(row, file=stream)
    print("local-first privacy guardrails for medical data", file=stream)
