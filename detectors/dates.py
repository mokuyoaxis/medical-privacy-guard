"""Date detector.

Detects full calendar dates (year + month + day) in common textual formats
and validates them against the real calendar before emitting an EXACT_DATE
fact. Month-only or year-only values are deliberately not flagged: they are
far less identifying and the pattern space is too noisy.
"""

from __future__ import annotations

import re
from datetime import date

from core.model import DetectedFact

from .base import Detector

_FULLWIDTH_DIGITS = str.maketrans("０１２３４５６７８９", "0123456789")
_YEAR = r"(?P<y>19[0-9]{2}|20[0-9]{2})"
_MONTH = r"(?P<m>0?[1-9]|1[0-2])"
_DAY = r"(?P<d>0?[1-9]|[12][0-9]|3[01])"
_DATE_START = r"(?<!\d)(?<!\d[-/.])"
_DATE_END = r"(?!\d)(?![-/.]\d)"
_DATE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"{_DATE_START}{_YEAR}(?P<sep>[-/.]){_MONTH}(?P=sep){_DAY}{_DATE_END}"),
    re.compile(rf"{_DATE_START}{_MONTH}/{_DAY}/{_YEAR}{_DATE_END}"),
    re.compile(rf"{_DATE_START}{_YEAR}年{_MONTH}月{_DAY}日{_DATE_END}"),
)


class DateDetector(Detector):
    """Detects valid full dates; reports them as EXACT_DATE."""

    name = "exact_date"
    fact_type = "EXACT_DATE"
    confidence = 1.0

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        normalized = text.translate(_FULLWIDTH_DIGITS)
        for pattern in _DATE_PATTERNS:
            for m in pattern.finditer(normalized):
                year, month, day = (int(m.group(k)) for k in ("y", "m", "d"))
                try:
                    date(year, month, day)
                except ValueError:
                    continue  # e.g. 2023-02-30
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=m.start(),
                        end=m.end(),
                        confidence=self.confidence,
                        source=f"regex.{self.name}",
                        value=text[m.start() : m.end()],
                    )
                )
        return tuple(facts)
