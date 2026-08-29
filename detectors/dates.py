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

# ISO-ish and locale formats. Named groups: y/m/d.
_DATE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<!\d)(?P<y>19\d{2}|20\d{2})-(?P<m>0[1-9]|1[0-2])-(?P<d>0[1-9]|[12]\d|3[01])(?!\d)"),
    re.compile(r"(?<!\d)(?P<y>19\d{2}|20\d{2})/(?P<m>0[1-9]|1[0-2])/(?P<d>0[1-9]|[12]\d|3[01])(?!\d)"),
    re.compile(r"(?<!\d)(?P<y>19\d{2}|20\d{2})\.(?P<m>0[1-9]|1[0-2])\.(?P<d>0[1-9]|[12]\d|3[01])(?!\d)"),
    re.compile(r"(?<!\d)(?P<m>0[1-9]|1[0-2])/(?P<d>0[1-9]|[12]\d|3[01])/(?P<y>19\d{2}|20\d{2})(?!\d)"),
    # 2026年8月29日 (month/day may be single-digit in Chinese text)
    re.compile(r"(?<!\d)(?P<y>19\d{2}|20\d{2})年(?P<m>1[0-2]|[1-9])月(?P<d>3[01]|[12]\d|[1-9])日(?!\d)"),
)


class DateDetector(Detector):
    """Detects valid full dates; reports them as EXACT_DATE."""

    name = "exact_date"
    fact_type = "EXACT_DATE"
    confidence = 1.0

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for pattern in _DATE_PATTERNS:
            for m in pattern.finditer(text):
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
                        value=m.group(0),
                    )
                )
        return tuple(facts)
