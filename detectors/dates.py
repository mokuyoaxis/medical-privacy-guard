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
from .demographics import parse_cn_numeral

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

# Fully Chinese-numeral dates ("二〇二六年九月二十一日") are how formal documents
# and some signatures write a date. They were invisible to every pattern above,
# so the note was released with the date intact.
_CN_YEAR_DIGITS = str.maketrans("〇零一二三四五六七八九", "00123456789")
_CN_DATE_RE = re.compile(
    r"(?P<y>[〇零一二三四五六七八九]{4})年"
    r"(?P<m>[一二三四五六七八九十]{1,3})月"
    r"(?P<d>[一二三四五六七八九十]{1,3})日"
)


def parse_cn_date(value: str) -> date | None:
    """Parse a fully Chinese-numeral date, or return None.

    Used by the detector, the transformer and the verifier so all three agree
    on what a Chinese-numeral date is; a mismatch between them is how a fact
    gets detected but never transformed.
    """
    match = _CN_DATE_RE.fullmatch(value)
    if not match:
        return None
    year = int(match.group("y").translate(_CN_YEAR_DIGITS))
    month = parse_cn_numeral(match.group("m"))
    day = parse_cn_numeral(match.group("d"))
    if month is None or day is None:
        return None
    try:
        return date(year, month, day)
    except ValueError:
        return None  # e.g. 二〇二三年二月三十日


class DateDetector(Detector):
    """Detects valid full dates; reports them as EXACT_DATE."""

    name = "exact_date"
    fact_type = "EXACT_DATE"
    confidence = 1.0

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        normalized = text.translate(_FULLWIDTH_DIGITS)
        for m in _CN_DATE_RE.finditer(text):
            parsed = parse_cn_date(m.group(0))
            if parsed is None or not 1900 <= parsed.year <= 2099:
                continue
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start(),
                    end=m.end(),
                    confidence=self.confidence,
                    source=f"regex.{self.name}.numeral",
                    value=m.group(0),
                )
            )
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
