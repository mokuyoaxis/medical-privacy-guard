"""Generalization transformation.

GENERALIZE reduces a value's precision without removing the clinical meaning
the recipient needs. The strategy depends on the fact type, because "less
precise" means different things for a date, an age and an institution:

- EXACT_DATE      → drop the day (2026-08-29 → 2026-08 / 2026年8月)
- PRECISE_LOCATION→ replace with a non-identifying marker
- AGE             → map to a band (67岁 → 60-69岁)
- AGE_90_PLUS     → collapse to a single band marker
- HOSPITAL_NAME   → institution-type marker
- DEPARTMENT      → department-type marker
- WARD            → ward-type marker

Unsupported fact types raise TransformerError rather than silently passing the
value through: a generalization that cannot be performed must fail closed, and
the caller (verification) then treats the sanitization as incomplete.
"""

from __future__ import annotations

import re

from core.errors import TransformerError
from detectors.demographics import parse_cn_numeral
from core.model import DetectedFact, TransformationOp

from .base import TokenRegistry, Transformer
from .dates import _parse_full_date

_AGE_RE = re.compile(r"(\d{1,3})\s*(?:岁|周岁)")
_CN_AGE_RE = re.compile(r"([一二两三四五六七八九十]{1,3})\s*(?:岁|周岁)")

# Age bands. Width 10 below 90 keeps cohorts clinically meaningful while
# preventing an exact age from selecting a single person in a small dataset.
_AGE_BANDS: tuple[tuple[int, int, str], ...] = (
    (0, 0, "不足1岁"),
    (1, 9, "1-9岁"),
    (10, 19, "10-19岁"),
    (20, 29, "20-29岁"),
    (30, 39, "30-39岁"),
    (40, 49, "40-49岁"),
    (50, 59, "50-59岁"),
    (60, 69, "60-69岁"),
    (70, 79, "70-79岁"),
    (80, 89, "80-89岁"),
    (90, 200, "90岁及以上"),
)

_TYPE_MARKERS: dict[str, str] = {
    "PRECISE_LOCATION": "[LOCATION_GENERALIZED]",
    "HOSPITAL_NAME": "[INSTITUTION_GENERALIZED]",
    "DEPARTMENT": "[DEPARTMENT_GENERALIZED]",
    "WARD": "[WARD_GENERALIZED]",
}


class GeneralizeTransformer(Transformer):
    """Reduces precision of dates, ages, locations and institution names."""

    handles = ("GENERALIZE",)

    def apply(
        self,
        fact: DetectedFact,
        op: TransformationOp,
        tokens: TokenRegistry,
    ) -> str:
        del op, tokens
        fact_type = fact.type

        if fact_type in _TYPE_MARKERS:
            return _TYPE_MARKERS[fact_type]
        if fact_type == "AGE_90_PLUS":
            return "90岁及以上"
        if fact_type == "AGE":
            return self._band(fact.value or "")
        if fact_type == "EXACT_DATE":
            return self._generalize_date(fact.value or "")
        raise TransformerError(
            f"cannot generalize fact type '{fact_type}'; no strategy configured"
        )

    # -- dates --------------------------------------------------------------

    @staticmethod
    def _generalize_date(value: str) -> str:
        parsed = _parse_full_date(value)
        if "年" in value:
            return f"{parsed.year:04d}年{parsed.month}月"
        ymd = re.fullmatch(r"\d{4}([-/.])\d{1,2}\1\d{1,2}", value)
        sep = ymd.group(1) if ymd else "-"
        return f"{parsed.year:04d}{sep}{parsed.month:02d}"

    # -- ages ---------------------------------------------------------------

    @staticmethod
    def _band(value: str) -> str:
        m = _AGE_RE.fullmatch(value)
        if m:
            age = int(m.group(1))
        else:
            # Chinese numerals are the other common way an age is written
            # ("五十六岁"). The detector reports the whole token, so the band
            # has to come from the numeral rather than from digits; without
            # this the fact is detected, policy plans GENERALIZE, and the
            # transformation raises instead of releasing anything.
            numeral = _CN_AGE_RE.fullmatch(value)
            age = parse_cn_numeral(numeral.group(1)) if numeral else None
            if age is None:
                # A month-age fact carries the whole token ("6个月" from
                # "患儿6个月"), because replacing only the digits would leave a
                # dangling "个月" and produce incoherent clinical text.
                m_month = re.fullmatch(r"(\d{1,2})\s*个?月(?:龄|大)?", value)
                if m_month:
                    months = int(m_month.group(1))
                    if not 1 <= months <= 36:
                        raise TransformerError("month age out of supported range")
                    return "不足1岁" if months < 12 else "1-9岁"
                raise TransformerError("cannot generalize age value")
        for low, high, label in _AGE_BANDS:
            if low <= age <= high:
                return label
        raise TransformerError("age out of supported range")
