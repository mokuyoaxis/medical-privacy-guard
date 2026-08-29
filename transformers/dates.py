"""Generalization and date-shift transformations.

- GENERALIZE: drop a date's day component (2026-08-29 → 2026-08), or replace
  a precise labelled location with a non-identifying location marker.
- DATE_SHIFT: shift a full date by a fixed number of days. Within one
  sanitization run the shift is derived deterministically from the payload
  text, so all dates move together (intervals preserved) but different
  payloads do not reuse the same predictable offset. v0.1 uses a simple
  text-hash seed; production key management is out of scope for this step.
"""

from __future__ import annotations

import re
from datetime import date, timedelta

from core.errors import TransformerError
from core.model import DetectedFact, TransformationOp

from .base import TokenRegistry, Transformer

# Capture year and month; `sep` is the original separator (backreference
# (?P=sep) keeps the day separator consistent, e.g. 2026/08/29).
_YMD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^(?P<y>\d{4})(?P<sep>[-/.])(?P<m>\d{2})(?P=sep)\d{2}$"),
    re.compile(r"^(?P<m>\d{2})/(?P<d>\d{2})/(?P<y>\d{4})$"),
    re.compile(r"^(?P<y>\d{4})年(?P<m>\d{1,2})月\d{1,2}日$"),
)


def _parse_full_date(value: str) -> date:
    from datetime import datetime

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    cn = re.fullmatch(r"(\d{4})年(\d{1,2})月(\d{1,2})日", value)
    if cn:
        return date(int(cn.group(1)), int(cn.group(2)), int(cn.group(3)))
    raise TransformerError(f"cannot parse date value for transformation: {value!r}")


class DateTransformer(Transformer):
    """Handles date shifting and date/location generalization."""

    handles = ("GENERALIZE", "DATE_SHIFT")

    def apply(
        self,
        fact: DetectedFact,
        op: TransformationOp,
        tokens: TokenRegistry,
    ) -> str:
        del tokens
        value = fact.value or ""
        if op.op == "GENERALIZE" and fact.type == "PRECISE_LOCATION":
            return "[LOCATION_GENERALIZED]"
        if op.op == "GENERALIZE":
            return self._generalize(value)
        if op.op == "DATE_SHIFT":
            days = self._shift_days(op)
            return self._shift(value, days)
        raise TransformerError(f"op '{op.op}' not handled by {type(self).__name__}")

    # -- GENERALIZE ---------------------------------------------------------

    def _generalize(self, value: str) -> str:
        for pattern in _YMD_PATTERNS:
            m = pattern.match(value)
            if m:
                year, month = m.group("y"), m.group("m")
                if "sep" in m.groupdict() and m.group("sep"):
                    return f"{year}{m.group('sep')}{month}"
                if "年" in value:
                    return f"{year}年{int(month)}月"
                return f"{year}-{month}"
        raise TransformerError(f"cannot generalize date value: {value!r}")

    # -- DATE_SHIFT ---------------------------------------------------------

    @staticmethod
    def _shift_days(op: TransformationOp) -> int:
        configured = op.parameters.get("shift_days")
        if configured is not None:
            return int(configured)
        # Fall back to a deterministic seed provided by the caller; the
        # registry injects a payload-derived seed when none is configured.
        seed = op.parameters.get("_seed")
        if seed is not None:
            return int(seed)
        raise TransformerError("DATE_SHIFT requires 'shift_days' or '_seed' parameter")

    @staticmethod
    def _shift(value: str, days: int) -> str:
        original = _parse_full_date(value)
        shifted = original + timedelta(days=days)
        if "年" in value:
            return f"{shifted.year}年{shifted.month}月{shifted.day}日"
        sep = "/" if "/" in value else "-"
        return f"{shifted.year:04d}{sep}{shifted.month:02d}{sep}{shifted.day:02d}"
