"""Date-shift transformation.

- DATE_SHIFT: shift a full date by a fixed number of days. Within one
  sanitization run the shift is derived deterministically from the payload
  text, so all dates move together (intervals preserved). The nonzero
  text-hash offset is predictable and may collide across payloads; it is not
  an anonymity guarantee. Production key management is out of scope.

Generalization (dropping precision) lives in ``generalize.py`` because it
applies to dates, ages, locations and institution names alike.
"""

from __future__ import annotations

import re
from datetime import date, timedelta

from core.errors import TransformerError
from core.model import DetectedFact, TransformationOp

from .base import TokenRegistry, Transformer


def _parse_full_date(value: str) -> date:
    from datetime import datetime

    value = value.translate(str.maketrans("０１２３４５６７８９", "0123456789"))
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    cn = re.fullmatch(r"(\d{4})年(\d{1,2})月(\d{1,2})日", value)
    if cn:
        try:
            return date(int(cn.group(1)), int(cn.group(2)), int(cn.group(3)))
        except ValueError:
            pass
    raise TransformerError("cannot parse date value for transformation")


class DateTransformer(Transformer):
    """Handles date shifting."""

    handles = ("DATE_SHIFT",)

    def apply(
        self,
        fact: DetectedFact,
        op: TransformationOp,
        tokens: TokenRegistry,
    ) -> str:
        del tokens
        if op.op != "DATE_SHIFT":
            raise TransformerError(f"op '{op.op}' not handled by {type(self).__name__}")
        return self._shift(fact.value or "", self._shift_days(op))

    # -- DATE_SHIFT ---------------------------------------------------------

    @staticmethod
    def _shift_days(op: TransformationOp) -> int:
        days = op.parameters.get("shift_days", op.parameters.get("_seed"))
        if type(days) is not int or days == 0:
            raise TransformerError("DATE_SHIFT requires a nonzero integer day offset")
        return days

    @staticmethod
    def _shift(value: str, days: int) -> str:
        original = _parse_full_date(value)
        try:
            shifted = original + timedelta(days=days)
        except (OverflowError, ValueError):
            raise TransformerError("DATE_SHIFT exceeds the supported date range") from None
        if "年" in value:
            return f"{shifted.year}年{shifted.month}月{shifted.day}日"
        sep = "/" if "/" in value else "-"
        return f"{shifted.year:04d}{sep}{shifted.month:02d}{sep}{shifted.day:02d}"
