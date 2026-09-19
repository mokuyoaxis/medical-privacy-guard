"""Conservative precise-location detector for explicitly labelled fields."""

from __future__ import annotations

import re

from core.model import DetectedFact, is_placeholder

from .base import Detector
from .field_syntax import FIELD_SEP

_ADDRESS_FIELD_RE = re.compile(
    r"(?:家庭住址|联系地址|现住址|住址|地址)"
    + FIELD_SEP
    + r"(?P<value>[^\n\r,，。；;]{4,100})(?=[\n\r,，。；;]|$)"
)


class PreciseLocationDetector(Detector):
    """Detect a precise address only when an explicit field label is present."""

    name = "precise_location_field"
    fact_type = "PRECISE_LOCATION"
    confidence = 0.95

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for match in _ADDRESS_FIELD_RE.finditer(text):
            value = match.group("value").strip()
            # 联系地址：[LOCATION_GENERALIZED] is the guard's own output, not a
            # fresh address; re-detecting it would block every release.
            if is_placeholder(value):
                continue
            start = match.start("value")
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=start,
                    end=start + len(value),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=value,
                )
            )
        return tuple(facts)
