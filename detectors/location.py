"""Conservative precise-location detector for explicitly labelled fields."""

from __future__ import annotations

import re

from core.model import DetectedFact, is_placeholder

from .base import Detector
from .field_syntax import FIELD_SEP

_ADDRESS_FIELD_RE = re.compile(
    r"(?:家庭住址|联系地址|现住址|户籍所在地|户籍地|籍贯|工作单位|单位地址|住址|地址)"
    + FIELD_SEP
    + r"(?P<value>[^\n\r,，。；;]{4,100})(?=[\n\r,，。；;]|$)"
)


# An unlabelled address is introduced by a residence verb rather than a field
# label: "患者住北京市朝阳区建国路1号。" carries a full street address and was
# released unchanged, while the labelled form "住址：..." was sanitized. The
# value must end at an administrative or street suffix, which is what keeps
# ordinary prose out: 住院 / 住所 / 住房 are excluded explicitly, and a
# sentence like "患者住本院" finds no suffix and does not match.
_ADDRESS_VERB_RE = re.compile(
    r"(?:现住|居住于|居住在|住在|家住|户籍在|户籍地|籍贯|住(?!院|所|房))"
    r"\s*[:：]?\s*"
    r"(?P<value>[\u4e00-\u9fff\d]{2,30}"
    r"(?:省|市|区|县|旗|镇|乡|街道|路|街|巷|号|室|栋|楼|单元|村|组|社区))"
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
        for match in _ADDRESS_VERB_RE.finditer(text):
            value = match.group("value")
            if is_placeholder(value):
                continue
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=match.start("value"),
                    end=match.end("value"),
                    confidence=self.confidence,
                    source=f"regex.{self.name}.verb",
                    value=value,
                )
            )
        return tuple(facts)
