"""Medical record identifier detector.

Detects MRN / admission / visit numbers that appear in labelled fields such
as "病历号：" / "住院号：" / "就诊号：" / "MRN:" / "medical record:".
Like the person-name detector, this is a Layer 2 field-marker rule: bare
digit strings are never reported.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector
from .field_syntax import FIELD_SEP, label_with_value

# Field values are bounded but never prefix-matched: the trailing lookahead is
# important because a partial MRN can otherwise be redacted and then pass
# verification with the unmatched suffix still present.
_CN_MRN_RE = re.compile(
    label_with_value(
        r"病历号|住院号|入院号|登记号|就诊号|门诊号|病案号|档案号|患者编号|病人编号",
        r"[A-Za-z0-9][A-Za-z0-9_\-]{2,63}",
    )
    + r"(?![A-Za-z0-9_\-])"
)
# English labels follow the same whole-token rule. The long and short
# "medical record [number]" forms are separate alternatives guarded by a
# lookahead: without it the short form matches "medical record" and treats the
# word "number" as the value, so a redacted record re-detects as fresh PHI and
# verification can never pass.
_EN_MRN_RE = re.compile(
    r"\b(?:mrn|admission\s*id|visit\s*id"
    r"|medical\s*record\s*number|medical\s*record(?!\s*number\b))\b"
    + FIELD_SEP
    + r"(?P<value>[A-Za-z0-9][A-Za-z0-9_\-]{2,63})(?![A-Za-z0-9_\-])",
    re.IGNORECASE,
)


class MedicalRecordDetector(Detector):
    """Detects medical record / admission / visit numbers after field labels."""

    name = "medical_record_field"
    fact_type = "MEDICAL_RECORD_NUMBER"
    confidence = 0.95

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for pattern in (_CN_MRN_RE, _EN_MRN_RE):
            for m in pattern.finditer(text):
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=m.start("value"),
                        end=m.end("value"),
                        confidence=self.confidence,
                        source=f"regex.{self.name}",
                        value=m.group("value"),
                    )
                )
        return tuple(facts)
