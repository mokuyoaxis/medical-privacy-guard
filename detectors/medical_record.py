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

# Field values are bounded but never prefix-matched: the trailing lookahead is
# important because a partial MRN can otherwise be redacted and then pass
# verification with the unmatched suffix still present.
_CN_MRN_RE = re.compile(
    r"(?:病历号|住院号|就诊号|门诊号|病案号)\s*[:：]?\s*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9_\-]{3,63})(?![A-Za-z0-9_\-])"
)
# English labels follow the same whole-token rule.
_EN_MRN_RE = re.compile(
    r"\b(?:mrn|medical\s*record(?:\s*number)?|admission\s*id|visit\s*id)\b\s*[:]?\s*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9_\-]{3,63})(?![A-Za-z0-9_\-])",
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
                value = m.group("value")
                start = m.end() - len(value)
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=start,
                        end=m.end(),
                        confidence=self.confidence,
                        source=f"regex.{self.name}",
                        value=value,
                    )
                )
        return tuple(facts)
