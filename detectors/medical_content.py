"""Small deterministic baseline for explicit medical-content signals.

This is deliberately a baseline classifier, not medical NER.  It records that
clinical content is present so policy and audit do not call such text "clean".
It does not transform diagnosis/treatment content by itself.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector

_MEDICAL_SIGNAL_RE = re.compile(
    r"(?:诊断|疾病|病史|症状|检验|检查结果|用药|药物|治疗|手术|过敏史|"
    r"diagnosis|disease|medication|treatment|laboratory|lab\s+result|"
    r"HIV|AIDS|Crohn(?:'s)?\s+disease)",
    re.IGNORECASE,
)


class MedicalContentDetector(Detector):
    """Emit MEDICAL_CONTENT for explicit clinical labels or terms."""

    name = "medical_content_baseline"
    fact_type = "MEDICAL_CONTENT"
    confidence = 0.8

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        return tuple(
            DetectedFact(
                type=self.fact_type,
                start=match.start(),
                end=match.end(),
                confidence=self.confidence,
                source=f"regex.{self.name}",
                value=match.group(0),
            )
            for match in _MEDICAL_SIGNAL_RE.finditer(text)
        )
