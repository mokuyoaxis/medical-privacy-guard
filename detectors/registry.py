"""Detector registry and the merged detection pipeline.

`detect_all` runs every registered detector and merges the results into a
single ordered, non-overlapping tuple of facts:
- sorted by start offset (then longest-first);
- overlapping matches keep the highest-confidence fact;
- identical (same span + type) matches are deduplicated.

The merge is deterministic: the same text always yields the same fact list.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from core.model import DetectedFact

from .base import Detector
from .cn_identifiers import CnIdDetector, CnPhoneDetector
from .dates import DateDetector
from .location import PreciseLocationDetector
from .medical_content import MedicalContentDetector
from .medical_record import MedicalRecordDetector
from .person import PersonNameDetector
from .regex import EmailDetector, IpAddressDetector, UrlDetector

DEFAULT_DETECTORS: tuple[Detector, ...] = (
    CnPhoneDetector(),
    CnIdDetector(),
    EmailDetector(),
    UrlDetector(),
    IpAddressDetector(),
    DateDetector(),
    PersonNameDetector(),
    MedicalRecordDetector(),
    PreciseLocationDetector(),
    MedicalContentDetector(),
)


def detect_all(text: str, detectors: Sequence[Detector] | None = None) -> tuple[DetectedFact, ...]:
    """Run all detectors on *text* and return merged, ordered facts."""
    if detectors is None:
        detectors = DEFAULT_DETECTORS
    raw: list[DetectedFact] = []
    for detector in detectors:
        raw.extend(detector.detect(text))
    return _merge(raw)


def _merge(facts: Iterable[DetectedFact]) -> tuple[DetectedFact, ...]:
    ordered = sorted(
        facts,
        key=lambda f: (f.start, -(f.end - f.start), f.confidence, f.type),
    )
    merged: list[DetectedFact] = []
    for fact in ordered:
        if not merged:
            merged.append(fact)
            continue
        last = merged[-1]
        if fact.start >= last.end:
            merged.append(fact)
            continue
        # Overlap: keep the higher-confidence fact, then the longer one.
        if fact.confidence > last.confidence:
            merged[-1] = fact
        elif fact.confidence == last.confidence and (fact.end - fact.start) > (last.end - last.start):
            merged[-1] = fact
        # Otherwise keep the existing one.
    return tuple(merged)
