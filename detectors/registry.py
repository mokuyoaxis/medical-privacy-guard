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
from .clinical_context import (
    AccessionNumberDetector,
    DoctorNameDetector,
    LandlineDetector,
    NurseNameDetector,
    PostalCodeDetector,
    RareContextDetector,
    RelativeNameDetector,
    SocialMediaIdDetector,
    SpecimenIdDetector,
)
from .cn_identifiers import CnIdDetector, CnPhoneDetector
from .dates import DateDetector
from .demographics import AgeDetector, SexDetector
from .institution import (
    BedNumberDetector,
    DepartmentDetector,
    HospitalNameDetector,
    WardDetector,
)
from .location import PreciseLocationDetector
from .medical_content import MedicalContentDetector
from .medical_record import MedicalRecordDetector
from .person import PersonNameDetector
from .recall_guard import NarrativeNameDetector
from .regex import EmailDetector, IpAddressDetector, UrlDetector

DEFAULT_DETECTORS: tuple[Detector, ...] = (
    # Layer 1: unambiguous machine formats
    CnPhoneDetector(),
    CnIdDetector(),
    EmailDetector(),
    UrlDetector(),
    IpAddressDetector(),
    DateDetector(),
    LandlineDetector(),
    # Layer 2: labelled fields
    PersonNameDetector(),
    MedicalRecordDetector(),
    PreciseLocationDetector(),
    SpecimenIdDetector(),
    AccessionNumberDetector(),
    PostalCodeDetector(),
    SocialMediaIdDetector(),
    # Layer 3: clinical narrative and institution context
    HospitalNameDetector(),
    DepartmentDetector(),
    WardDetector(),
    BedNumberDetector(),
    DoctorNameDetector(),
    NurseNameDetector(),
    RelativeNameDetector(),
    AgeDetector(),
    SexDetector(),
    RareContextDetector(),
    # Layer 4: document-level classification
    MedicalContentDetector(),
    # Layer 5: independent recall guard. Registered last and with lower
    # confidence than the labelled-field detectors, so it only ever adds
    # coverage for forms the primary rules cannot see.
    NarrativeNameDetector(),
)


def detect_all(text: str, detectors: Sequence[Detector] | None = None) -> tuple[DetectedFact, ...]:
    """Run all detectors on *text* and return merged, ordered facts."""
    if detectors is None:
        detectors = DEFAULT_DETECTORS
    raw: list[DetectedFact] = []
    for detector in detectors:
        raw.extend(detector.detect(text))
    return _merge(raw)


#: Document-level classifications describe the payload as a whole rather than
#: one span. They must never displace a span-level fact: a rare-context signal
#: overlapping a generic "疾病" match is the more specific claim, and dropping
#: it would silently skip the ASK path for a patient-attributed rare disease.
_DOCUMENT_LEVEL_TYPES = frozenset({"MEDICAL_CONTENT", "PARSER_FAILURE", "UNSUPPORTED_FORMAT"})


def _rank(fact: DetectedFact) -> tuple[int, float, int]:
    """Overlap priority: span-level first, then confidence, then length."""
    return (
        0 if fact.type in _DOCUMENT_LEVEL_TYPES else 1,
        fact.confidence,
        fact.end - fact.start,
    )


def merge_facts(facts: Iterable[DetectedFact]) -> tuple[DetectedFact, ...]:
    """Merge facts from several passes into one ordered, non-overlapping tuple.

    The public counterpart of the merge ``detect_all`` performs, for callers
    that run the detectors over more than one probe of the same value: a
    structured leaf is offered under its Chinese label and, when its key is
    English, under the key's own words as well.
    """
    return _merge(facts)


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
        # Overlap: keep the span-level fact, then the higher-confidence, longer one.
        if _rank(fact) > _rank(last):
            merged[-1] = fact
    return tuple(merged)
