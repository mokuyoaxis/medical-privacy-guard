"""China-specific deterministic identifier detectors.

Covers:
- Mainland China mobile phone numbers (PHONE)
- Mainland China resident ID numbers (GOVERNMENT_ID) with GB 11643-1999
  check-digit validation
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector

_PHONE_DIGIT = r"[0-9０-９]"
_PHONE_PREFIX = rf"[1１][3-9３-９]{_PHONE_DIGIT}"
_PHONE_SEPARATOR = r"(?:[ \u00a0\u3000]+|[-－])"
_PHONE_RE = re.compile(
    rf"(?<!\d){_PHONE_PREFIX}"
    rf"(?:{_PHONE_DIGIT}{{8}}|{_PHONE_SEPARATOR}{_PHONE_DIGIT}{{4}}"
    rf"{_PHONE_SEPARATOR}{_PHONE_DIGIT}{{4}})(?!\d)"
)

# Candidate 18-digit ID. The check digit X may be upper or lower case.
_ID18_CANDIDATE_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")

# GB 11643-1999 weights and check map.
_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_MAP = ("1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2")


def validate_id18(value: str) -> bool:
    """Validate an 18-digit Mainland China resident ID (GB 11643-1999).

    Checks length, numeric prefix, and the mod-11 check digit. Date-of-birth
    sanity (month/day ranges) is deliberately light here; the check digit is
    the strong discriminator.
    """
    if len(value) != 18:
        return False
    body, check = value[:17], value[17].upper()
    if not body.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(body, _ID_WEIGHTS))
    expected = _ID_CHECK_MAP[total % 11]
    return check == expected


class CnPhoneDetector(Detector):
    """Detects Mainland China mobile phone numbers."""

    name = "cn_phone"
    fact_type = "PHONE"
    confidence = 1.0

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts = []
        for m in _PHONE_RE.finditer(text):
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start(),
                    end=m.end(),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=m.group(0),
                )
            )
        return tuple(facts)


class CnIdDetector(Detector):
    """Detects 18-digit Mainland China resident IDs with check-digit validation.

    A candidate that fails validation is reported as a LOW-confidence
    GOVERNMENT_ID fact rather than dropped silently: an invalid check digit
    could still be a genuine ID in a legacy or malformed record, and
    fail-closed is preferred over silent discard.
    """

    name = "cn_id18"
    fact_type = "GOVERNMENT_ID"
    confidence_valid = 1.0
    confidence_invalid = 0.4

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts = []
        for m in _ID18_CANDIDATE_RE.finditer(text):
            raw = m.group(0)
            valid = validate_id18(raw)
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start(),
                    end=m.end(),
                    confidence=self.confidence_valid if valid else self.confidence_invalid,
                    source=f"regex.{self.name}",
                    value=raw,
                )
            )
        return tuple(facts)
