"""Deterministic detectors for the text MVP.

Layer 1 format detectors (phone / ID / email / date) plus Layer 2 field-marker
rules (person name, medical record number). Detectors produce facts only;
policy decides the verdict (plan.md §9.1).
"""

from .base import Detector, RegexDetector
from .cn_identifiers import CnIdDetector, CnPhoneDetector
from .dates import DateDetector
from .location import PreciseLocationDetector
from .medical_content import MedicalContentDetector
from .medical_record import MedicalRecordDetector
from .person import PersonNameDetector
from .regex import EmailDetector, IpAddressDetector, UrlDetector
from .registry import DEFAULT_DETECTORS, detect_all

__all__ = [
    "Detector",
    "RegexDetector",
    "CnIdDetector",
    "CnPhoneDetector",
    "DateDetector",
    "PreciseLocationDetector",
    "MedicalContentDetector",
    "MedicalRecordDetector",
    "PersonNameDetector",
    "EmailDetector",
    "UrlDetector",
    "IpAddressDetector",
    "DEFAULT_DETECTORS",
    "detect_all",
]
