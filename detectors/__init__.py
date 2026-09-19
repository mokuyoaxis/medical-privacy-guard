"""Deterministic detectors for the text MVP.

Layer 1 format detectors (phone / ID / email / date / landline), Layer 2
field-marker rules (person name, MRN, address, specimen/accession, postal,
social media), Layer 3 clinical narrative and institution context (hospital,
department, ward, bed, staff, relatives, age, sex, rare context) plus a
Layer 4 document-level medical-content classifier. Detectors produce facts
only; policy decides the verdict.
"""

from .base import Detector, RegexDetector
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
    "AgeDetector",
    "SexDetector",
    "HospitalNameDetector",
    "DepartmentDetector",
    "WardDetector",
    "BedNumberDetector",
    "DoctorNameDetector",
    "NurseNameDetector",
    "RelativeNameDetector",
    "SpecimenIdDetector",
    "AccessionNumberDetector",
    "LandlineDetector",
    "PostalCodeDetector",
    "SocialMediaIdDetector",
    "RareContextDetector",
    "DEFAULT_DETECTORS",
    "detect_all",
]
