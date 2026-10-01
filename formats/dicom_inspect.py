"""Read-only DICOM metadata inspection.

The scanner answers one question: *what identifying metadata does this file
carry, and can it be released?* It reads; it never writes. De-identification
means producing a new valid DICOM file — rewritten group lengths, new SOP
Instance UIDs, re-encoded sequences — and that is a different tool with a
different failure surface, deliberately out of scope here.

The report separates three things that are easy to blur:

- **metadata findings** — elements whose value carries an identifier, either
  because the tag is on a known-PHI list (``PatientName``, ``PatientID``...)
  or because the value trips the guard's own detectors over free text;
- **private tags** — vendor-written elements in odd groups. Their meaning is
  unknowable by construction, so the report counts them and marks the risk
  HIGH without claiming to know what they hold;
- **pixel risk** — burned-in annotations and recognizable surface features.
  No check is implemented, so both stay UNKNOWN and ``safe_to_release`` stays
  false. A pixel-perfect scan that does not exist must not be claimed
  (``docs/scope.md``, prohibited claims).

pydicom is an optional extra. The import failure is reported as an
:class:`~core.errors.ParserError` — fail closed, the same as every other
format this library cannot read — rather than guessed at byte by byte.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from core.errors import ParserError

__all__ = ["DicomFinding", "DicomReport", "inspect_dicom_file", "report_to_json"]

#: Known-PHI metadata tags. The value is the report category; every one of
#: these identifies the patient, a person, an institution or an encounter.
#:
#: The category is the snake_case of the element's DICOM keyword, and
#: ``tests/test_dicom_inspect.py`` asserts that against pydicom's own
#: dictionary. It has to be pinned: this list was written by hand and fifteen
#: of its entries named the wrong element, including PatientAge filed as
#: "patient_occupation", MilitaryRank as "patient_address",
#: CountryOfResidence as "phone_number_home" and PerformingPhysicianName as
#: "referring_physician_name". An operator reading that report would have
#: looked for a home phone number and found a country.
_PHI_TAGS: dict[int, str] = {
    # -- patient demographics -------------------------------------------
    0x00100010: "patient_name",
    0x00100020: "patient_id",
    0x00100030: "patient_birth_date",
    0x00100032: "patient_birth_time",
    0x00100040: "patient_sex",
    0x00101000: "other_patient_ids",
    0x00101010: "patient_age",
    0x00101040: "patient_address",
    0x00101080: "military_rank",
    0x00102150: "country_of_residence",
    0x00102152: "region_of_residence",
    0x00102154: "patient_telephone_numbers",
    0x00102180: "occupation",
    0x00104000: "patient_comments",
    # -- institution and staff -------------------------------------------
    0x00080080: "institution_name",
    0x00080081: "institution_address",
    0x00081040: "institutional_department_name",
    0x00081048: "physicians_of_record",
    0x00081050: "performing_physician_name",
    0x00081060: "name_of_physicians_reading_study",
    0x00081070: "operators_name",
    0x00081090: "manufacturer_model_name",  # device, not PHI, but identifying
    0x00080090: "referring_physician_name",
    0x00080092: "referring_physician_address",
    0x00080094: "referring_physician_telephone_numbers",
    # -- de-identification markers ---------------------------------------
    0x00120062: "patient_identity_removed",
    0x00120063: "deidentification_method",
    # -- dates and times -------------------------------------------------
    0x00080012: "instance_creation_date",
    0x00080013: "instance_creation_time",
    0x00080020: "study_date",
    0x00080021: "series_date",
    0x00080022: "acquisition_date",
    0x00080023: "content_date",
    0x0008002A: "acquisition_datetime",
    0x00080030: "study_time",
    0x00080031: "series_time",
    0x00080032: "acquisition_time",
    0x00080033: "content_time",
    # -- encounter identifiers -------------------------------------------
    0x00080050: "accession_number",
    0x00200010: "study_id",
    0x0008103E: "series_description",
}

#: Categories whose detection reuses the guard's text detectors over the
#: decoded value, because the value is free text rather than a coded field.
_FREE_TEXT_CATEGORIES = frozenset(
    {"patient_name", "patient_comments", "institution_name",
     "institutional_department_name", "physician_of_record",
     "referring_physician_name", "name_of_physicians_reading_study",
     "operators_name", "series_description", "study_description"}
)


@dataclass(frozen=True)
class DicomFinding:
    """One metadata element carrying an identifier."""

    tag: str          # "0010,0010"
    name: str         # element keyword or the report category
    category: str     # report category
    value_kind: str   # "known_phi_tag" | "detector_match" | "private"
    risk: str         # "HIGH" | "MEDIUM"
    detail: str = ""  # no raw value: category and tag only


@dataclass(frozen=True)
class DicomReport:
    """The inspection result. Raw values never enter the report."""

    file: str
    transfer_syntax: str
    specific_character_set: str
    sop_class: str
    findings: tuple[DicomFinding, ...]
    private_tag_count: int
    pixel_annotation_risk: str = "UNKNOWN"
    recognizable_visual_features_risk: str = "UNKNOWN"

    @property
    def metadata_risk(self) -> str:
        return "HIGH" if self.findings or self.private_tag_count else "LOW"

    @property
    def safe_to_release(self) -> bool:
        """False while any pixel check is UNKNOWN. Metadata alone cannot clear it."""
        return (
            self.pixel_annotation_risk == "NONE"
            and self.recognizable_visual_features_risk == "NONE"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "transfer_syntax": self.transfer_syntax,
            "specific_character_set": self.specific_character_set,
            "sop_class": self.sop_class,
            "metadata_risk": self.metadata_risk,
            "findings": [
                {"tag": f.tag, "name": f.name, "category": f.category,
                 "kind": f.value_kind, "risk": f.risk, "detail": f.detail}
                for f in self.findings
            ],
            "private_tag_count": self.private_tag_count,
            "private_tags_risk": "HIGH" if self.private_tag_count else "LOW",
            "pixel_annotation_risk": self.pixel_annotation_risk,
            "recognizable_visual_features_risk": self.recognizable_visual_features_risk,
            "safe_to_release": self.safe_to_release,
        }


def report_to_json(report: DicomReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def _detector_guard():
    """Build the text guard once; detectors run over free-text values."""
    from medical_privacy_guard import Guard

    return Guard(profile="external-ai-strict")


def inspect_dicom_file(path: str) -> DicomReport:
    """Read *path* and report its identifying metadata. Never writes."""
    try:
        import pydicom
    except ImportError as exc:  # pragma: no cover - exercised via optional extra
        raise ParserError(
            "DICOM inspection requires the optional pydicom extra: "
            "pip install medical-privacy-guard[dicom]"
        ) from exc

    try:
        dataset = pydicom.dcmread(path, force=False)
    except Exception as exc:
        raise ParserError(f"cannot read DICOM file {path}: {exc}") from exc

    guard = _detector_guard()
    findings: list[DicomFinding] = []
    private_count = 0

    for element in dataset:
        tag = element.tag
        if tag.is_private:
            private_count += 1
            continue
        category = _PHI_TAGS.get(int(tag))
        if category is None:
            continue
        value = element.value
        text = value if isinstance(value, str) else str(value or "")
        kind = "known_phi_tag"
        detail = ""
        if category in _FREE_TEXT_CATEGORIES and text:
            probes = [text]
            if element.VR == "PN":
                # A PN value is a personal name by construction -- the tag is
                # the label, so no heuristic is needed. The ``^`` separates the
                # name components (family^given^middle); a comma is what the
                # detectors' punctuation boundaries already understand, and
                # joining the components without it lets the adjacent-name
                # rules see the whole name.
                component_join = "，"
                probes.append("姓名：" + text.replace("^", component_join))
                probes.append("姓名：" + text.replace("^", ""))
            types: set[str] = set()
            for probe in probes:
                types |= {f.type for f in guard.detect(probe)}
            if types:
                detail = "detectors: " + ", ".join(sorted(types))
        findings.append(DicomFinding(
            tag=f"{tag.group:04X},{tag.element:04X}",
            name=element.keyword or category,
            category=category,
            value_kind=kind,
            risk="HIGH",
            detail=detail,
        ))

    ts = str(dataset.file_meta.TransferSyntaxUID) if "TransferSyntaxUID" in dataset.file_meta else "unknown"
    sop = str(dataset.file_meta.MediaStorageSOPClassUID) if "MediaStorageSOPClassUID" in dataset.file_meta else "unknown"
    charset = str(dataset.get("SpecificCharacterSet", "")) or "default"
    return DicomReport(
        file=str(path),
        transfer_syntax=ts,
        specific_character_set=charset,
        sop_class=sop,
        findings=tuple(findings),
        private_tag_count=private_count,
    )
