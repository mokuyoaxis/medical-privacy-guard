"""DICOM de-identification: write a new file with identifying metadata removed.

The companion scanner (:mod:`medical_privacy_guard.formats.dicom_inspect`)
only reads. This module is the different tool its docstring pointed at: it
produces a new DICOM file whose metadata has been rewritten under an
explicit disposition table modelled on the DICOM PS3.15 Annex E Basic
Application Confidentiality Profile, plus this project's own text
detectors for free-text descriptors.

Design decisions (see ``.internal/design-0.7-dicom-deidentify.md``,
approved 2026-11-21):

- dates are emptied by default; a consistent day shift is an explicit
  option (``date_shift_days``), never a silent default;
- a file whose pixels carry burned-in annotation (``BurnedInAnnotation``
  = YES) is refused by default: the pixels are not touched, so exporting
  would ship the very identifiers the metadata pass removed;
- private tags are removed by default: their meaning is unknowable, the
  same stance the scanner takes when it marks them HIGH;
- patient characteristics and device identity are removed by default and
  kept only on explicit request;
- names are emptied, never replaced with a dummy that downstream systems
  would index as a real name;
- pixel risk stays UNKNOWN in the report. Metadata de-identification is
  not a release clearance, and this module never claims one.

Raw values never enter the report or the audit event: counts and
categories only, the same red line as the scanner.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from medical_privacy_guard.core.errors import ParserError

__all__ = [
    "DicomDeidReport",
    "DicomTreeReport",
    "deidentify_dicom_file",
    "deidentify_dicom_tree",
    "report_to_json",
    "TABLE_VERSION",
]

#: Version of the disposition table below. Written into
#: DeidentificationMethod so a produced file names the rules it was
#: produced under. v2: row-by-row audit against PS3.15 Table E.1-1
#: (2026-11-21) — see .internal/design-0.7-dicom-deidentify.md.
TABLE_VERSION = "ps315-basic-v2"

# Disposition actions, PS3.15 notation plus two internal ones.
_X = "X"      # remove the element
_Z = "Z"      # replace with a zero-length value
_U = "U"      # replace a UID by its remapped value
_C = "C"      # clean free text through the guard's pipeline
_K = "K"      # keep unchanged
_DATE = "DATE"  # empty, or shift by a fixed number of days when asked
_CH = "CH"    # patient characteristic: remove unless explicitly retained
_DV = "DV"    # device identity: remove unless explicitly retained

#: Explicit dispositions by tag. Everything not listed falls to the
#: generic rules in :func:`_process_dataset`: private tags are removed,
#: overlay/curve groups are removed, UI values are remapped (except
#: DICOM-standard UIDs), DA/DT values follow the date action, PN values
#: are removed, and long-text elements whose keyword marks them as a
#: description or comment are cleaned.
_TABLE: dict[int, str] = {
    # -- patient ------------------------------------------------------
    0x00100010: _Z,      # PatientName (emptied, never a dummy name)
    0x00100020: _Z,      # PatientID
    0x00100030: _DATE,   # PatientBirthDate
    0x00100032: _X,      # PatientBirthTime
    0x00100040: _CH,     # PatientSex
    0x00101000: _X,      # OtherPatientIDs
    0x00101002: _X,      # OtherPatientIDsSequence
    0x00101010: _CH,     # PatientAge
    0x00101020: _CH,     # PatientSize
    0x00101030: _CH,     # PatientWeight
    0x00101040: _X,      # PatientAddress
    0x00101080: _X,      # MilitaryRank
    0x00102150: _X,      # CountryOfResidence
    0x00102152: _X,      # RegionOfResidence
    0x00102154: _X,      # PatientTelephoneNumbers
    0x00102180: _X,      # Occupation
    0x00104000: _C,      # PatientComments
    0x001021B0: _C,      # AdditionalPatientHistory
    # -- audit additions (Table E.1-1 cross-check, 2026-11-21) ---------
    0x00100021: _X,      # IssuerOfPatientID
    0x00100050: _X,      # PatientInsurancePlanCodeSequence
    0x00100101: _X,      # PatientPrimaryLanguageCodeSequence
    0x00100102: _X,      # PatientPrimaryLanguageModifierCodeSequence
    0x00101100: _X,      # ReferencedPatientPhotoSequence (holds photos)
    0x00102155: _X,      # PatientTelecomInformation
    0x001021F0: _X,      # PatientReligiousPreference
    0x00100041: _X,      # GenderIdentitySequence
    0x00100044: _X,      # GenderIdentityCodeSequence
    0x00100011: _X,      # PersonNamesToUseSequence
    0x00100015: _X,      # PronounCodeSequence
    0x00102000: _C,      # MedicalAlerts
    0x00102110: _C,      # Allergies
    0x00100045: _C,      # GenderIdentityComment
    0x00100016: _C,      # PronounComment
    0x001021C0: _CH,     # PregnancyStatus
    0x001021A0: _CH,     # SmokingStatus
    # -- institution and staff ----------------------------------------
    0x00080080: _X,      # InstitutionName
    0x00080081: _X,      # InstitutionAddress
    0x00081040: _X,      # InstitutionalDepartmentName
    0x00080090: _X,      # ReferringPhysicianName
    0x00080092: _X,      # ReferringPhysicianAddress
    0x00080094: _X,      # ReferringPhysicianTelephoneNumbers
    0x00081048: _X,      # PhysiciansOfRecord
    0x00081050: _X,      # PerformingPhysicianName
    0x00081060: _X,      # NameOfPhysiciansReadingStudy
    0x00081070: _X,      # OperatorsName
    0x00321032: _X,      # RequestingPhysician
    0x00321033: _X,      # RequestingService
    0x00080082: _X,      # InstitutionCodeSequence
    0x00080201: _X,      # TimezoneOffsetFromUTC
    0x00401102: _X,      # PersonAddress
    0x00401103: _X,      # PersonTelephoneNumbers
    0x00401104: _X,      # PersonTelecomInformation
    0x00402009: _X,      # OrderEntererLocation
    0x00402010: _X,      # OrderCallbackPhoneNumber
    0x00402011: _X,      # OrderCallbackTelecomInformation
    0x0040A07A: _X,      # ParticipantSequence
    0x00401011: _X,      # IntendedRecipientsOfResultsIdentificationSequence
    # -- encounter -----------------------------------------------------
    0x00080050: _Z,      # AccessionNumber
    0x00200010: _Z,      # StudyID
    0x00380010: _X,      # AdmissionID
    0x00380011: _X,      # IssuerOfAdmissionID
    0x00380060: _X,      # ServiceEpisodeID
    0x00380061: _X,      # IssuerOfServiceEpisodeID
    0x00380300: _X,      # CurrentPatientLocation
    0x00380400: _X,      # PatientInstitutionResidence
    0x00380004: _X,      # ReferencedPatientAliasSequence
    0x00320012: _X,      # StudyIDIssuer
    0x00401001: _X,      # RequestedProcedureID
    0x00401005: _X,      # RequestedProcedureLocation
    0x00402016: _Z,      # PlacerOrderNumberImagingServiceRequest
    0x00402017: _Z,      # FillerOrderNumberImagingServiceRequest
    0x00380500: _C,      # PatientState
    0x00321030: _C,      # ReasonForStudy
    0x00321066: _C,      # ReasonForVisit
    0x00401002: _C,      # ReasonForTheRequestedProcedure
    # -- free-text descriptors -----------------------------------------
    0x00081030: _C,      # StudyDescription
    0x0008103E: _C,      # SeriesDescription
    0x00081080: _C,      # AdmittingDiagnosesDescription
    0x00204000: _C,      # ImageComments
    0x0040A160: _C,      # TextValue (structured report content)
    0x00700006: _C,      # UnformattedTextValue (graphic annotation text)
    # -- structures that must not survive at all ------------------------
    0x00081120: _X,      # ReferencedPatientSequence
    0x00880200: _X,      # IconImageSequence (nested pixel data)
    0x04000500: _X,      # EncryptedAttributesSequence
    0x04000550: _X,      # ModifiedAttributesSequence
    0x04000551: _X,      # NonconformingModifiedAttributesSequence
    0x04000552: _X,      # NonconformingDataElementValue
    0x04000561: _X,      # OriginalAttributesSequence
    0x04000402: _X,      # ReferencedDigitalSignatureSequence
    0x04000403: _X,      # ReferencedSOPInstanceMACSequence
    0x04000404: _X,      # MAC
    0xFFFAFFFA: _X,      # DigitalSignaturesSequence
    0x00880130: _Z,      # StorageMediaFileSetID
    # -- device identity ------------------------------------------------
    0x00080070: _DV,     # Manufacturer
    0x00081090: _DV,     # ManufacturerModelName
    0x00181000: _DV,     # DeviceSerialNumber
    0x00081010: _DV,     # StationName
    0x00080054: _DV,     # RetrieveAETitle
    0x00400241: _DV,     # PerformedStationAETitle
    0x00400001: _DV,     # ScheduledStationAETitle
    0x00321021: _DV,     # ScheduledStudyLocationAETitle
    0x00741234: _DV,     # ReceivingAE
    0x00741236: _DV,     # RequestingAE
    0x21000140: _DV,     # DestinationAE
    0x00400010: _DV,     # ScheduledStationName
    0x00400242: _DV,     # PerformedStationName
    0x00181004: _DV,     # PlateID
    0x00181005: _DV,     # GeneratorID
    0x00181007: _DV,     # CassetteID
    0x00181008: _DV,     # GantryID
    0x00181010: _DV,     # SecondaryCaptureDeviceID
    0x0018700A: _DV,     # DetectorID
    0x00181002: _U,      # DeviceUID (remapped, not removed)
    0x0018100B: _K,      # ManufacturerDeviceClassUID (registered vocabulary)
    # -- file meta -------------------------------------------------------
    0x00020012: _K,      # ImplementationClassUID (names the software)
    # -- clinical trial --------------------------------------------------
    0x00120010: _X, 0x00120020: _X, 0x00120021: _X, 0x00120030: _X,
    0x00120031: _X, 0x00120040: _X, 0x00120042: _X, 0x00120050: _X,
    0x00120051: _X, 0x00120060: _X, 0x00120071: _X, 0x00120072: _X,
    0x00120081: _X, 0x00120082: _X,
    0x00120022: _X, 0x00120032: _X, 0x00120041: _X, 0x00120043: _X,
    0x00120055: _X, 0x00120073: _X,  # trial ID issuers
}

#: DICOM-standard UIDs (SOP classes, transfer syntaxes, coding schemes)
#: live under this root and are vocabulary, not identifiers: never remap.
_STANDARD_UID_PREFIX = "1.2.840.10008"

#: Encapsulated PDF Storage: its payload is a document, and no metadata
#: disposition covers a document's content.
_ENCAPSULATED_PDF_SOP_CLASS = "1.2.840.10008.5.1.4.1.1.104.1"

_DEID_METHOD_TEXT = "medical-privacy-guard deidentify, PS3.15 basic profile"


@dataclass(frozen=True)
class DicomDeidReport:
    """What was done to one file. Counts and categories only, no values."""

    source: str
    output: str
    actions: dict[str, int]
    uid_remapped: int
    burned_in_annotation: str  # "YES" | "NO" | "ABSENT"
    private_removed: int
    table_version: str = TABLE_VERSION
    pixel_annotation_risk: str = "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "output": self.output,
            "actions": dict(self.actions),
            "uid_remapped": self.uid_remapped,
            "burned_in_annotation": self.burned_in_annotation,
            "private_removed": self.private_removed,
            "table_version": self.table_version,
            "pixel_annotation_risk": self.pixel_annotation_risk,
        }


@dataclass(frozen=True)
class DicomTreeReport:
    """Aggregate over a directory run. One UID map covers the whole tree."""

    files: tuple[DicomDeidReport, ...]
    skipped: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        totals: dict[str, int] = {}
        for f in self.files:
            for key, count in f.actions.items():
                totals[key] = totals.get(key, 0) + count
        return {
            "files": [f.to_dict() for f in self.files],
            "skipped": list(self.skipped),
            "totals": totals,
            "uid_remapped": sum(f.uid_remapped for f in self.files),
            "private_removed": sum(f.private_removed for f in self.files),
        }


def report_to_json(report: DicomDeidReport | DicomTreeReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


class _Context:
    """Per-run state: one salt, one UID map, one guard, running counts."""

    def __init__(
        self,
        *,
        profile: str,
        salt: bytes,
        date_shift_days: int | None,
        retain_private: bool,
        retain_characteristics: bool,
        retain_device: bool,
    ) -> None:
        from medical_privacy_guard import Guard

        self.guard = Guard(profile=profile)
        self.salt = salt
        self.date_shift_days = date_shift_days
        self.retain_private = retain_private
        self.retain_characteristics = retain_characteristics
        self.retain_device = retain_device
        self.uid_map: dict[str, str] = {}
        self.actions: dict[str, int] = {}
        # (tag, original value) pairs that must not survive, for the
        # post-write self-check. Values live only in memory, never in
        # the report or on disk.
        self.fingerprints: set[tuple[int, str]] = set()

    def count(self, action: str) -> None:
        self.actions[action] = self.actions.get(action, 0) + 1

    def remap_uid(self, uid: str) -> str:
        if uid in self.uid_map:
            return self.uid_map[uid]
        digest = hashlib.sha256(self.salt + b"\x00" + uid.encode("utf-8")).digest()
        number = str(int.from_bytes(digest, "big"))
        remapped = "2.25." + number[:59]  # 5 + 59 = 64 chars, the UID limit
        self.uid_map[uid] = remapped
        return remapped


def _is_overlay_or_curve(group: int) -> bool:
    return 0x5000 <= group <= 0x501E and group % 2 == 0 or \
        0x6000 <= group <= 0x601E and group % 2 == 0


def _shift_date(value: str, days: int) -> str:
    try:
        parsed = datetime.strptime(value, "%Y%m%d")
    except ValueError:
        return ""  # unparseable: empty the field rather than guess
    return (parsed + timedelta(days=days)).strftime("%Y%m%d")


def _apply_date(value: str, ctx: _Context) -> str:
    if ctx.date_shift_days is None:
        return ""
    return _shift_date(value, ctx.date_shift_days)


def _apply_datetime(value: str, ctx: _Context) -> str:
    if ctx.date_shift_days is None:
        return ""
    if len(value) >= 8 and value[:8].isdigit():
        shifted = _shift_date(value[:8], ctx.date_shift_days)
        return shifted + value[8:] if shifted else ""
    return ""


def _clean_text(text: str, ctx: _Context) -> str:
    """Run one descriptor value through the guard's sanitize pipeline.

    The strictest pairing is used on purpose: this is a disclosure-grade
    cleaning, and anything the pipeline will not release in cleaned form
    (BLOCK, or an ASK nobody is present to approve) empties the element
    instead of passing through.

    The cleaned value is then probed again — plainly and behind a name
    label, the scanner's own trick — because a bare name in narrative
    text is a documented detector boundary (no anchor, no detection).
    Any residual detection empties the element: a descriptor is
    expendable, an identifier is not.
    """
    if not text.strip():
        return text
    result = ctx.guard.sanitize(text, "external_unknown", "EXTERNAL_AI_ASSISTANCE")
    if result.sanitized_payload is None:
        return ""
    cleaned = result.text
    if not isinstance(cleaned, str):
        return text
    for probe in (cleaned, "姓名：" + cleaned):
        if ctx.guard.detect(probe):
            return ""
    return cleaned


def _map_values(value: Any, fn) -> Any:
    if isinstance(value, (list, tuple)):
        return [fn(v) for v in value]
    return fn(value)


def _process_dataset(ds: Any, ctx: _Context) -> None:
    """Apply the disposition table to one dataset, recursing into sequences."""
    for element in list(ds):
        tag = element.tag
        tag_int = int(tag)
        vr = element.VR

        if vr == "SQ" and tag_int not in _TABLE:
            for item in element.value or []:
                _process_dataset(item, ctx)
            continue

        action = _TABLE.get(tag_int)
        if action is None:
            if tag.is_private:
                action = _K if ctx.retain_private else "PRIVATE"
            elif tag.group == 0x0016:
                # Photographic/EXIF-style elements: every row for this
                # group in Table E.1-1 is X (GPS, camera owner, lens).
                action = _X
            elif _is_overlay_or_curve(tag.group):
                action = "OVERLAY"
            elif vr == "UI":
                action = _U
            elif vr == "DA":
                action = _DATE
            elif vr == "DT":
                action = "DATETIME"
            elif vr == "TM":
                action = "TIME"
            elif vr == "PN":
                action = _X
            elif vr in ("LO", "LT", "ST", "UT") and (
                element.keyword.endswith("Description")
                or element.keyword.endswith("Comments")
            ):
                action = _C
            elif vr in ("LO", "LT", "ST") and element.keyword.endswith("Name"):
                action = _X
            else:
                action = _K

        if action == _K:
            continue
        if action == _CH and ctx.retain_characteristics:
            continue
        if action == _DV and ctx.retain_device:
            continue

        original = element.value
        if action in (_X, "PRIVATE", "OVERLAY"):
            if isinstance(original, str) and original:
                ctx.fingerprints.add((tag_int, original))
            del ds[tag]
            ctx.count({"PRIVATE": "private_removed", "OVERLAY": "overlay_removed"}.get(action, _X))
            continue
        if action == _Z:
            if isinstance(original, str) and original:
                ctx.fingerprints.add((tag_int, original))
            element.value = ""
            ctx.count(_Z)
            continue
        if action == _CH or action == _DV:
            if isinstance(original, str) and original:
                ctx.fingerprints.add((tag_int, original))
            del ds[tag]
            ctx.count(_X)
            continue
        if action == _U:
            changed = False

            def _remap(v: Any) -> Any:
                nonlocal changed
                if not isinstance(v, str) or not v:
                    return v
                if v.startswith(_STANDARD_UID_PREFIX):
                    return v
                ctx.fingerprints.add((tag_int, v))
                changed = True
                return ctx.remap_uid(v)

            element.value = _map_values(original, _remap)
            if changed:
                ctx.count(_U)
            continue
        if action == "TIME":
            # A time of day is temporal identity once its date is gone;
            # it only stays meaningful when dates are shifted, not emptied.
            if ctx.date_shift_days is None:
                if isinstance(original, str) and original:
                    ctx.fingerprints.add((tag_int, original))
                element.value = _map_values(original, lambda v: "")
                ctx.count(_DATE)
            continue
        if action == _DATE or action == "DATETIME":
            fn = _apply_date if action == _DATE else _apply_datetime
            if isinstance(original, str) and original:
                ctx.fingerprints.add((tag_int, original))
            element.value = _map_values(
                original, lambda v: fn(v, ctx) if isinstance(v, str) else v
            )
            ctx.count(_DATE)
            continue
        if action == _C:
            def _clean(v: Any) -> Any:
                if not isinstance(v, str) or not v:
                    return v
                if ctx.guard.detect(v):
                    ctx.fingerprints.add((tag_int, v))
                return _clean_text(v, ctx)

            element.value = _map_values(original, _clean)
            ctx.count(_C)
            continue


def _collect_values(ds: Any, sink: set[tuple[int, str]]) -> None:
    for element in ds:
        if element.VR == "SQ":
            for item in element.value or []:
                _collect_values(item, sink)
            continue
        value = element.value
        values = value if isinstance(value, (list, tuple)) else [value]
        for v in values:
            if isinstance(v, str) and v:
                sink.add((int(element.tag), v))


def _stamp_markers(ds: Any, ctx: _Context) -> None:
    """Record that de-identification happened, and under which rules."""
    from pydicom.dataset import Dataset

    ds.PatientIdentityRemoved = "YES"
    ds.DeidentificationMethod = _DEID_METHOD_TEXT
    codes = [("113100", "Basic Application Confidentiality Profile"),
             ("113105", "Clean Descriptors Option"),
             ("113104", "Clean Structured Content Option")]
    if ctx.date_shift_days is not None:
        codes.append(("113107", "Retain Longitudinal With Modified Dates Option"))
        ds.LongitudinalTemporalInformationModified = "MODIFIED"
    if ctx.retain_device:
        codes.append(("113109", "Retain Device Identity Option"))
    sequence = []
    for code_value, code_meaning in codes:
        item = Dataset()
        item.CodeValue = code_value
        item.CodingSchemeDesignator = "DCM"
        item.CodeMeaning = code_meaning
        sequence.append(item)
    ds.DeidentificationMethodCodeSequence = sequence


def _load_dataset(path: str):
    try:
        import pydicom
    except ImportError as exc:  # pragma: no cover - exercised via optional extra
        raise ParserError(
            "DICOM de-identification requires the optional pydicom extra: "
            "pip install medical-privacy-guard[dicom]"
        ) from exc
    try:
        return pydicom.dcmread(path, force=False)
    except Exception as exc:
        raise ParserError(f"cannot read DICOM file {path}: {exc}") from exc


def deidentify_dicom_file(
    path: str,
    out_path: str,
    *,
    profile: str = "external-ai-strict",
    salt: str | None = None,
    date_shift_days: int | None = None,
    allow_burned_in: bool = False,
    retain_private: bool = False,
    retain_characteristics: bool = False,
    retain_device: bool = False,
    _ctx: _Context | None = None,
) -> DicomDeidReport:
    """De-identify one DICOM file into *out_path*. The input is never modified.

    Raises :class:`ParserError` — and writes nothing — when the file
    cannot be read, carries burned-in annotation without
    *allow_burned_in*, encapsulates a document, or fails the post-write
    self-check.
    """
    import pydicom

    source = Path(path)
    target = Path(out_path)
    if source.resolve() == target.resolve():
        raise ParserError("output path must differ from the input file")

    ctx = _ctx or _Context(
        profile=profile,
        salt=(salt.encode("utf-8") if salt is not None else os.urandom(16)),
        date_shift_days=date_shift_days,
        retain_private=retain_private,
        retain_characteristics=retain_characteristics,
        retain_device=retain_device,
    )
    actions_before = dict(ctx.actions)
    uids_before = len(ctx.uid_map)
    fingerprints_before = set(ctx.fingerprints)

    dataset = _load_dataset(path)

    sop_class = str(getattr(dataset, "SOPClassUID", "") or "")
    if sop_class == _ENCAPSULATED_PDF_SOP_CLASS or "EncapsulatedDocument" in dataset:
        raise ParserError(
            "refusing to de-identify: the file encapsulates a document, "
            "whose content no metadata disposition can cover"
        )
    burned_in = str(getattr(dataset, "BurnedInAnnotation", "") or "").strip().upper()
    burned_in_state = burned_in if burned_in in ("YES", "NO") else "ABSENT"
    if burned_in == "YES" and not allow_burned_in:
        raise ParserError(
            "refusing to de-identify: BurnedInAnnotation is YES and pixel "
            "data is not processed; pass allow_burned_in to export anyway "
            "(the report will keep the pixel risk UNKNOWN)"
        )

    if dataset.file_meta:
        _process_dataset(dataset.file_meta, ctx)
    _process_dataset(dataset, ctx)
    _stamp_markers(dataset, ctx)

    # Self-check on the in-memory result: no fingerprinted original value
    # may survive under its tag.
    survivors: set[tuple[int, str]] = set()
    if dataset.file_meta:
        _collect_values(dataset.file_meta, survivors)
    _collect_values(dataset, survivors)
    leaked = {
        (tag, value)
        for tag, value in ctx.fingerprints - fingerprints_before
        if (tag, value) in survivors
    }
    if leaked:
        tags = ", ".join(f"{tag >> 16:04X},{tag & 0xFFFF:04X}" for tag, _ in sorted(leaked))
        raise ParserError(f"de-identification self-check failed; residual values at: {tags}")

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    os.close(fd)
    try:
        pydicom.dcmwrite(tmp_name, dataset, enforce_file_format=True)
        # Second self-check on what actually landed on disk: re-inspect
        # and require the private-tag count the options promise.
        from medical_privacy_guard.formats.dicom_inspect import inspect_dicom_file

        check = inspect_dicom_file(tmp_name)
        if not retain_private and check.private_tag_count:
            raise ParserError(
                "de-identification self-check failed; private tags remain in the output"
            )
        os.replace(tmp_name, target)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise

    run_actions = {
        key: count - actions_before.get(key, 0)
        for key, count in ctx.actions.items()
        if count - actions_before.get(key, 0)
    }
    return DicomDeidReport(
        source=str(source),
        output=str(target),
        actions=run_actions,
        uid_remapped=len(ctx.uid_map) - uids_before,
        burned_in_annotation=burned_in_state,
        private_removed=run_actions.get("private_removed", 0),
    )


def deidentify_dicom_tree(
    root: str,
    out_root: str,
    **options: Any,
) -> DicomTreeReport:
    """De-identify every readable DICOM file under *root* into *out_root*.

    The relative layout is preserved and one UID map covers the tree, so
    references between files stay consistent. Files that do not parse as
    DICOM are listed in ``skipped`` rather than silently passed over.
    Refusals (burned-in annotation, encapsulated documents) abort the
    run: a partial tree that looks complete is worse than no tree.
    """
    source_root = Path(root)
    target_root = Path(out_root)
    if source_root.resolve() == target_root.resolve():
        raise ParserError("output directory must differ from the input directory")
    ctx = _Context(
        profile=options.get("profile", "external-ai-strict"),
        salt=(options["salt"].encode("utf-8") if options.get("salt") is not None else os.urandom(16)),
        date_shift_days=options.get("date_shift_days"),
        retain_private=options.get("retain_private", False),
        retain_characteristics=options.get("retain_characteristics", False),
        retain_device=options.get("retain_device", False),
    )
    reports: list[DicomDeidReport] = []
    skipped: list[str] = []
    for candidate in sorted(source_root.rglob("*")):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(source_root)
        try:
            reports.append(
                deidentify_dicom_file(
                    str(candidate),
                    str(target_root / relative),
                    allow_burned_in=options.get("allow_burned_in", False),
                    _ctx=ctx,
                )
            )
        except ParserError as exc:
            if str(exc).startswith("cannot read DICOM file"):
                skipped.append(str(relative))
                continue
            raise
    return DicomTreeReport(files=tuple(reports), skipped=tuple(skipped))


def write_audit_event(report: DicomDeidReport | DicomTreeReport, audit_dir: str) -> str:
    """Append one hash-chained audit event for a de-identification run.

    Counts only: file counts, action distribution, UID remap count. No
    file values, no salt, no paths beyond what the caller chose to log.
    """
    from medical_privacy_guard.core.audit import AuditEvent, AuditWriter

    data = report.to_dict()
    if isinstance(report, DicomTreeReport):
        counts = dict(data["totals"])
        counts["files"] = len(data["files"])
        counts["uid_remapped"] = data["uid_remapped"]
    else:
        counts = dict(data["actions"])
        counts["files"] = 1
        counts["uid_remapped"] = data["uid_remapped"]
    event = AuditEvent(
        event_id=uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        decision="SANITIZE",
        reason_codes=("DICOM_DEIDENTIFY",),
        entity_counts=counts,
        risk_level="LOW",
        risk_score=0,
        recipient_class="LOCAL",
        purpose="DEIDENTIFICATION",
        policy_profile="dicom-deidentify",
        policy_version=TABLE_VERSION,
        transformations=tuple(sorted(data.get("totals", data.get("actions", {})).keys())),
        verification="passed",
    )
    return AuditWriter(audit_dir).record(event)
