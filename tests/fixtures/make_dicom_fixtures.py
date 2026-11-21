"""Generate the DICOM fixtures used by the scanner tests.

Run once with the ``dicom`` extra installed; the generated ``.dcm`` files are
committed so the test suite itself needs no pydicom and no network:

    python tests/fixtures/make_dicom_fixtures.py [--out DIR] [--pydicom-path P]

Every identifier in the fixtures is synthetic.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build(pydicom_path: str | None) -> "Dataset":  # noqa: F821
    if pydicom_path:
        sys.path.insert(0, pydicom_path)
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    meta.MediaStorageSOPInstanceUID = generate_uid(entropy_srcs=["fixture"])
    meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = Dataset()
    ds.file_meta = meta
    ds.SpecificCharacterSet = "ISO_IR 192"
    ds.PatientName = "张三"
    ds.PatientID = "MRN-888"
    ds.PatientBirthDate = "19900307"
    ds.PatientSex = "M"
    ds.InstitutionName = "协和新医院"
    ds.ReferringPhysicianName = "王^建国"
    ds.PerformingPhysicianName = "李^娜"
    ds.StudyDate = "20260312"
    ds.SeriesDate = "20260312"
    ds.AccessionNumber = "ACC-2026-001"
    ds.StudyID = "ST-1"
    ds.Modality = "OT"
    # One private tag block, as a real-world file would carry.
    ds.add_new(0x00090001, "LO", "vendor note")
    ds.add_new(0x00090002, "LO", "inner-dept 扩展")
    return ds


def build_rich(pydicom_path: str | None) -> "Dataset":  # noqa: F821
    """A study-shaped file: UIDs, descriptors with identifiers, device data,
    a request-attributes sequence and an overlay group."""
    if pydicom_path:
        sys.path.insert(0, pydicom_path)
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    meta.MediaStorageSOPInstanceUID = generate_uid(entropy_srcs=["rich-sop"])
    meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = Dataset()
    ds.file_meta = meta
    ds.SpecificCharacterSet = "ISO_IR 192"
    ds.PatientName = "张三"
    ds.PatientID = "MRN-888"
    ds.PatientBirthDate = "19900307"
    ds.PatientSex = "M"
    ds.PatientAge = "036Y"
    ds.InstitutionName = "协和新医院"
    ds.ReferringPhysicianName = "王^建国"
    ds.Manufacturer = "SyntheticMed"
    ds.ManufacturerModelName = "ScannerOne"
    ds.DeviceSerialNumber = "SN-12345"
    ds.StationName = "CT-ROOM-1"
    ds.StudyInstanceUID = generate_uid(entropy_srcs=["rich-study"])
    ds.SeriesInstanceUID = generate_uid(entropy_srcs=["rich-series"])
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.StudyDate = "20260312"
    ds.StudyTime = "101500"
    ds.SeriesDate = "20260312"
    ds.AccessionNumber = "ACC-2026-001"
    ds.StudyID = "ST-1"
    ds.Modality = "CT"
    ds.StudyDescription = "张三术后复查 电话13800001234"
    ds.SeriesDescription = "HEAD ROUTINE 5MM"
    ds.BurnedInAnnotation = "NO"
    # A sequence whose items carry their own identifiers.
    item = Dataset()
    item.ScheduledProcedureStepID = "SPS-1"
    item.ScheduledPerformingPhysicianName = "李^娜"
    item.RequestedProcedureID = "RP-1"
    ds.RequestAttributesSequence = [item]
    # An overlay group element: a classic hiding place for annotations.
    ds.add_new(0x60000010, "US", 512)
    # One private tag block.
    ds.add_new(0x00090001, "LO", "vendor note")
    return ds


def build_burned_in(pydicom_path: str | None) -> "Dataset":  # noqa: F821
    """Same shape as the base fixture, but the pixels carry burned-in text."""
    ds = build(pydicom_path)
    ds.BurnedInAnnotation = "YES"
    return ds


def build_jpeg2000(pydicom_path: str | None) -> "Dataset":  # noqa: F821
    """A compressed-transfer-syntax file (JPEG 2000 lossless) with a tiny
    encapsulated pixel frame: the de-identifier must pass the pixels
    through byte-for-byte and still rewrite the metadata."""
    if pydicom_path:
        sys.path.insert(0, pydicom_path)
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.encaps import encapsulate
    from pydicom.uid import JPEG2000Lossless, generate_uid

    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    meta.MediaStorageSOPInstanceUID = generate_uid(entropy_srcs=["j2k-sop"])
    meta.TransferSyntaxUID = JPEG2000Lossless

    ds = Dataset()
    ds.file_meta = meta
    ds.SpecificCharacterSet = "ISO_IR 192"
    ds.PatientName = "张三"
    ds.PatientID = "MRN-888"
    ds.StudyInstanceUID = generate_uid(entropy_srcs=["j2k-study"])
    ds.SeriesInstanceUID = generate_uid(entropy_srcs=["j2k-series"])
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.Rows = 2
    ds.Columns = 2
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = encapsulate([b"\xff\x4f\xff\x51synthetic-j2k-frame"])
    return ds


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "dicom"))
    ap.add_argument("--pydicom-path", default=None)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for builder, name in (
        (build, "ct_head_synthetic.dcm"),
        (build_rich, "ct_study_rich.dcm"),
        (build_burned_in, "ct_burned_in.dcm"),
        (build_jpeg2000, "ct_jpeg2000.dcm"),
    ):
        ds = builder(args.pydicom_path)
        target = out / name
        ds.save_as(target, enforce_file_format=True)
        print(f"written {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
