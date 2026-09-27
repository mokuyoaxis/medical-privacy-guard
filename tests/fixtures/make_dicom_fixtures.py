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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "dicom"))
    ap.add_argument("--pydicom-path", default=None)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ds = build(args.pydicom_path)
    target = out / "ct_head_synthetic.dcm"
    ds.save_as(target, enforce_file_format=True)
    print(f"written {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
