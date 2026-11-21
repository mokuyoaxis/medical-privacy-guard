"""The DICOM de-identifier: produce a new file with identifiers rewritten.

Fixtures are committed binary files (see ``make_dicom_fixtures.py``).
Tests skip when the optional pydicom extra is absent, like the scanner's.
Every identifier in the fixtures is synthetic.
"""

from __future__ import annotations

import pytest

from medical_privacy_guard.core.errors import ParserError

pytest.importorskip("pydicom")

import pydicom  # noqa: E402

from medical_privacy_guard.formats.dicom_deidentify import (  # noqa: E402
    deidentify_dicom_file,
    deidentify_dicom_tree,
)
from medical_privacy_guard.formats.dicom_inspect import inspect_dicom_file  # noqa: E402

BASE = "tests/fixtures/dicom/ct_head_synthetic.dcm"
RICH = "tests/fixtures/dicom/ct_study_rich.dcm"
BURNED = "tests/fixtures/dicom/ct_burned_in.dcm"


def _read(path):
    return pydicom.dcmread(str(path))


class TestDispositions:
    def test_direct_identifiers_are_emptied_or_removed(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert ds.PatientName == ""
        assert ds.PatientID == ""
        assert ds.PatientBirthDate == ""
        assert ds.AccessionNumber == ""
        assert ds.StudyID == ""
        assert "InstitutionName" not in ds
        assert "ReferringPhysicianName" not in ds

    def test_characteristics_and_device_removed_by_default(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert "PatientSex" not in ds and "PatientAge" not in ds
        assert "Manufacturer" not in ds and "DeviceSerialNumber" not in ds

    def test_characteristics_and_device_kept_on_request(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(
            RICH, str(out), salt="s1",
            retain_characteristics=True, retain_device=True,
        )
        ds = _read(out)
        assert ds.PatientSex == "M" and ds.PatientAge == "036Y"
        assert ds.Manufacturer == "SyntheticMed"
        codes = [i.CodeValue for i in ds.DeidentificationMethodCodeSequence]
        assert "113109" in codes

    def test_private_tags_and_overlays_removed(self, tmp_path):
        out = tmp_path / "out.dcm"
        report = deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert report.private_removed == 1
        assert report.actions.get("overlay_removed") == 1
        assert inspect_dicom_file(str(out)).private_tag_count == 0
        assert (0x6000, 0x0010) not in ds

    def test_private_tags_kept_on_request(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1", retain_private=True)
        assert inspect_dicom_file(str(out)).private_tag_count == 1

    def test_sequence_items_are_processed_recursively(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        item = _read(out).RequestAttributesSequence[0]
        assert "ScheduledPerformingPhysicianName" not in item
        assert item.ScheduledProcedureStepID == "SPS-1"

    def test_input_file_is_never_modified(self, tmp_path):
        before = open(RICH, "rb").read()
        deidentify_dicom_file(RICH, str(tmp_path / "out.dcm"), salt="s1")
        assert open(RICH, "rb").read() == before


class TestUids:
    def test_uids_remapped_and_references_consistent(self, tmp_path):
        original = _read(RICH)
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert ds.StudyInstanceUID != original.StudyInstanceUID
        assert ds.SeriesInstanceUID != original.SeriesInstanceUID
        assert ds.SOPInstanceUID != original.SOPInstanceUID
        assert ds.file_meta.MediaStorageSOPInstanceUID == ds.SOPInstanceUID
        for uid in (ds.StudyInstanceUID, ds.SeriesInstanceUID, ds.SOPInstanceUID):
            assert uid.startswith("2.25.") and len(uid) <= 64

    def test_standard_uids_are_vocabulary_not_identifiers(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert ds.SOPClassUID == "1.2.840.10008.5.1.4.1.1.2"
        assert str(ds.file_meta.TransferSyntaxUID) == "1.2.840.10008.1.2.1"

    def test_same_salt_reproduces_mapping_other_salt_does_not(self, tmp_path):
        a, b, c = tmp_path / "a.dcm", tmp_path / "b.dcm", tmp_path / "c.dcm"
        deidentify_dicom_file(RICH, str(a), salt="fixed")
        deidentify_dicom_file(RICH, str(b), salt="fixed")
        deidentify_dicom_file(RICH, str(c), salt="other")
        assert _read(a).StudyInstanceUID == _read(b).StudyInstanceUID
        assert _read(a).StudyInstanceUID != _read(c).StudyInstanceUID


class TestDates:
    def test_dates_and_times_emptied_by_default(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert ds.StudyDate == "" and ds.SeriesDate == "" and ds.StudyTime == ""

    def test_date_shift_is_consistent_and_marks_the_file(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1", date_shift_days=-30)
        ds = _read(out)
        assert ds.StudyDate == "20260210"       # 20260312 - 30d
        assert ds.PatientBirthDate == "19900205"  # 19900307 - 30d
        assert ds.StudyTime == "101500"  # time of day survives a day shift
        assert ds.LongitudinalTemporalInformationModified == "MODIFIED"
        codes = [i.CodeValue for i in ds.DeidentificationMethodCodeSequence]
        assert "113107" in codes


class TestFreeText:
    def test_descriptor_with_identifiers_is_emptied(self, tmp_path):
        """The fixture's StudyDescription carries a name and a phone number.

        The phone is transformable; the bare name is a documented detector
        boundary, so the residual probe empties the whole descriptor.
        """
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert ds.StudyDescription == ""
        assert "13800001234" not in str(ds.StudyDescription)

    def test_clean_descriptor_survives(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        assert _read(out).SeriesDescription == "HEAD ROUTINE 5MM"


class TestMarkers:
    def test_deidentification_markers_are_stamped(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(RICH, str(out), salt="s1")
        ds = _read(out)
        assert ds.PatientIdentityRemoved == "YES"
        assert "PS3.15" in ds.DeidentificationMethod
        codes = [i.CodeValue for i in ds.DeidentificationMethodCodeSequence]
        assert codes[0] == "113100" and "113105" in codes

    def test_report_carries_no_values_and_keeps_pixel_risk_unknown(self, tmp_path):
        report = deidentify_dicom_file(RICH, str(tmp_path / "out.dcm"), salt="s1")
        d = report.to_dict()
        assert d["pixel_annotation_risk"] == "UNKNOWN"
        assert d["burned_in_annotation"] == "NO"
        blob = str(d)
        assert "张三" not in blob and "MRN-888" not in blob


class TestRefusals:
    def test_burned_in_annotation_refused_by_default(self, tmp_path):
        out = tmp_path / "out.dcm"
        with pytest.raises(ParserError, match="BurnedInAnnotation"):
            deidentify_dicom_file(BURNED, str(out))
        assert not out.exists()

    def test_burned_in_annotation_exportable_with_explicit_override(self, tmp_path):
        out = tmp_path / "out.dcm"
        report = deidentify_dicom_file(BURNED, str(out), allow_burned_in=True)
        assert report.burned_in_annotation == "YES"
        assert report.pixel_annotation_risk == "UNKNOWN"

    def test_output_must_differ_from_input(self, tmp_path):
        with pytest.raises(ParserError, match="must differ"):
            deidentify_dicom_file(RICH, RICH)

    def test_encapsulated_document_refused(self, tmp_path):
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, generate_uid

        meta = FileMetaDataset()
        meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.104.1"
        meta.MediaStorageSOPInstanceUID = generate_uid()
        meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds = Dataset()
        ds.file_meta = meta
        ds.SOPClassUID = meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
        ds.EncapsulatedDocument = b"%PDF-synthetic"
        src = tmp_path / "encap.dcm"
        ds.save_as(src, enforce_file_format=True)
        with pytest.raises(ParserError, match="encapsulates a document"):
            deidentify_dicom_file(str(src), str(tmp_path / "out.dcm"))


class TestTree:
    def test_tree_run_shares_one_uid_map(self, tmp_path):
        src = tmp_path / "in"
        src.mkdir()
        for name in ("a.dcm", "b.dcm"):
            (src / name).write_bytes(open(RICH, "rb").read())
        (src / "notes.txt").write_text("not dicom")
        report = deidentify_dicom_tree(str(src), str(tmp_path / "out"), salt="tree")
        assert len(report.files) == 2
        assert report.skipped == ("notes.txt",)
        a = _read(tmp_path / "out" / "a.dcm")
        b = _read(tmp_path / "out" / "b.dcm")
        # Same study in both files: one shared map keeps references equal.
        assert a.StudyInstanceUID == b.StudyInstanceUID


class TestTableIntegrity:
    def test_table_tags_name_the_elements_they_claim(self):
        """The hand-written table is checked against pydicom's dictionary.

        The scanner's hand-written list once misnamed fifteen elements;
        a disposition table with a wrong tag would remove or keep the
        wrong element, so every entry is pinned to its keyword.
        """
        from pydicom.datadict import keyword_for_tag

        from medical_privacy_guard.formats.dicom_deidentify import _TABLE

        expected = {
            0x00100010: "PatientName", 0x00100020: "PatientID",
            0x00100030: "PatientBirthDate", 0x00080050: "AccessionNumber",
            0x00200010: "StudyID", 0x00081030: "StudyDescription",
            0x0008103E: "SeriesDescription", 0x00181000: "DeviceSerialNumber",
            0x00080070: "Manufacturer", 0x00104000: "PatientComments",
        }
        for tag, keyword in expected.items():
            assert tag in _TABLE
            assert keyword_for_tag(tag) == keyword
