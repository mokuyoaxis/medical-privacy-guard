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
J2K = "tests/fixtures/dicom/ct_jpeg2000.dcm"


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
        # The Basic Profile removes Scheduled Procedure Step ID (X);
        # an earlier version kept it and this test pinned that — the
        # 2026-11-21 mechanical table diff corrected the disposition.
        assert "ScheduledProcedureStepID" not in item

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

    def _mechanical_diff_source(self, tmp_path):
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, generate_uid

        meta = FileMetaDataset()
        meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        meta.MediaStorageSOPInstanceUID = generate_uid()
        meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds = Dataset()
        ds.file_meta = meta
        ds.SOPClassUID = meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
        ds.PatientName = "张三"
        ds.EthnicGroup = "合成族群"
        ds.ManufacturerDeviceClassUID = generate_uid()
        ds.RTPlanLabel = "plan-a"
        ds.SelectorLOValue = "selector-x"
        ds.PatientSexNeutered = "N"
        src = tmp_path / "mech.dcm"
        ds.save_as(src, enforce_file_format=True)
        return src, ds.ManufacturerDeviceClassUID

    def test_mechanical_diff_additions(self, tmp_path):
        src, class_uid = self._mechanical_diff_source(tmp_path)
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(str(src), str(out), salt="s1")
        ds = _read(out)
        assert "EthnicGroup" not in ds
        # Basic action is U (remap); a manual pass once misread it as K.
        assert ds.ManufacturerDeviceClassUID != class_uid
        assert str(ds.ManufacturerDeviceClassUID).startswith("2.25.")
        assert ds.RTPlanLabel == ""  # Basic D: emptied, no dummy produced
        assert ds.SelectorLOValue == ""
        assert "PatientSexNeutered" not in ds

    def test_mechanical_diff_characteristic_retained_on_request(self, tmp_path):
        src, _ = self._mechanical_diff_source(tmp_path)
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(
            str(src), str(out), salt="s1", retain_characteristics=True,
        )
        assert _read(out).PatientSexNeutered == "N"


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


class TestAdversarial:
    """Cases nastier than the fixtures, built in memory (from the
    2026-11-21 acceptance probe; both probe 'failures' turned out to be
    probe assertions misreading emptied-but-present tags)."""

    def _build(self, tmp_path):
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, generate_uid

        meta = FileMetaDataset()
        meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        meta.MediaStorageSOPInstanceUID = generate_uid(entropy_srcs=["adv-sop"])
        meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds = Dataset()
        ds.file_meta = meta
        ds.SpecificCharacterSet = "ISO_IR 192"
        ds.PatientName = "李四"
        ds.PatientID = "MRN-999"
        ds.SOPClassUID = meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
        ds.StudyInstanceUID = generate_uid(entropy_srcs=["adv-study"])
        ds.SeriesInstanceUID = generate_uid(entropy_srcs=["adv-series"])
        ds.Modality = "CT"
        ds.StudyDescription = "身份证110101199003077758复查"
        ds.AcquisitionDateTime = "20260312101530.123456+0800"
        inner = Dataset()
        inner.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        inner.ReferencedSOPInstanceUID = generate_uid(entropy_srcs=["adv-ref"])
        inner.add_new(0x00110001, "LO", "nested private value")
        mid = Dataset()
        mid.PatientName = "王五"
        mid.ReferencedImageSequence = [inner]
        ds.CurrentRequestedProcedureEvidenceSequence = [mid]
        ds.add_new(0x60020010, "US", 256)
        src = tmp_path / "adv.dcm"
        ds.save_as(src, enforce_file_format=True)
        return str(src)

    def test_nested_and_block_level_content(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(self._build(tmp_path), str(out), salt="adv")
        ds = _read(out)
        # A government ID in a descriptor is BLOCK-level: the element empties.
        assert ds.StudyDescription == ""
        assert ds.AcquisitionDateTime == ""
        item = ds.CurrentRequestedProcedureEvidenceSequence[0]
        # Two levels down: the PN is emptied (Z), the private tag removed.
        assert item.PatientName == ""
        ref = item.ReferencedImageSequence[0]
        assert str(ref.ReferencedSOPInstanceUID).startswith("2.25.")
        assert str(ref.ReferencedSOPClassUID) == "1.2.840.10008.5.1.4.1.1.2"
        assert (0x0011, 0x1001) not in ref
        assert (0x6002, 0x0010) not in ds
        assert inspect_dicom_file(str(out)).private_tag_count == 0


class TestCompressedSyntax:
    def test_jpeg2000_pixels_pass_through_and_metadata_is_rewritten(self, tmp_path):
        before = _read(J2K)
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(J2K, str(out), salt="j2k")
        ds = _read(out)
        assert str(ds.file_meta.TransferSyntaxUID) == str(
            before.file_meta.TransferSyntaxUID
        )
        assert ds.PixelData == before.PixelData  # bytes untouched
        assert ds.PatientName == ""
        assert str(ds.StudyInstanceUID).startswith("2.25.")


class TestAuditAdditions:
    """Structures the Table E.1-1 cross-check (2026-11-21) caught the
    first disposition table leaving behind."""

    def _build(self, tmp_path):
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, generate_uid

        meta = FileMetaDataset()
        meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        meta.MediaStorageSOPInstanceUID = generate_uid(entropy_srcs=["audit-sop"])
        meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds = Dataset()
        ds.file_meta = meta
        ds.SpecificCharacterSet = "ISO_IR 192"
        ds.PatientName = "张三"
        ds.PatientID = "MRN-888"
        ds.SOPClassUID = meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
        ds.StudyInstanceUID = generate_uid(entropy_srcs=["audit-study"])
        ds.SeriesInstanceUID = generate_uid(entropy_srcs=["audit-series"])
        ds.Modality = "CT"
        ds.IssuerOfPatientID = "协和新医院"
        ds.TimezoneOffsetFromUTC = "+0800"
        ds.MedicalAlerts = "联系电话13800001234"
        ds.GantryID = "GANTRY-7"
        code_item = Dataset()
        code_item.CodeValue = "INST-01"
        code_item.CodingSchemeDesignator = "99LOCAL"
        code_item.CodeMeaning = "协和新医院"
        ds.InstitutionCodeSequence = [code_item]
        icon_item = Dataset()
        icon_item.Rows = 1
        icon_item.Columns = 1
        icon_item.BitsAllocated = 8
        icon_item.PixelData = b"\x00"
        ds.IconImageSequence = [icon_item]
        orig_item = Dataset()
        orig_item.PatientName = "张三"
        ds.OriginalAttributesSequence = [orig_item]
        content_item = Dataset()
        content_item.ValueType = "TEXT"
        content_item.TextValue = "联系电话13800001234"
        ds.ContentSequence = [content_item]
        ds.add_new(0x00160072, "DS", "39.9")  # GPSLatitude: group 0016 is X
        src = tmp_path / "audit.dcm"
        ds.save_as(src, enforce_file_format=True)
        return str(src)

    def test_structures_removed_and_text_cleaned(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(self._build(tmp_path), str(out), salt="audit")
        ds = _read(out)
        assert "IssuerOfPatientID" not in ds
        assert "TimezoneOffsetFromUTC" not in ds
        assert "InstitutionCodeSequence" not in ds
        assert "IconImageSequence" not in ds  # nested pixels cannot be cleaned
        assert "OriginalAttributesSequence" not in ds  # holds unedited originals
        assert "GantryID" not in ds  # device identity, off by default
        assert (0x0016, 0x0072) not in ds
        assert ds.MedicalAlerts == ""  # phone inside: cleaned value emptied
        assert ds.ContentSequence[0].TextValue == ""  # SR text cleaned too
        codes = [i.CodeValue for i in ds.DeidentificationMethodCodeSequence]
        assert "113104" in codes  # Clean Structured Content is claimed

    def test_device_ids_kept_on_request(self, tmp_path):
        out = tmp_path / "out.dcm"
        deidentify_dicom_file(
            self._build(tmp_path), str(out), salt="audit", retain_device=True
        )
        ds = _read(out)
        assert ds.GantryID == "GANTRY-7"


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


class TestHardeningCoverage:
    """Branches the fixture-driven tests do not reach: date-helper edges,
    the VR fallback for unlisted elements, both self-checks, tree
    aggregation and the audit-event writer."""

    def _context(self, **overrides):
        from medical_privacy_guard.formats.dicom_deidentify import _Context

        options = dict(
            profile="external-ai-strict",
            salt=b"unit-test-salt",
            date_shift_days=None,
            retain_private=False,
            retain_characteristics=False,
            retain_device=False,
        )
        options.update(overrides)
        return _Context(**options)

    def test_map_values_maps_each_item_of_a_multi_value(self):
        from medical_privacy_guard.formats.dicom_deidentify import _map_values

        assert _map_values(["a", "b"], str.upper) == ["A", "B"]
        assert _map_values("a", str.upper) == "A"

    def test_shift_date_empties_an_unparseable_value(self):
        from medical_privacy_guard.formats.dicom_deidentify import _shift_date

        assert _shift_date("not-a-date", 5) == ""
        assert _shift_date("20261301", 5) == ""  # month 13 does not exist

    def test_apply_datetime_branches(self):
        from medical_privacy_guard.formats.dicom_deidentify import _apply_datetime

        shifting = self._context(date_shift_days=10)
        assert _apply_datetime("20260101123000", shifting) == "20260111123000"
        assert _apply_datetime("20269901123000", shifting) == ""
        assert _apply_datetime("garbage", shifting) == ""
        assert _apply_datetime("20260101123000", self._context()) == ""

    def test_clean_text_passes_whitespace_through(self):
        from medical_privacy_guard.formats.dicom_deidentify import _clean_text

        assert _clean_text("   ", self._context()) == "   "

    def test_clean_text_passes_the_original_through_when_the_result_is_not_text(self):
        from types import SimpleNamespace

        from medical_privacy_guard.formats.dicom_deidentify import _clean_text

        ctx = self._context()
        ctx.guard = SimpleNamespace(
            sanitize=lambda *args: SimpleNamespace(sanitized_payload=object(), text=123)
        )
        assert _clean_text("原始文本", ctx) == "原始文本"

    def test_unlisted_elements_fall_back_to_vr_rules(self, tmp_path):
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, generate_uid

        meta = FileMetaDataset()
        meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        meta.MediaStorageSOPInstanceUID = generate_uid(entropy_srcs=["fb-sop"])
        meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds = Dataset()
        ds.file_meta = meta
        ds.SpecificCharacterSet = "ISO_IR 192"
        ds.PatientName = "张三"
        ds.PatientID = "MRN-001"
        ds.SOPClassUID = meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
        ds.StudyInstanceUID = generate_uid(entropy_srcs=["fb-study"])
        ds.SeriesInstanceUID = generate_uid(entropy_srcs=["fb-series"])
        ds.Modality = "CT"
        # None of the four elements below is in the disposition table, so
        # the VR/keyword fallback decides: *Name (LO) is removed,
        # *Description / *Comments text is cleaned, UI values are remapped.
        ds.ProtocolName = "头部平扫协议"
        ds.DerivationDescription = "联系电话13800000000"
        ds.TransactionUID = ""
        ds.StudyComments = ["", "电话13800000000"]
        ds.StudyDescription = ""
        source = tmp_path / "in.dcm"
        ds.save_as(source, enforce_file_format=True)

        out = tmp_path / "out.dcm"
        deidentify_dicom_file(str(source), str(out), salt="s1")
        result = _read(out)
        assert "ProtocolName" not in result
        assert "13800000000" not in str(result.DerivationDescription)
        assert result.TransactionUID == ""
        assert "13800000000" not in str(result.StudyComments)

    def test_self_check_withholds_the_output_when_cleaning_is_bypassed(
        self, tmp_path, monkeypatch
    ):
        import medical_privacy_guard.formats.dicom_deidentify as dd

        monkeypatch.setattr(dd, "_clean_text", lambda text, ctx: text)
        out = tmp_path / "out.dcm"
        with pytest.raises(ParserError, match="self-check failed"):
            deidentify_dicom_file(RICH, str(out), salt="s1")
        assert not out.exists()

    def test_private_tag_self_check_removes_the_temp_file(self, tmp_path, monkeypatch):
        import medical_privacy_guard.formats.dicom_deidentify as dd

        monkeypatch.setattr(dd, "_process_dataset", lambda ds, ctx: None)
        out_dir = tmp_path / "out"
        with pytest.raises(ParserError, match="private tags remain"):
            deidentify_dicom_file(RICH, str(out_dir / "out.dcm"), salt="s1")
        assert not (out_dir / "out.dcm").exists()
        assert list(out_dir.glob("*.tmp")) == []

    def test_tree_rejects_an_output_directory_equal_to_the_input(self, tmp_path):
        with pytest.raises(ParserError, match="must differ"):
            deidentify_dicom_tree(str(tmp_path), str(tmp_path))

    def test_tree_report_aggregates_totals(self, tmp_path):
        import json
        import shutil

        from medical_privacy_guard.formats.dicom_deidentify import report_to_json

        source_root = tmp_path / "in"
        (source_root / "sub").mkdir(parents=True)
        shutil.copy(BASE, source_root / "a.dcm")
        shutil.copy(BASE, source_root / "sub" / "b.dcm")
        (source_root / "notes.txt").write_text("not dicom", encoding="utf-8")
        report = deidentify_dicom_tree(str(source_root), str(tmp_path / "out"), salt="s1")
        assert report.skipped == ("notes.txt",)
        data = json.loads(report_to_json(report))
        assert len(data["files"]) == 2
        assert data["totals"]
        # Both files are copies of one fixture and the tree shares a single
        # UID map, so only the first file registers new mappings.
        assert data["uid_remapped"] >= 1

    def test_tree_aborts_on_a_burned_in_file(self, tmp_path):
        import shutil

        source_root = tmp_path / "in"
        source_root.mkdir()
        shutil.copy(BURNED, source_root / "burned.dcm")
        with pytest.raises(ParserError, match="BurnedInAnnotation"):
            deidentify_dicom_tree(str(source_root), str(tmp_path / "out"))

    def test_write_audit_event_for_single_and_tree_reports(self, tmp_path):
        from medical_privacy_guard.core.audit import AuditWriter
        from medical_privacy_guard.formats.dicom_deidentify import write_audit_event

        audit_dir = tmp_path / "audit"
        report = deidentify_dicom_file(BASE, str(tmp_path / "out.dcm"), salt="s1")
        write_audit_event(report, str(audit_dir))

        source_root = tmp_path / "in"
        source_root.mkdir()
        import shutil

        shutil.copy(BASE, source_root / "a.dcm")
        tree = deidentify_dicom_tree(str(source_root), str(tmp_path / "tree-out"), salt="s1")
        write_audit_event(tree, str(audit_dir))

        writer = AuditWriter(audit_dir)
        events = writer.read_all()
        assert len(events) == 2
        assert all(event.decision == "SANITIZE" for event in events)
        assert all("DICOM_DEIDENTIFY" in event.reason_codes for event in events)
        assert events[0].entity_counts["files"] == 1
        assert events[1].entity_counts["files"] == 1
        assert writer.verify().verified
