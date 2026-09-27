"""The DICOM scanner: read-only metadata inspection.

Fixtures are committed binary files (see ``make_dicom_fixtures.py``); the test
suite needs no pydicom unless it runs the scanner itself. Tests skip when the
optional extra is absent -- a missing feature is not a broken one.
"""

from __future__ import annotations

import json

import pytest

from core.errors import ParserError

pytest.importorskip("pydicom")

from formats.dicom_inspect import inspect_dicom_file, report_to_json  # noqa: E402

FIXTURE = "tests/fixtures/dicom/ct_head_synthetic.dcm"


@pytest.fixture(scope="module")
def report():
    return inspect_dicom_file(FIXTURE)


class TestMetadataFindings:
    def test_patient_name_is_found(self, report):
        cats = {f.category for f in report.findings}
        assert "patient_name" in cats

    def test_patient_id_and_accession_are_found(self, report):
        cats = {f.category for f in report.findings}
        assert "patient_id" in cats and "accession_number" in cats

    def test_dates_are_found(self, report):
        cats = {f.category for f in report.findings}
        assert "study_date" in cats and "patient_birth_date" in cats

    def test_institution_and_staff_are_found(self, report):
        cats = {f.category for f in report.findings}
        assert "institution_name" in cats
        assert "referring_physician_name" in cats

    def test_chinese_values_reach_the_detectors(self, report):
        """GB18030-decoded 张三 trips PERSON_NAME; the tag alone is not enough."""
        names = [f for f in report.findings if f.category == "patient_name"]
        assert names and "PERSON_NAME" in names[0].detail

    def test_findings_never_carry_raw_values(self, report):
        for f in report.findings:
            assert "张三" not in f.detail and "MRN-888" not in f.detail


class TestPrivateTags:
    def test_private_tags_are_counted_and_high_risk(self, report):
        assert report.private_tag_count == 2
        assert report.to_dict()["private_tags_risk"] == "HIGH"


class TestPixelRisk:
    def test_pixel_risk_stays_unknown(self, report):
        assert report.pixel_annotation_risk == "UNKNOWN"
        assert report.recognizable_visual_features_risk == "UNKNOWN"

    def test_safe_to_release_is_false(self, report):
        assert report.safe_to_release is False

    def test_metadata_risk_is_high(self, report):
        assert report.metadata_risk == "HIGH"


class TestReportShape:
    def test_json_round_trip(self, report):
        d = json.loads(report_to_json(report))
        assert d["file"] == report.file
        assert d["safe_to_release"] is False
        assert d["specific_character_set"] == "ISO_IR 192"

    def test_transfer_syntax_is_recorded(self, report):
        assert "1.2.840.10008.1.2.1" in report.transfer_syntax


class TestFailClosed:
    def test_a_non_dicom_file_is_a_parser_error(self, tmp_path):
        p = tmp_path / "not.dcm"
        p.write_text("hello, world", encoding="utf-8")
        with pytest.raises(ParserError):
            inspect_dicom_file(str(p))

    def test_a_missing_file_is_a_parser_error(self):
        with pytest.raises(ParserError):
            inspect_dicom_file("tests/fixtures/dicom/nope.dcm")
