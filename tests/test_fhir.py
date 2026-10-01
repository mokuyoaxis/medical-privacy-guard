"""FHIR minimal resource support (v0.6).

The acceptance criteria are: path-level reports, JSON structure preserved, no
raw field values in audit, and unsupported resources defaulting to ASK/BLOCK.
Each of those is asserted here, including the direction that fails silently --
a resource that parses fine but names something the guard was never taught.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.errors import ParserError
from core.model import Payload, Purpose, Recipient, TrustLevel, Verdict
from formats.fhir import (
    FHIR_RESOURCES,
    inspect_fhir,
    parse_fhir_payload,
)
from medical_privacy_guard import Guard

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "fhir"


def load(name: str):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture()
def guard():
    return Guard(profile="external-ai-strict")


RECIPIENT = Recipient(kind="api", trust_level=TrustLevel.EXTERNAL_APPROVED)


class TestResourceAdmission:
    def test_supported_resources_are_the_declared_set(self):
        assert FHIR_RESOURCES == frozenset(
            {
                "Patient", "Observation", "DiagnosticReport", "Condition",
                "MedicationRequest", "Encounter", "ImagingStudy", "Bundle",
            }
        )

    def test_an_unsupported_resource_is_withheld(self, guard):
        """A resource the guard was never taught is not walked as JSON."""
        result = guard.sanitize(
            Payload(kind="fhir", content=load("unsupported_provenance")),
            RECIPIENT,
            Purpose.RESEARCH,
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None

    def test_an_unsupported_entry_inside_a_supported_bundle_is_withheld(self, guard):
        """A Bundle is not made safe by the Bundle itself being supported."""
        bundle = load("bundle")
        bundle["entry"].append({"resource": {"resourceType": "Provenance"}})
        result = guard.sanitize(
            Payload(kind="fhir", content=bundle), RECIPIENT, Purpose.RESEARCH
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None

    def test_a_document_with_no_resource_type_is_withheld(self, guard):
        """Declaring FHIR does not route an untyped object to the JSON path.

        It used to: a document with no resourceType fell through and was
        sanitized as ordinary JSON. That is the divergence the shared
        admission rule exists to prevent.
        """
        result = guard.sanitize(
            Payload(kind="fhir", content={"patient": "张三"}),
            RECIPIENT,
            Purpose.RESEARCH,
        )
        assert result.decision_before.verdict is Verdict.BLOCK
        assert result.sanitized_payload is None

    def test_a_non_fhir_value_is_a_parser_error(self):
        with pytest.raises(ParserError):
            inspect_fhir("not a document")


class TestNameCompletion:
    def test_a_split_name_is_detected(self, guard):
        """family and given are each only half a name.

        ``姓名：张`` and ``姓名：伟`` match nothing; the joined ``张伟`` does.
        Without the completion a Patient resource is released with the surname
        intact, which is the whole point of detecting it.
        """
        doc = {"resourceType": "Patient", "name": [{"family": "张", "given": ["伟"]}]}
        result = guard.sanitize(
            Payload(kind="fhir", content=doc), RECIPIENT, Purpose.RESEARCH
        )
        assert result.decision_before.verdict is Verdict.SANITIZE
        released = json.loads(result.sanitized_payload.content)
        assert "张" not in released["name"][0]["family"]
        assert "伟" not in released["name"][0]["given"][0]

    def test_a_whole_name_in_text_is_detected(self, guard):
        doc = {"resourceType": "Patient", "name": [{"text": "张伟"}]}
        result = guard.sanitize(
            Payload(kind="fhir", content=doc), RECIPIENT, Purpose.RESEARCH
        )
        assert result.decision_before.verdict is Verdict.SANITIZE
        assert "张伟" not in result.sanitized_payload.content

    def test_a_compound_surname_survives_completion(self, guard):
        doc = {"resourceType": "Patient", "name": [{"family": "欧阳", "given": ["明"]}]}
        result = guard.sanitize(
            Payload(kind="fhir", content=doc), RECIPIENT, Purpose.RESEARCH
        )
        assert result.decision_before.verdict is Verdict.SANITIZE

    def test_narrative_text_is_not_read_as_a_name(self, guard):
        """``text`` is also the narrative key; it must not be labelled blindly."""
        doc = {
            "resourceType": "Patient",
            "text": {"status": "generated", "div": "<div>随访记录</div>"},
        }
        result = guard.evaluate(
            Payload(kind="fhir", content=doc), RECIPIENT, Purpose.RESEARCH
        )
        assert not [f for f in result.facts if f.type == "PERSON_NAME"]


class TestStructurePreservation:
    def test_the_released_document_keeps_its_shape(self, guard):
        original = load("patient")
        result = guard.sanitize(
            Payload(kind="fhir", content=original), RECIPIENT, Purpose.RESEARCH
        )
        assert result.decision_before.verdict is Verdict.SANITIZE
        released = json.loads(result.sanitized_payload.content)
        assert released["resourceType"] == "Patient"
        assert released["name"][0]["given"][0] != "伟"
        # Keys, array lengths and ordering survive the round trip.
        assert list(released) == list(original)
        assert len(released["name"]) == len(original["name"])

    def test_a_numeric_value_that_is_an_identifier_is_withheld(self, guard):
        """The read-only leaf rule holds for FHIR as for any JSON payload."""
        doc = {"resourceType": "Patient", "identifier": [{"value": 13800000000}]}
        result = guard.sanitize(
            Payload(kind="fhir", content=doc), RECIPIENT, Purpose.RESEARCH
        )
        assert result.decision_before.verdict in {Verdict.ASK, Verdict.BLOCK}
        assert result.sanitized_payload is None


class TestAudit:
    def test_no_raw_field_value_enters_the_audit_log(self, guard, tmp_path):
        result = guard.sanitize(
            Payload(kind="fhir", content=load("patient")),
            RECIPIENT,
            Purpose.RESEARCH,
            audit_dir=str(tmp_path),
        )
        assert result.decision_before.verdict is Verdict.SANITIZE
        log = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
        for raw in ("张伟", "13800000000", "北京市朝阳区建国路1号", "MRN-9001"):
            assert raw not in log, raw
        event = json.loads(log.strip().splitlines()[-1])
        assert event["entity_counts"], "the audit must record what was found"


class TestBundle:
    def test_a_bundle_of_supported_resources_is_walked(self, guard):
        result = guard.sanitize(
            Payload(kind="fhir", content=load("bundle")),
            RECIPIENT,
            Purpose.RESEARCH,
        )
        assert result.decision_before.verdict is Verdict.SANITIZE
        assert result.sanitized_payload is not None

    def test_resources_are_reported_with_their_pointers(self):
        found = inspect_fhir(load("bundle"))
        pointers = {r.pointer for r in found}
        assert "/entry/0/resource" in pointers
        assert "/entry/1/resource" in pointers
        assert all(r.supported for r in found)


class TestPathReporting:
    def test_leaves_are_addressable_and_completion_is_attached(self):
        payload = parse_fhir_payload(load("patient"))
        paths = {leaf.path for leaf in payload.leaves}
        assert "/name/0/family" in paths
        completed = {
            leaf.path: leaf.completed
            for leaf in payload.leaves
            if leaf.completed
        }
        assert completed["/name/0/family"] == "张伟"
