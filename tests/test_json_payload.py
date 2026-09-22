"""JSON payload support.

The design decision these tests pin: a structured payload gets **one decision
for the whole document** and per-leaf transformation. A single direct identifier
withholds the record, because a partially released record is exactly where
cross-field quasi-identifiers do their damage.

The other decision worth stating: a JSON key acts as a field label. In
``{"name": "张三"}`` the key already says what the value is, and the detectors are
label-driven, so without that mapping the name would be treated as bare prose
and deliberately not detected — which is what happened on the first run.
"""

from __future__ import annotations

import json

import pytest

from core.model import Payload, Purpose, Recipient, TrustLevel
from formats import dumps, from_document, parse_json_payload, rebuild
from formats.json_payload import label_for
from medical_privacy_guard import Guard


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


def sanitize_json(guard, approved, document):
    result = guard.sanitize(Payload(kind="json", content=document), approved,
                            Purpose.EXTERNAL_AI_ASSISTANCE)
    return result


# -- traversal ---------------------------------------------------------------


class TestLeafExtraction:
    def test_paths_follow_the_structure(self):
        parsed = parse_json_payload('{"a": {"b": ["x", "y"]}, "c": "z"}')
        assert [(leaf.path, leaf.text) for leaf in parsed.leaves] == [
            ("/a/b/0", "x"),
            ("/a/b/1", "y"),
            ("/c", "z"),
        ]

    def test_numbers_booleans_and_null_are_not_leaves(self):
        parsed = parse_json_payload('{"age": 67, "flag": true, "none": null, "name": "张三"}')
        assert [leaf.text for leaf in parsed.leaves] == ["张三"]

    @pytest.mark.parametrize(
        "key, expected",
        [
            ("/a~1b", "slash"),
            ("/c~0d", "tilde"),
            ("/e~01", "both"),
        ],
    )
    def test_json_pointer_escaping(self, key, expected):
        document = {"a/b": "slash", "c~d": "tilde", "e~1": "both"}
        parsed = parse_json_payload(json.dumps(document, ensure_ascii=False))
        assert {leaf.path: leaf.text for leaf in parsed.leaves}[key] == expected

    def test_array_of_objects(self):
        parsed = parse_json_payload('[{"name": "李四"}, {"name": "王五"}]')
        assert [leaf.path for leaf in parsed.leaves] == ["/0/name", "/1/name"]

    @pytest.mark.parametrize("text", ['"just a string"', "42", "null", "{broken", ""])
    def test_non_containers_are_rejected(self, text):
        from core.errors import ParserError

        with pytest.raises(ParserError):
            parse_json_payload(text)

    def test_from_document_accepts_a_decoded_object(self):
        parsed = from_document({"name": "张三"})
        assert [leaf.text for leaf in parsed.leaves] == ["张三"]


# -- keys act as labels ------------------------------------------------------


class TestKeyLabels:
    @pytest.mark.parametrize(
        "key, expected",
        [
            ("name", "姓名"),
            ("patient_name", "患者姓名"),
            ("patientName", "患者姓名"),
            ("Patient Name", "患者姓名"),
            ("phone", "电话"),
            ("mrn", "病历号"),
            ("unknown_field", None),
        ],
    )
    def test_label_lookup(self, key, expected):
        assert label_for(key) == expected

    def test_a_labelled_key_makes_the_value_detectable(self, guard, approved):
        """Without the key mapping this value is bare prose and stays put."""
        result = sanitize_json(guard, approved, {"name": "张三"})
        assert result.decision_before.verdict.value == "SANITIZE"
        assert "张三" not in result.sanitized_payload.content

    def test_an_unlabelled_key_does_not_invent_a_fact(self, guard, approved):
        result = sanitize_json(guard, approved, {"note": "张三"})
        assert result.decision_before.verdict.value == "ALLOW"


# -- rebuilding --------------------------------------------------------------


class TestRebuild:
    def test_structure_is_preserved(self):
        document = {"patient": {"name": "张三", "age": 67}, "notes": ["a", "b"]}
        rebuilt = rebuild(document, {"/patient/name": "[PERSON_NAME_001]"})
        assert set(rebuilt) == set(document)
        assert set(rebuilt["patient"]) == {"name", "age"}
        assert rebuilt["notes"] == ["a", "b"]
        assert rebuilt["patient"]["age"] == 67
        assert isinstance(rebuilt["patient"]["age"], int)

    def test_the_original_is_not_mutated(self):
        document = {"name": "张三"}
        rebuild(document, {"/name": "x"})
        assert document == {"name": "张三"}

    def test_escaping_survives_a_round_trip(self):
        document = {"a/b": "v", "c~d": "w"}
        rebuilt = rebuild(document, {"/a~1b": "V", "/c~0d": "W"})
        assert rebuilt == {"a/b": "V", "c~d": "W"}

    def test_dumps_keeps_unicode_and_nesting(self):
        text = dumps({"name": "张三", "nested": {"x": [1, 2]}})
        assert "张三" in text
        assert json.loads(text) == {"name": "张三", "nested": {"x": [1, 2]}}


# -- end to end --------------------------------------------------------------


class TestStructuredPipeline:
    def test_values_are_sanitized_and_structure_survives(self, guard, approved):
        document = {
            "patient": {"name": "张三", "phone": "13800000000", "age": 67},
            "note": "因脑梗死入院",
        }
        result = sanitize_json(guard, approved, document)
        assert result.decision_before.verdict.value == "SANITIZE"
        assert result.verification is not None and result.verification.passed
        rebuilt = json.loads(result.sanitized_payload.content)
        assert rebuilt["patient"]["name"] == "[PERSON_NAME_001]"
        assert rebuilt["patient"]["phone"] == "[REDACTED]"
        assert rebuilt["patient"]["age"] == 67
        assert rebuilt["note"] == "因脑梗死入院"

    def test_the_verdict_covers_the_whole_document(self, guard, approved):
        """The record is the unit of disclosure, not the field.

        A field carrying no identifier of its own is released or withheld with
        the record, never decided separately.
        """
        document = {"name": "张三", "note": "普通随访"}
        result = sanitize_json(guard, approved, document)
        assert result.decision_before.verdict.value == "SANITIZE"
        rebuilt = json.loads(result.sanitized_payload.content)
        assert "张三" not in rebuilt["name"]
        assert rebuilt["note"] == "普通随访"

    def test_a_blocking_identifier_withholds_the_whole_record(self, guard):
        """One field the policy refuses takes the entire record with it."""
        document = {"id_card": "110101199003078888", "note": "普通随访"}
        result = guard.sanitize(
            Payload(kind="json", content=document),
            "external-unknown",
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.decision_before.verdict.value == "BLOCK"
        assert result.sanitized_payload is None

    def test_adjacent_leaves_do_not_form_a_false_match(self, guard, approved):
        """Flattening joins leaves; the separator must prevent cross-leaf hits.

        "患者张" and "三入院" are harmless apart and would form a patient name
        plus an admission verb if concatenated.
        """
        document = {"a": "患者张", "b": "三入院"}
        result = sanitize_json(guard, approved, document)
        assert result.decision_before.verdict.value == "ALLOW"

    def test_consistent_tokens_across_leaves(self, guard, approved):
        document = {"primary": {"name": "张三"}, "secondary": {"name": "张三"}}
        result = sanitize_json(guard, approved, document)
        rebuilt = json.loads(result.sanitized_payload.content)
        assert rebuilt["primary"]["name"] == rebuilt["secondary"]["name"]

    def test_malformed_payload_blocks(self, guard, approved):
        result = guard.sanitize(
            Payload(kind="json", content="{not json"),
            approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.decision_before.verdict.value == "BLOCK"
        assert result.sanitized_payload is None

    def test_deeply_nested_payload_is_handled_without_recursion(self, guard, approved):
        """Nesting depth is caller-controlled and must not reach a traceback."""
        document = json.loads("[" * 1500 + '"x"' + "]" * 1500)
        result = guard.sanitize(
            Payload(kind="json", content=document), approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert result.decision_before.verdict.value in {"ALLOW", "SANITIZE"}

    def test_audit_counts_cover_every_leaf(self, tmp_path, guard):
        audit_dir = tmp_path / "audit"
        guard_with_audit = Guard(profile="external-ai-strict", audit_dir=str(audit_dir))
        guard_with_audit.sanitize(
            Payload(kind="json", content={"name": "张三", "phone": "13800000000"}),
            "external-approved",
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        event = json.loads((audit_dir / "events.jsonl").read_text(encoding="utf-8").strip())
        assert event["decision"] == "SANITIZE"
        assert event["entity_counts"] == {"PERSON_NAME": 1, "PHONE": 1}
        stream = (audit_dir / "events.jsonl").read_text(encoding="utf-8")
        assert "张三" not in stream and "13800000000" not in stream
