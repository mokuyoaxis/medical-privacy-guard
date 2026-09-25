"""Adapter ingress: what the guard is looking at when it decides.

The contract these tests pin: an adapter classifies the call, never the caller.
A JSON document that arrives as a string is still a JSON document, and scanning
it as prose drops the key-derived field labels that make the label-driven
detectors apply at all.
"""

from __future__ import annotations

import json

import pytest

from adapters import evaluate_call, payload_for, sanitize_call
from core.model import Payload, Purpose, Recipient, TrustLevel, Verdict
from formats.admission import payload_for_text
from medical_privacy_guard import Guard


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def approved() -> Recipient:
    return Recipient(kind="test", trust_level=TrustLevel("EXTERNAL_APPROVED"))


# -- classification ----------------------------------------------------------


class TestPayloadFor:
    @pytest.mark.parametrize(
        "content, expected_kind",
        [
            ({"name": "张三"}, "json"),
            ([{"name": "张三"}], "json"),
            ('{"name": "张三"}', "json"),
            ('[{"name": "张三"}]', "json"),
            ("患者：张三", "text"),
            ("", "text"),
            # Ordinary prose that happens to start with a bracket is not a
            # broken container, and must not be refused for looking like one.
            ("[随访] 记录", "text"),
            # A container that parses and leaves content behind is a format
            # problem, not prose.
            ('{"a": 1} trailing', "unsupported"),
            # Kinds the guard cannot inspect fail closed rather than guess.
            (b'{"name": "x"}', "unsupported"),
            (12345, "unsupported"),
            (None, "unsupported"),
        ],
    )
    def test_kind_by_content(self, content, expected_kind):
        assert payload_for(content).kind == expected_kind

    def test_control_characters_are_refused(self):
        """A NUL cannot occur in clinical prose and joins leaves internally."""
        assert payload_for("患者\x00张三").kind == "unsupported"

    def test_a_document_marker_is_refused(self):
        assert payload_for("%PDF-1.7\n患者：张三").kind == "unsupported"

    def test_a_decoded_container_is_passed_through_unchanged(self):
        document = {"name": "张三", "age": 67}
        payload = payload_for(document)
        assert payload.kind == "json"
        assert payload.content is document


# -- the reason the module exists -------------------------------------------


class TestLabelsSurviveTheBoundary:
    def test_a_json_string_keeps_its_field_labels(self, guard, approved):
        """The same document, two routes, one verdict.

        Scanning the string as prose yields no fact at all: the key is not a
        Chinese label and a bare name is deliberately not detected, so that
        route used to release the document. The Guard's own string entry now
        classifies with the same shared rule the adapter uses, so the two agree.
        The assertion is written as an agreement rather than as one hard-coded
        verdict, because a divergence in either direction is the defect.
        """
        as_string = '{"name": "张三"}'
        direct = guard.evaluate(as_string, approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        adapted = evaluate_call(guard, as_string, approved, Purpose.EXTERNAL_AI_ASSISTANCE)

        assert direct.decision.verdict is adapted.decision.verdict
        assert direct.decision.verdict is Verdict.SANITIZE
        assert any(f.type == "PERSON_NAME" for f in direct.facts)
        assert any(f.type == "PERSON_NAME" for f in adapted.facts)

    @pytest.mark.parametrize(
        "content",
        [
            '{"mrn": "1234567"}',
            {"mrn": "1234567"},
            {"name": "张三", "mrn": "1234567"},
            [{"name": "张三"}],
        ],
    )
    def test_structured_content_is_never_quietly_allowed(self, guard, approved, content):
        result = evaluate_call(guard, content, approved, Purpose.EXTERNAL_AI_ASSISTANCE)
        assert result.decision.verdict is not Verdict.ALLOW
        assert result.facts

    def test_sanitize_call_releases_a_rebuilt_document(self, guard, approved):
        result = sanitize_call(
            guard, {"name": "张三", "phone": "13800000000"}, approved,
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        assert result.verification is not None and result.verification.passed
        rebuilt = json.loads(result.sanitized_payload.content)
        assert "张三" not in rebuilt["name"]
        assert rebuilt["phone"] == "[REDACTED]"

    def test_sanitize_call_agrees_with_the_guard_on_a_payload(self, guard, approved):
        """The adapter must not change a decision the guard already made."""
        document = {"name": "张三"}
        direct = guard.sanitize(
            Payload(kind="json", content=document), approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        through_adapter = sanitize_call(
            guard, document, approved, Purpose.EXTERNAL_AI_ASSISTANCE
        )
        assert through_adapter.decision_before.verdict is direct.decision_before.verdict
        assert (
            through_adapter.sanitized_payload.content
            == direct.sanitized_payload.content
        )


# -- one implementation ------------------------------------------------------


class TestSharedWithTheCli:
    @pytest.mark.parametrize(
        "text",
        [
            '{"name": "张三"}',
            "[1, 2]",
            "患者：张三",
            "[随访] 记录",
            '{"a": 1} trailing',
            "not a container at all",
        ],
    )
    def test_the_adapter_classifies_exactly_as_the_cli_does(self, text):
        """Two entry points, one decision about what a document is.

        A second copy of this rule is how the two drift apart: one of them
        starts treating a JSON document as prose and its labels disappear.
        """
        assert payload_for(text).kind == payload_for_text(text).kind
