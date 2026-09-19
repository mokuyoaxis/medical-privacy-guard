"""Unit tests for the audit subsystem (Phase 1 Step 5).

Coverage:
- append-only JSONL writing and reading
- event schema completeness (metadata only)
- canary leak test: raw PHI values never appear anywhere in the audit stream
- strict mode write failure → AuditError (fail closed)
- building events from real decisions (detect → policy → audit)
"""

import json

import pytest

from core.audit import AuditEvent, AuditWriter, build_audit_event
from core.errors import AuditError
from core.model import (
    Decision,
    DetectedFact,
    DisclosurePlan,
    Purpose,
    Recipient,
    RiskLevel,
    RiskSummary,
    TransformationOp,
    TrustLevel,
    Verdict,
)
from core.policy import PolicyEvaluator, load_builtin_profile
from detectors import detect_all
from transformers import apply_plan


def external_recipient() -> Recipient:
    return Recipient(kind="llm", trust_level=TrustLevel.EXTERNAL_UNKNOWN)


def sample_event() -> AuditEvent:
    return AuditEvent(
        event_id="e1",
        timestamp="2026-08-29T00:00:00.000000Z",
        decision="SANITIZE",
        reason_codes=("CONTACT_IDENTIFIER_PRESENT", "EXTERNAL_RECIPIENT"),
        entity_counts={"PHONE": 1},
        risk_level="HIGH",
        risk_score=55,
        recipient_class="EXTERNAL_UNKNOWN",
        purpose="EXTERNAL_AI_ASSISTANCE",
        policy_profile="external-ai-strict",
        policy_version="external-ai-strict/1",
        transformations=("REMOVE_PHONE",),
        verification="PASS",
    )


def _write_concurrent_events(directory, worker):
    from dataclasses import replace

    writer = AuditWriter(directory)
    for index in range(12):
        event = replace(sample_event(), event_id=f"{worker}-{index}",
                        reason_codes=("合成元数据" * 2048,))
        assert writer.record(event) == event.event_id


# -- writing / reading -------------------------------------------------------


class TestWriter:
    def test_writes_append_only_jsonl(self, tmp_path):
        writer = AuditWriter(tmp_path)
        writer.record(sample_event())
        writer.record(sample_event())
        assert len(writer) == 2
        with open(writer.filename, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        assert len(lines) == 2
        for line in lines:
            payload = json.loads(line)
            assert payload["event_id"] == "e1"
            assert payload["decision"] == "SANITIZE"

    def test_append_does_not_overwrite(self, tmp_path):
        writer = AuditWriter(tmp_path)
        writer.record(sample_event())
        writer.record(sample_event())
        # A fresh writer on the same directory continues appending.
        writer2 = AuditWriter(tmp_path)
        writer2.record(sample_event())
        assert len(writer2) == 3

    def test_read_all_roundtrip(self, tmp_path):
        writer = AuditWriter(tmp_path)
        event = sample_event()
        writer.record(event)
        (read_back,) = writer.read_all()
        assert read_back == event
        assert read_back.entity_counts == {"PHONE": 1}
        assert read_back.transformations == ("REMOVE_PHONE",)

    def test_read_missing_file_returns_empty(self, tmp_path):
        writer = AuditWriter(tmp_path / "nonexistent")
        assert writer.read_all() == ()

    def test_file_permissions_restricted(self, tmp_path):
        writer = AuditWriter(tmp_path)
        writer.record(sample_event())
        import stat

        mode = stat.S_IMODE(writer.filename.stat().st_mode)
        assert mode & 0o077 == 0  # no group/other permissions


class TestWriteIntegrity:
    @pytest.mark.parametrize("strict", [True, False])
    @pytest.mark.parametrize("failure", ["short", "zero", "write", "fsync"])
    def test_incomplete_write_never_succeeds(self, tmp_path, monkeypatch, strict, failure):
        import os
        from dataclasses import replace

        writer = AuditWriter(tmp_path, strict=strict)
        event = replace(sample_event(), reason_codes=("合成元数据",))
        data = (event.to_json_line() + "\n").encode("utf-8")
        original_write = os.write
        original_close = os.close
        writes = []
        synced = []
        closed = []

        def write(fd, content):
            writes.append(bytes(content))
            if failure == "write":
                raise OSError("synthetic write failure")
            if failure == "zero":
                return 0
            return original_write(fd, content[:1] if failure == "short" else content)

        def fsync(fd):
            synced.append(fd)
            if failure == "fsync":
                raise OSError("synthetic fsync failure")

        def close(fd):
            closed.append(fd)
            original_close(fd)

        monkeypatch.setattr(os, "write", write)
        monkeypatch.setattr(os, "fsync", fsync)
        monkeypatch.setattr(os, "close", close)
        if strict:
            with pytest.raises(AuditError):
                writer.record(event)
        else:
            assert writer.record(event) == ""
        assert writes == [data]
        assert len(closed) == 1
        assert len(synced) == (1 if failure == "fsync" else 0)
        expected = data if failure == "fsync" else data[:1] if failure == "short" else b""
        assert writer.filename.read_bytes() == expected

    def test_utf8_bytes_written_once_before_fsync(self, tmp_path, monkeypatch):
        import os
        from dataclasses import replace

        writer = AuditWriter(tmp_path)
        event = replace(sample_event(), reason_codes=("合成元数据",))
        original_write = os.write
        original_fsync = os.fsync
        calls = []

        def write(fd, data):
            calls.append(("write", data))
            return original_write(fd, data)

        def fsync(fd):
            calls.append(("fsync", None))
            return original_fsync(fd)

        monkeypatch.setattr(os, "write", write)
        monkeypatch.setattr(os, "fsync", fsync)
        assert writer.record(event) == event.event_id
        assert calls == [("write", (event.to_json_line() + "\n").encode("utf-8")),
                         ("fsync", None)]
        assert writer.read_all() == (event,)

    @pytest.mark.parametrize("executor_kind", ["threads", "processes"])
    def test_concurrent_append_keeps_complete_events(self, tmp_path, executor_kind):
        import multiprocessing
        from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

        if executor_kind == "processes":
            executor = ProcessPoolExecutor(max_workers=4,
                                           mp_context=multiprocessing.get_context("spawn"))
        else:
            executor = ThreadPoolExecutor(max_workers=4)
        with executor:
            futures = [executor.submit(_write_concurrent_events, str(tmp_path), worker)
                       for worker in range(4)]
            for future in futures:
                future.result(timeout=30)
        events = AuditWriter(tmp_path).read_all()
        assert len(events) == 48
        assert {event.event_id for event in events} == {
            f"{worker}-{index}" for worker in range(4) for index in range(12)
        }
        assert all(event.reason_codes == ("合成元数据" * 2048,) for event in events)


# -- no raw PHI (canary) -----------------------------------------------------


class TestNoRawPhi:
    def test_canary_values_never_reach_audit(self, tmp_path):
        canary_name = "张伟"
        canary_phone = "13800000000"
        canary_id = "11010519491231002X"
        canary_mrn = "MRN7777777"
        text = f"患者：{canary_name} 电话{canary_phone} 证件{canary_id} 病历号：{canary_mrn}"

        facts = detect_all(text)
        assert {f.type for f in facts} >= {"PERSON_NAME", "PHONE", "GOVERNMENT_ID", "MEDICAL_RECORD_NUMBER"}

        decision = PolicyEvaluator(load_builtin_profile("external-ai-strict")).evaluate(
            facts, external_recipient(), Purpose.EXTERNAL_AI_ASSISTANCE
        )
        event = build_audit_event(decision, facts, external_recipient(), Purpose.EXTERNAL_AI_ASSISTANCE)

        writer = AuditWriter(tmp_path)
        writer.record(event)

        # The entire audit stream must not contain any canary.
        stream = "\n".join(e.to_json_line() for e in writer.read_all())
        for canary in (canary_name, canary_phone, canary_id, canary_mrn):
            assert canary not in stream

    def test_event_has_no_value_fields(self):
        event = build_audit_event(
            Decision(
                verdict=Verdict.SANITIZE,
                reason_codes=(),
                explanation="x",
                risk=RiskSummary(
                    level=RiskLevel.LOW,
                    score=0,
                    factors=(),
                ),
                plan=DisclosurePlan(operations=()),
                policy_version="p/1",
            ),
            (DetectedFact(type="PHONE", start=0, end=11, confidence=1.0, source="t", value="13800000000"),),
            external_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
        )
        # entity_counts has types only, never values.
        assert event.entity_counts == {"PHONE": 1}
        assert "13800000000" not in event.to_json_line()

    def test_build_audit_event_includes_transform_labels(self):
        decision = Decision(
            verdict=Verdict.SANITIZE,
            reason_codes=(),
            explanation="x",
            risk=RiskSummary(level=RiskLevel.LOW, score=5, factors=()),
            plan=DisclosurePlan(
                operations=(
                    TransformationOp(op="TOKENIZE", target="PERSON_NAME", entity_type="PERSON_NAME"),
                    TransformationOp(op="REMOVE", target="PHONE", entity_type="PHONE"),
                )
            ),
            policy_version="external-ai-strict/1",
        )
        event = build_audit_event(
            decision,
            (),
            external_recipient(),
            Purpose.EXTERNAL_AI_ASSISTANCE,
            verification="PASS",
        )
        assert event.transformations == ("TOKENIZE_PERSON_NAME", "REMOVE_PHONE")
        assert event.verification == "PASS"
        assert event.policy_profile == "external-ai-strict"
        assert event.policy_version == "external-ai-strict/1"


# -- failure modes -----------------------------------------------------------


class TestFailureModes:
    def test_strict_write_failure_raises(self, tmp_path):
        writer = AuditWriter(tmp_path)
        # Point the log at a path that cannot be opened as a file.
        writer.filename = tmp_path / "subdir" / "events.jsonl"
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir").rmdir()  # remove it so open fails differently
        with pytest.raises(AuditError):
            writer.record(sample_event())

    def test_unwritable_directory_raises(self, tmp_path):
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        blocked.chmod(0o500)
        try:
            with pytest.raises(AuditError):
                AuditWriter(blocked / "audit")
        finally:
            blocked.chmod(0o700)


# -- full pipeline -----------------------------------------------------------


class TestFullPipeline:
    def test_detect_policy_transform_verify_audit(self, tmp_path):
        text = "联系电话 13800000000"
        profile = load_builtin_profile("external-ai-strict")
        recipient = external_recipient()
        purpose = Purpose.EXTERNAL_AI_ASSISTANCE

        facts = detect_all(text)
        decision = PolicyEvaluator(profile).evaluate(facts, recipient, purpose)
        outcome = apply_plan(text, facts, decision.plan)
        from core.verify import verify_sanitized

        verification = verify_sanitized(
            profile=profile,
            sanitized_text=outcome.text,
            original_facts=facts,
            recipient=recipient,
            purpose=purpose,
        )

        event = build_audit_event(
            decision, facts, recipient, purpose,
            verification="PASS" if verification.passed else "FAIL",
        )
        writer = AuditWriter(tmp_path)
        writer.record(event)

        (read_back,) = writer.read_all()
        assert read_back.decision == "SANITIZE"
        assert read_back.entity_counts == {"PHONE": 1}
        assert read_back.verification == "PASS"
        assert "13800000000" not in read_back.to_json_line()
