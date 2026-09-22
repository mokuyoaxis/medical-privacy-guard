"""Unit tests for the audit subsystem (Phase 1 Step 5).

Coverage:
- append-only JSONL writing and reading
- event schema completeness (metadata only)
- canary leak test: raw PHI values never appear anywhere in the audit stream
- strict mode write failure → AuditError (fail closed)
- building events from real decisions (detect → policy → audit)
"""

import json
from dataclasses import replace

import pytest

from core.audit import (
    GENESIS_HASH,
    AuditEvent,
    AuditWriter,
    build_audit_event,
    verify_chain,
)
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
        # The stored record is the event linked to the chain head (genesis in an
        # empty log); every other field round-trips unchanged.
        assert read_back == event.chained(GENESIS_HASH)
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
        # The log starts empty, so the first record chains from genesis and the
        # exact bytes are deterministic.
        data = (event.chained(GENESIS_HASH).to_json_line() + "\n").encode("utf-8")
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
        chained = event.chained(GENESIS_HASH)
        assert calls == [("write", (chained.to_json_line() + "\n").encode("utf-8")),
                         ("fsync", None)]
        assert writer.read_all() == (chained,)

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


# -- chained integrity -------------------------------------------------------


class TestChainIntegrity:
    """Each record links to the previous one, so edits and deletions show up.

    What the chain does *not* cover is pinned here too: tail truncation and
    whole-chain rewriting are outside its reach. See
    ``.internal/audit-hash-chain-plan-2026-09-22.md``.
    """

    def test_sequential_writes_verify(self, tmp_path):
        writer = AuditWriter(tmp_path)
        for index in range(5):
            writer.record(replace(sample_event(), event_id=f"e{index}"))
        report = writer.verify()
        assert report.verified, report.failures
        assert (report.total, report.chained, report.unchained) == (5, 5, 0)

    def test_first_record_links_to_genesis(self, tmp_path):
        writer = AuditWriter(tmp_path)
        writer.record(sample_event())
        (event,) = writer.read_all()
        assert event.prev_hash == GENESIS_HASH

    def test_deleting_a_middle_record_is_detected(self, tmp_path):
        writer = AuditWriter(tmp_path)
        for index in range(4):
            writer.record(replace(sample_event(), event_id=f"e{index}"))
        lines = writer.filename.read_text(encoding="utf-8").splitlines()
        del lines[1]
        writer.filename.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = verify_chain(AuditWriter(tmp_path).read_all())
        assert not report.verified
        assert any("prev_hash" in failure for failure in report.failures)

    def test_editing_a_field_is_detected(self, tmp_path):
        writer = AuditWriter(tmp_path)
        writer.record(sample_event())
        payload = json.loads(writer.filename.read_text(encoding="utf-8").strip())
        payload["decision"] = "ALLOW"
        writer.filename.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report = verify_chain(AuditWriter(tmp_path).read_all())
        assert not report.verified
        assert any("event_hash" in failure for failure in report.failures)

    def test_reordering_is_detected(self, tmp_path):
        writer = AuditWriter(tmp_path)
        for index in range(3):
            writer.record(replace(sample_event(), event_id=f"e{index}"))
        lines = writer.filename.read_text(encoding="utf-8").splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        writer.filename.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert not verify_chain(AuditWriter(tmp_path).read_all()).verified

    def test_tail_truncation_is_not_detected(self, tmp_path):
        """A documented limit, pinned rather than papered over.

        Removing the last records leaves a chain that is still self-consistent.
        Detecting it needs an external anchor holding the expected length, which
        this library deliberately does not provide.
        """
        writer = AuditWriter(tmp_path)
        for index in range(4):
            writer.record(replace(sample_event(), event_id=f"e{index}"))
        lines = writer.filename.read_text(encoding="utf-8").splitlines()
        writer.filename.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        report = verify_chain(AuditWriter(tmp_path).read_all())
        assert report.verified
        assert report.total == 2

    def test_records_without_hashes_are_pre_chain(self, tmp_path):
        """A log written by v0.2.1 or earlier must keep verifying."""
        writer = AuditWriter(tmp_path)
        legacy = replace(sample_event(), event_id="legacy")
        writer.filename.write_text(legacy.to_json_line() + "\n", encoding="utf-8")
        writer.record(replace(sample_event(), event_id="chained"))
        report = writer.verify()
        assert report.verified, report.failures
        assert (report.unchained, report.chained) == (1, 1)

    def test_hmac_key_authenticates_records(self, tmp_path):
        key = b"synthetic-test-key"
        AuditWriter(tmp_path, key=key).record(sample_event())
        assert AuditWriter(tmp_path, key=key).verify().verified
        wrong = AuditWriter(tmp_path, key=b"another-key").verify()
        assert not wrong.verified
        assert any("event_hash" in failure for failure in wrong.failures)

    def test_unkeyed_verification_of_a_keyed_log_fails(self, tmp_path):
        AuditWriter(tmp_path, key=b"synthetic-test-key").record(sample_event())
        assert not AuditWriter(tmp_path).verify().verified

    def test_partial_trailing_record_is_not_a_predecessor(self, tmp_path):
        """A failed write can leave a fragment; the next record must not chain
        from it, and the corrupt fragment must not be silently skipped."""
        writer = AuditWriter(tmp_path)
        writer.record(replace(sample_event(), event_id="e0"))
        with open(writer.filename, "ab") as handle:
            handle.write(b'{"event_id": "partial"')
        writer.record(replace(sample_event(), event_id="e1"))
        assert writer.filename.read_bytes().count(b"\n") == 2
        with pytest.raises(AuditError):
            writer.read_all()

    def test_chain_stays_continuous_under_concurrent_writes(self, tmp_path):
        """The lock is what keeps a fork from appearing across processes."""
        import multiprocessing
        from concurrent.futures import ProcessPoolExecutor

        with ProcessPoolExecutor(
            max_workers=4, mp_context=multiprocessing.get_context("spawn")
        ) as executor:
            futures = [
                executor.submit(_write_concurrent_events, str(tmp_path), worker)
                for worker in range(4)
            ]
            for future in futures:
                future.result(timeout=30)
        report = AuditWriter(tmp_path).verify()
        assert report.verified, report.failures
        assert report.chained == 48
