"""Privacy-safe append-only audit (plan.md §18).

Every decision is auditable without the audit log becoming a new privacy
leak: events carry metadata only — verdict, reason codes, entity type counts,
risk, recipient class, purpose, policy version, applied transformations, and
verification outcome. Raw payloads and raw detector values NEVER enter the
audit stream.

Write failures surface as AuditError so strict profiles can fail closed.
"""

from __future__ import annotations

import json
import os
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from .errors import AuditError
from .model import (
    Decision,
    DetectedFact,
    Purpose,
    Recipient,
    TransformationOp,
)

_ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime(_ISO)


@dataclass(frozen=True)
class AuditEvent:
    """One immutable audit record. Contains no raw sensitive values."""

    event_id: str
    timestamp: str
    decision: str
    reason_codes: tuple[str, ...]
    entity_counts: Mapping[str, int]
    risk_level: str
    risk_score: int
    recipient_class: str
    purpose: str
    policy_profile: str
    policy_version: str
    transformations: tuple[str, ...]
    verification: str

    # -- serialization ------------------------------------------------------

    def to_json_line(self) -> str:
        payload = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "entity_counts": dict(self.entity_counts),
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "recipient_class": self.recipient_class,
            "purpose": self.purpose,
            "policy_profile": self.policy_profile,
            "policy_version": self.policy_version,
            "transformations": list(self.transformations),
            "verification": self.verification,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json_line(cls, line: str) -> "AuditEvent":
        payload = json.loads(line)
        return cls(
            event_id=payload["event_id"],
            timestamp=payload["timestamp"],
            decision=payload["decision"],
            reason_codes=tuple(payload["reason_codes"]),
            entity_counts=dict(payload["entity_counts"]),
            risk_level=payload["risk_level"],
            risk_score=payload["risk_score"],
            recipient_class=payload["recipient_class"],
            purpose=payload["purpose"],
            policy_profile=payload["policy_profile"],
            policy_version=payload["policy_version"],
            transformations=tuple(payload["transformations"]),
            verification=payload["verification"],
        )


def build_audit_event(
    decision: Decision,
    facts: Sequence[DetectedFact],
    recipient: Recipient,
    purpose: Purpose,
    verification: str = "N/A",
    event_id: str | None = None,
) -> AuditEvent:
    """Build an audit event from a decision; raw values are never included.

    entity_counts records only fact *types*; transformations are described by
    op+entity_type only. DetectedFact values are deliberately ignored.
    """
    counts = Counter(f.type for f in facts)
    transformations = _transform_labels(decision.plan.operations if decision.plan else ())
    return AuditEvent(
        event_id=event_id or uuid.uuid4().hex,
        timestamp=_now_iso(),
        decision=decision.verdict.value,
        reason_codes=tuple(rc.value for rc in decision.reason_codes),
        entity_counts=dict(counts),
        risk_level=decision.risk.level.value,
        risk_score=decision.risk.score,
        recipient_class=recipient.trust_level.value,
        purpose=purpose.value,
        policy_profile=decision.policy_version.split("/", 1)[0],
        policy_version=decision.policy_version,
        transformations=transformations,
        verification=verification,
    )


def _transform_labels(ops: Sequence[TransformationOp]) -> tuple[str, ...]:
    return tuple(f"{op.op}_{op.entity_type or op.target}" for op in ops)


class AuditWriter:
    """Appends AuditEvents to an append-only JSONL file.

    Every record() call opens the file in append mode and fsyncs the write, so
    the log is durable and immutable-by-convention. `strict=True` (default)
    raises AuditError on any write failure so callers can BLOCK.
    """

    def __init__(self, directory: str | Path, strict: bool = True) -> None:
        self.directory = Path(directory)
        self.strict = strict
        self.filename = self.directory / "events.jsonl"
        self._ensure_writable()

    def _ensure_writable(self) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditError(f"cannot create audit directory {self.directory}: {exc}") from exc
        try:
            # Create the log with owner-only permissions; tighten existing
            # files too (the audit stream is sensitive metadata).
            fd = os.open(self.filename, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
            current = os.stat(self.filename).st_mode & 0o777
            if current & 0o077:
                os.chmod(self.filename, 0o600)
        except OSError as exc:
            raise AuditError(f"cannot open audit log {self.filename}: {exc}") from exc

    def record(self, event: AuditEvent) -> str:
        """Append one event; returns its event_id."""
        line = event.to_json_line() + "\n"
        try:
            fd = os.open(
                self.filename,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                0o600,
            )
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            if self.strict:
                raise AuditError(f"audit write failed: {exc}") from exc
            # Non-strict mode: degrade silently, but never partially succeed.
            return ""
        return event.event_id

    # -- reading (for tests and status commands) ----------------------------

    def read_all(self) -> tuple[AuditEvent, ...]:
        """Read every event in the log, in append order."""
        if not self.filename.is_file():
            return ()
        events: list[AuditEvent] = []
        with open(self.filename, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    events.append(AuditEvent.from_json_line(stripped))
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise AuditError(f"corrupt audit line: {exc}") from exc
        return tuple(events)

    def __len__(self) -> int:
        return len(self.read_all())
