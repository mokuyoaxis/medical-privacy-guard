"""Privacy-safe append-only audit.

Every decision is auditable without the audit log becoming a new privacy
leak: events carry metadata only — verdict, reason codes, entity type counts,
risk, recipient class, purpose, policy version, applied transformations, and
verification outcome. Raw payloads and raw detector values NEVER enter the
audit stream.

Write failures surface as AuditError so strict profiles can fail closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

try:  # POSIX advisory locking; not available on Windows.
    import fcntl
except ImportError:  # pragma: no cover - Windows only
    fcntl = None

from .errors import AuditError
from .model import (
    Decision,
    DetectedFact,
    Purpose,
    Recipient,
    TransformationOp,
)

_ISO = "%Y-%m-%dT%H:%M:%S.%fZ"

#: Predecessor hash of the first chained record.
GENESIS_HASH = "0" * 64

#: Initial window when reading the chain head from the tail. Grown until it
#: covers the file: a single event can exceed 30 KB, because reason_codes
#: carry long synthetic metadata in the concurrency tests.
_TAIL_WINDOW = 65536


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
    #: Chained-integrity fields. Empty on records written before v0.2.2; such
    #: records are treated as pre-chain rather than corrupt, so an existing
    #: audit log keeps verifying.
    prev_hash: str = ""
    event_hash: str = ""

    # -- serialization ------------------------------------------------------

    def _payload(self) -> dict:
        """Canonical payload excluding ``event_hash``, which hashes it."""
        return {
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
            "prev_hash": self.prev_hash,
        }

    def to_json_line(self) -> str:
        payload = {**self._payload(), "event_hash": self.event_hash}
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)

    def compute_hash(self, key: bytes | None = None) -> str:
        """Hash the canonical payload, with ``prev_hash`` chained in.

        With *key* this is an HMAC-SHA256, which also authenticates the record
        against rewriting. Without a key the chain detects accidental damage
        and naive tampering (deleted, reordered or edited records) only; a
        writer can always recompute a whole chain. See
        ``.internal/audit-hash-chain-plan-2026-09-22.md`` for the threat table.
        """
        canonical = json.dumps(self._payload(), ensure_ascii=False, sort_keys=True)
        data = canonical.encode("utf-8")
        if key:
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def chained(self, prev_hash: str, key: bytes | None = None) -> "AuditEvent":
        """Return a copy linked to *prev_hash*, with its hash computed."""
        linked = replace(self, prev_hash=prev_hash)
        return replace(linked, event_hash=linked.compute_hash(key))

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
            prev_hash=payload.get("prev_hash", ""),
            event_hash=payload.get("event_hash", ""),
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
    """Appends chained AuditEvents to an append-only JSONL file.

    Each event uses one O_APPEND write followed by fsync. Short writes fail
    without retrying: retries could interleave concurrent events. A failed
    write may leave a partial record; it is never reported as success.

    Every event also carries the previous event's hash, so deleting,
    reordering or editing a record is detectable. A chain turns the append into
    a read-modify-write, so the read and the write happen under an exclusive
    ``flock``; without ``fcntl`` (Windows) the chain is still written but
    concurrency falls back to the filesystem's append semantics. Locking is
    advisory and not guaranteed on network filesystems.

    Truncating the tail is not detectable without an external anchor, and an
    unkeyed chain can be recomputed wholesale by anyone able to write the file.
    Pass *key* for an HMAC that also authenticates records.

    `strict=True` (default) raises AuditError on any write failure.
    """

    def __init__(
        self, directory: str | Path, strict: bool = True, key: bytes | None = None
    ) -> None:
        self.directory = Path(directory)
        self.strict = strict
        self.key = key
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
        """Append one chained event; returns its event_id.

        The link is read and written under one lock, because a chain turns the
        append into a read-modify-write: two writers that both read the same
        predecessor would fork it. Read and write share a single file
        descriptor, since ``flock`` binds to the open file description and a
        second descriptor for the same file would block against the first.
        """
        try:
            fd = os.open(
                self.filename,
                os.O_RDWR | os.O_APPEND | os.O_CREAT,
                0o600,
            )
            try:
                locked = self._acquire(fd)
                try:
                    linked = event.chained(self._chain_head(fd), self.key)
                    data = (linked.to_json_line() + "\n").encode("utf-8")
                    if os.write(fd, data) != len(data):
                        raise OSError("incomplete audit event write")
                    os.fsync(fd)
                finally:
                    if locked:
                        self._release(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            if self.strict:
                raise AuditError(f"audit write failed: {exc}") from exc
            return ""
        return event.event_id

    # -- chained integrity --------------------------------------------------

    @staticmethod
    def _acquire(fd: int) -> bool:
        """Take the exclusive lock, or report that locking is unavailable."""
        if fcntl is None:
            return False
        fcntl.flock(fd, fcntl.LOCK_EX)
        return True

    @staticmethod
    def _release(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    def _chain_head(self, fd: int) -> str:
        """Return the last chained record's hash, or GENESIS_HASH.

        Reads backwards from the tail, growing the window until it covers the
        file so a single large event cannot be missed. A trailing partial
        record (the documented outcome of a failed write) is discarded rather
        than treated as a link.
        """
        size = os.fstat(fd).st_size
        if size == 0:
            return GENESIS_HASH
        window = _TAIL_WINDOW
        while True:
            start = max(0, size - window)
            chunk = os.pread(fd, size - start, start)
            lines = chunk.split(b"\n")
            if start > 0:
                # The window may open mid-record; drop that fragment.
                lines = lines[1:]
            elif chunk and not chunk.endswith(b"\n"):
                # Partial trailing record: never a valid predecessor.
                lines = lines[:-1]
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                digest = payload.get("event_hash")
                if digest:
                    return digest
            if start == 0:
                return GENESIS_HASH
            window *= 2

    # -- reading (for tests and status commands) ----------------------------

    def read_all(self) -> tuple[AuditEvent, ...]:
        """Read every event in the log, in append order."""
        return read_events(self.filename)

    def verify(self) -> "ChainVerification":
        """Verify chained integrity of the whole log."""
        return verify_chain(self.read_all(), self.key)

    def __len__(self) -> int:
        return len(self.read_all())


def read_events(filename: str | Path) -> tuple[AuditEvent, ...]:
    """Read every event from *filename*, in append order.

    Read-only: unlike ``AuditWriter`` this never creates the directory or the
    log, so a verification command cannot turn a typo into an empty audit log.
    A missing file reads as an empty log.
    """
    path = Path(filename)
    if not path.is_file():
        return ()
    events: list[AuditEvent] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                events.append(AuditEvent.from_json_line(stripped))
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise AuditError(f"corrupt audit line: {exc}") from exc
    return tuple(events)


@dataclass(frozen=True)
class ChainVerification:
    """Outcome of verifying an audit chain."""

    total: int
    chained: int
    unchained: int
    failures: tuple[str, ...]

    @property
    def verified(self) -> bool:
        """True when every chained record links and hashes correctly."""
        return not self.failures


def verify_chain(
    events: Sequence[AuditEvent], key: bytes | None = None
) -> ChainVerification:
    """Verify chained integrity across *events*, in append order.

    Records written before the chain existed carry no hash. They are counted as
    ``unchained`` and do not fail verification, so a log written by v0.2.1 or
    earlier keeps verifying; the chain starts at the first hashed record.

    Truncation of the tail is deliberately not detectable here: the surviving
    links stay self-consistent. Detecting it needs an external anchor holding
    the expected length, which this library does not provide.
    """
    previous = GENESIS_HASH
    chained = 0
    unchained = 0
    failures: list[str] = []
    for index, event in enumerate(events):
        if not event.event_hash:
            unchained += 1
            continue
        if event.prev_hash != previous:
            failures.append(
                f"record {index}: prev_hash does not match the preceding record"
            )
        expected = event.compute_hash(key)
        if not hmac.compare_digest(expected, event.event_hash):
            failures.append(f"record {index}: event_hash does not match its contents")
        previous = event.event_hash
        chained += 1
    return ChainVerification(
        total=len(events),
        chained=chained,
        unchained=unchained,
        failures=tuple(failures),
    )
