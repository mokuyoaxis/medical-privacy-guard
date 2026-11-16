"""Persistent grant budgets, real multi-process releases and failure boundaries."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import sqlite3
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event, get_ident

import pytest

from medical_privacy_guard import Guard
from medical_privacy_guard.core.errors import AuditError, GrantError
from medical_privacy_guard.core.grant import Grant, GrantIssuer
from medical_privacy_guard.core.grant_sqlite import SqliteGrantRegistry, initialize_grant_registry
from medical_privacy_guard.core.model import Payload, Purpose, Verdict

KEY = b"synthetic-sqlite-grant-key"
DOCUMENT = {"name": "测试患者甲", "phone": 13800000000, "mobile": "13900000000"}
RECIPIENT = "external_approved"
PURPOSE = Purpose.RESEARCH
_START = None


def _request(guard):
    return guard.sanitize(Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE)


def _issue(*, uses=1, ttl=300):
    request = _request(Guard(grant_key=KEY)).approval_request
    return GrantIssuer(KEY, issuer="synthetic-deployment").issue(
        request, ttl_seconds=ttl, uses_allowed=uses, accepted_types=("PHONE",)
    )


def _start_workers(barrier):
    global _START
    _START = barrier


def _release_worker(arguments):
    path, raw = arguments
    registry = SqliteGrantRegistry(path)
    guard = Guard(grant_key=KEY, registry=registry)
    if _START is not None:
        _START.wait(timeout=120)
    result = guard.sanitize(
        Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE, grant=Grant.from_json(raw)
    )
    if result.sanitized_payload is None:
        return False
    assert result.decision_before.verdict is Verdict.ASK
    assert result.verification is not None and result.verification.passed
    output = json.loads(result.sanitized_payload.content)
    assert output["phone"] == DOCUMENT["phone"]
    assert output["mobile"] != DOCUMENT["mobile"] and output["name"] != DOCUMENT["name"]
    return True


def _crash_worker(path, raw, after_commit):
    registry = SqliteGrantRegistry(path)
    if not after_commit:
        connect = sqlite3.connect

        class CrashBeforeCommit(sqlite3.Connection):
            def execute(self, statement, parameters=()):
                if statement == "COMMIT":
                    os._exit(17)
                return super().execute(statement, parameters)

        def crash_connection(*args, **kwargs):
            return connect(*args, **kwargs, factory=CrashBeforeCommit)

        sqlite3.connect = crash_connection
    registry.consume(Grant.from_json(raw))
    os._exit(17)


def _revoke_worker(path, grant_id):
    return SqliteGrantRegistry(path).revoke(grant_id)


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "private" / "grants.sqlite3"
    initialize_grant_registry(path)
    return path


def test_initialization_creates_private_schema_and_refuses_overwrite(database):
    assert database.parent.stat().st_mode & 0o777 == 0o700
    assert database.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    original = database.read_bytes()
    with pytest.raises(GrantError, match="initialize") as error:
        initialize_grant_registry(database)
    assert isinstance(error.value.__cause__, FileExistsError)
    assert database.read_bytes() == original


@pytest.mark.parametrize("operation", [initialize_grant_registry, SqliteGrantRegistry])
def test_relative_paths_are_refused(operation):
    with pytest.raises(GrantError, match="absolute"):
        operation("synthetic-relative.sqlite3")


def test_missing_database_is_never_created(tmp_path):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(GrantError) as error:
        SqliteGrantRegistry(path)
    assert isinstance(error.value.__cause__, FileNotFoundError)
    assert not path.exists()


@pytest.mark.parametrize("target, mode", [("file", 0o644), ("directory", 0o755)])
def test_insecure_permissions_are_refused_without_changing_them(database, target, mode):
    path = database if target == "file" else database.parent
    path.chmod(mode)
    with pytest.raises(GrantError, match="mode"):
        SqliteGrantRegistry(database)
    assert path.stat().st_mode & 0o777 == mode


@pytest.mark.parametrize("target", ["file", "directory"])
def test_symlinks_are_refused(database, tmp_path, target):
    link = tmp_path / "link"
    link.symlink_to(database if target == "file" else database.parent)
    path = link if target == "file" else link / database.name
    with pytest.raises(GrantError, match="symlinks"):
        SqliteGrantRegistry(path)


@pytest.mark.parametrize("timeout", [-1, True, "5", float("nan"), float("inf"), 2_147_484])
def test_invalid_timeouts_are_explicit_errors(database, timeout):
    with pytest.raises(GrantError, match="timeout"):
        SqliteGrantRegistry(database, timeout_seconds=timeout)


def test_corrupt_file_is_not_recreated(tmp_path):
    path = tmp_path / "corrupt.sqlite3"
    path.write_bytes(b"synthetic-invalid-database")
    path.chmod(0o600)
    with pytest.raises(GrantError) as error:
        SqliteGrantRegistry(path)
    assert isinstance(error.value.__cause__, sqlite3.DatabaseError)
    assert path.read_bytes() == b"synthetic-invalid-database"


@pytest.mark.parametrize("change", ["future-version", "missing-table", "changed-table", "wal"])
def test_unknown_state_fails_without_reinitialization(database, change):
    with sqlite3.connect(database) as connection:
        if change == "future-version":
            connection.execute("PRAGMA user_version=2")
        elif change == "missing-table":
            connection.execute("DROP TABLE grant_uses")
        elif change == "changed-table":
            connection.execute("ALTER TABLE grant_uses ADD COLUMN unexpected TEXT")
        else:
            connection.execute("PRAGMA journal_mode=WAL")
    with pytest.raises(GrantError, match="schema|journal"):
        SqliteGrantRegistry(database)


def test_committed_state_survives_a_new_registry(database):
    grant = _issue(uses=3)
    first = SqliteGrantRegistry(database)
    assert first.remaining(grant.grant_id) == 0
    assert first.consume(grant)
    second = SqliteGrantRegistry(database)
    assert second.remaining(grant.grant_id) == 1
    assert second.consume(grant) and first.consume(grant)
    assert not SqliteGrantRegistry(database).consume(grant)
    assert first.remaining(grant.grant_id) == 3


def test_database_stores_only_hashed_identity_binding_and_budget(database):
    grant = replace(_issue(), grant_id="SYNTH-SENSITIVE-ID").signed(KEY)
    registry = SqliteGrantRegistry(database)
    assert registry.consume(grant)
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT * FROM grant_uses").fetchone()
    assert row[0] == hashlib.sha256(grant.grant_id.encode()).hexdigest()
    assert len(row[1]) == 64 and row[2:4] == (1, 1) and row[4] == grant.expires_at
    raw = database.read_bytes()
    for value in [grant.grant_id, grant.issuer, grant.signature, *map(str, DOCUMENT.values())]:
        assert value.encode() not in raw
    assert KEY not in raw


@pytest.mark.parametrize("field, value", [("uses_allowed", 3), ("issuer", "synthetic-other")])
def test_a_conflicting_identity_cannot_reset_or_increase_the_budget(database, field, value):
    registry = SqliteGrantRegistry(database)
    grant = _issue()
    assert registry.consume(grant)
    with pytest.raises(GrantError, match="binding"):
        registry.consume(replace(grant, **{field: value}).signed(KEY))
    assert registry.remaining(grant.grant_id) == 1
    assert not registry.consume(grant)


def test_external_mapping_cannot_bypass_sqlite(database):
    registry = SqliteGrantRegistry(database)
    grant = _issue()
    with pytest.raises(GrantError, match="external mapping"):
        registry.consume(grant, store={})
    assert registry.remaining(grant.grant_id) == 0


def test_too_large_a_budget_is_an_explicit_storage_boundary(database):
    registry = SqliteGrantRegistry(database)
    with pytest.raises(GrantError, match="integer range"):
        registry.consume(_issue(uses=2**63))


@pytest.mark.parametrize("uses", [1, 3])
def test_real_guards_in_32_processes_share_one_budget(database, uses):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(32)
    grant = _issue(uses=uses)
    with ProcessPoolExecutor(
        max_workers=32, mp_context=context, initializer=_start_workers, initargs=(barrier,)
    ) as executor:
        released = list(executor.map(_release_worker, [(str(database), grant.to_json())] * 32))
    assert sum(released) == uses
    assert SqliteGrantRegistry(database).remaining(grant.grant_id) == uses
    with ProcessPoolExecutor(max_workers=1, mp_context=context) as executor:
        assert not executor.submit(_release_worker, (str(database), grant.to_json())).result(45)


def test_a_shared_registry_opens_connections_in_the_calling_thread(database):
    registry = SqliteGrantRegistry(database)
    grant = _issue(uses=3)
    barrier = Barrier(8)

    def consume(_):
        barrier.wait(timeout=15)
        return registry.consume(grant)

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(consume, range(8))) == 3
    assert registry.remaining(grant.grant_id) == 3


@pytest.mark.parametrize("after_commit", [False, True])
def test_process_crash_retains_only_committed_uses(database, after_commit):
    grant = _issue()
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_crash_worker, args=(str(database), grant.to_json(), after_commit))
    process.start()
    process.join(45)
    assert process.exitcode == 17
    registry = SqliteGrantRegistry(database)
    assert registry.remaining(grant.grant_id) == int(after_commit)
    assert registry.consume(grant) is (not after_commit)


def test_lock_timeout_fails_closed_without_fallback(database):
    registry = SqliteGrantRegistry(database, timeout_seconds=0.02)
    grant = _issue()
    with sqlite3.connect(database, isolation_level=None) as lock:
        lock.execute("BEGIN IMMEDIATE")
        with pytest.raises(GrantError) as error:
            registry.consume(grant)
        assert isinstance(error.value.__cause__, sqlite3.OperationalError)
        lock.execute("ROLLBACK")
    assert registry.remaining(grant.grant_id) == 0
    assert registry.consume(grant)


def test_expiry_is_checked_after_acquiring_the_write_lock(database, monkeypatch):
    from medical_privacy_guard.core import grant_sqlite

    grant = _issue()
    registry = SqliteGrantRegistry(database)
    locked = False
    connect = sqlite3.connect

    class ObserveLock(sqlite3.Connection):
        def execute(self, statement, parameters=()):
            nonlocal locked
            cursor = super().execute(statement, parameters)
            if statement == "BEGIN IMMEDIATE":
                locked = True
            return cursor

    def observe_connection(*args, **kwargs):
        return connect(*args, **kwargs, factory=ObserveLock)

    def expired_clock():
        assert locked
        return datetime.strptime(grant.expires_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        ) + timedelta(seconds=1)

    monkeypatch.setattr(sqlite3, "connect", observe_connection)
    monkeypatch.setattr(grant_sqlite, "_now", expired_clock)
    assert not registry.consume(grant)
    assert registry.remaining(grant.grant_id) == 0


@pytest.mark.parametrize("operation", ["consume", "revoke"])
def test_commit_failure_never_reports_success_or_changes_state(database, monkeypatch, operation):
    registry = SqliteGrantRegistry(database)
    grant = _issue()
    connect = sqlite3.connect

    class FailingCommit(sqlite3.Connection):
        def execute(self, statement, parameters=()):
            if statement == "COMMIT":
                raise sqlite3.OperationalError("synthetic commit failure")
            return super().execute(statement, parameters)

    def failing_connection(*args, **kwargs):
        return connect(*args, **kwargs, factory=FailingCommit)

    monkeypatch.setattr(sqlite3, "connect", failing_connection)
    with pytest.raises(GrantError) as error:
        if operation == "consume":
            registry.consume(grant)
        else:
            registry.revoke(grant.grant_id)
    assert str(error.value.__cause__) == "synthetic commit failure"
    assert registry.remaining(grant.grant_id) == 0
    assert not registry.is_revoked(grant.grant_id)


def test_a_grant_that_expires_while_waiting_is_not_consumed(database):
    registry = SqliteGrantRegistry(database)
    grant = _issue(ttl=1)
    with sqlite3.connect(database, isolation_level=None) as lock:
        lock.execute("BEGIN IMMEDIATE")
        with ThreadPoolExecutor(max_workers=1) as executor:
            attempt = executor.submit(registry.consume, grant)
            time.sleep(1.1)
            lock.execute("ROLLBACK")
            assert not attempt.result(10)
    assert registry.remaining(grant.grant_id) == 0


def test_runtime_database_loss_raises_without_recreation_or_release(database):
    registry = SqliteGrantRegistry(database)
    grant = _issue()
    saved = database.with_suffix(".saved")
    database.rename(saved)
    with pytest.raises(GrantError) as error:
        Guard(grant_key=KEY, registry=registry).sanitize(
            Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE, grant=grant
        )
    assert isinstance(error.value.__cause__, FileNotFoundError)
    assert not database.exists() and saved.exists()


def test_initialization_failure_preserves_the_file_for_diagnosis(tmp_path, monkeypatch):
    path = tmp_path / "failed.sqlite3"

    def fail_connection(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic initialization failure")

    monkeypatch.setattr(sqlite3, "connect", fail_connection)
    with pytest.raises(GrantError) as error:
        initialize_grant_registry(path)
    assert str(error.value.__cause__) == "synthetic initialization failure"
    assert path.exists() and path.stat().st_mode & 0o777 == 0o600


def test_invalid_signature_does_not_consume_durable_state(database):
    registry = SqliteGrantRegistry(database)
    guard = Guard(grant_key=KEY, registry=registry)
    grant = _issue()
    rejected = guard.sanitize(
        Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE,
        grant=replace(grant, signature="invalid"),
    )
    assert rejected.sanitized_payload is None
    assert registry.remaining(grant.grant_id) == 0
    assert guard.sanitize(
        Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE, grant=grant
    ).sanitized_payload is not None


def test_unseen_grant_can_be_revoked_before_any_use(database):
    grant = _issue()
    registry = SqliteGrantRegistry(database)
    assert not registry.is_revoked(grant.grant_id)
    assert registry.revoke(grant.grant_id)
    assert not registry.revoke(grant.grant_id)
    other = SqliteGrantRegistry(database)
    assert other.is_revoked(grant.grant_id)
    assert not other.consume(grant)
    assert other.remaining(grant.grant_id) == 0
    assert grant.grant_id.encode() not in database.read_bytes()


def test_revocation_from_another_process_stops_a_remaining_budget(database):
    registry = SqliteGrantRegistry(database)
    grant = _issue(uses=3)
    assert registry.consume(grant)
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=1, mp_context=context) as executor:
        assert executor.submit(_revoke_worker, str(database), grant.grant_id).result(45)
        assert not executor.submit(_release_worker, (str(database), grant.to_json())).result(45)
    assert registry.is_revoked(grant.grant_id)
    assert registry.remaining(grant.grant_id) == 1


@pytest.mark.parametrize("grant_id", ["", None, 1])
def test_revocation_requires_an_explicit_string_id(database, grant_id):
    with pytest.raises(GrantError, match="non-empty"):
        SqliteGrantRegistry(database).revoke(grant_id)


@pytest.mark.parametrize("first", ["consume", "revoke"])
def test_revocation_and_consumption_serialize_in_commit_order(database, monkeypatch, first):
    registry = SqliteGrantRegistry(database)
    grant = _issue(uses=3)
    commit_reached, second_started, finish_commit = Event(), Event(), Event()
    held_thread = None
    connect = sqlite3.connect

    class ObserveTransactions(sqlite3.Connection):
        def execute(self, statement, parameters=()):
            if statement == "BEGIN IMMEDIATE" and get_ident() != held_thread:
                second_started.set()
            if statement == "COMMIT" and get_ident() == held_thread:
                commit_reached.set()
                assert finish_commit.wait(15)
            return super().execute(statement, parameters)

    def observe_connection(*args, **kwargs):
        return connect(*args, **kwargs, factory=ObserveTransactions)

    def operation(name, hold=False):
        nonlocal held_thread
        if hold:
            held_thread = get_ident()
        return registry.consume(grant) if name == "consume" else registry.revoke(grant.grant_id)

    monkeypatch.setattr(sqlite3, "connect", observe_connection)
    with ThreadPoolExecutor(max_workers=2) as executor:
        held = executor.submit(operation, first, True)
        try:
            assert commit_reached.wait(15)
            other = executor.submit(operation, "revoke" if first == "consume" else "consume")
            assert second_started.wait(15)
        finally:
            finish_commit.set()
        assert held.result(15)
        assert other.result(15) is (first == "consume")
    assert registry.is_revoked(grant.grant_id)
    assert registry.remaining(grant.grant_id) == (1 if first == "consume" else 0)
    assert not registry.consume(grant)


@pytest.mark.parametrize("failure", ["transform", "audit"])
def test_failures_after_consumption_do_not_refund_the_budget(database, monkeypatch, failure):
    registry = SqliteGrantRegistry(database)
    guard = Guard(grant_key=KEY, registry=registry)
    grant = _issue()
    if failure == "transform":
        monkeypatch.setattr(
            "medical_privacy_guard.transformers.text.TextTransformer.apply", lambda self, fact, op, tokens: fact.value
        )
        result = guard.sanitize(
            Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE, grant=grant
        )
        assert result.sanitized_payload is None
        assert result.verification is not None and not result.verification.passed
    else:
        def fail_audit(self, event):
            raise AuditError("synthetic audit failure")

        monkeypatch.setattr("medical_privacy_guard.core.audit.AuditWriter.record", fail_audit)
        with pytest.raises(AuditError, match="synthetic"):
            guard.sanitize(
                Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE, grant=grant,
                audit_dir=str(database.parent / "audit"),
            )
    assert registry.remaining(grant.grant_id) == 1
    assert guard.sanitize(
        Payload(kind="json", content=DOCUMENT), RECIPIENT, PURPOSE, grant=grant
    ).sanitized_payload is None
