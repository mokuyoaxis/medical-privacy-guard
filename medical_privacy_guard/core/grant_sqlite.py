"""Durable grant consumption for processes sharing one private local database.

Guard checks signatures and disclosure scope before calling this registry.
The registry owns the committed use budget, not approval or issuance. Each
operation opens its own connection; no connection is shared across threads or
forks. The database must be initialized explicitly and is never recreated on
the consumption path.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

from .errors import GrantError
from .grant import Grant, GrantRegistry, _canonical, _now, _parse_iso

__all__ = ["DEFAULT_GRANT_DB_PATH", "SqliteGrantRegistry", "initialize_grant_registry"]

DEFAULT_GRANT_DB_PATH = Path.home() / ".local/state/medical-privacy-guard/grants.sqlite3"

_SCHEMA_VERSION = 1
_USES_SCHEMA = """CREATE TABLE grant_uses (
    grant_key TEXT PRIMARY KEY NOT NULL,
    binding_hash TEXT NOT NULL,
    uses_allowed INTEGER NOT NULL CHECK (
        typeof(uses_allowed) = 'integer' AND uses_allowed > 0
    ),
    uses_consumed INTEGER NOT NULL CHECK (
        typeof(uses_consumed) = 'integer' AND uses_consumed BETWEEN 0 AND uses_allowed
    ),
    expires_at TEXT NOT NULL
)"""
_REVOCATIONS_SCHEMA = """CREATE TABLE grant_revocations (
    grant_key TEXT PRIMARY KEY NOT NULL
)"""


def _absolute_path(path: str | Path) -> Path:
    result = Path(path)
    if not result.is_absolute():
        raise GrantError("grant database path must be absolute")
    return result


def _private_path(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_mode = 0o700 if directory else 0o600
    if (not expected_type(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != expected_mode):
        raise GrantError(
            f"grant {'directory' if directory else 'database'} must be owned by "
            f"the current user with mode {expected_mode:04o}; symlinks are not supported"
        )


def _open(path: Path, timeout: float) -> sqlite3.Connection:
    _private_path(path.parent, directory=True)
    _private_path(path)
    return sqlite3.connect(
        path.as_uri() + "?mode=rw", uri=True, timeout=timeout, isolation_level=None
    )


def _durability(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
        raise GrantError("grant database requires DELETE journal mode")
    connection.execute("PRAGMA synchronous=EXTRA")
    if connection.execute("PRAGMA synchronous").fetchone()[0] != 3:
        raise GrantError("grant database requires EXTRA synchronization")


def _check_schema(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION:
        raise GrantError("grant database has an unsupported or uninitialized schema")
    tables = dict(connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ))
    if tables != {"grant_uses": _USES_SCHEMA, "grant_revocations": _REVOCATIONS_SCHEMA}:
        raise GrantError("grant database schema does not match its version")


def initialize_grant_registry(path: str | Path = DEFAULT_GRANT_DB_PATH) -> None:
    """Create a new private database; refuse to overwrite any existing file.

    The immediate parent is created with mode 0700 if absent. Existing parent
    permissions are checked, never changed. A failed initialization leaves its
    file in place for diagnosis; there is no automatic cleanup or migration.
    """
    target = _absolute_path(path)
    try:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _private_path(target.parent, directory=True)
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        with closing(_open(target, 5.0)) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            _durability(connection)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_USES_SCHEMA)
            connection.execute(_REVOCATIONS_SCHEMA)
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            connection.execute("COMMIT")
            _check_schema(connection)
    except (OSError, sqlite3.Error) as exc:
        raise GrantError("could not initialize the grant database") from exc


class SqliteGrantRegistry(GrantRegistry):
    """Atomic committed use budgets for one machine and one system user.

    All consumers must share this absolute path on private local Linux storage.
    Restoring an old database or replacing it can restore spent uses: the store
    is not an authenticated rollback detector. Use a new signing key or let all
    old grants expire before switching from memory or restoring old state.
    """

    def __init__(
        self, path: str | Path = DEFAULT_GRANT_DB_PATH, *, timeout_seconds: float = 5.0
    ) -> None:
        self.path = _absolute_path(path)
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0 <= timeout_seconds <= 2_147_483.647):
            raise GrantError("grant database timeout must be between 0 and 2147483.647 seconds")
        self.timeout_seconds = float(timeout_seconds)
        # Validate without keeping a connection or allocating an in-memory store.
        with self._connection():
            pass

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        try:
            with closing(_open(self.path, self.timeout_seconds)) as connection:
                _durability(connection)
                _check_schema(connection)
                yield connection
        except (OSError, sqlite3.Error) as exc:
            raise GrantError("SQLite grant registry operation failed") from exc

    def remaining(self, grant_id: str) -> int:
        """Return committed uses, retaining GrantRegistry's legacy naming."""
        key = hashlib.sha256(grant_id.encode("utf-8")).hexdigest()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT uses_consumed FROM grant_uses WHERE grant_key=?", (key,)
            ).fetchone()
            return row[0] if row is not None else 0

    def revoke(self, grant_id: str) -> bool:
        """Permanently revoke an ID, including one not consumed yet.

        Return True for a new tombstone, False if already revoked. This is a
        deployment-side operation, not an authorization service. Revocation
        commits under the same writer lock as consumption; it stops subsequent
        consumption, not a release already accepted before that commit.
        """
        if not isinstance(grant_id, str) or not grant_id:
            raise GrantError("revocation requires a non-empty grant ID")
        key = hashlib.sha256(grant_id.encode("utf-8")).hexdigest()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            inserted = connection.execute(
                "INSERT OR IGNORE INTO grant_revocations VALUES (?)", (key,)
            ).rowcount
            connection.execute("COMMIT")
            return inserted == 1

    def is_revoked(self, grant_id: str) -> bool:
        """Read committed revocation status without changing the use budget."""
        key = hashlib.sha256(grant_id.encode("utf-8")).hexdigest()
        with self._connection() as connection:
            return connection.execute(
                "SELECT 1 FROM grant_revocations WHERE grant_key=?", (key,)
            ).fetchone() is not None

    def consume(self, grant: Grant, store: dict[str, int] | None = None) -> bool:
        """Commit one use, or return False for expiry, revocation or exhaustion.

        Storage failures and conflicting identities raise GrantError. A later
        transformation, verification, audit or sending failure never refunds a
        committed use. Guard owns signature and disclosure-scope validation.
        """
        if store is not None:
            raise GrantError("SQLite grant consumption cannot use an external mapping")
        if grant.uses_allowed > 2**63 - 1:
            raise GrantError("grant use budget exceeds SQLite's integer range")
        key = hashlib.sha256(grant.grant_id.encode("utf-8")).hexdigest()
        binding = hashlib.sha256(_canonical(
            {**grant._payload(), "signature": grant.signature}
        )).hexdigest()
        expires = _parse_iso(grant.expires_at)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Lock waiting must not carry a formerly valid grant past its expiry.
            if expires <= _now():
                return False
            if connection.execute(
                "SELECT 1 FROM grant_revocations WHERE grant_key=?", (key,)
            ).fetchone() is not None:
                return False
            row = connection.execute(
                "SELECT binding_hash, uses_allowed, expires_at FROM grant_uses WHERE grant_key=?",
                (key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO grant_uses VALUES (?, ?, ?, 0, ?)",
                    (key, binding, grant.uses_allowed, grant.expires_at),
                )
            elif row != (binding, grant.uses_allowed, grant.expires_at):
                raise GrantError("grant identity conflicts with its stored binding")
            updated = connection.execute(
                "UPDATE grant_uses SET uses_consumed=uses_consumed+1 "
                "WHERE grant_key=? AND uses_consumed<uses_allowed", (key,),
            ).rowcount
            connection.execute("COMMIT")
            return updated == 1
