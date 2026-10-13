# Persistent grant consumption

`core.grant_sqlite.SqliteGrantRegistry` provides committed use budgets and
revocation for processes on one machine sharing one private local database.
It uses Python's standard-library SQLite; no extra dependency is required.
The default Guard registry remains in memory. Inject this backend explicitly
into each Guard that must share durable state.

## Initialization and configuration

The default path is `~/.local/state/medical-privacy-guard/grants.sqlite3`, resolved
against the current user's home directory. All consumers must use the same absolute path and system
user. The directory and its ancestors must be deployment-controlled, on private
local Linux storage, rather than Android shared storage or a network filesystem.

Initialize once, before consumers start:

```python
from core.grant_sqlite import initialize_grant_registry

initialize_grant_registry()  # Refuses any existing file, including an empty one.
```

The immediate parent is created with mode `0700` if absent, and the database
with mode `0600`. Existing permissions are checked, never silently changed.
Opening a registry checks the schema and uses `mode=rw`: a missing, corrupt or
unsupported database raises `GrantError` and is never replaced by an empty one.
A failed initialization leaves its file for explicit diagnosis. There is no
automatic migration, cleanup or database restoration.

Inject a registry into each consumer:

```python
from core.grant_sqlite import SqliteGrantRegistry
from medical_privacy_guard import Guard

registry = SqliteGrantRegistry(timeout_seconds=5.0)
guard = Guard(registry=registry)
```

Guard uses the existing deployment-configured grant key. The registry does not
issue grants or authenticate an approver. A custom absolute path and lock-wait
timeout can be supplied to the constructor. SQLite waits for at most that timeout
on a lock; there is no additional retry or memory fallback.

The deployment target is 9–32 concurrent CLI/MCP/Python processes. Worker count
belongs to the caller and can be changed; the registry neither starts workers
nor enforces a process limit. Tests exercise 32 independent Python processes
competing for one-use and three-use grants. CLI and MCP can explicitly select
this registry and use private local grant files through the
[local approval workflow](approval-workflow.md).

## Consumption and revocation

Guard checks the signature, disclosure fingerprint, time window and accepted
read-only types before consumption. Each operation opens and closes its own
connection, including when the registry object is shared across threads or
inherited by a fork. A short [`BEGIN IMMEDIATE` transaction](https://www.sqlite.org/lang_transaction.html)
serializes the binding check and counter update. Expiry is checked again after obtaining the
writer lock. `DELETE` journaling with
[`synchronous=EXTRA`](https://www.sqlite.org/pragma.html#pragma_synchronous) is required.

Only a successful commit returns an accepted use. Conversion, verification,
audit or sending failure after that commit does not refund it. Reusing an ID
with different signed fields or a larger budget raises `GrantError` instead of
resetting its counter. Storage failures also raise; exhaustion, revocation or
expiry while waiting return False and leave Guard's ASK withheld.

```python
registry.revoke(grant_id)       # True if newly revoked, False if already revoked.
registry.is_revoked(grant_id)   # Read committed status.
registry.remaining(grant_id)    # Legacy name: returns uses consumed, not uses left.
```

Revocation stores a hashed ID even when no consumption record exists. It
commits under the same writer lock as consumption. After it commits, no new
use of that ID is accepted, including in another process or after restart.
A use accepted before revocation may already be transforming or sending data;
revocation cannot retract it. There is no un-revoke operation or automatic
tombstone expiry. Issue a new grant with a new ID for a new approval.

## Data and recovery boundary

Schema v1 stores SHA-256 grant IDs, a digest of the signed binding, budget,
committed uses, expiry and hashed revocation tombstones. It stores no payload,
PHI, grant signature, signing key or token-to-original mapping.

These digests do not authenticate database history. Replacing the database or
restoring an old backup can restore spent uses or erase later revocations.
Before switching from memory or restoring older state, stop issuance and
consumers, then rotate the signing key or wait for every old grant to expire.
Do not restore state while old consumers or valid old grants remain active.

Crash tests establish rollback before commit and retained consumption after
commit. Device power loss is not tested; durability also depends on the local
filesystem honoring SQLite synchronization. Filesystem replacement races and
an actor with the same storage privileges are outside this backend's protection.
