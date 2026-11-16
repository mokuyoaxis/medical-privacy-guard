# Local approval workflow

The CLI and stdio gateway accept deployment-issued grants from private local
files. Requests produced by Guard include a signature over the metadata an
approver reviews. The CLI checks this signature before issuing a grant; an
edited risk score, fact count or purpose cannot silently reach issuance.
Existing trusted Python callers can still construct requests directly.

The signing key is supplied through `MEDICAL_PRIVACY_GUARD_GRANT_KEY` in the
trusted process environment. It is never a command argument, written into a
request/grant file, or printed. These commands do not load a `.env` file or
create/rotate a signing key. The deployment decides who may hold it and issue
grants. `--approve` records the local operator's explicit decision; it does not
authenticate a person or provide an approval UI. Review the local disclosure
and intended recipient before using it.

## CLI

Use a private directory for request and grant files. Writers create new files
with mode `0600` and refuse existing paths. Readers require a regular,
current-user-owned `0600` file and refuse symlinks and non-regular files.

```bash
# Once, on a new private database; skip this if it is already initialized.
medical-privacy-guard grant-db-init

# Exit 3 (ASK), writing only signed metadata, without releasing the input.
medical-privacy-guard sanitize synthetic.json \
  --recipient external_approved --purpose research \
  --approval-request-out request.json

# After local human review. Name only the read-only types being accepted.
medical-privacy-guard grant-issue request.json --approve \
  --issuer local-reviewer --ttl-seconds 300 --accepted-type PHONE \
  --output grant.json

# Exit 0 only when the resulting minimized payload can be released.
medical-privacy-guard sanitize synthetic.json \
  --recipient external_approved --purpose research \
  --grant-file grant.json --output minimized.json
```

`inspect --approval-request-out request.json` can prepare the same disclosure
without transforming or consuming anything. `sanitize --grant-file` uses the
initialized SQLite default; `--grant-db` chooses another absolute path and
`--grant-timeout` configures its lock wait. No grant file means the existing
unapproved-ASK behavior. There is no creation or memory fallback on a missing
database.

An approved release still has verdict ASK inside Guard and the audit. The CLI
returns 0 for its verified release, 3 for a withheld ASK, 2 for BLOCK or failed
verification, and 4 for malformed files/configuration or storage faults.
Rejected or exhausted grants can return a fresh signed review request; request
export still refuses to overwrite an earlier file.

Issuance prints grant ID, expiry and budget, not the signature. With that ID:

```bash
medical-privacy-guard grant-status GRANT_ID
medical-privacy-guard grant-revoke GRANT_ID
```

Status reports **uses consumed**, not uses remaining. Revocation works before
first consumption and after partial consumption. The database is shared across
independent CLI processes and survives restart.

## MCP stdio

Assign an opaque, stable, unique deployment ID to each upstream server. Do not
use a server-reported name as proof of its identity. The
[MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
scopes tool-name uniqueness to one server. Here the disclosure fingerprint also
binds that deployment ID, the actual tool name and the inspected field.

```bash
medical-privacy-guard mcp-gateway \
  --recipient external_approved --purpose research \
  --approval-scope local-service-a \
  --grant-file arguments-grant.json \
  --approval-request-dir approvals \
  -- python -m your_mcp_server
```

The gateway returns signed review requests in JSON-RPC refusal `error.data`
and optionally saves them as private files in the configured `0700` directory.
It can return requests while a configured grant file is absent. After local
review and `grant-issue`, retry the call; files are read again on each call.
Client `approved`, `grant` or `_meta` values are never treated as authorization.

Repeat `--grant-file` for different inspected fields. Files with the same
fingerprint are ambiguous and refused. All fields are preflighted before any
approval is spent, so missing approval for `inputResponses` does not spend an
otherwise valid `arguments` grant. This does not reserve budgets: a concurrent
consumer, conversion/audit failure or later field failure can still spend an
accepted use without forwarding the call. There is no refund or partial forward.

The audit log must be distinct from all configured grant files and the database,
including symlink/hardlink aliases. The gateway checks this before audit creation;
directories are deployment-controlled rather than a hostile filesystem sandbox.

The gateway removes the grant and audit signing-key variables from the upstream
environment. Other server environment variables remain available. This is not
isolation from a malicious process with the same OS privileges. Responses,
stderr and opaque `requestState` remain outside inspection; this is privacy
approval of outbound fields, not authorization of every tool side effect.

Switching old consumers and keys remains an explicit deployment operation; see
[persistent registry recovery](grant-registry.md#data-and-recovery-boundary).

## First adoption without existing consumers

Choose one private local Linux database shared by all consumers under the same
system user. Use the initialized default if it already exists; never reinitialize
it to start another CLI or MCP process. Android shared storage is not the target
for this registry. The lock timeout is configurable; 32 independent processes
have been tested, but the deployment controls its worker count and workload.

Provision the signing key through a trusted process environment. Start with
synthetic input and the CLI workflow above, then select a stable unique MCP
scope and an explicit upstream argv for each server. Verify minimized release,
replay refusal after restart and persistent revocation before handling real data.
Record the installed version, database path and scopes without recording keys,
raw inputs or token-to-original maps. No old-grant migration or key rotation is
needed when no existing consumers or credentials exist.

A successful local rehearsal establishes these runtime paths, not operational
experience under a real workload. Gather that evidence before promoting the
candidate to a stable release; power-loss and old-state rollback limitations
still apply.
