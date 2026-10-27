# Architecture

## Positioning

`medical-privacy-guard` is a privacy execution layer that sits between medical data and AI/external capabilities. It does not perform clinical decisions, legal certification, or complete anonymization. Its job is to decide:

> **May this disclosure happen, and if so, what is the minimum safe representation that may cross the trust boundary?**

## High-level pipeline

The implemented path accepts plain text, JSON, CSV and a minimal FHIR resource
set. The MCP stdio gateway and the OpenAI-compatible and Anthropic wrappers
ship. Batch-scoped token consistency and aggregate quasi-identifier combination
measurements are implemented as engineering aids; XLSX, DICOM write-back, full
dataset-level re-identification/population-risk analysis and anonymization
models are future work.

```text
Text / JSON / CSV / FHIR (shared admission and normalization)
  │
  ▼
Detect sensitive facts
  │
  ▼
Build disclosure context + engineering risk summary
  │
  ▼
Policy decision
  │
  ├── BLOCK ────────▶ audit when configured + refuse
  ├── ASK ──────────▶ withhold without a valid deployment-issued grant
  │    └── valid grant ▶ transform + verify + audit + minimized release
  ├── ALLOW ────────▶ audit when configured + return unchanged payload
  └── SANITIZE
         │
         ▼
      Transform + internal execution evidence
         │
         ▼
      Verify evidence / postconditions + re-scan / re-evaluate policy
         │
         ├── fail ───▶ audit when configured + withhold
         └── pass ───▶ audit when configured + return sanitized payload
```

Every transformation must be verified before release; a configured audit
failure must prevent release. The evidence/postcondition checks are the
hardening contract, not proof of complete anonymization. See
[evaluation.md](evaluation.md) for validation status.

## Components

| Component | Responsibility | Output |
|---|---|---|
| `medical_privacy_guard/guard.py`, `cli/main.py` | Evaluate a caller-declared payload and decide | `Decision` |
| `formats/admission.py` | Decide what content is *before* it is scanned; shared by the CLI and the adapters | `Payload` |
| `detectors` | Output sensitive-entity facts, not policy decisions | `DetectedFact` |
| `core/policy.py` | Summarize engineering risk and evaluate facts + context | `Decision` + `DisclosurePlan` |
| `core/grant.py` | Bind approval to a disclosure, verify the grant and consume its use budget | `ApprovalRequest` / accepted or rejected grant |
| `core/grant_sqlite.py` | Persist atomic budgets and ID revocation for processes sharing private local disk | committed acceptance / refusal / `GrantError` |
| `core/grant_files.py` | Read/write private local approval files without key exposure | signed request / grant objects |
| `core/dataset.py` | Share batch tokens and report aggregate selected-column combinations | per-file Guard results / engineering counts |
| `transformers` | Execute deterministic planned operations | transformed text + internal evidence |
| `core/verify.py` | Independently check evidence/postconditions, re-scan and re-run policy | pass / fail |
| `core/audit.py` | Append metadata-only events with a hash chain when configured | JSONL event |
| `core/dictionary.py` | Load a local institution vocabulary (CSV/JSON) | `InstitutionDictionary` |
| `formats/` | Flatten a JSON, CSV or FHIR payload into string leaves and rebuild it | `StructuredPayload` |
| `formats/dicom_inspect.py` | Read DICOM metadata and report identifiers; never writes | `DicomReport` |
| `core/benchmark.py` | Evaluate detection and per-document lifecycle expectations | benchmark report |
| `adapters/` | Classify an external call into a payload and enforce the decision before sending | `Payload` (`payload_for`, `release_or_raise`) |
| `adapters/mcp_gateway.py` | Proxy a stdio MCP session, holding back `tools/call` the guard refuses | rewritten / refused JSON-RPC |
| `adapters/openai_compat.py`, `adapters/anthropic_compat.py` | Evaluate every egress field of a vendor SDK call before it is sent | rewritten kwargs / raised verdict |

## Component boundaries

- **Detectors do not decide.** They emit facts; policy chooses the outcome.
- **A structured payload is one disclosure.** Its leaves are flattened into a
  single text for detection, transformation and verification, and the verdict
  covers the whole document: an untransformable identifier withholds the record
  until a valid grant accepts its residual risk. Leaves
  are joined with NUL so two adjacent values cannot form a pattern that exists
  in neither.
- **No facts is not proof of safety.** Unrecognized content may produce ALLOW;
  re-scanning with the same detectors cannot independently establish recall.
- **Core is deterministic.** The same request and policy version should yield
  the same decision and reason codes; risk scores are not re-identification probabilities.
- **Transform is explicit.** The plan names each operation. Internal evidence
  links original targets to output replacements and parameters, and may contain
  sensitive data; it must stay in local memory, not public facts or audit logs.
- **Verification does not trust an action label.** No-op, incomplete or
  mismatched operations must fail. GENERALIZE needs type-specific postconditions;
  DATE_SHIFT needs the expected offset and interval consistency. An unchanged
  exact date is not exempt merely because its planned action is DATE_SHIFT or
  GENERALIZE. Context-only signals may remain only as permitted by policy.
- **Approval is explicit.** Guard forwards approval state only after signature,
  scope, validity and consumption checks. The verifier and rebuilt-document gate
  both need that state for ASK; accepted types alone do not represent approval.
  Approved read-only spans are traced through execution offsets, while writable
  spans of the same type still require full transformation.
- **Adapters do not contain privacy rules.** Their role is to translate
  external calls and enforce the core result, not to redefine policy.

## Trust boundary

```text
┌──────────────────── Trusted Local Boundary ────────────────────┐
│                                                                │
│  EHR / local files / DICOM / FHIR                              │
│             │                                                  │
│             ▼                                                  │
│       medical-privacy-guard                                    │
│             │                                                  │
│      ┌──────┴───────┐                                          │
│      │              │                                          │
│    BLOCK       sanitized payload                               │
│                     │                                          │
└─────────────────────┼──────────────────────────────────────────┘
                      ▼
             external trust boundary
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
    Cloud LLM       MCP tool       Web/API
```

Deployment objective: **route medical payloads through the Guard before
external disclosure**. The diagram shows the intended boundary, not network
enforcement: the library cannot prevent a caller from sending raw content
directly, and DICOM support is read-only inspection, not de-identification.

## Current security contract and hardening requirements

1. **Verify-after-transform**: SANITIZE requires independent transformation
   evidence/postcondition checks plus re-scan and policy re-evaluation.
2. **No-silent-fallback**: verification or transformation failures must not
   return the original payload as releasable content.
3. **Audit-no-raw-PHI**: configured audit events contain metadata, not raw values,
   token maps or internal execution evidence. Audit failure, including short
   writes, must withhold release; unsupported typed payloads also need BLOCK events.
   Events are chained by hash so deletion, reordering and edits are detectable;
   tail truncation and keyless whole-chain rewriting are not, and are documented
   as such rather than implied to be covered.
4. **Bounded input admission**: unsupported declared payload kinds BLOCK. String
   inputs are classified through the shared admission rule: valid JSON/FHIR
   containers are walked as structured documents. Known unsupported extensions,
   unsupported control characters and recognized malformed containers are
   refused. Explicit `Payload(kind="text")` skips classification, but still
   undergoes normalization; arbitrary disguised formats cannot all be identified.
5. **Output separation**: input/output/audit collisions, including existing
   hard-link aliases, must be rejected before writes. Static path checks are
   not a guarantee against filesystem races.
6. **Unknown-recipient-is-not-trusted**: unknown endpoints are not approved.
   The deployment supplies trusted recipient metadata; the library is not
   an authorization service for self-declared `EXTERNAL_APPROVED` values.
7. **Policy version is auditable**: decisions carry the policy profile/version.
8. **Approval remains scoped**: a granted ASK still transforms and verifies the
   releasable payload. All default Guard instances in a process share one locked
   registry, so concurrent callers cannot exceed the signed use budget. An
   injected registry owns its consumption scope and must consume atomically.

The hardening requirements above need code and fault-injection validation;
historical corpus scores do not establish them. No-facts ALLOW and detector
blind spots remain possible despite fail-closed handling of recognized errors.

## Integration invariants

These hold for the shipped adapters and for anything built on top of them:

- An adapter calls Guard before sending and does not reimplement policy.
- Callers may supply their own detectors through ``Guard(detectors=...)``,
  including model-backed ones. They may only extend recall: they must return
  ``DetectedFact`` and must not decide verdicts, skip verification, or write
  audit records. The built-in rule set stays the default and the only path that
  requires no optional dependencies.
- A real egress boundary still needs network and credential restrictions outside
  this library.

Not yet implemented:

- Full dataset-level re-identification/population-risk analysis and anonymization
  models. The shipped combination measurements are aggregate engineering aids
  only.
- Approval UI, roles and approval chains. Scoped/expiring grants, process-local
  consumption and an optional SQLite consumption/revocation backend are
  implemented; deployment-side code decides who may issue or revoke them.
- Multi-machine consumption and authenticated detection of restored old state.
- DICOM write-back must keep metadata cleaning and pixel risk separate. The
  read-only scanner already reports them separately; it does not write.

## Relationship to agent-guard

The concept for `medical-privacy-guard` grew partly out of the earlier
`agent-guard` project. They remain independent sibling projects with separate
threat models and execution engines while sharing the same Guard philosophy:

```text
Irreversible consequences must cross a guard.
```

They differ in what they protect:

| | agent-guard | medical-privacy-guard |
|---|---|---|
| Protected consequence | destructive effect | sensitive disclosure |
| Core question | Can this action be recovered? | Can this disclosure be minimized and verified? |
| Automatic safe action | compensation / relocation | sanitize / minimize |
| Post-action verification | recoverability state | re-scan / verification |

The two projects are independent repositories with no runtime dependency.

## Directory layout

```text
medical-privacy-guard/
├── README.md
├── LICENSE
├── SECURITY.md
├── ROADMAP.md
├── pyproject.toml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── decision-protocol.md
│   ├── scope.md
│   ├── grant-registry.md
│   ├── approval-workflow.md
│   ├── datasets.md
│   └── evaluation.md
├── core/
│   ├── __init__.py
│   ├── model.py
│   ├── errors.py
│   ├── policy.py
│   ├── grant.py
│   ├── grant_sqlite.py
│   ├── grant_files.py
│   ├── dataset.py
│   ├── verify.py
│   ├── benchmark.py
│   └── audit.py
├── detectors/
│   ├── __init__.py
│   ├── base.py
│   ├── registry.py
│   ├── surnames.py
│   ├── regex.py
│   ├── cn_identifiers.py
│   ├── dates.py
│   ├── person.py
│   ├── location.py
│   ├── medical_content.py
│   ├── medical_record.py
│   ├── demographics.py
│   ├── institution.py
│   └── clinical_context.py
├── transformers/
│   ├── __init__.py
│   ├── base.py
│   ├── registry.py
│   ├── text.py
│   ├── generalize.py
│   └── dates.py
├── policies/
│   ├── external-ai-strict.yaml
│   └── research.yaml
├── cli/
│   ├── __init__.py
│   └── main.py
├── formats/                   # admission + json / csv / fhir; dicom_inspect (read-only)
├── adapters/                  # mcp_gateway + openai_compat + anthropic_compat
├── tools/
│   └── generate_synthetic_cn_notes.py
├── skills/
│   └── medical-privacy-guard/
│       └── SKILL.md
└── tests/
    ├── fixtures/
    │   ├── synthetic/
    │   └── synthetic_cn_notes/
    └── test_*.py
```

## Current implemented scope

- plain-text input through the Python API and UTF-8 CLI;
- deterministic Chinese clinical identifier and context detectors, including
  narrative names anchored on a gender marker, a complaint verb or a connective;
- policy-driven transformations followed by mandatory verification;
- metadata-only JSONL audit before release when configured;
- JSON, CSV and a minimal FHIR resource set, plus a read-only DICOM scanner;
- CSV/JSON batch token consistency and aggregate combination measurements
  (engineering-only; they do not authorize release or claim anonymity);
- MCP stdio gateway and OpenAI-compatible / Anthropic client wrappers;
- explicit non-text payloads BLOCK; format admission has the bounded checks
  described in [scope.md](scope.md), not universal format identification;
- a synthetic evaluation corpus and benchmark with strict per-document gates,
  plus a hand-written generalisation corpus that is not a build gate.

The library offers a guarded application path, not a network-level enforcement
boundary or an anonymity guarantee.

## Authoritative scope

The supported/unsupported capability list is owned by [scope.md](scope.md);
version planning and acceptance criteria live in [ROADMAP.md](../ROADMAP.md).
Where prose in this document disagrees with those files, those files win.
