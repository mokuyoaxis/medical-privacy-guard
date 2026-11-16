# ROADMAP

Single version-based roadmap. Each version states its goal, scope, acceptance
criteria, test requirements, and documentation updates. Status is mirrored in
[README.md](README.md); the authoritative capability boundary lives in
[docs/scope.md](docs/scope.md).

Acceptance criteria under completed versions describe their release-time scope;
current capabilities are defined by scope.md and the latest delivered stage.

## Status at a glance

| Version | Theme | Status |
|---|---|---|
| v0.1 | Text core MVP | Released (`v0.1.0`) |
| v0.2 | Chinese medical text detection & evaluation | Released (`v0.2.0`) |
| v0.2.1 | Name-span completeness hotfix | Released (`v0.2.1`) |
| v0.2.2 | Chained audit integrity | Released (`v0.2.2`) |
| v0.2.3 | Audit leak gate false positive | Released (`v0.2.3`) |
| v0.2.4 | Detection coverage | Released (`v0.2.4`) |
| v0.2.5 | Institution vocabulary + detector extension point | Released (`v0.2.5`) |
| v0.2.6 | Remaining detection gaps (numeral dates, out-of-inventory names) | Released (`v0.2.6`) |
| v0.3 | CSV / JSON | **Done** (`v0.3.0` JSON, `v0.3.1` CSV); XLSX deferred (CSV covers the need) |
| v0.3.2 | Generalisation fixes | Released (`v0.3.2`) |
| v0.3.4 | Audit fixes: admission, invisible characters, rebuilt-document gate | Released (`v0.3.4`) |
| v0.4 | Structured formats + egress adapters | Released (`v0.4.0`); DICOM is read-only and experimental |
| v0.5 | ASK approval grants + security hardening | Released (`v0.5.0`), including SQLite consumption/revocation, local approvals and initial dataset measurements |
| v0.6 | Namespace convergence + zero-code gateway | Release candidate (`v0.6.0-rc.1`) |
| v1.0 | Medical AI egress privacy gateway | Target |

The current package version is `0.6.0rc1`, with candidate tag `v0.6.0-rc.1`.
The stable `v0.5.0` tag contains the `v0.5.0-rc.3` code plus documentation
corrections. The work that was planned as separate v0.5 (DICOM)
and v0.6 (FHIR) releases was written in the same week and is folded into v0.4.
Three version numbers in six days would not have been earned by the release
process, and a read-only scanner that cannot clear pixel risk does not deserve
its own minor version.

## Non-goals

These are out of scope for every version:

- Compliance certification of any kind (HIPAA / GDPR / PIPL / institutional).
- Complete-anonymization guarantees.
- Clinical decision support or medical advice.
- Preventing intentional bypass by actors that already hold raw PHI.
- DICOM pixel-data de-identification claims before an implemented pixel-risk
  check exists.

---

## v0.1 — Text core MVP

**Goal**: a stable, honest, installable, tested text privacy guard.

**Delivered**:

- UTF-8 plain text input (Python API + CLI);
- deterministic baseline detectors: CN mobile, CN ID with check digit, email,
  exact dates, labelled patient names / MRNs, HTTP(S) URLs, IPv4, labelled
  precise addresses, baseline medical-content signal;
- policy-driven decision protocol (ALLOW / SANITIZE / ASK / BLOCK);
- REMOVE / MASK / TOKENIZE / GENERALIZE / DATE_SHIFT;
- post-transformation verification plus residual policy re-evaluation;
- metadata-only JSONL audit (0600 permissions, fail-closed writes);
- policy fallback: a detected fact type with no matching policy rule fails
  closed to BLOCK (never ALLOW), covered by unit tests in both builtin
  profiles, including when mixed with transformable fact types.

**Remaining**:

- release engineering: `__version__` ↔ pyproject consistency, CHANGELOG,
  first tagged pre-release.

**Acceptance criteria**:

- all existing tests pass;
- docs claim only implemented capabilities;
- `pip install -e ".[test]"` and the CLI work;
- explicitly typed non-text payloads return BLOCK; CLI rejects known unsupported
  extensions, NUL/control characters and JSON-container content. Arbitrary
  disguised-format detection is not promised; API text callers supply plain text.

**Test requirements**: existing suite stays green; fail-closed behavior
covered by release-gate tests; policy fallback covered by unit tests.

**Docs**: README Implemented / Not implemented / Never claim sections;
ROADMAP.md; docs/scope.md.

---

## v0.2 — Chinese medical text detection & evaluation

**Goal**: move from demo-grade regex detection to a usable Chinese clinical
text baseline, with a measurable evaluation harness. Order matters: build the
evaluation harness and synthetic corpus FIRST, then add detectors one at a
time and quantify the recall/precision change per detector.

**Delivered**:

- synthetic Chinese clinical note corpus: 175 documents across 7 note types
  and 14 departments — 140 positive (1474 character-level span annotations)
  and 35 deliberately identifier-free — with a deterministic generator
  (`tools/generate_synthetic_cn_notes.py`);
- `benchmark` CLI command and `medical_privacy_guard/core/benchmark.py` harness reporting span
  recall/precision, `false_positives_on_clean_documents`,
  `false_allow_count`, `residual_phi_count`, `audit_raw_leak_count`,
  `verification_failure_count` and latency;
- `docs/evaluation.md` with baseline numbers and an explicit statement of what
  the numbers do not prove;
- corpus self-checks (structure, annotation integrity, synthetic-only
  guarantees, byte-exact reproducibility, `PYTHONHASHSEED` independence) and
  benchmark unit/end-to-end tests;
- 15 new fact types, each with policy rules in both builtin profiles and
  positive/negative unit tests: AGE, SEX, HOSPITAL_NAME, DEPARTMENT, WARD,
  BED_NUMBER, DOCTOR_NAME, NURSE_NAME, RELATIVE_NAME, SPECIMEN_ID,
  ACCESSION_NUMBER, LANDLINE, POSTAL_CODE, SOCIAL_MEDIA_ID, RARE_CONTEXT.
  The normal corpus carries 1474 spans across 24 types; its historical overlap
  scorer reported `labelled == detected` and zero residuals, not proof of
  strict exact-span coverage;
- identifier-free near-miss notes supplement annotated notes for false-positive
  measurement. They exposed five over-redaction defects (WARD, HOSPITAL_NAME,
  AGE, RARE_CONTEXT, DEPARTMENT) and a cross-process reproducibility bug;
- a release path that permits policy-approved context-only signals to remain,
  with inert transformer markers and generalized age bands. Context exceptions
  must not exempt untransformed dates or substitute for execution evidence;
- an approved-recipient benchmark with declared verdicts and release counters.
  Its historical aggregate/non-vacuity checks were insufficient: all SANITIZE
  verifications could fail while 35 ALLOW releases still produced PASS, and an
  empty audit log could pass its raw-leak check. Hardened per-document gates
  and strict metrics require fresh validation, described below;
- a generalize transformer for ages (bands), dates (month), locations and
  institution/department/ward names (type markers), replacing the
  date-only generalization path;
- non-transformable context types (`SEX`, `MEDICAL_CONTENT`, `RARE_CONTEXT`)
  are explicitly allow-listed in policy: they contribute risk and can trigger
  ASK, but never demand a transformation plan, and any type outside that
  allow-list still fails closed.

**Remaining**:

- ~~local institution dictionary loading (currently a built-in department list);~~ delivered in v0.2.5 as a local `.csv` / `.json` vocabulary.
- validate security hardening: independent transformation evidence and
  postconditions, bounded CLI format admission, complete audit writes and
  input/output/audit collision protection;
- validate the per-document benchmark gates and strict one-to-one span metrics;
- release engineering for v0.2 (version bump, CHANGELOG and standard release
  checks). Implementation status is not evidence of a passed release build.

**Acceptance criteria**:

- preserve the normal 175-document, 1474-span corpus across 7 note types;
- retain 35 identifier-free near-miss notes and measure false positives on
  annotated notes as well;
- strict one-to-one type/start/end matching has zero false negatives and false
  positives; historical overlap metrics are reported separately;
- zero false ALLOW decisions, residual labelled sensitive values, audit raw
  leaks, verification failures and pipeline errors;
- validate each declared lifecycle: **135 SANITIZE** with completed transformations,
  successful verification and release; **5 ASK** with no release; **35 ALLOW**
  with unchanged release. Aggregate release counts alone are insufficient;
- every document has the expected valid audit event, linked to its decision and
  verification status; missing, corrupt, unreadable or mismatched audit must fail;
- no-op/incomplete transformations, untransformed dates, short audit writes and
  input/output/audit aliases must withhold output;
- known unsupported CLI extensions, NUL/control characters and JSON containers
  must not release. Text API callers remain responsible for plain-text inputs;
- grouped/full-width phone and valid non-padded date variants retain exact source
  spans; independent synthetic challenges do not replace the normal baseline;
- every new detector has positive AND negative tests, including SEX near misses;
- `docs/evaluation.md` distinguishes historical results from newly verified ones.

**Test requirements**: benchmark self-tests and real CLI failure exits for
all/single verification failures, missing/partial/corrupt audit and partial-span
matches; detector, transformation and policy-fallback regressions; standard
build/test/release checks. This list is an acceptance contract, not new test results.

**Docs**: docs/evaluation.md; scope.md update; README status flip to v0.2.

---

## v0.3 — CSV / JSON (XLSX deferred)

**Goal**: serve real clinical research table data.

**Delivered**:

- `medical_privacy_guard/formats/` module: JSON object/array traversal (`v0.3.0`) and CSV parsing
  (`v0.3.1`), both flattening a document into addressable string leaves and
  rebuilding it with its structure intact;
- a key or column name acts as a field label for its value
  (`medical_privacy_guard/formats/leaf.py`), so the label-driven detectors apply to a structured field
  that carries no in-band label. Cells and leaves are scanned regardless, so an
  unconventional header costs a label, not detection;
- one decision per document: a single direct identifier withholds the whole
  record, because a partially released record is where cross-field
  quasi-identifiers do their damage;
- numeric JSON leaves are inspected but never rewritten, and withhold the record
  rather than releasing a number the transformer cannot reach;
- encoding is stated with `--encoding` and never guessed. A wrong codec is
  reported rather than silently retried: mojibake that reaches a model is worse
  than an error that reaches the operator.

**Deferred at v0.3 (later status noted below)**:

- XLSX. CSV covers the same need, and an XLSX reader would add a dependency to a
  project that currently has one;
- `sanitize_file()` as a separate entry point: `Guard.sanitize` with a
  `Payload(kind="csv"|"json")` covers the path, and the CLI writes to a separate
  output file rather than overwriting the input;
- the file-scoped token map, and with it consistent tokenization across a
  dataset: at v0.3, `TokenRegistry` was in-memory and scoped to one
  sanitization, so two rows naming the same person did not share a token across
  files. Batch-scoped consistency was later delivered in rc.3;
- the dataset-level uniqueness check over quasi-identifier columns, and the
  acceptance criterion that depended on it (unique high-risk combinations
  returning ASK/BLOCK);
- GBK / GB18030 auto-detection. Declaring the encoding is the deliberate choice
  above, not an omission.

These are v0.3-time deferrals. Batch-scoped token consistency and initial
aggregate combination measurements were delivered in rc.3; full re-identification
and anonymity models remain out of scope.

**Test requirements**: format regression tests and audit-no-raw-PHI tests for
file outputs are in place. Date-shift consistency across a dataset is not tested;
batch token consistency is covered, but no dataset-wide date-shift guarantee is
claimed.

**Docs**: scope.md; README status flip.

---

## v0.4 — Structured formats + egress adapters

**Goal**: carry the guard beyond plain text, into structured medical formats and
the real call chains that send them.

**Status**: released as `v0.4.0`. The work previously planned as separate v0.5
(DICOM) and v0.6 (FHIR) releases is included here; see the status note above for
why the numbers were collapsed.

### Delivered

- OpenAI-compatible and Anthropic wrappers (`medical_privacy_guard/adapters/`): message content, tool
  arguments, tool descriptions and metadata pass through the guard before the
  SDK call goes out;
- MCP stdio gateway: `tools/call` is forwarded, rewritten or refused; every
  other method, including `server/discover`, is forwarded byte for byte;
- `DisclosureBlocked` / `HumanApprovalRequired` / `VerificationFailed`
  exceptions with documented caller behavior;
- FHIR minimal resource set: `Patient`, `Observation`, `DiagnosticReport`,
  `Condition`, `MedicationRequest`, `Encounter`, `ImagingStudy` and `Bundle`.
  A name split across `Patient.name.family` / `.given` is completed before
  detection; any other resource is withheld (BLOCK);
- read-only DICOM scanner (`dicom-inspect`, optional `dicom` extra): known-PHI
  tags, detector matches over free-text values, private tags counted and marked
  HIGH, pixel risk UNKNOWN so `safe_to_release` is false for every file. The
  scanner never writes a DICOM file;
- multimodal content fails closed.

### Deferred from the original v0.4 scope

- **ASK approval grants** (scoped to a request, expiring, one-time). The
  v0.4.0 release withheld ASK content without implementing grants. The grant
  path is implemented in the v0.5.0-rc.1 candidate below.
- **Tool-name risk classes** (`file_upload`, `email_send`,
  `cloud_storage_upload`). The gateway evaluates the arguments of a call, not
  the tool's name. A caller can add the classification without a protocol
  change, so it is not a blocker for this release.

### Acceptance criteria

- raw PHI never reaches an external LLM request or MCP tool without a Guard
  decision;
- SANITIZE results are verified before send; BLOCK has no fallback;
- wrapper behavior matches Guard API semantics;
- DICOM metadata PHI is detected, including Chinese values under ISO_IR 192;
  private tags are reported HIGH; `safe_to_release` is false while pixel risk is
  UNKNOWN; the scanner never writes a file;
- FHIR reports are path-level, the JSON structure is intact, unsupported
  resources are withheld, and no raw field value enters the audit;
- examples use environment variables for credentials, never literals.

**Test requirements**: wrapper unit tests against a stubbed transport; an MCP
gateway integration test with a stub MCP server; DICOM fixtures under pydicom;
FHIR synthetic fixtures. All are in place.

**Docs**: scope.md; threat-model.md; README status flip.

---

## v0.5 — ASK approvals and security hardening

**Goal**: complete the scoped ASK approval path and verify its release and audit
contracts, including durable SQLite consumption and revocation. Broader dataset
re-identification risk remains planned; initial aggregate combination measurements
are delivered in rc.3.

### Delivered: ASK approval grants

ASK was the one verdict with no working end-to-end path: the guard withheld the
payload and told the caller a scoped grant was required, with nothing in the
library able to say what a grant is. ``medical_privacy_guard/core/grant.py`` closes it.

The guard does **not** decide who may approve — that stays with the deployment,
the same way ``EXTERNAL_APPROVED`` does. It describes what needs approving,
checks a grant against it, and records granted releases in the audit.

- ``ApprovalRequest``: what needs approval. No raw values; binds a fingerprint
  over the payload, recipient, purpose, policy version and decision.
- ``Grant``: deployment-issued, HMAC-signed, with ``expires_at`` and
  ``uses_allowed`` (default 1). Issuing needs a key the payload cannot hold.
- An approved release is still a **minimized** release. The grant carries the
  residual risk of a value the transformer cannot rewrite (a JSON number); it
  does not switch the transformation off. Releasing the original instead would
  mean an approval silently undoes every detector that did fire.
- The verdict stays ``ASK`` through a granted release, and the audit records
  ``grant_id`` / ``grant_issuer``. The record must show that a person accepted a
  risk, not that policy became comfortable with the payload.
- Every grant failure — missing key, bad signature, wrong fingerprint, expired,
  already used, type not accepted — falls back to ASK. None can widen to ALLOW.
- Single-use is enforced by one shared, locked in-memory registry across default
  Guard instances in the process. Concurrent callers cannot exceed the signed
  use budget. It does not survive a restart and is not shared between processes;
  a deployment needing durable single-use injects a registry with atomic
  persistent consumption through ``Guard(registry=...)``.

**Acceptance criteria**: a grant cannot be replayed; does not outlive its scope;
cannot be issued by the payload it authorizes; is not a blanket allow; and never
turns a rejected grant into an ALLOW. Covered by ``tests/test_grants.py``.

### Delivered in rc.2: persistent consumption and revocation

- `SqliteGrantRegistry` for a single machine, private local disk and concurrent
  processes, injected through the existing Guard interface. No new dependency.
- Explicit initialization; schema and private permissions checked; missing state
  and storage errors fail without recreation or memory fallback.
- Atomic committed use budgets and persistent hashed-ID revocations, including
  before first use; timeout configurable and worker count controlled by callers.
- The default remains process-local memory. Backend switches and old backups
  require isolating old valid grants; no rollback-detection claim is made.

**Docs**: [deployment and recovery](docs/grant-registry.md).

### Delivered in rc.3: local approvals and dataset measurements

- Signed review metadata, local human CLI issuance, private grant files and
  SQLite consumption in CLI/MCP. MCP grants bind configured server scope,
  actual tool name and field; client approval claims do not authorize release.
- Batch-scoped in-memory tokens for identical type/value pairs across CSV/JSON
  files. This does not identify people or persist original-value maps.
- Aggregate selected-column combination group sizes and singleton/small-group
  fractions. Engineering measurements remain separate from release decisions.

**Docs**: [local approvals](docs/approval-workflow.md); [datasets](docs/datasets.md).

### Planned follow-up: broader dataset privacy

- Distinct-person analysis, richer quasi-identifiers and external knowledge;
- generalized/suppressed outputs and stronger privacy models;
- deployment approval roles/UI and authenticated detection of restored old state.

**Docs**: scope.md; threat-model.md; README status flip.

---

## v1.0 — Medical AI egress privacy gateway

**Goal**: a real, evaluated, bounded privacy infrastructure project.

**Must have**: text / CSV / XLSX / JSON support; Chinese PHI benchmark; LLM
SDK wrappers; MCP gateway; audit system; ASK approval workflow; institution
dictionaries (local-only loading, synthetic examples in the repo); risk
assessment reports; security boundary docs; release gate; no overstated
compliance claims.

**Release gate (every release)**: unit and integration tests green; synthetic
benchmark metrics met; 0 audit raw leaks; 0 false allows; README/scope claims
match code; `__version__` consistent with pyproject; CHANGELOG updated.
