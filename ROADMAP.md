# ROADMAP

Single version-based roadmap. Each version states its goal, scope, acceptance
criteria, test requirements, and documentation updates. Status is mirrored in
[README.md](README.md); the authoritative capability boundary lives in
[docs/scope.md](docs/scope.md).

## Status at a glance

| Version | Theme | Status |
|---|---|---|
| v0.1 | Text core MVP | Released (`v0.1.0`) |
| v0.2 | Chinese medical text detection & evaluation | Released (`v0.2.0`) |
| v0.3 | CSV / XLSX / JSON | Not started |
| v0.4 | LLM SDK wrapper + MCP gateway | Not started |
| v0.5 | FHIR minimal resource set | Not started |
| v0.6 | DICOM metadata scanner | Not started |
| v1.0 | Medical AI egress privacy gateway | Target |

## Non-goals

These are out of scope for every version:

- Compliance certification of any kind (HIPAA / GDPR / PIPL / institutional).
- Complete-anonymization guarantees.
- Clinical decision support or medical advice.
- Preventing intentional bypass by actors that already hold raw PHI.
- DICOM pixel-data de-identification claims before an implemented pixel-risk
  check exists.

---

## v0.1 — Text core MVP (current)

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
- `benchmark` CLI command and `core/benchmark.py` harness reporting span
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

- local institution dictionary loading (currently a built-in department list);
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

## v0.3 — CSV / XLSX / JSON

**Goal**: serve real clinical research table data.

**Scope**:

- `formats/` module: csv, xlsx (openpyxl), json path traversal;
- column-level detection driven by header-name patterns plus cell-level
  scanning;
- `sanitize_file()` preserving sheet names, row/column structure, headers,
  and data types; output never overwrites input;
- consistent tokenization within a dataset via a file-scoped token map stored
  locally, never written to audit;
- dataset-level uniqueness check over quasi-identifier columns;
- explicit encoding handling for GBK / GB18030 and UTF-8 CSV.

**Acceptance criteria**:

- multi-sheet XLSX handled; structure preserved;
- sanitized reports contain no raw PHI;
- unique high-risk quasi-identifier combinations return ASK/BLOCK.

**Test requirements**: format regression tests; date-shift consistency
tests; audit-no-raw-PHI tests for file outputs.

**Docs**: scope.md; README status flip.

---

## v0.4 — LLM SDK wrapper + MCP gateway

**Goal**: put the guard inside real AI call chains.

**Scope**:

- OpenAI-compatible and Anthropic wrappers (`integrations/`): message
  content, tool arguments, file upload names, and metadata all pass through
  the guard;
- `DisclosureBlocked` / `HumanApprovalRequired` / `VerificationFailed`
  exceptions with documented caller behavior;
- ASK result schema with one-time, expiring grants; no permanent blanket
  allows for high-risk content;
- MCP gateway MVP: stdio transport only; tool arguments become
  DisclosureRequest; high-risk tools (file_upload, email_send,
  cloud_storage_upload) default to ASK/BLOCK;
- multimodal content fails closed in this version.

**Acceptance criteria**:

- raw PHI never reaches an external LLM request without a Guard decision;
- SANITIZE results are verified before send; BLOCK has no fallback;
- wrapper behavior matches Guard API semantics;
- examples use environment variables for credentials, never literals.

**Test requirements**: wrapper unit tests against a stubbed transport; MCP
gateway integration test with a stub MCP server.

**Docs**: scope.md; threat-model.md update for the new trust boundaries;
README status flip.

---

## v0.5 — FHIR minimal

**Goal**: minimal usable FHIR support without promising full
de-identification.

**Scope**:

- Patient, Observation, DiagnosticReport, Condition, MedicationRequest,
  Encounter, ImagingStudy, Bundle;
- path-level transformation plans; JSON structure preserved;
- unsupported resources fail closed (ASK/BLOCK);
- FHIR synthetic fixtures; FHIR-specific audit events (resource type + path,
  never raw values).

**Acceptance criteria**: path-level reports; JSON structure intact; no raw
field values in audit; unsupported resources default to ASK/BLOCK.

**Docs**: scope.md; README status flip.

---

## v0.6 — DICOM metadata scanner

**Goal**: enter medical imaging privacy with an explicit, conservative
boundary.

**Scope**:

- `dicom-inspect` CLI; metadata PHI detection (PatientName, PatientID,
  PatientBirthDate, AccessionNumber, StudyDate / SeriesDate, InstitutionName,
  referring physician / operator names); private tags default REMOVE unless
  allowlisted;
- metadata de-identification with DATE_SHIFT for study/series dates;
- explicit pixel-risk status: `pixel_annotation_risk` and
  `recognizable_visual_features_risk` are UNKNOWN unless an implemented check
  exists; `safe_to_release = false` while UNKNOWN.

**Acceptance criteria**:

- metadata PHI detected; private tags reported high-risk by default;
- `safe_to_release = false` when pixel risk is UNKNOWN;
- reports clearly separate metadata risk from pixel risk.

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
