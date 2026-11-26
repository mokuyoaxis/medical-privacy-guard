# Roadmap

Where this project has been, and where it is going — the short version.
Each release's full goals and acceptance criteria are preserved in
[docs/roadmap-details.md](docs/roadmap-details.md); the authoritative
capability boundary is [docs/scope.md](docs/scope.md).

## Where we are

Current stable: **v0.7.0** (package version `0.7.0`).
Previous stable: **v0.6.3**. Next stop: **v1.0**.

| Version | Theme | Status |
|---|---|---|
| v0.1 | Text core: detect, decide, transform, verify, audit | Released (`v0.1.0`) |
| v0.2 | Chinese clinical text detection + a real evaluation corpus | Released (`v0.2.0`) |
| v0.2.1–v0.2.6 | Hotfixes and coverage: name spans, chained audit, numeral ages and dates, institution vocabulary | Released |
| v0.3 | JSON, then CSV, for structured clinical data | Released (`v0.3.0`, `v0.3.1`); XLSX deferred — CSV covers the need |
| v0.3.2 / v0.3.4 | Generalisation fixes; admission and audit fixes | Released |
| v0.4 | Structured formats + egress adapters: FHIR set, read-only DICOM scanner, SDK wrappers, MCP gateway | Released (`v0.4.0`) |
| v0.5 | ASK approval grants + hardening: signed grants, SQLite registry, local approvals, dataset measurements | Released (`v0.5.0`) |
| v0.6 | One namespace (`medical_privacy_guard`), stable public API, zero-code HTTP gateway | Released (`v0.6.0`) |
| v0.6.1 | Static HTML audit and grant report (`report`, English and Simplified Chinese) | Released (`v0.6.1`) |
| v0.6.2 | Dataset re-identification risk in the report, benchmark over-redaction rate, challenge-corpus evidence-line detector fixes | Released (`v0.6.2`) |
| v0.6.3 | Third policy preset (`teaching-demo`), discoverable presets, LiteLLM deployment example | Released (`v0.6.3`) |
| v0.7.0 | DICOM de-identification export (PS3.15 Basic Profile, mechanical full-table diff) with conformance statement; LiteLLM guide finalized on pinned 1.108.0 LTS | Released (`v0.7.0`) |
| v1.0 | Medical AI egress privacy gateway | Target |

A note on numbering, because it confuses people: the work once planned as
separate v0.5 (DICOM) and v0.6 (FHIR) releases was written in the same week
and folded into v0.4. Three version numbers in six days would not have been
earned by the release process, and a read-only scanner that cannot clear
pixel risk does not deserve its own minor version.

## The road to v1.0

**Goal**: a real, evaluated, bounded privacy gateway for medical AI egress —
the thing the README describes, finished and proven.

Must have:

- Text / CSV / JSON support (done), XLSX only if a real need shows up —
  CSV currently covers the same ground;
- the Chinese PHI benchmark, kept honest (done, and kept growing);
- LLM SDK wrappers and the zero-code gateway (done);
- the MCP gateway (done);
- the audit system with chained integrity (done);
- the ASK approval workflow (done);
- institution dictionaries, local-only loading with synthetic examples
  (done in v0.2.5);
- risk assessment reports (partly: dataset measurements shipped in v0.5;
  fuller re-identification analysis is still open);
- security boundary docs (done) and a release gate (below);
- and no compliance claims the code cannot back up.

Publishing to PyPI landed with v0.6.0 (2026-11-18), so
`pip install medical-privacy-guard` simply works. Still genuinely open on the
way to v1.0: growing the hand-written generalisation corpus so the evaluation
says more about real text and less about templates.

## Non-goals

Out of scope for every version, by design:

- Compliance certification of any kind (HIPAA / GDPR / PIPL / institutional).
- Complete-anonymisation guarantees.
- Clinical decision support or medical advice.
- Preventing intentional bypass by actors who already hold raw PHI.
- DICOM pixel-data de-identification claims before an implemented
  pixel-risk check exists.

## Release gate (every release)

Unit and integration tests green; synthetic benchmark metrics met; zero
audit raw leaks; zero false allows; README/scope claims match the code;
`__version__` consistent with pyproject; CHANGELOG updated.
