# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-21

### Added

- Evaluation harness over a 175-document synthetic Chinese clinical corpus
  (140 labelled documents, 1474 spans; 35 identifier-free documents), with
  strict one-to-one span matching, per-document lifecycle gates and
  audit-integrity gates. Expected paths: 135 SANITIZE, 5 ASK, 35 ALLOW.
- CLI format admission: known unsupported extensions, NUL and other unsupported
  control characters, and JSON-container content are blocked before detection.
- Independent recall guard (`detectors/recall_guard.py`) covering the narrative
  `姓名，性别` opener that label-anchored detectors structurally miss.
- Shared field separator (`detectors/field_syntax.py`): colon, equals,
  whitespace, no separator, and bracketed values.
- Detectors for landlines, social-media handles, staff names, relatives named in
  the history, postal codes (label-required), institution, department, ward and
  bed designations, ages in months (1–36), and encounter/action terms as
  medical-content signals.

### Changed

- Transformations and verification enforce type-specific postconditions (date
  precision, age bands, location/institution type markers) rather than
  accepting any value change.
- Audit writes fail closed: short or zero writes, and persistence errors,
  withhold the payload.

### Fixed

- Adjacent person-field over-capture. `患者张三入院` reported `PERSON_NAME`
  `张三入院`, and `患者于协和医院住院治疗` reported `于协和医院住院` while never
  emitting `HOSPITAL_NAME`; sanitizing the latter released
  `患者[PERSON_NAME_001]治疗` with exit `0`. The adjacent form is now capped at
  four characters, excludes institution words, and stops at clinical verbs and
  connectives.
- Institution names preceded by a function word (`患者在宣武医院住院`) were
  discarded whole instead of truncated at the last rejected character.
- Age in months (`患儿6个月`) produced no `AGE` fact.
- Address labels `户籍地`, `户籍所在地`, `籍贯`, `工作单位`, `单位地址` were missing.
- Narrative medical statements without a label word (`因脑梗死入院`) bypassed the
  ASK path for unknown recipients.
- The labelled rare-context phrase `罕见变异型病例` was detected only as
  `罕见变异`, and a document-level `MEDICAL_CONTENT` match then displaced the
  shorter rare-context fact, silently skipping the ASK path.
- English MRN `medical record number` self-matched, making that field
  impossible to verify.
- Record/specimen numbers reported spans via `m.end() - len(value)`, absorbing a
  trailing bracket and raising `TransformerError`.

### Documentation

- `docs/scope.md` is the authoritative capability boundary, with explicit
  measured-vs-unmeasured, deliberate non-detection, and prohibited-claims
  sections.
- `docs/evaluation.md` records strict results, fault-injection evidence, and the
  corpus's structural blind spots.
- `docs/threat-model.md` and `docs/decision-protocol.md`.

## [0.1.0] - 2026-08-29

### Added

- UTF-8 plain-text input through the Python API and the CLI.
- Deterministic baseline detectors: CN mobile numbers, CN resident ID with GB
  11643-1999 check digit, email, exact dates, labelled patient names and MRNs,
  HTTP(S) URLs, IPv4 addresses, labelled precise addresses, and a baseline
  medical-content signal.
- Policy-driven decision protocol: ALLOW / SANITIZE / ASK / BLOCK, with a
  fail-closed fallback for a detected fact type that has no matching rule.
- Transformations: REMOVE, MASK, TOKENIZE, GENERALIZE, DATE_SHIFT.
- Post-transformation verification and residual policy re-evaluation.
- Metadata-only JSONL audit (owner-only permissions, fail-closed writes).

[Unreleased]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.2.0
[0.1.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.1.0
