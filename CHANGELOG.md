# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-09-22

### Fixed

- **Staff and relative names were released partially redacted.** The nurse,
  physician and relative detectors bounded a labelled name with the given-name
  character inventory, which cannot be complete. A name whose given character
  was outside it was captured only up to the surname and the remainder was
  released: ``责任护士：郑爽。`` sanitized to ``责任护士：[NURSE_NAME_001]爽。``
  while verification reported success, because an orphaned given-name character
  no longer matches a name pattern. A labelled value is now bounded by its
  separator and a following-boundary word instead of the inventory, so the whole
  name is captured whatever characters it uses.
- ``医生：X``, ``主刀医生：X``, ``管床医生：X`` and ``值班医生：X`` produced no
  ``DOCTOR_NAME`` fact at all — the title list omitted them. ``护士：X`` and
  ``护师：X`` were missing from the nurse list in the same way.
- Adjacent staff and relative names (``其妻郑爽陪同``) truncated at the same
  character inventory. The inventory is extended with given-name characters that
  are overwhelmingly names rather than ordinary words.
- A bracketed value after a staff or relative label (``家属：王芳（女儿）``,
  ``主治医师：王建国（主任）``) yielded no fact at all, and a compound surname in
  the title-suffix form (``欧阳娜娜医生``) was missed because that branch carried
  no compound-surname alternative.

### Added

- Verification rejects a name span that stops inside the name, or that is
  followed by text no boundary word explains. The check reads the original text,
  because re-detection cannot see a character the detector never captured. A
  truncated name withholds release instead of being silently released.
- ``NAME_FOLLOW_BOUNDARY`` (shared boundary words) and ``FIELD_SEP_REQUIRED`` (a
  separator that must be present), so the labelled and adjacent name shapes are
  handled by distinct rules instead of one permissive rule that has to guess.
- ``tests/test_name_span_completeness.py`` (55 cases) and six challenge-corpus
  regression probes covering labelled values outside the inventory, the added
  staff labels, and two over-redaction controls.

### Documentation

- ``docs/scope.md`` records the name-span completeness requirement and the
  fail-closed condition for a name followed by unexplained text.
- ``docs/architecture.md`` no longer states that v0.2 is unreleased.

### Notes

- Remaining trade-off, unchanged in kind from v0.2.0: the adjacent form still
  needs the character inventory, so a name whose given character is outside it is
  missed there (``主治医师欧阳修远`` yields no fact). A labelled field
  (``姓名：``, ``主治医师：``) does not have this limitation.

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

[Unreleased]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.2.0
[0.1.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.1.0
