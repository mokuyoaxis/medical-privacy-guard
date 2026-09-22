# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.6] - 2026-09-22

### Added

- **Chinese numeral dates** (``二〇二六年九月二十一日``). Formal documents and
  signature lines write dates this way; they matched no pattern, so the note was
  released with the date intact. Now detected, generalized to the month and
  verified, and the digit and numeral forms reach the same output. Impossible
  calendar dates (``二〇二三年二月三十日``) are still not facts.
- **Title-suffix names whose given character is outside the inventory**
  (``郑沫医生``, ``欧阳修远医生``). The title already supplies the end boundary,
  so the inventory only caused misses here; the same names behind a labelled
  field were captured whole.
- Ten challenge probes that had been deleted are absorbed: eight reach their
  declared verdict and now run in CI, two are bare-name forms that stay outside
  the baseline and are recorded as exploratory. Six further coverage probes
  cover the new forms and their over-redaction controls.

### Changed

- ``_DOCTOR_SUFFIX_RE`` and ``_NURSE_SUFFIX_RE`` capture a lazy 0–2 given-name
  characters instead of drawing from the name inventory. The negative
  lookbehinds that stop 主任医师 and 责任护士 from matching inside a title word
  are unchanged, and a full title is still not absorbed (``患者李四住院医师``
  yields no doctor).

### Documentation

- ``tests/fixtures/challenge/README.md`` dimensions: narrative 24 regression /
  6 exploratory, coverage 16 regression.

## [0.2.5] - 2026-09-22

### Added

- **Local institution vocabulary** (``.csv`` or ``.json``), loading institution,
  department, ward and staff terms. Terms are detected alongside the built-in
  rules — an institution's own records are stronger evidence than a shape match,
  so the dictionary detector reports higher confidence and wins on overlap.
- **The first genuinely independent verification signal.** A term the rules
  never knew cannot be found by re-scanning with those same rules; the
  vocabulary can. A surviving term fails verification with
  ``DICTIONARY_RESIDUAL``.
- ``Guard(dictionary_path=...)`` and ``--dictionary`` on ``inspect`` and
  ``sanitize``. No dictionary means no behaviour change.
- ``Guard(detectors=...)``, the reserved extension point for callers that want
  to add their own detectors (including models). Supplied detectors may only
  extend recall: policy still decides, verification still runs, audit is still
  written by the guard.
- Audit events carry ``dictionary_loaded`` and ``dictionary_entries`` — counts
  only. The vocabulary names real institutions and real staff, so its contents
  never enter an audit record, a log line or an error message.

### Notes

- A dictionary term in a referral context (``建议神经内科会诊``) stays
  undetected, and verification agrees: the residual check reuses the detector
  rather than re-implementing the match rules, so the two cannot disagree and
  no note containing a referral is blocked. ``docs/scope.md`` owns that
  judgement, not the vocabulary.
- Loading fails closed: an unreadable file, a missing header, an unknown
  category or an empty term raises rather than being skipped, because a
  vocabulary the deployment believes is active but which loaded nothing is
  worse than none.
- ``.xlsx`` is deliberately not supported; ``.csv`` covers the same need
  without adding a dependency.

## [0.2.4] - 2026-09-22

### Added

- **Chinese numeral ages** (``五十六岁``, ``两岁``) are detected and
  generalized. Digits and numerals now reach the same verdict: previously
  ``患者，女，56岁。`` was sanitized while ``患者，女，五十六岁。`` produced no
  fact at all and was released unchanged — including the sex beside it, because
  the sex rule keyed off the digits.
- **Comma-separated sex** (``患者，女，67岁``). The adjacent-only form missed it
  while the digits-only variant still matched, so the gap was invisible.
- **Bracketed name values** (``患者（张三）``, ``患者姓名（李四）``).
- **Labelled bed numbers** (``床号 12``, ``床号：A03``). ``床位`` is
  deliberately not a label: it is a capacity concept, not an identifier.
- **Unlabelled addresses** introduced by a residence verb
  (``患者住北京市朝阳区建国路1号。``). The value must end at an administrative or
  street suffix, and ``住院`` / ``住所`` / ``住房`` are excluded explicitly, so
  ordinary prose does not match.

### Fixed

- Age generalization and the age postcondition now understand Chinese numerals.
  Detection alone was not enough: the fact was reported, policy planned
  GENERALIZE, and the transformer raised ``cannot generalize age value`` —
  turning a silent release into a failed request. Detection, transformation and
  verification are pinned together by the new tests.

### Documentation

- ``tests/fixtures/challenge/`` gains a ``coverage`` dimension with ten probes,
  four of them over-redaction controls.

## [0.2.3] - 2026-09-22

### Fixed

- **The audit leak gate reported raw leaks on logs that leaked nothing.** The
  gate scans the whole audit stream for corpus values with a naive substring
  test, and the stream carries random hex: ``event_id`` (a UUID, 32 characters)
  and, since v0.2.2, ``prev_hash`` / ``event_hash`` (64 characters each). A
  six-digit postal code such as ``730908`` occurs inside a 64-character hash by
  chance, and because the gate is absolute (must be 0) a single chance hit
  failed the whole run. The three random fields are now stripped before
  scanning; they carry no payload, so a genuine leak in a semantic field is
  still caught. Eight regression tests pin both directions.

### Notes

- This is the intermittent benchmark failure recorded in
  ``.internal/ci-flaky-investigation-2026-09-21.md``, previously attributed to
  runner resource timing. That conclusion was wrong: the failing gate was
  ``audit_raw_leak``, not one of the three counters the note suggested checking.
  The defect predates v0.2.2 — the chain hashes raised the random hex from 32 to
  160 characters per record, which made the existing flake reproducible rather
  than causing it.

## [0.2.2] - 2026-09-22

### Added

- **Chained audit integrity.** Every audit event now carries ``prev_hash`` and
  ``event_hash``, so a deleted, reordered or edited record is detectable.
  ``AuditWriter`` reads and writes the link under an exclusive ``flock``,
  because a chain turns the append into a read-modify-write and two writers that
  read the same predecessor would fork it. Without ``fcntl`` (Windows) the chain
  is still written, but concurrency falls back to the filesystem's append
  semantics as in v0.2.1.
- ``audit-verify`` CLI command and ``verify_chain()`` API, reporting total,
  chained and pre-chain counts plus per-record failures. Exit codes: ``0``
  intact, ``2`` broken, ``4`` unreadable. A missing log is an error, not an
  intact chain.
- Optional HMAC key through ``Guard(audit_key=...)`` or the
  ``MEDICAL_PRIVACY_GUARD_AUDIT_KEY`` environment variable. A key authenticates
  records against wholesale rewriting; an unkeyed chain only detects accidental
  damage and naive tampering. The key is read from the environment rather than
  argv so it never appears in a process listing.
- ``read_events()`` for read-only log access that never creates the directory or
  the log.

### Changed

- Audit records written by v0.2.1 and earlier carry no hashes. They are read as
  "pre-chain", counted separately, and do not fail verification, so an existing
  log keeps verifying; the chain starts at the first hashed record.
- The benchmark's audit schema gate expects the two new fields. Its exact
  field-set check is unchanged and still rejects any unexpected field.

### Notes

- What the chain does **not** cover, stated rather than implied: tail truncation
  (the surviving links stay self-consistent), whole-chain rewriting without a
  key, and timestamp authenticity. Detecting the first needs an external anchor
  holding the expected length, which this library deliberately does not provide.
  See ``.internal/audit-hash-chain-plan-2026-09-22.md``.

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

[Unreleased]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.6...HEAD
[0.2.6]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.2.0
[0.1.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.1.0
