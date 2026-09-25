# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **MCP stdio gateway**: ``medical-privacy-guard mcp-gateway -- <server command>``
  spawns an MCP server and mediates one stdio session with it, so an MCP client
  can be pointed at the guard instead of at the server. Newline-delimited
  JSON-RPC is forwarded byte for byte except for ``tools/call``: ALLOW forwards,
  SANITIZE rewrites ``params.arguments`` and ``params.inputResponses``, and
  ASK/BLOCK return a JSON-RPC error without reaching the server. Byte streams are
  used throughout, because text mode would translate newlines and corrupt the
  framing. The wrapped server's exit code is propagated, and Ctrl+C terminates
  it rather than orphaning it.

- ``adapters.ingress``: ``payload_for``, ``evaluate_call`` and ``sanitize_call``,
  the entry half of the adapter contract, so an adapter classifies the call
  rather than trusting the caller's guess. A JSON document arriving as a string
  is declared a JSON payload. Scanned as prose it loses the key-derived field
  labels, and ``{"name": "张三"}`` yields no fact at all — the key is not a
  Chinese label and a bare name is deliberately not detected — so the call would
  have been released with the name in it.
- ``formats/admission.py``: the classification the CLI already had, extracted so
  both entry points share one implementation instead of two that drift. The CLI
  now calls it rather than owning it. ``tools/audit_contracts.py`` gains a fifth
  section that fails when a second classifier appears or when a structured call
  reaches ALLOW; it was confirmed to fail with the adapter degraded to treating
  strings as prose.

### Fixed

- **An invisible character switched name detection off entirely.** The name
  detectors end a captured value on punctuation, whitespace or a boundary word,
  and Unicode's format characters are none of those. One U+200B after — or
  inside — a name made ``PERSON_NAME``, ``DOCTOR_NAME``, ``NURSE_NAME`` and
  ``RELATIVE_NAME`` miss, while verification re-ran the same detectors and
  reported success: ``患者姓名：张伟<U+200B>，联系电话13800000000`` was released
  with the name intact, and ``{"name": "张伟<U+200B>"}`` likewise.
  ``core/textnorm.strip_invisible`` now removes format characters, variation
  selectors and the tag block once, at the entry to the pipeline, so the string
  that is detected, transformed, verified and released is one string throughout
  and no span offset has to be remapped. The detectors' end conditions accept
  the same characters as boundaries as a second layer, so a rule that reads text
  without passing through the entry points cannot be blinded either. A sweep of
  all 23 detectors against 29 invisible characters found only those four
  affected; the contract check now pins every one of them.
- **A JSON escape carried a control character past the admission check.**
  ``"\u0000"`` and ``"\u200b"`` are legal JSON escapes, so a file whose bytes
  contain no control character at all still reached the detectors with a NUL
  inside a leaf — and the leaf-internal NUL broke the same end conditions.
  Structured leaves are now admitted exactly as text is:
  ``formats/json_payload.py`` and ``formats/csv_payload.py`` put every leaf
  through ``strip_invisible`` and ``reject_if_binary``, so a NUL in a JSON
  escape is a BLOCK instead of a silent release.
- **The guard's string entry did not classify its input.** ``Guard.evaluate``
  and ``Guard.sanitize`` declared every ``str`` plain text, so one document was
  a structured payload to the CLI and to the adapters and prose to a library
  caller — the divergence ``docs/scope.md`` states cannot happen.
  ``{"患者姓名": "张伟"}`` reached ALLOW and was released untouched, and
  ``{"phone": 13800000000}`` was rewritten into ``{"phone": [REDACTED]}``,
  which is not JSON. The entry now classifies through ``formats.admission``,
  and a decoded ``dict``/``list`` is accepted as a JSON payload, the way the
  adapters accept it.
- **``inspect`` and ``sanitize`` reached different conclusions about one file.**
  ``inspect`` ran the content classifier over a CSV file, where it has no
  meaning: a first cell that looked like a JSON container was refused with exit
  code 2, while ``sanitize`` read the same file as CSV and released it. Both
  commands now admit input through ``_payload_for_path``.
- **A rebuild could release a value verification never saw.** Verification reads
  the flattened text; the released string is the rebuilt document, and the two
  are different strings. The rebuilt document is now re-decided before release,
  so a rebuild that dropped, mis-keyed or reintroduced a value produces a
  verdict that is not releasable and the payload is withheld instead of being
  reported as a verified sanitization.
- **A non-string object key was written back as a second key.** Leaf paths are
  JSON Pointers built from ``str(key)``, so replacing a value held under an
  ``int`` key added a key rather than overwriting one: ``{1: "姓名：张伟"}``
  released a document carrying the original, unredacted value under a duplicate
  ``"1"``. A non-string key is now an admission failure, as is a value JSON
  cannot carry (``bytes``, ``set``, an arbitrary object), which used to surface
  as a ``TypeError`` from inside the transformation rather than as a verdict.
- ``Guard`` no longer registers a second ``DictionaryDetector`` when a caller's
  own detector set already contains one.
- **An English key disabled the English rules.** ``{"name": "John Smith"}`` was
  probed as ``姓名：John Smith``: the Chinese rules need ideographs to capture,
  the English rules look for ``name:``/``patient:``, and neither fired, so the
  document reached ALLOW and was released with the name intact. A leaf now
  carries every label spelling its key implies (``probes`` in
  ``formats/leaf.py``), each spelling is probed, and the passes are merged into
  one non-overlapping fact set, so the same value matched under both spellings
  is still one fact. The probe separator is a half-width colon, which every
  label-driven rule accepts and the English rules require.
- The interpunct that joins the parts of a transliterated name was accepted in
  one encoding only: ``阿依古丽·买买提`` (U+00B7) was detected, the same name
  written with U+30FB — the mark a Chinese IME produces — or U+2027 was not.
  ``detectors/surnames.NAME_MARKS`` holds the closed list of what may stand
  inside a name, and all name captures use it.

## [0.3.3] - 2026-09-24

### Fixed

- **A JSON number that is an identifier was released untouched.** Numbers were
  not collected as leaves at all, so ``{"mrn": 1234567}`` produced no fact, the
  verdict was ALLOW, and the record went out with the number intact. The same
  value as a string was sanitized, and ``{"id_card": <number>}`` bypassed the
  hard government-ID BLOCK rule. Numeric leaves are now collected as
  **read-only**: detection sees them, the transformation layer never writes over
  them, and a payload carrying one can no longer reach SANITIZE. The verdict is
  ASK, or BLOCK where a hard rule applies. Booleans and null still produce no
  leaf.

### Added

- ``read_only`` on ``DetectedFact``, ``PublicDetectedFact`` and ``Leaf``, plus
  the ``UNTRANSFORMABLE_IDENTIFIER`` reason code, so a withheld payload states
  why instead of only that it was withheld.
- A fourth section in ``tools/audit_contracts.py``: read-only leaves against the
  verdict. It was confirmed to fail with the policy guard disabled — the three
  existing sections were all green while this defect was live, which is the
  point of adding it.
- ``tests/test_json_payload.py::TestReadOnlyLeaves``: numeric against string
  verdicts, hard-rule precedence, nested and array forms, the approved-recipient
  case, and an audit event carrying no raw value.
- **v0.4 skeleton**: the ``adapters/`` package with ``release_or_raise``, the
  single verdict-to-caller mapping every vendor transport will use, plus the
  caller-facing exception family ``DisclosureBlocked``,
  ``HumanApprovalRequired`` and ``VerificationFailed`` in ``core/errors.py``.
  Vendor transports are not started, and ASK grants are not implemented:
  ``HumanApprovalRequired`` says a scoped grant is required, not how one is
  obtained. The package name follows ``docs/architecture.md``, which already
  described ``adapters/``; ``ROADMAP.md`` said ``integrations/`` and now agrees.
- Release-gate checks for version consistency: ``__version__`` against
  ``pyproject.toml``, the current version against a CHANGELOG section, section
  uniqueness and ordering, and a section running ahead of the version. The first
  two were listed as release-gate conditions in ``ROADMAP.md`` and nothing
  enforced them. Both were confirmed to fail when the version is bumped without
  the matching changes.

### Notes

- ``EXTERNAL_APPROVED`` does not relax this. An approved recipient lowers risk
  scores, not transformability. A government ID in a number is still BLOCK for
  ``EXTERNAL_UNKNOWN``, because the hard rules run before the read-only path.
- Known boundary, unchanged by this fix: a bare 8-digit date (``{"date":
  20260921}``) is detected in neither form. The date detector requires a
  separator or Chinese numerals, so ``日期：20260921`` is missed as text too.
  Recorded here because a number is exactly where the separator-less spelling
  appears in practice.
- Five defects were found by adversarial review of the gateway **while every
  test was green**, which is the point of doing it:
  - a JSON-RPC **batch** carrying a ``tools/call`` was forwarded whole, so its
    arguments crossed the boundary unchecked. MCP does not define batching, and
    a batch cannot be rewritten in part, so one carrying a tool call is now
    refused entirely;
  - a **missing server command** raised an uncaught ``FileNotFoundError``: a
    traceback and exit 1 instead of the documented configuration-error code 4.
    It is now a ``GatewayError``;
  - the **reader thread died with a traceback** when the client disconnected,
    which reads like a crash rather than a disconnect;
  - a ``tools/call`` sent as a **notification** (no ``id``) was answered with a
    JSON-RPC error, which the specification forbids — a receiver must not reply
    to a notification. The call is still not forwarded, but no reply is sent;
  - **SIGTERM left the wrapped server running** as an orphan (PPID 1), because
    only Ctrl+C was handled and SIGTERM's default action skips cleanup. This
    leaks a server per stop under systemd or docker. SIGTERM now routes through
    the same path, and shutdown has a bounded wait before escalating to kill.
- The gateway's first draft treated SANITIZE as permission. A call whose
  arguments carried a phone number was forwarded with the number intact — visible
  only because the probe's upstream server echoed back what it had received.
  SANITIZE means "may proceed only with the identifiers removed", so the decision
  is three-way.
- Refusals use JSON-RPC code ``4001``. The specification reserves
  ``-32020..-32099`` for itself and marks ``-32000..-32019`` legacy, saying new
  codes SHOULD be allocated outside the reserved range entirely; ``-32001`` would
  have been wrong.
- Not inspected, and recorded in ``docs/scope.md``: responses (this is an egress
  guard), methods other than ``tools/call``, the server's ``stderr``, and the
  MRTR ``requestState`` blob, which the specification forbids a client from
  examining or modifying.
- ``ROADMAP.md``'s v0.3 section still described the plan — XLSX,
  ``sanitize_file()``, a file-scoped token map, a dataset-level uniqueness check
  — while its status row said XLSX was deferred. The section now separates what
  shipped from what did not and records why: CSV covers the XLSX need, the CLI
  writes to a separate output file rather than overwriting its input, and
  declaring the encoding was a deliberate choice rather than an omission.

## [0.3.2] - 2026-09-23

### Fixed

- **`person.py` never adopted `field_syntax`.** It spelled out its own "colon
  or whitespace", so ``姓名=张伟`` was missed while ``病历号=ZY1`` was caught.
  It now uses ``FIELD_SEP_REQUIRED`` like every other labelled field.
- **The department label rule had the same gap** (``科室=神经内科`` and the
  bracketed form were missed). It now uses ``FIELD_SEP`` / ``VALUE_OPEN``.
- **Signature and assistant lines were not covered**: ``医师签名：王强`` and
  ``助手：邓超`` produced no fact. Both are standard in surgical and outpatient
  notes.
- **A department reached by a movement verb was missed**: in
  ``由急诊科转入心血管内科`` neither the label rule nor the trailing-suffix rule
  applied. ``_DEPARTMENT_AFTER_RE`` now includes the movement verbs.
- **A nested kinship value was missed**: ``家属：其妻白洁陪同`` failed because the
  value must start with a surname and 其 is not one. The kinship term may now
  repeat after the label.
- **The adjacent person form and the verifier kept separate boundary lists.**
  Adding a word to one and not the other turns a detection into a verification
  failure. `person.py` now uses the shared `NAME_FOLLOW_BOUNDARY`.

### Added

- ``tools/evaluate_simulation.py`` with a hand-written corpus under
  ``tests/fixtures/simulation/``. It measures **generalisation** rather than
  agreement with the template generator, and is deliberately not a build gate.
  Baseline was 10.0% missed / 5.3% over-redacted; after these fixes it is
  **2.7% / 0.0%**, and the two remaining misses are the documented
  bare-name non-detection.
- ``tools/audit_contracts.py``: checks separator spelling across fields, fact
  types against the policy tables, and detection against transformation. It
  catches the "declared but not wired" defect class, which has now occurred four
  times (v0.2.1, v0.2.4, v0.3.x, and once more while fixing this release).

### Notes

- A judgement was reversed during this work. ``会诊科室：X`` was initially
  treated as a referral target to leave alone, but the corpus marks 40 such
  fields as detectable and ``docs/scope.md``'s deliberate non-detection covers
  the *verb* form (``建议神经内科会诊``), not the labelled field. The exclusion
  was reverted and the simulation corpus labels were corrected to match.
- README's capability list had fallen behind: it still listed CSV and JSON
  traversal as unimplemented and described CLI admission as rejecting JSON
  containers. Corrected.

## [0.3.1] - 2026-09-22

### Added

- **CSV support**, completing the v0.3 format set apart from XLSX. A table is
  flattened into its cells, run through the text pipeline, and rebuilt with the
  header, row and column structure intact. Recognised by suffix, since no byte
  pattern marks a CSV file.
- **Column detection is two-sided.** Column names supply the field label, which
  is what makes a value detectable at all; cell scanning is the source of truth
  for facts, because a header can be wrong, missing or duplicated. A table with
  unconventional headers simply gets no labels and still has its cells scanned.
- ``--encoding`` on ``inspect`` and ``sanitize``. The encoding is stated and
  **never guessed**: a wrong codec is reported with the codec named, because
  mojibake that reaches a model is worse than an error that reaches the
  operator. ``gb18030`` covers legacy exports.

### Notes

- Token consistency is a file-level property. Because a whole table is flattened
  and transformed in one pass, the same patient name in several rows maps to the
  same token — row identity does not leak through token numbering.
- Rebuilt CSV follows the csv module's minimal quoting: an input that quoted
  every field comes back minimally quoted. The data is identical, the bytes are
  not.
- ``.tsv`` remains unsupported: it needs a delimiter choice, not just a codec.
- A first row is treated as a header when any of its cells is a recognised field
  name. That heuristic can misread a data row whose first cell is a field name.

## [0.3.0] - 2026-09-22

### Added

- **JSON payload support.** An object or array is flattened into its string
  leaves, run through the existing text pipeline, and written back into a copy
  of the original structure. Keys, array lengths, ordering and non-string values
  are preserved; only the values the plan targeted change.
- **A JSON key acts as a field label.** ``{"name": "张三"}`` is detected because
  the key says what the value is; without that mapping the value is bare prose,
  which the detectors deliberately leave alone. Key lookup is case-insensitive
  and ignores ``_``/``-``/spaces, so ``patient_name``, ``patientName`` and
  ``Patient Name`` all resolve.
- ``Payload(kind="json", ...)`` accepts either serialised text or an
  already-decoded object, and the CLI routes ``.json`` files to the structured
  path.

### Design

- **One decision per document, transformation per leaf.** A structured payload
  is the unit of disclosure, not the field: one direct identifier withholds the
  record, because a partially released record is exactly where cross-field
  quasi-identifiers do their damage. Audit and verification contracts are
  therefore unchanged.
- **Leaves are joined with NUL** when flattened. NUL cannot appear in a JSON
  string and no detector matches it, so two adjacent leaves can never form a
  pattern that exists in neither — ``{"a": "患者张", "b": "三入院"}`` stays
  clean.
- **Nesting is walked iteratively.** Depth is caller-controlled, and a payload
  of a few thousand brackets overflows Python's recursion limit before any size
  limit applies.

### Known boundary

- Numeric, boolean and null leaves are **not** inspected: rewriting a number
  would change its JSON type and silently break the consumer. A numeric value
  that happens to be an identifier (``{"phone": 13800000000}``) is therefore not
  detected. Recorded in ``docs/scope.md`` rather than left implicit.
- JSON keys themselves are not treated as values, so a name used as a key is not
  detected.
- CSV is not implemented yet; ``.csv`` files remain blocked.

### Changed

- CLI admission: a well-formed JSON container now takes the structured path
  instead of being blocked. Something that looks like a container but does not
  parse (truncated, double-wrapped) is still an admission failure, while
  ordinary text starting with a bracket (``[随访] 记录``) stays on the plain-text
  path.

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

[Unreleased]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.6...v0.3.0
[0.2.6]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/mokuyoaxis/medical-privacy-guard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.2.0
[0.1.0]: https://github.com/mokuyoaxis/medical-privacy-guard/releases/tag/v0.1.0
