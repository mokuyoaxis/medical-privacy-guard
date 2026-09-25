# Scope

The authoritative capability boundary for medical-privacy-guard. This file,
[README.md](../README.md), and [architecture.md](architecture.md) must agree;
when they disagree, this file wins and the other two are updated.

## Supported

- UTF-8 plain text input (Python API and CLI);
- CSV files (``Payload(kind="csv")`` or a ``.csv`` file): cells are sanitized
  and the header/row/column structure is preserved. A column name acts as a
  field label for its cells; cells are scanned regardless, so an unconventional
  header costs labels but not detection. The encoding is stated with
  ``--encoding`` and never guessed;
- JSON objects and arrays (``Payload(kind="json")`` or a ``.json`` file): leaves
  are sanitized and the structure is preserved. A key acts as a field label for
  its value. Numeric leaves are inspected but never rewritten: writing a string
  over a number would change the document's JSON type, so a number that matches
  an identifier withholds the record (ASK, or BLOCK under a hard rule) rather
  than producing a SANITIZE that quietly left the value in place. Booleans and
  null carry no identifier and produce no leaf; keys themselves are not treated
  as values;
- deterministic baseline detectors: CN mobile numbers, landlines, CN resident
  ID candidates (GB 11643-1999 check digit), email, social-media handles,
  exact dates, labelled patient names, narrative ``姓名，性别`` openers,
  staff names (title, suffix, signature or assistant form), relatives named in
  the history (including a kinship term repeated after a label), medical
  record / specimen / accession numbers, HTTP(S) URLs, IPv4 addresses, labelled
  precise addresses, postal codes (label-required), institution names,
  department names (labelled, or reached by a movement verb), ward designations,
  bed numbers (suffix and labelled forms),
  ages in digits and in Chinese numerals, sex (clinical-context only, adjacent
  or comma-separated) and a baseline medical-content signal; addresses with a
  residence verb and no field label are detected when the value ends at an
  administrative or street suffix; Label/value
  separators — colon, equals, whitespace, none, or a bracketed value — are
  shared across detectors (``detectors/field_syntax.py``), so every labelled
  field accepts the same spellings — a detector that spells out its own
  separator silently diverges and is caught by ``tools/audit_contracts.py``;
- whole-name spans: a labelled name value is bounded by its separator and a
  following-boundary word rather than by the given-name inventory, so a name
  whose given character is outside that inventory is still captured whole. A
  staff or relative label carrying no name (``责任护士每班交接``) yields no fact,
  and verification withholds release when a name span stops inside a name or is
  followed by text no boundary word explains;
- mobile-number variants: contiguous and 3-4-4 grouping, ASCII/full-width digits;
  valid calendar dates in 1900–2099, including YMD/MDY with non-zero-padded month
  and day, and fully Chinese-numeral dates (``二〇二六年九月二十一日``). Detection retains original source spans; these are bounded format
  families, not universal Unicode or OCR normalization;
- ages in years and in months (1–36 months, the primary infant form), kept
  distinct from a duration ("反复头痛3个月");
- institution names even when preceded by function words ("患者在宣武医院住院");
- address labels that carry a full street address, including 户籍地 and 工作单位;
- medical-content signals beyond label words, including encounter/action terms
  (入院, 出院, 主诉, 既往, 会诊, 急诊, 病程, 转科, 服药, 住院). A bare
  diagnosis with no such term ("考虑脑梗死") is still not detected; the baseline
  is a term list, not medical NER;
- policy-driven decisions: ALLOW / SANITIZE / ASK / BLOCK;
- transformations: REMOVE, MASK, TOKENIZE and GENERALIZE (dates to month, ages
  to bands, location/institution/department/ward to type markers), plus
  DATE_SHIFT;
- post-transformation verification and residual policy re-evaluation; the
  hardening contract requires independent checks of execution evidence and
  type-specific postconditions, not exemptions for untransformed dates;
- metadata-only JSONL audit when configured (no raw PHI, token maps or internal
  transformation evidence); incomplete/short writes must prevent release;
- an optional local institution vocabulary (``.csv`` or ``.json``) supplying
  institution, department, ward and staff terms. Terms are detected alongside
  the built-in rules and give verification a signal independent of them: a term
  that survives into the released text fails verification. Terms in a referral
  context stay undetected, exactly as in the deliberate non-detection table
  below — the vocabulary does not override that judgement. The vocabulary is a
  sensitive asset: audit records carry only whether it was loaded and how many
  terms it held, and failures name the category, never the term;
- chained audit integrity: each event carries the previous event's hash, so a
  deleted, reordered or edited record is detectable, with an optional HMAC key
  for records that must be authenticated rather than merely consistent. What the
  chain does not cover is stated in [evaluation.md](evaluation.md) and the
  design note: tail truncation, whole-chain rewriting without a key, and
  timestamp authenticity;
- BLOCK for explicitly typed unsupported payloads and failed verification;
- an evaluation harness over 175 synthetic Chinese clinical notes (140 with
  labelled identifiers, 1474 spans, and 35 identifier-free notes). Expected
  paths are **135 SANITIZE, 5 ASK, 35 ALLOW**. The hardened contract adds strict
  one-to-one exact-span scoring and per-document release/verification/audit
  gates — see [evaluation.md](evaluation.md) for validation status.

## Measured vs unmeasured

The normal corpus is generated to match detector capabilities. Its historical
1.0 **overlap** recall shows agreement with those templates, not strict full-span
coverage or real-world generalisation. Narrative names, uncommon surnames, local
institution vocabulary and quasi-identifier combination risk are not
comprehensively evaluated by it.

The corpus also cannot see forms its templates never produce: every document
carries a medical-content label and writes names after an explicit field label,
so a narrative opener (``张伟，男，67岁``) was invisible to every gate until an
independent probe found it reaching release with the name intact. The
`姓名，性别` opener is now covered; other narrative forms remain outside the
baseline. See [evaluation.md](evaluation.md).

The challenge corpus under `tests/fixtures/challenge/` holds independent probes
for these forms. Its `regression/` half runs in CI; its `exploratory/` half
records forms that are outside the baseline and is expected to fail.

Adjacent person fields (`患者张三`, `其妻郑爽`) require the given name to come
from the name-character inventory in `detectors/surnames.py`. An ordinary word
following a surname is therefore not read as a name — `患者周转正常` does not
yield a person called 周转正常 — at the cost of missing a real name whose given
character is outside that inventory. A *labelled* value (`姓名：`, `主治医师：`) is
bounded by its separator instead and does not have this limitation, which is why
`主治医师欧阳修远` yields no fact while `主治医师：欧阳修远` yields the whole name.
A bare name token with no field label is not detected at all.

The historical run released 135 sanitized notes and 35 unchanged ALLOW notes;
the five annotated rare-context notes correctly returned ASK. That run did not
prove the gates reject failures: verification failures and missing audit records
could pass the old benchmark. The hardened contract checks each expected
lifecycle, verification failure, and missing/corrupt/mismatched audit events.
Those stronger requirements need fresh validation, not reuse of historical
scores. Over-redaction is measurable on both annotated and identifier-free
notes; withholding every note cannot satisfy the expected SANITIZE/ALLOW paths.

## Deliberate non-detection

Some identifier-shaped text is left alone on purpose, because redacting it
removes clinical meaning while protecting nobody. The test in each case is
whether the value is attributed to *this patient*:

| Pattern | Example | Why it is not redacted |
|---|---|---|
| population age | `多见于50岁以上人群` | describes a cohort, not the patient |
| generic institution | `转诊至上级医院`, `三级甲等医院` | names no institution |
| referral target | `建议神经内科会诊` | names a service, not the patient's department |
| generic ward | `本病区`, `各病区` | refers to no specific ward |
| rare-disease policy | `加强罕见病诊疗管理` | names no patient |
| capacity concept | `床位紧张` | a bed count, not a bed identifier |

These are measured, not assumed: the benchmark's 35 identifier-free documents
contain them, and a detector firing on one of them fails the precision gate.

## Unsupported

No parsers or sanitization support exist for:

- XLSX (deferred: CSV covers the need), TSV (needs a delimiter choice)
- FHIR (planned v0.5)
- DICOM (planned v0.6)
- PDF / DOCX
- arbitrary binary files
- multimodal content (images / audio / video)
- streaming request inspection (planned v0.4 with explicit semantics)

Explicit non-text `Payload.kind` values return BLOCK. `str` and
`Payload(kind="text")` are caller declarations: the API caller is responsible
for supplying plain text, not encoded JSON, CSV or binary content.

The admission contract blocks known unsupported extensions, NUL and other
unsupported control characters, and JSON-container content before detection.
UTF-8 decoding is necessary but is not format validation. Extension/content
checks cannot reliably recognize arbitrary disguised formats: a renamed CSV
or encoded structured value is not made supported by escaping those checks.

The classification itself is shared: ``formats/admission.py`` holds the rule used
by both the CLI and the adapters, so a payload cannot be plain text to one entry
point and a structured document to the other. An adapter does not accept the
caller's word for what its content is — ``adapters.ingress`` classifies it,
because a JSON document scanned as prose loses the key-derived field labels and
the label-driven detectors then see nothing at all.

CLI output must not alias its input or the configured audit log, including
existing hard-link aliases. Collision checks must happen before writes. These
checks do not promise protection against concurrent filesystem changes in
attacker-writable directories; use deployment-controlled paths. Configured
audit writes must be complete and durable before release: short/zero writes
and persistence errors must withhold the payload. These hardening requirements
need implementation-level regression validation, not just documentation.

## Experimental

Nothing. Experimental capabilities live behind explicit feature flags and are
listed here only when they exist.

## Definitions

- **Direct identifier**: a value that identifies a person on its own (name,
  phone, government ID, MRN).
- **Quasi-identifier**: a value that identifies only in combination (age,
  sex, region, exact dates, rare diagnosis).
- **PHI**: protected health information — any health-related data tied to an
  identifiable person.
- **Trust boundary**: the edge where data leaves the deploying organization's
  control (external LLM API, MCP tool, HTTP endpoint, file upload).
- **Fail closed**: withhold content on recognized unsupported types, failed
  verification, configured audit failures or policy uncertainty; errors may
  raise/exit rather than produce a verdict. This does not mean all unrecognized
  sensitive content is detected and blocked. No facts is not proof of safety.
- **Residual PHI**: sensitive values surviving a required transformation;
  benchmark counts are bounded checks, not proof that all residual PHI is found.

## Safety claims allowed

- "reduces accidental disclosure risk before data crosses a trust boundary"
- "detects a defined baseline of deterministic identifier patterns"
- "withholds release on explicitly unsupported payload types and failed verification"
- "produces metadata-only audit records when configured"

## Safety claims prohibited

- HIPAA / GDPR / PIPL / institutional compliance certification of any kind
- "fully anonymized" / "de-identified data is anonymous"
- "guarantees data safety" / "prevents all leaks"
- "replaces ethics review, legal review, or institutional data governance"
- DICOM pixel-clean claims before an implemented pixel-risk check exists
- any claim that a declared purpose equals patient consent
