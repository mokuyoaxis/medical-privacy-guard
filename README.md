# medical-privacy-guard

**English | [简体中文](README.zh-CN.md)**

> Local-first privacy guardrails for medical data before it crosses a trust boundary.

---

## What is this?

`medical-privacy-guard` is a lightweight, embeddable, fail-closed policy layer that sits between your medical data pipeline and external AI systems (LLMs, MCP tools, HTTP APIs). It detects sensitive identifiers, evaluates disclosure risk, transforms payloads where it can, verifies the result, and produces an auditable decision before the data leaves your environment.

The concept for this project grew partly out of the earlier
[`agent-guard`](https://github.com/mokuyoaxis/agent-guard) project. They are
independent sibling projects with separate threat models and execution
engines, while sharing a Guard philosophy: minimize irreversible consequences,
increase restrictions under uncertainty, keep decisions explicit, and retain
an audit trail.

| | `agent-guard` | `medical-privacy-guard` |
|---|---|---|
| **Core concern** | Destructive effects | Sensitive disclosures |
| **Goal** | Recover before damage happens | Reduce / transform / block before data escapes |
| **Plan object** | RecoveryPlan | DisclosurePlan / TransformationPlan |

---

## Quickstart

```bash
python -m pip install -e ".[test]"
python -m pytest -q
```

```python
from medical_privacy_guard import Guard

guard = Guard(profile="external-ai-strict")
result = guard.sanitize(
    "患者：测试患者甲，电话 13800000000",
    recipient="external_unknown",
    purpose="EXTERNAL_AI_ASSISTANCE",
)

if result.sanitized_payload is not None:
    payload_to_release = result.sanitized_payload.content
```

CLI:

```bash
medical-privacy-guard inspect note.txt --json
medical-privacy-guard sanitize note.txt -o note.sanitized.txt --audit-dir audit/
medical-privacy-guard benchmark tests/fixtures/synthetic_cn_notes
medical-privacy-guard audit-verify audit/
```

Exit codes: `0` = ALLOW or verified SANITIZE (for `audit-verify`, an intact
chain), `2` = BLOCK (for `audit-verify`, a broken chain), `3` = ASK,
`4` = parser/configuration/internal error.

Audit events are chained by hash, so a deleted, reordered or edited record is
detectable. Set `MEDICAL_PRIVACY_GUARD_AUDIT_KEY` to authenticate records with
an HMAC as well. Tail truncation and keyless whole-chain rewriting are not
detectable and are documented as such.

Reported risk is the engineering risk of the **input before transformation**.
A high/critical input may still receive SANITIZE when every direct identifier
has a deterministic operation; only the verified output may be released.

### Implemented

**Detection.** Deterministic rules over Chinese clinical text: CN mobile and
landline numbers, email, social-media handles, CN resident ID candidates
(GB 11643-1999 check digit), exact dates, HTTP(S) URLs, IPv4 addresses, labelled
patient names, staff and relative names, medical record / specimen / accession
numbers, labelled addresses and postal codes, institution / department / ward
names, bed numbers, ages in years, months and Chinese numerals,
clinical-context sex, and a baseline medical-content signal.

Narrative names are covered in three shapes that carry no field label:

| Shape | Example | Anchor |
|---|---|---|
| gender opener | `张伟，男，67岁` | `男` / `女` |
| complaint verb | `陈曦诉头晕`, `潘婷主诉腹痛` | `诉` / `主诉` / `自诉` / `自述` |
| connective at a clause boundary | `陈曦因胸痛入院`, `汪洋由急诊科转入` | `因` / `由` / `以` |

A bare name in ordinary prose is still not detected, and a clause-initial
common word shaped like a surname plus a given-name character (`文明因…`) is
read as a person. Both boundaries are recorded in [docs/scope.md](docs/scope.md).

**Transformation.** REMOVE, MASK, TOKENIZE, GENERALIZE (dates to month, ages to
bands, location / institution / department / ward to type markers) and
DATE_SHIFT. Every SANITIZE is verified before release; a failed verification
withholds the payload.

**Structured input.** JSON objects/arrays, CSV files and a minimal FHIR resource
set are flattened to string leaves, sanitized and rebuilt with their structure
intact. A key or column name labels its value. JSON numbers are inspected but
never rewritten, because writing a string over a number would change its type,
so a number that matches an identifier withholds the record. A FHIR resource outside
the supported set is withheld.

**Egress adapters.** OpenAI-compatible and Anthropic client wrappers, and an MCP
stdio gateway. In the gateway, `tools/call` is forwarded, rewritten or refused
according to the verdict; everything else, including `server/discover`, is
forwarded byte for byte. Responses are not inspected, and neither adapter covers
every egress path; see [docs/scope.md](docs/scope.md).

**Audit.** Metadata-only JSONL when configured, chained by hash so a deleted,
reordered or edited record is detectable, with an optional HMAC key and an
`audit-verify` command. Tail truncation and keyless whole-chain rewriting are
not detectable.

**Evaluation.** A synthetic corpus of 175 Chinese clinical notes (140 with 1474
labelled spans across 24 types, 35 identifier-free) and a strict one-to-one
benchmark with per-document lifecycle and audit gates. Declared outcomes are
135 SANITIZE, 5 ASK and 35 ALLOW. A separate hand-written corpus under
`tests/fixtures/simulation/` measures generalisation rather than template
agreement (`python tools/evaluate_simulation.py`); it is deliberately not tuned
to the detectors and is not a build gate.

**Admission.** Plain text, JSON, CSV and FHIR are supported; other explicitly
typed non-text payloads return BLOCK. Admission rejects known unsupported
extensions, NUL and other unsupported control characters, and containers that do
not parse, but it does not identify every disguised format. One rule
(`formats/admission.py`) serves the CLI, the adapters and the guard's own string
entry, so a document cannot be plain text to one of them and structured to
another. A `str` is classified rather than trusted: `{"name": "张三"}` is a JSON
document whether it arrives as text or as a decoded mapping, and scanning it as
prose would release the name. `Payload(kind="text")` skips classification but
not normalisation. Medical-content classification is a rule baseline, not
medical NER and not proof of anonymity.

Medical content without a direct identifier is still sensitive. Under the strict
profile it may remain local/internal, but disclosure to an `EXTERNAL_UNKNOWN`
recipient returns `ASK`; a declared purpose is not consent. Use
`EXTERNAL_APPROVED` only for endpoints approved by the deploying organization.

### Not implemented yet

- XLSX and TSV (CSV covers the same need)
- PDF / DOCX
- DICOM write-back and pixel-risk checking (the shipped scanner is read-only)
- HTTP egress proxy
- ASK approval grants (scoped, expiring, one-time)
- dataset-level re-identification and quasi-identifier combination metrics
- multimodal content (images, audio, video)
- `resources/read` and `prompts/get` inspection in the MCP gateway

### Never claim

This project does not certify HIPAA, GDPR, PIPL, or institutional
compliance. It reduces accidental disclosure risk but cannot prove complete
anonymization.

### Synthetic data only

Repository examples and tests use manually constructed placeholders, reserved
example domains/private IP space, `SYNTH-*` identifiers, and a documented
public checksum example. Do not submit real patient records, production audit
logs, screenshots, credentials, or token-to-original mappings in issues, pull
requests, fixtures, or CI artifacts. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Honest Guarantees

This project is engineering infrastructure. It is not legal advice and not a
compliance certification.

1. **No compliance certification.** It does not certify HIPAA, GDPR, PIPL or
   any institutional policy, and does not replace legal review or a formal
   audit.
2. **No complete anonymization.** De-identification reduces risk; it does not
   remove it. Residual quasi-identifiers can still allow re-identification in
   some settings.
3. **No protection against a same-privilege bypass.** A process that can already
   read raw PHI can skip this guard. It protects against accidental disclosure
   by agents and pipelines, not against an intentional insider.
4. **Fail closed only for recognized failures.** Unsupported declared types,
   failed verification and configured audit failures withhold release. A missed
   identifier is not a recognized failure: no detected facts is not proof of
   safety, and re-scanning with the same detectors does not remove their shared
   blind spots.

## Status

Single version-based roadmap; details and acceptance criteria in [ROADMAP.md](ROADMAP.md).

- **v0.1 — Text core MVP**: released as `v0.1.0` (baseline detectors, decision protocol, transformations, verification, metadata-only audit).
- **v0.2 — Chinese medical text detection & evaluation**: released as `v0.2.0`. Strict evaluation results and fault-injection evidence are recorded in [docs/evaluation.md](docs/evaluation.md); the corpus is template-generated, so a strict 1.0 measures internal consistency, not real-world generalisation.
- **v0.2.1 — Name-span completeness hotfix**: released as `v0.2.1`. Staff and
  relative names bounded by the given-name inventory were released partially
  redacted; a labelled value is now bounded by its separator instead, and
  verification withholds release when a name span stops inside a name.
- **v0.2.2 — Chained audit integrity**: released as `v0.2.2`. Audit events carry
  the previous event's hash so deletion, reordering and edits are detectable,
  with an optional HMAC key and an `audit-verify` command.
- **v0.2.3 — Audit leak gate false positive**: released as `v0.2.3`. The audit
  leak gate scanned random hex fields, so a short labelled value could occur
  inside a hash by chance and fail an otherwise clean run.
- **v0.2.4 — Detection coverage**: released as `v0.2.4`. Chinese numeral ages,
  comma-separated sex, bracketed names, labelled bed numbers and unlabelled
  addresses; age generalization learned numerals too.
- **v0.2.5 — Institution vocabulary**: released as `v0.2.5`. An optional local
  `.csv` / `.json` vocabulary of institution, department, ward and staff terms,
  detected alongside the rules and used as an independent verification signal.
- **v0.2.6 — Remaining detection gaps**: released as `v0.2.6`. Chinese numeral
  dates and title-suffix names whose given character is outside the inventory.
- **v0.3 — CSV / XLSX / JSON**: **JSON done** (`v0.3.0`), **CSV done**
  (`v0.3.1`); XLSX deferred (CSV covers the need).
- **v0.3.2 — Generalisation fixes**: released as `v0.3.2`. Six detection gaps
  found by an independent hand-written corpus, plus a contract audit tool.
- **v0.4 — Structured formats + egress adapters**: **delivered in the working
  tree, untagged**. Adds OpenAI-compatible and Anthropic client wrappers, an MCP
  stdio gateway, a minimal FHIR resource set and a read-only DICOM scanner
  (`dicom-inspect`). The work planned as separate v0.5/v0.6 releases is folded
  here: three version numbers in a week were not earned by the release process.
  DICOM is experimental — it reports identifying metadata, leaves pixel risk
  UNKNOWN (so `safe_to_release` is false for every file) and never writes a
  file. Responses are not inspected; see [scope](docs/scope.md) for the
  boundaries.
- **v0.5 — Approval and dataset risk**: planned. ASK approval grants (scoped,
  expiring, one-time), a file-scoped token map and dataset-level
  quasi-identifier combination risk.
- **v1.0 — Medical AI egress privacy gateway**: target.

---

## License

MIT License — see [LICENSE](LICENSE).
