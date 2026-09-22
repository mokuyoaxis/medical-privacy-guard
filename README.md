# medical-privacy-guard

**English | [简体中文](README.zh-CN.md)**

> Local-first privacy guardrails for medical data before it crosses a trust boundary.

---

## What is this?

`medical-privacy-guard` is a lightweight, embeddable, fail-closed policy layer that sits between your medical data pipeline and external AI systems (LLMs, MCP tools, HTTP APIs). It detects sensitive identifiers, evaluates disclosure risk, transforms payloads when possible, verifies the result, and produces an auditable decision—**before** the data leaves your environment.

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

## Quickstart (Text MVP)

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

### Implemented in v0.1 / v0.2

- UTF-8 plain text;
- deterministic detection of CN mobile numbers and landlines, email,
  social-media handles, CN ID candidates, exact dates, labelled patient names,
  narrative ``姓名，性别`` openers,
  staff names (title or suffix form), relatives named in the history, medical
  record / specimen / accession numbers, HTTP(S) URLs, IPv4 addresses,
  labelled precise addresses (including 户籍地 / 工作单位), label-anchored
  postal codes, institution names (including after function words), department
  names, ward designations, bed numbers, ages in years and months, clinical-context
  sex and a baseline medical-content signal now covering encounter/action terms;
- mobile-number variants with 3-4-4 grouping and ASCII/full-width digits;
  real calendar dates in 1900–2099, including non-zero-padded YMD/MDY forms,
  retaining original source spans (see [scope](docs/scope.md));
- REMOVE, MASK, TOKENIZE, GENERALIZE (dates to month, ages to bands,
  location/institution/department/ward to type markers) and DATE_SHIFT;
- metadata-only JSONL audit when configured;
- an evaluation harness (`benchmark`) over a synthetic corpus of 175 Chinese
  clinical notes — 140 with labelled identifiers (1474 spans, 24 types) and 35
  identifier-free documents. The declared outcomes are **135 SANITIZE, 5 ASK,
  and 35 ALLOW**, not 140 sanitized releases. False positives are measured on
  both labelled and identifier-free notes. The hardened benchmark contract adds
  per-document lifecycle checks, verification-failure and missing/corrupt-audit
  gates, and strict one-to-one exact-span detection metrics; historical overlap
  scores are not evidence that those stronger checks passed.
  See [docs/evaluation.md](docs/evaluation.md) for the baseline and validation status.

Only plain text is supported. Explicitly typed non-text API payloads return
BLOCK. CLI admission checks reject known unsupported extensions, NUL and other
unsupported control characters, and JSON-container content; they do not reliably
identify every disguised format. Callers using `str` or `Payload(kind="text")`
are responsible for supplying plain text, not serialized structured/binary data.
Medical-content classification is a rule baseline, not full medical NER or
proof of anonymity.

Medical content without a direct identifier is still sensitive. Under the
strict profile it may remain local/internal, but disclosure to an
`EXTERNAL_UNKNOWN` recipient returns `ASK`; callers must not treat a declared
purpose as consent. Use `EXTERNAL_APPROVED` only for endpoints approved by the
deploying organization.

### Not implemented yet

- CSV / XLSX
- JSON payload traversal
- FHIR
- DICOM
- PDF / DOCX
- MCP gateway
- HTTP egress proxy
- LLM SDK wrappers
- Dataset-level re-identification risk metrics

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

This project is **engineering infrastructure**, not legal or compliance certification.

1. **Not legal advice or HIPAA/GDPR certification.** This tool helps reduce accidental disclosure risk; it does not replace legal review, institutional policy, or formal compliance audits.
2. **Does not guarantee complete anonymization.** De-identification is risk reduction, not risk elimination. Residual quasi-identifiers may still allow re-identification under specific conditions.
3. **Does not prevent malicious bypass by same-privilege actors.** A process that already has direct access to raw PHI can skip this guard. The tool protects against *accidental* or *unintentional* disclosure by agents and pipelines, not against intentional insider attacks.
4. **Fail-closed for recognized failures.** Unsupported declared types, failed verification and configured audit failures withhold release; some CLI errors return a nonzero error exit rather than a policy verdict. Undetected identifiers can still pass. No detected facts is not proof of safety, and reusing the same detectors during verification does not eliminate shared blind spots.

---

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
- **v0.3 — CSV / XLSX / JSON**: not started (XLSX deferred; CSV covers the need).
- **v0.4 — LLM SDK wrapper + MCP gateway**: not started.
- **v0.5 — FHIR minimal resource set**: not started.
- **v0.6 — DICOM metadata scanner**: not started.
- **v1.0 — Medical AI egress privacy gateway**: target.

---

## License

MIT License — see [LICENSE](LICENSE).
