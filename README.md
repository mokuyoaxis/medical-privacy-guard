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
```

Exit codes: `0` = ALLOW or verified SANITIZE, `2` = BLOCK, `3` = ASK,
`4` = parser/configuration/internal error.

Reported risk is the engineering risk of the **input before transformation**.
A high/critical input may still receive SANITIZE when every direct identifier
has a deterministic operation; only the verified output may be released.

### Supported in v0.1

- UTF-8 plain text;
- deterministic detection of CN mobile numbers, email, CN ID candidates,
  exact dates, labelled patient names and MRNs, HTTP(S) URLs, IPv4 addresses,
  labelled precise addresses, and a baseline medical-content signal;
- REMOVE, MASK, TOKENIZE, date/location GENERALIZE, and DATE_SHIFT;
- metadata-only JSONL audit.

JSON-like payloads, FHIR, DICOM and arbitrary binary files are **not supported
in v0.1 and fail closed**. Medical-content classification is a conservative
rule baseline, not full medical NER or proof of anonymity.

Medical content without a direct identifier is still sensitive. Under the
strict profile it may remain local/internal, but disclosure to an
`EXTERNAL_UNKNOWN` recipient returns `ASK`; callers must not treat a declared
purpose as consent. Use `EXTERNAL_APPROVED` only for endpoints approved by the
deploying organization.

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
4. **Fail-closed by design.** When in doubt, it blocks or asks. This is a feature, not a bug.

---

## Status

- **Phase 0** (skeleton + core types): ✅ Done
- **Phase 1** (text MVP implementation): ✅ Done
- **v0.1 release stabilization** (packaging + release-gate tests): ✅ Done; release pending CI/versioning
- **Phase 1.2** (re-identification hardening): Not started
- **Phase 2** (FHIR + MCP): Not started
- **Phase 3** (DICOM): Not started

---

## License

MIT License — see [LICENSE](LICENSE).
