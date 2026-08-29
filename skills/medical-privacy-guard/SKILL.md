---
name: medical-privacy-guard
description: >-
  Local-first privacy guardrails for medical or patient data. Use when content
  may contain PHI or medical identifiers, including Chinese-language records
  and labels such as 姓名, 手机号, 身份证号, 病历号, 住院号, or 就诊号, or before
  sending medical content to an external AI, LLM, MCP server, HTTP API, or
  third-party tool. Detect, evaluate, sanitize, verify, and audit locally before
  release. Do not use for ordinary non-medical data.
---

# medical-privacy-guard

Disclosure is irreversible: once raw patient data reaches an external model or
API, deletion cannot undo the exposure. Preserve this invariant:

```text
Irreversible disclosure must cross a guard.
```

Minimize disclosure, sanitize before release, make decisions explainable, and
audit without recording raw PHI.

## When to use

Use this skill when any of the following applies:

- data comes from a medical or clinical context, such as a patient record,
  laboratory result, discharge summary, imaging report, follow-up note, or
  research dataset;
- content may contain direct identifiers such as a name, phone number, email,
  government ID, MRN, encounter ID, exact date, or precise location;
- text or a file may be sent to an external AI, LLM, MCP server, HTTP API, or
  third-party tool.

When the presence of medical data is uncertain, invoke the Guard
conservatively. Do not use an external LLM to classify raw content because that
would disclose the content before the decision is made.

## Workflow

### 1. Identify the disclosure context

Determine the payload, intended purpose, recipient trust level, and whether the
data will cross a trust boundary. Treat an unknown endpoint as
`external_unknown`, never as trusted.

Distinguish:

- direct identifiers: names, phone numbers, email addresses, government IDs,
  medical record or encounter numbers, exact dates, and precise locations;
- quasi-identifiers and medical content: diagnoses, test results, medications,
  symptoms, rare conditions, and combinations that may identify a person;
- ordinary content with no medical or identifying information.

Do not reproduce detected PHI values in explanations, logs, or audit output.

### 2. Evaluate locally

```python
from medical_privacy_guard import Guard

guard = Guard(profile="external-ai-strict")
result = guard.evaluate(
    payload=text,
    recipient="external_unknown",
    purpose="EXTERNAL_AI_ASSISTANCE",
)
print(result.decision.verdict, result.public_facts)
```

CLI equivalent:

```bash
medical-privacy-guard inspect note.txt --json --profile external-ai-strict
```

Use `public_facts` and `reason_codes` for reporting. Internal detector facts may
contain raw values and must not be logged or shown to a human.

### 3. Enforce the verdict

| Verdict | Required action |
|---|---|
| `ALLOW` | Release the original payload only for the evaluated context. |
| `SANITIZE` | Run `sanitize`; release only the verified transformed payload. |
| `ASK` | Present reason codes and the public explanation to a human; do not reveal hidden PHI. |
| `BLOCK` | Stop the disclosure and report the public reason codes. |

```python
san = guard.sanitize(
    payload=text,
    recipient="external_unknown",
    purpose="EXTERNAL_AI_ASSISTANCE",
    audit_dir="audit/",
)
if san.sanitized_payload is not None and san.verification.passed:
    payload_to_send = san.sanitized_payload.content
```

`SANITIZE` is not equivalent to `ALLOW`. A transformed payload may leave the
trust boundary only after verification succeeds.

### 4. Verify the release payload

Before any tool call, upload, paste, HTTP request, or MCP invocation, confirm:

1. the outgoing content is exactly the Guard-approved original payload or
   `sanitized_payload.content`;
2. verification passed for a sanitized payload;
3. no original identifier value has been reintroduced by later composition;
4. audit recording succeeded when `audit_dir` is configured.

If parsing, policy loading, transformation, verification, or required audit
recording fails, stop. Never route around a block through another channel.

## Profiles and recipients

| Profile | Use | Key behavior |
|---|---|---|
| `external-ai-strict` | Default for third-party LLM, MCP, or API disclosure | Direct identifiers cannot be released; unknown recipients are restricted; parser or audit failures block; exact dates are generalized to month. |
| `research` | Longitudinal research | Dates use deterministic shifting to preserve intervals; rare-condition checks are stricter. |

Recipient trust levels are `local`, `internal_trusted`, `external_approved`,
`external_unknown`, and `external_blocked`. Use `external_approved` only when
the deploying organization has approved that endpoint; a declared purpose is
not consent.

Unsupported JSON-like payloads, FHIR, DICOM, and arbitrary binary files fail
closed in v0.1. Do not describe them as supported or assume an unsupported
payload is clean.
