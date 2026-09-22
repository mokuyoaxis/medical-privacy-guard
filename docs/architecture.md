# Architecture

## Positioning

`medical-privacy-guard` is a privacy execution layer that sits between medical data and AI/external capabilities. It does not perform clinical decisions, legal certification, or complete anonymization. Its job is to decide:

> **May this disclosure happen, and if so, what is the minimum safe representation that may cross the trust boundary?**

## High-level pipeline

The implemented v0.1/v0.2 path accepts plain text. Structured-format parsers,
MCP/SDK adapters and dataset-level re-identification analysis are future work.

```text
Plain text (caller-declared in API; admission checks in CLI)
  │
  ▼
Detect sensitive facts
  │
  ▼
Build disclosure context + engineering risk summary
  │
  ▼
Policy decision
  │
  ├── BLOCK ────────▶ audit when configured + refuse
  ├── ASK ──────────▶ audit when configured + return for caller escalation
  ├── ALLOW ────────▶ audit when configured + return unchanged payload
  └── SANITIZE
         │
         ▼
      Transform + internal execution evidence
         │
         ▼
      Verify evidence / postconditions + re-scan / re-evaluate policy
         │
         ├── fail ───▶ audit when configured + BLOCK
         └── pass ───▶ audit when configured + return sanitized payload
```

Every transformation must be verified before release; a configured audit
failure must prevent release. The evidence/postcondition checks are the
hardening contract, not proof of complete anonymization. See
[evaluation.md](evaluation.md) for validation status.

## Components

| Component | Responsibility | Output |
|---|---|---|
| `medical_privacy_guard/guard.py`, `cli/main.py` | Accept caller-declared text / check CLI file admission | `Payload` |
| `detectors` | Output sensitive-entity facts, not policy decisions | `DetectedFact` |
| `core/policy.py` | Summarize engineering risk and evaluate facts + context | `Decision` + `DisclosurePlan` |
| `transformers` | Execute deterministic planned operations | transformed text + internal evidence |
| `core/verify.py` | Independently check evidence/postconditions, re-scan and re-run policy | pass / fail |
| `core/audit.py` | Append metadata-only events when configured | JSONL event |
| `core/benchmark.py` | Evaluate detection and per-document lifecycle expectations | benchmark report |
| `formats` (planned) | Parse CSV / XLSX / JSON / FHIR / DICOM | format-specific representation |
| `adapters` (planned) | Translate external calls and enforce decisions before sending | adapter-specific |

## Component boundaries

- **Detectors do not decide.** They emit facts; policy chooses the outcome.
- **No facts is not proof of safety.** Unrecognized content may produce ALLOW;
  re-scanning with the same detectors cannot independently establish recall.
- **Core is deterministic.** The same request and policy version should yield
  the same decision and reason codes; risk scores are not re-identification probabilities.
- **Transform is explicit.** The plan names each operation. Internal evidence
  links original targets to output replacements and parameters, and may contain
  sensitive data; it must stay in local memory, not public facts or audit logs.
- **Verification does not trust an action label.** No-op, incomplete or
  mismatched operations must fail. GENERALIZE needs type-specific postconditions;
  DATE_SHIFT needs the expected offset and interval consistency. An unchanged
  exact date is not exempt merely because its planned action is DATE_SHIFT or
  GENERALIZE. Context-only signals may remain only as permitted by policy.
- **Future adapters do not contain privacy rules.** Their role is to translate
  external calls and enforce the core result, not to redefine policy.

## Trust boundary

```text
┌──────────────────── Trusted Local Boundary ────────────────────┐
│                                                                │
│  EHR / local files / DICOM / FHIR                              │
│             │                                                  │
│             ▼                                                  │
│       medical-privacy-guard                                    │
│             │                                                  │
│      ┌──────┴───────┐                                          │
│      │              │                                          │
│    BLOCK       sanitized payload                               │
│                     │                                          │
└─────────────────────┼──────────────────────────────────────────┘
                      ▼
             external trust boundary
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
    Cloud LLM       MCP tool       Web/API
```

Deployment objective: **route medical payloads through the Guard before
external disclosure**. The diagram includes future integrations, not current
FHIR/DICOM support or enforced network interception. The current library cannot
prevent a caller from sending raw content directly.

## Current security contract and hardening requirements

1. **Verify-after-transform**: SANITIZE requires independent transformation
   evidence/postcondition checks plus re-scan and policy re-evaluation.
2. **No-silent-fallback**: verification or transformation failures must not
   return the original payload as releasable content.
3. **Audit-no-raw-PHI**: configured audit events contain metadata, not raw values,
   token maps or internal execution evidence. Audit failure, including short
   writes, must withhold release; unsupported typed payloads also need BLOCK events.
4. **Bounded input admission**: typed non-text payloads BLOCK. CLI checks reject
   known unsupported extensions, NUL/control characters and JSON containers,
   not every possible disguised format. API text declarations are trusted.
5. **Output separation**: input/output/audit collisions, including existing
   hard-link aliases, must be rejected before writes. Static path checks are
   not a guarantee against filesystem races.
6. **Unknown-recipient-is-not-trusted**: unknown endpoints are not approved.
   The deployment supplies trusted recipient metadata; the library is not
   an authorization service for self-declared `EXTERNAL_APPROVED` values.
7. **Policy version is auditable**: decisions carry the policy profile/version.

The hardening requirements above need code and fault-injection validation;
historical corpus scores do not establish them. No-facts ALLOW and detector
blind spots remain possible despite fail-closed handling of recognized errors.

## Future integration requirements (not current enforced invariants)

- SDK/MCP adapters must call Guard before sending and must not reimplement policy.
- A deployment-controlled approval service must scope and expire ASK grants;
  the current ASK result withholds content but does not implement such grants.
- Future DICOM support must distinguish metadata cleaning from pixel risk.
- A real egress boundary needs network/credential restrictions outside this library.

## Relationship to agent-guard

The concept for `medical-privacy-guard` grew partly out of the earlier
`agent-guard` project. They remain independent sibling projects with separate
threat models and execution engines while sharing the same Guard philosophy:

```text
Irreversible consequences must cross a guard.
```

They differ in what they protect:

| | agent-guard | medical-privacy-guard |
|---|---|---|
| Protected consequence | destructive effect | sensitive disclosure |
| Core question | Can this action be recovered? | Can this disclosure be minimized and verified? |
| Automatic safe action | compensation / relocation | sanitize / minimize |
| Post-action verification | recoverability state | re-scan / verification |

The two projects are independent repositories with no runtime dependency.

## Directory layout

```text
medical-privacy-guard/
├── README.md
├── LICENSE
├── SECURITY.md
├── ROADMAP.md
├── pyproject.toml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── decision-protocol.md
│   ├── scope.md
│   └── evaluation.md
├── core/
│   ├── __init__.py
│   ├── model.py
│   ├── errors.py
│   ├── policy.py
│   ├── verify.py
│   ├── benchmark.py
│   └── audit.py
├── detectors/
│   ├── __init__.py
│   ├── base.py
│   ├── registry.py
│   ├── surnames.py
│   ├── regex.py
│   ├── cn_identifiers.py
│   ├── dates.py
│   ├── person.py
│   ├── location.py
│   ├── medical_content.py
│   ├── medical_record.py
│   ├── demographics.py
│   ├── institution.py
│   └── clinical_context.py
├── transformers/
│   ├── __init__.py
│   ├── base.py
│   ├── registry.py
│   ├── text.py
│   ├── generalize.py
│   └── dates.py
├── policies/
│   ├── external-ai-strict.yaml
│   └── research.yaml
├── cli/
│   ├── __init__.py
│   └── main.py
├── formats/                   # planned (v0.3+): csv / xlsx / json / fhir / dicom
├── adapters/                  # planned (v0.4+): SDK wrappers, MCP gateway
├── tools/
│   └── generate_synthetic_cn_notes.py
├── skills/
│   └── medical-privacy-guard/
│       └── SKILL.md
└── tests/
    ├── fixtures/
    │   ├── synthetic/
    │   └── synthetic_cn_notes/
    └── test_*.py
```

## Current implemented scope (v0.1/v0.2 text baseline)

- plain-text input through the Python API and UTF-8 CLI;
- deterministic Chinese clinical identifier and context detectors;
- policy-driven transformations followed by mandatory verification;
- metadata-only JSONL audit before release when configured;
- explicit non-text payloads BLOCK; CLI format admission has the bounded checks
  described in [scope.md](scope.md), not universal format identification;
- a synthetic evaluation corpus and benchmark, with historical results separate
  from the stronger remediation contract in [evaluation.md](evaluation.md).

v0.2.0 is released; v0.2.1 is a correctness fix to name-span completeness.
FHIR, DICOM, MCP and provider egress adapters remain roadmap items. The library offers a guarded application path,
not a network-level enforcement boundary or an anonymity guarantee.

## Authoritative scope

The supported/unsupported capability list is owned by [scope.md](scope.md);
version planning and acceptance criteria live in [ROADMAP.md](../ROADMAP.md).
Where prose in this document disagrees with those files, those files win.
