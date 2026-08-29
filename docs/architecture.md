# Architecture

## Positioning

`medical-privacy-guard` is a privacy execution layer that sits between medical data and AI/external capabilities. It does not perform clinical decisions, legal certification, or complete anonymization. Its job is to decide:

> **May this disclosure happen, and if so, what is the minimum safe representation that may cross the trust boundary?**

## High-level pipeline

```text
Input (text / JSON / FHIR / DICOM)
  │
  ▼
[1] Normalize / Parse
  │
  ▼
[2] Detect sensitive facts
  │
  ▼
[3] Build disclosure context (recipient, purpose, environment, policy profile)
  │
  ▼
[4] Re-identification risk analysis
  │
  ▼
[5] Policy decision
  │
  ├── BLOCK ────────▶ audit summary + refuse
  ├── ASK ──────────▶ human escalation
  ├── ALLOW ────────▶ audit summary + release
  └── SANITIZE
         │
         ▼
      Transform
         │
         ▼
      Re-scan / Verify
         │
         ├── fail ───▶ BLOCK
         └── pass ───▶ release sanitized payload
```

Key invariant: **every Transform must be followed by verification before release**.

## Components

| Component | Responsibility | Output |
|---|---|---|
| `formats` | Parse text / JSON / FHIR / DICOM into a traversable representation | `Payload` |
| `detectors` | Output facts about sensitive entities, not policy decisions | `DetectedFact` |
| `risk` | Summarize re-identification risk based on facts and context | `RiskSummary` |
| `policy` | Given facts + context + risk, produce a stable decision | `Decision` + `DisclosurePlan` |
| `transformers` | Execute deterministic operations from the plan | sanitized `Payload` |
| `verify` | Re-scan transformed payload and re-run policy | pass / fail |
| `audit` | Append-only, metadata-only event log | JSONL event |
| `adapters` | Map external calls to `DisclosureRequest` and decisions to enforcement actions | adapter-specific |

## Component boundaries

- **Adapters do not contain privacy rules.** They only translate external calls into `DisclosureRequest` and apply the returned `Decision`.
- **Detectors do not decide.** They emit `DetectedFact` objects; policy decides what to do.
- **Core is deterministic.** Given the same request and policy version, the core must produce the same `Decision` and `ReasonCode` set.
- **Transform is explicit.** Every operation is recorded in `DisclosurePlan` and can be audited.

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

Invariant: **raw medical payload must not cross the external trust boundary without passing through the Guard.**

## Security invariants

These are enforced in code and tests:

1. **Raw-before-release**: raw sensitive payload is never sent to an external adapter before a Guard decision.
2. **Fail-closed parse**: parsing failures default to BLOCK, not ALLOW.
3. **Verify-after-transform**: every SANITIZE is followed by re-scan and policy re-evaluation.
4. **Audit-no-raw-PHI**: normal audit events do not contain raw sensitive values or token-to-original mappings.
5. **Adapter-policy separation**: adapters do not re-implement policy rules.
6. **Unknown-recipient-is-not-trusted**: an unknown endpoint is not treated as trusted.
7. **No-silent-fallback**: sanitization failures do not fall back to the original payload.
8. **Unsupported-is-not-clean**: unknown formats or unknown DICOM pixel risk are not assumed de-identified.
9. **Human escalation is scoped**: ASK grants are scoped and time-bound, not permanent blanket allow.
10. **Policy version is auditable**: every Decision carries the policy profile and version.

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
├── pyproject.toml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── decision-protocol.md
│   └── ...
├── core/
│   ├── __init__.py
│   ├── model.py
│   ├── errors.py
│   ├── classifier.py
│   ├── policy.py
│   ├── risk.py
│   ├── transform.py
│   ├── verify.py
│   └── audit.py
├── detectors/
│   ├── base.py
│   ├── registry.py
│   ├── regex.py
│   ├── cn_identifiers.py
│   ├── dates.py
│   ├── person.py
│   └── medical_record.py
├── transformers/
│   ├── base.py
│   ├── registry.py
│   ├── text.py
│   ├── tokenization.py
│   └── dates.py
├── policies/
│   ├── external-ai-strict.yaml
│   └── research.yaml
├── formats/
│   ├── text.py
│   ├── json.py
│   ├── fhir.py          # phase 2
│   └── dicom.py         # phase 3
├── adapters/
│   ├── cli/
│   ├── python/
│   └── mcp/             # phase 2
├── skills/
│   └── medical-privacy-guard/
│       └── SKILL.md
└── tests/
    ├── unit/
    ├── integration/
    ├── conformance/
    ├── adversarial/
    └── fixtures/
        └── synthetic/
```

## Current implemented scope (v0.1 text MVP)

- UTF-8 text input through the Python API and CLI;
- deterministic identifier, network, labelled-address and medical-content
  baseline detectors;
- policy-driven transformations followed by mandatory verification;
- metadata-only JSONL audit completed before release when configured;
- unsupported structured/binary formats fail closed.

FHIR, DICOM, MCP and provider egress adapters remain roadmap items. The v0.1
library is a safe application path, not a network-level enforcement boundary.
