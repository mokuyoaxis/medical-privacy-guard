# Threat Model

## Purpose

This document describes what `medical-privacy-guard` protects, what it does not protect, and the assumptions under which it operates. It is intentionally created before implementation, not after.

## Trust boundary

The Guard runs inside the **Trusted Local Boundary**. Data originating from local EHR files, FHIR endpoints, DICOM archives, or user input is considered within this boundary.

Anything outside this boundary is **external** until explicitly registered as trusted:

- Cloud LLM providers
- MCP servers
- Public web APIs
- Unregistered internal endpoints

```text
Trusted Local Boundary
  │
  ├─ EHR / DICOM / FHIR / local files
  ├─ medical-privacy-guard core
  └─ registered internal trusted endpoints (optional)
  │
  ▼
External trust boundary
  ├─ Cloud LLM
  ├─ MCP tool
  └─ Web/API
```

## Core security invariant

> **Unprocessed raw medical payload must not cross the external trust boundary.**

## Threats we mitigate

### T1. Agent pastes medical record into a prompt

**Scenario**: Agent receives text like `帮我分析这个患者：张三，手机号13800000000……` and forwards it to a cloud LLM.

**Mitigation**: input/output egress interception + PHI detectors + policy decision.

### T2. Agent invokes external MCP tool with sensitive arguments

**Scenario**: `mcp.search_web({query: patient_record})`

**Mitigation**: MCP adapter treats tool arguments as a `DisclosureRequest` and routes through core.

### T3. Agent uploads an attachment

**Scenario**: `upload(report.pdf)` containing raw PHI.

**Mitigation**: file type inspection + supported format handler; unknown binary defaults to ASK/BLOCK.

### T4. DICOM metadata is cleaned but pixel data still contains patient name

**Scenario**: DICOM metadata de-identified, but burned-in annotation or recognizable facial structure remains.

**Mitigation**: DICOM parser distinguishes `metadata-clean`, `pixel-clean`, and `visual-deidentified`. When pixel risk is unknown, strict policy BLOCKs.

### T5. Free text contains indirect identity clues

**Scenario**: `本县唯一一名103岁女性，县中学校长……`

**Mitigation**: quasi-identifier / re-identification risk engine flags rare combinations.

### T6. Audit itself becomes a privacy leak

**Scenario**: Audit log stores raw phone numbers or full prompts.

**Mitigation**: audit schema stores only detector types, counts, decision, policy version, and transformation names. No raw values, no token maps, no full payloads.

### T7. Detector or parser fails silently

**Scenario**: Parser crashes or detector fails; system continues and sends original data.

**Mitigation**: fail-closed:

```text
parser failure      → BLOCK
verification failure → BLOCK
unknown binary      → BLOCK / ASK per policy
audit failure (strict) → BLOCK
```

### T8. Agent bypasses adapter with direct HTTP call

**Scenario**: Agent has the same OS permissions as Guard and calls `requests.post(...)` directly.

**Mitigation in v0.x**: documented residual risk. Long-term mitigations include MCP gateway, provider egress proxy, host-managed credentials, and network-layer enforcement.

### T9. Human authorizes without understanding risk

**Scenario**: User clicks "Allow" on a generic consent prompt.

**Mitigation**: ASK must explain the risk category, not show full PHI; high-risk items cannot be permanently remembered without scope and expiry.

### T10. Policy drift or misconfiguration

**Scenario**: Invalid or outdated policy silently downgrades protection.

**Mitigation**: schema validation, policy lint, safe defaults, policy version in audit, unknown fields fail-closed.

## What we do not protect against in v0.x

| Threat | Reason | Future work |
|---|---|---|
| Malicious agent with same OS privileges | Guard cannot intercept what it cannot see | MCP gateway, provider proxy, constrained environment |
| Advanced steganography in images/audio | Out of v0.x scope | DICOM pixel research, Phase 3 |
| Legal compliance certification | This is engineering infrastructure, not legal advice | Docs stay honest; no certification claim |
| Complete scientific anonymization | k-anonymity / differential privacy require dataset-level analysis | Risk engine evolves in later phases |
| LLM prompt injection convincing the user | Human escalation is scoped; permanent blanket allow is prohibited | UX hardening |

## Assumptions

1. The Guard process is not compromised. Host compromise is outside the threat model.
2. Policies loaded by the Guard are authored or reviewed by the deploying organization.
3. The local boundary is under the deployer's control.
4. Adapters are written to call the Guard before forwarding data, until a network-level enforcement point is added.

## Residual risk statement

`medical-privacy-guard` reduces the risk of accidental PHI disclosure by AI agents. It does not eliminate all disclosure risks, especially when the agent and Guard share the same execution environment and the agent intentionally bypasses the adapter.
