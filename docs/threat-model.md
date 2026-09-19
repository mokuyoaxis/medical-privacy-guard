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

## Deployment objective and current boundary

> **Route medical payloads through the Guard before external disclosure.**

This is a deployment objective, not network enforcement supplied by the current
library. The implemented v0.1/v0.2 API and CLI process plain text locally and
return decisions; MCP/SDK adapters, structured-format parsers and scoped ASK
authorization are roadmap items. Callers must honor withheld payloads and use
only the returned releasable payload. The following threats distinguish current
mitigations from planned integrations.

## Threats and mitigation status

### T1. Agent pastes medical record into a prompt

**Scenario**: Agent receives text like `帮我分析这个患者：张三，手机号13800000000……` and forwards it to a cloud LLM.

**Current mitigation**: callers can run text through detectors and policy before
sending. Automatic egress interception and SDK wrappers are planned, not supplied
by the current library. Missed identifiers remain a disclosure risk.

### T2. Agent invokes external MCP tool with sensitive arguments

**Scenario**: `mcp.search_web({query: patient_record})`

**Planned mitigation**: an MCP adapter will translate arguments into a
`DisclosureRequest`. There is no current MCP gateway enforcing this path.

### T3. Agent uploads an attachment

**Scenario**: `upload(report.pdf)` containing raw PHI.

**Current boundary / hardening contract**: explicitly typed non-text payloads
BLOCK. CLI checks reject known unsupported extensions, NUL/unsupported control
characters and JSON-container content. They cannot identify arbitrary disguised
formats. `str`/text API callers must supply plain text; decoding arbitrary files
as UTF-8 does not make them supported. PDF extraction is not implemented.

### T4. DICOM metadata is cleaned but pixel data still contains patient name

**Scenario**: DICOM metadata de-identified, but burned-in annotation or recognizable facial structure remains.

**Current boundary**: DICOM is unsupported. **Future requirement**: a DICOM
handler must distinguish metadata, pixel and recognizable-visual-feature risks;
unknown pixel risk must not become a clean-release claim.

### T5. Free text contains indirect identity clues

**Scenario**: `本县唯一一名103岁女性，县中学校长……`

**Current mitigation**: deterministic age/sex/rare-context signals can increase
risk or trigger ASK. They are not dataset-level combination-risk analysis and do
not cover arbitrary indirect clues or estimate re-identification probability.

### T6. Audit itself becomes a privacy leak or is incomplete

**Scenario**: audit stores raw values, is missing, or a short write leaves a
truncated event while a payload is released.

**Current contract / hardening requirements**: configured audit stores metadata,
not raw values, payloads, token maps or transformation evidence. Complete writes
and persistence are required before release; short/zero writes and write/sync
errors must withhold content. Unsupported-type BLOCK requests also need events.
CLI input/output/audit collisions, including existing hard-link aliases, must
be rejected before side effects. These path checks do not fully resist races
in attacker-writable directories, and local audit is not a tamper-proof ledger.

### T7. A detected failure or an undetected identifier reaches release

**Scenario**: a transformer returns the original value, verification trusts its
action label, or an identifier produces no detection fact.

**Hardening requirements**: verification must independently check transformation
evidence and type-specific postconditions, not only re-run the same detectors.
No-op/incomplete operations must fail; untransformed dates are not exempt merely
because GENERALIZE or DATE_SHIFT was planned. Date shifts need expected-offset
and interval checks. Evidence remains local and may contain sensitive values.

Recognized failures withhold output: failed verification returns BLOCK;
unsupported typed payloads return BLOCK; configured audit failure or CLI
parsing/configuration errors may raise/exit nonzero rather than return a policy
verdict. None may silently fall back to raw output. Conversely, a missed pattern
is not a detected error: no facts does **not** prove safety. Shared detector
blind spots survive a second scan. New fault-injection and release validation
must confirm the hardening contract; historical benchmark PASS is insufficient.

### T8. Agent bypasses adapter with direct HTTP call

**Scenario**: Agent has the same OS permissions as Guard and calls `requests.post(...)` directly.

**Mitigation in v0.x**: documented residual risk. Long-term mitigations include MCP gateway, provider egress proxy, host-managed credentials, and network-layer enforcement.

### T9. Human authorizes without understanding risk

**Scenario**: User clicks "Allow" on a generic consent prompt.

**Current boundary**: ASK withholds the releasable payload; it does not implement
an approval workflow. **Future requirement**: explain risk without exposing full
PHI and issue only scoped, expiring grants, not permanent blanket approvals.

### T10. Policy drift or misconfiguration

**Scenario**: Invalid or outdated policy silently downgrades protection.

**Current mitigation**: policy configuration checks, BLOCK for detected fact
types without applicable rules, and policy-version metadata. These are not a
complete policy-security audit. The deployer must review custom policies and
control recipient approval; declaring a purpose does not establish consent.

## What we do not protect against in v0.x

| Threat | Reason | Future work |
|---|---|---|
| Malicious agent with same OS privileges | Guard cannot intercept what it cannot see | MCP gateway, provider proxy, constrained environment |
| Advanced steganography in images/audio | Outside current text scope | Format-specific research |
| Legal compliance certification | Engineering infrastructure, not legal advice | No certification claim |
| Complete scientific anonymization | Requires analysis beyond this text baseline | Dataset-level risk analysis |
| LLM prompt injection convincing the user | Current library cannot enforce informed approval | Scoped authorization and UX hardening |
| Missed identifiers or disguised formats | Detection and CLI admission checks have bounded coverage | Independent synthetic challenge sets and format parsers |

## Assumptions

1. The Guard process is not compromised. Host compromise is outside the threat model.
2. Policies loaded by the Guard are authored or reviewed by the deploying organization.
3. The local boundary and input/output/audit paths are under the deployer's control.
4. Callers invoke Guard before forwarding and honor withheld payloads; integrations
   and network restrictions are the deployer's responsibility.
5. Recipient trust comes from trusted deployment configuration, not untrusted
   payload claims. `EXTERNAL_APPROVED` is an input declaration, not authentication.
6. API callers passing `str` or text payloads supply only plain text and configure
   audit storage when durable event recording is required.

## Residual risk statement

`medical-privacy-guard` reduces the risk of accidental PHI disclosure by AI agents. It does not eliminate all disclosure risks, especially when the agent and Guard share the same execution environment and the agent intentionally bypasses the adapter.
