# Decision Protocol

## Verdicts

The core produces exactly one of four verdicts:

| Verdict | Meaning | Typical follow-up |
|---|---|---|
| `ALLOW` | No configured detector matched under current policy and context | Release payload as-is |
| `SANITIZE` | Sensitive content exists but can be transformed to a safe state | Execute `DisclosurePlan`, then verify |
| `ASK` | Risk is known but requires human intent / institutional policy | Withhold until a deployment-issued scoped grant is accepted; then release only the verified minimized payload |
| `BLOCK` | Unsafe or violates non-overridable rule | Refuse release, provide remediation |

## Core principle

```text
确定性安全       → ALLOW
确定可自动修复   → SANITIZE
需要人类语境     → ASK
无法证明安全     → BLOCK
```

Not:

```text
无法确定 → 大概没问题 → ALLOW
```

## Decision data structure

```python
@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason_codes: tuple[ReasonCode, ...]
    explanation: str
    risk: RiskSummary
    plan: DisclosurePlan | None
    policy_version: str
```

Rules:

- `verdict` is one of `ALLOW`, `SANITIZE`, `ASK`, `BLOCK`.
- `reason_codes` are stable, machine-readable, and contain no sensitive values.
- `explanation` is human-readable but must not include raw PHI.
- `plan` is present for `SANITIZE`, and is attached to an `ASK` only after a
  valid grant is consumed. An empty approved plan is possible when the payload
  carries only context signals; an unapproved ASK has no plan and no release.
- `policy_version` makes every decision auditable.

## ReasonCode design principles

A ReasonCode must be:

- Stable across releases (or documented with migration).
- Machine-readable, suitable for test assertions and adapter logic.
- Free of sensitive values.
- Not rewritten or reinterpreted by adapters.

## Initial ReasonCode set

```text
NO_SENSITIVE_DATA_DETECTED
SYNTHETIC_DATA_CONFIRMED

DIRECT_IDENTIFIER_PRESENT
CONTACT_IDENTIFIER_PRESENT
NETWORK_IDENTIFIER_PRESENT
GOVERNMENT_ID_PRESENT
MEDICAL_RECORD_IDENTIFIER_PRESENT
EXACT_DATE_PRESENT
PRECISE_LOCATION_PRESENT
BIOMETRIC_DATA_PRESENT
GENETIC_DATA_PRESENT

MEDICAL_CONTENT_PRESENT
QUASI_IDENTIFIER_COMBINATION
RARE_CONDITION_REIDENTIFICATION_RISK

EXTERNAL_RECIPIENT
UNKNOWN_RECIPIENT
UNTRUSTED_RECIPIENT

PURPOSE_NOT_DECLARED
PURPOSE_NOT_ALLOWED
CONSENT_REQUIRED
CONSENT_UNKNOWN

TRANSFORMATION_AVAILABLE
TRANSFORMATION_INCOMPLETE
VERIFICATION_FAILED
PARSER_FAILURE
UNSUPPORTED_FORMAT
AUDIT_UNAVAILABLE
POLICY_CONFIGURATION_INVALID
RISK_THRESHOLD_EXCEEDED
```

## SANITIZE workflow

```text
SANITIZE
   │
   ▼
Transform
   │
   ▼
Verify
   │
   ├── fail → withhold payload
   └── pass → release sanitized payload
```

Important: **SANITIZE is not ALLOW.** The payload is released only after verification passes.

## ASK approval workflow

With a configured grant key, an ASK result describes the disclosure in an
`ApprovalRequest` without raw values. The deployment decides who may approve
and issues an HMAC-signed `Grant` with an expiry and a use budget. The guard
checks its signature, fingerprint, time window and accepted read-only fact types
before atomically consuming one use.

The verifier and rebuilt-document gate receive explicit approval state from
Guard. Accepted types alone do not authorize an ASK, and an approved context-only
disclosure needs no read-only type exemption. Adapters require a PASS verification
before releasing any granted ASK. Audit identity fields describe only validated,
consumed grants; rejected or unused grant data never enters them.

A granted release keeps verdict ASK and still transforms and verifies every
rewritable target. Only accepted read-only residuals and approved context risk
may remain. A rejected grant withholds content. All default Guard instances
share the consumption registry within one process; restart and cross-process
replay prevention require a deployment-controlled persistent registry. Approval
UI, roles and informed-consent checks remain deployment responsibilities.

## Interaction tiers

| Tier | Verdict | User experience |
|---|---|---|
| SAFE | ALLOW / SANITIZE with verification PASS | Silent continue |
| AMBIGUOUS | ASK | Deployment issues explicit authorization; Guard checks the scoped grant and enforces its use budget |
| FORBIDDEN | BLOCK | Refuse with safe remediation |

## DisclosureRequest context

The decision depends on more than payload content:

```text
data + recipient + purpose + trust boundary + policy profile
```

```python
@dataclass(frozen=True)
class DisclosureRequest:
    payload: Payload
    recipient: Recipient
    purpose: Purpose
    environment: EnvironmentContext
    policy_profile: str
```

### Recipient trust levels

```text
LOCAL
INTERNAL_TRUSTED
EXTERNAL_APPROVED
EXTERNAL_UNKNOWN        # default for unknown endpoints
EXTERNAL_BLOCKED
```

Default rule: **unknown endpoint → EXTERNAL_UNKNOWN**, not trusted.

### Purpose values

```text
TREATMENT
RESEARCH
EDUCATION
OPERATIONS
PUBLICATION
EXTERNAL_AI_ASSISTANCE
UNKNOWN
```

Purpose is an input to policy, not a legal determination.

## Policy decision rules

Hard rules take precedence over risk scores:

```text
hard constraints > risk score
```

Example:

```text
GOVERNMENT_ID_PRESENT + EXTERNAL_UNKNOWN → BLOCK or SANITIZE
```

Even if the risk-score algorithm would produce a lower score, a hard rule must not be overridden.

## Security invariants

1. **Raw-before-release**: raw sensitive payload is not released before a Guard decision.
2. **Fail-closed parse**: unparseable input defaults to BLOCK.
3. **Verify-after-transform**: every SANITIZE must pass verification before release.
4. **Audit-no-raw-PHI**: audit does not contain raw sensitive values.
5. **Adapter-policy separation**: adapters do not implement policy.
6. **Unknown-recipient-is-not-trusted**: unknown endpoints default to EXTERNAL_UNKNOWN.
7. **No-silent-fallback**: sanitization failure does not fall back to original payload.
8. **Unsupported-is-not-clean**: unknown format or DICOM pixel risk is not treated as clean.
9. **Human escalation is scoped**: ASK must not be surfaced as a permanent blanket
   allow. Guard checks scoped, expiring grants and consumes their use budget
   atomically across default instances in a process. The deployment controls
   issuance, approval UX and persistent consumption across processes/restarts.
10. **Policy version is auditable**: every Decision carries policy profile and version.
