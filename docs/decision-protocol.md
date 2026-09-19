# Decision Protocol

## Verdicts

The core produces exactly one of four verdicts:

| Verdict | Meaning | Typical follow-up |
|---|---|---|
| `ALLOW` | No configured detector matched under current policy and context | Release payload as-is |
| `SANITIZE` | Sensitive content exists but can be transformed to a safe state | Execute `DisclosurePlan`, then verify |
| `ASK` | Risk is known but requires human intent / institutional policy | Escalate to a human; the caller owns scoping, expiry and one-time use |
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
- `plan` is present only when `verdict == SANITIZE`.
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
   ├── fail → BLOCK
   └── pass → release sanitized payload
```

Important: **SANITIZE is not ALLOW.** The payload is released only after verification passes.

## Interaction tiers

| Tier | Verdict | User experience |
|---|---|---|
| SAFE | ALLOW / SANITIZE with verification PASS | Silent continue |
| AMBIGUOUS | ASK | Explicit authorization; grant scoping and expiry are caller responsibilities |
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
   allow. Scoped/expiring grant objects, one-time use and enforcement are caller
   responsibilities (the ASK-approval workflow is planned, not implemented).
10. **Policy version is auditable**: every Decision carries policy profile and version.
