# Policy profiles (presets)

A policy profile is the parameter bundle the guard decides with: which
facts are removed, tokenized, generalized or blocked, how much risk each
fact, recipient and purpose contributes, and the score bands that separate
ALLOW from SANITIZE. The package ships three named profiles — the
presets. Pick one by name; override it with your own file when none fits.

```python
from medical_privacy_guard import Guard

guard = Guard(profile="external-ai-strict")   # the default
```

```bash
medical-privacy-guard sanitize case.txt --profile teaching-demo \
    --recipient internal_trusted --purpose education
```

Programmatic discovery is one call:
`medical_privacy_guard.core.policy.list_builtin_profiles()`.

## The three presets

| | `external-ai-strict` | `research` | `teaching-demo` |
|---|---|---|---|
| Intended boundary | Third-party LLM / MCP / API services | Internal research use | Classroom teaching, case demonstrations |
| Exact dates | Generalized | **Shifted** (longitudinal linkage preserved) | Generalized |
| Specimen / accession IDs | Removed | Tokenized (linkable across a study) | Removed |
| Government ID to an unknown external recipient | BLOCK | Removed after sanitization | BLOCK |
| Rare-condition risk weight | 20 | 30 | 25 |
| Home purpose (risk 0) | — | `RESEARCH` | `EDUCATION` |
| ALLOW band | risk 0 only | risk ≤ 10 | risk 0 only |

All three share the same hard rules where it matters: a blocked recipient
is always BLOCK; parser failures and unsupported formats are always
BLOCK; biometric and genetic facts never cross an external boundary; and
post-transformation verification is always required, with failure
escalating to BLOCK. The presets also cover exactly the same set of fact
types — a preset changes parameters, never the detection surface.

## Choosing

- Sending anything to an external AI service: `external-ai-strict`.
  This is the default everywhere (API, CLI, gateways, benchmark).
- Preparing a dataset inside the institution, where follow-up linkage
  across time is the point of the work: `research`.
- Preparing case material for students: `teaching-demo`. Names are
  tokenized so the narrative stays readable, direct identifiers are
  removed, dates are generalized (a teaching case does not need a
  linkable timeline), and nothing reaches the classroom un-sanitized.

## Custom profiles

Any preset is a YAML file under `medical_privacy_guard/policies/`, and
the same format loads from a path of your own:

```python
guard = Guard(profile_path="/path/to/my-profile.yaml")
```

Invalid profiles fail closed with `PolicyError` at load time; an
unrecognized fact type in a payload fails closed at decision time.

## What a preset is not

A preset is a parameter bundle, not a compliance guarantee and not a
disclosure authorization. It does not certify that output is anonymous,
and it does not replace the disclosure decision of the institution that
owns the data. The capability boundary in [scope.md](scope.md) applies
unchanged under every preset.
