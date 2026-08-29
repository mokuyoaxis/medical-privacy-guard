# Security Policy

## Supported Versions

| Version | Status |
|---|---|
| < 0.1.0 | Pre-alpha; not recommended for production use |
| 0.1.x   | Early development; security feedback welcome |

## Reporting a Vulnerability

If you discover a security issue in `medical-privacy-guard`, please use
[GitHub Private Vulnerability Reporting](https://github.com/mokuyoaxis/medical-privacy-guard/security/advisories/new)
instead of opening a public issue. If the private-reporting form is temporarily
unavailable, contact the repository maintainer without including PHI in a
public channel.

When reporting, please include:
- A description of the vulnerability
- Steps to reproduce (if applicable)
- The component or file involved
- Whether you believe the issue could lead to accidental PHI disclosure

Use synthetic data in reproductions. Do not attach real patient records,
production audit logs, credentials, or token-to-original mappings.

## Scope and Limitations

This project is pre-alpha engineering infrastructure. It is **not** a certified compliance tool, and it does not guarantee prevention of all data leakage paths. See [README.md](./README.md) for Honest Guarantees.

## Design Principles

- Fail-closed: uncertain inputs default to `BLOCK` or `ASK`
- Audit without raw PHI: logs contain metadata, not sensitive values
- Verify after transform: no sanitized payload is released without re-validation
- Immutable decisions: every decision carries a policy version for audit
