# Contributing

Thanks for helping improve `medical-privacy-guard`. Privacy safety applies to
the development process as well as the runtime.

## Language

Use English for public documentation, source comments, API and CLI text, issue
and pull-request templates, and skill instructions. Keep `README.md` as the
canonical English project overview and `README.zh-CN.md` as its Simplified
Chinese counterpart; update both when user-visible behavior or guarantees
change.

Chinese text remains appropriate when it is part of the product's behavior,
including detector dictionaries, labelled medical identifiers, and synthetic
test cases. These domain literals do not need to be translated or removed.

## Synthetic data only

Never submit:

- real patient or research-participant data;
- EHR/FHIR/DICOM exports, even if they appear de-identified;
- production prompts, audit logs, screenshots or crash dumps;
- credentials, endpoint secrets or token-to-original mappings;
- realistic records copied from public breach reports or case studies.

Tests and reproductions must be manually constructed. Prefer reserved example
domains (`example.com`), private documentation networks, explicit `SYNTH-*`
identifiers and generic names. If a detector requires a format-valid value,
document why it is a public standard example or generate it inside the test.

Security reports must use GitHub Private Vulnerability Reporting and must also
contain synthetic data only.

## Development checks

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
python -m bandit -q -r core detectors transformers medical_privacy_guard cli
python -m build
```

Changes to policy, detectors, transformers or verification require tests for:

- the intended decision or transformation;
- a failure/bypass case;
- absence of raw values in public output and audit metadata;
- API/CLI consistency when the behavior is user-visible.

Do not weaken fail-closed behavior or expand supported formats only in
documentation. Code, tests, policy and README claims must change together.
