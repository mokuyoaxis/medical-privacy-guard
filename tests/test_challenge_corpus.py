"""Regression probes from the independent challenge corpus.

These probes are written by hand rather than generated, so they do not share a
template or a vocabulary with the detector. See
``tests/fixtures/challenge/README.md`` for the format and for what the corpus
does and does not measure.

Only ``regression/`` runs here. ``exploratory/`` holds forms that are outside
the baseline today and is expected to fail; it is reported separately rather
than asserted, so a probe moving from "not detected" to "detected" surfaces as
a deliberate update instead of a silent drift.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.model import Purpose, Recipient, TrustLevel
from detectors import detect_all
from medical_privacy_guard import Guard

CHALLENGE_ROOT = Path(__file__).resolve().parent / "fixtures" / "challenge"
REGRESSION_ROOT = CHALLENGE_ROOT / "regression"


def _regression_probes() -> list[Path]:
    return sorted(REGRESSION_ROOT.rglob("*.probes.json"))


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(profile="external-ai-strict")


@pytest.fixture(scope="module")
def recipient() -> Recipient:
    return Recipient(kind="challenge", trust_level=TrustLevel("EXTERNAL_APPROVED"))


def test_regression_probes_exist() -> None:
    """A silent glob failure would make the whole file vacuously green."""
    probes = _regression_probes()
    assert probes, f"no regression probes found under {REGRESSION_ROOT}"
    assert len(probes) >= 10, f"expected at least 10 probes, found {len(probes)}"


@pytest.mark.parametrize(
    "sidecar", _regression_probes(), ids=lambda path: path.stem.removesuffix(".probes")
)
def test_regression_probe(sidecar: Path, guard: Guard, recipient: Recipient) -> None:
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    text = sidecar.with_name(f"{meta['doc_id']}.txt").read_text(encoding="utf-8").rstrip("\n")

    result = guard.sanitize(text, recipient, Purpose.EXTERNAL_AI_ASSISTANCE)
    verdict = result.decision_before.verdict.value
    assert verdict == meta["expected_verdict"], (
        f"{meta['doc_id']}: verdict {verdict}, expected {meta['expected_verdict']} "
        f"({meta.get('probe_note', '')})"
    )

    facts = detect_all(text)
    for expected in meta["must_detect"]:
        found = any(
            fact.type == expected["type"] and text[fact.start : fact.end] == expected["text"]
            for fact in facts
        )
        assert found, f"{meta['doc_id']}: missed {expected['type']} {expected['text']!r}"

    for forbidden in meta["must_not_detect"]:
        start = text.find(forbidden)
        if start < 0:
            continue
        overlap = any(
            fact.start < start + len(forbidden) and fact.end > start for fact in facts
        )
        assert not overlap, f"{meta['doc_id']}: over-detected {forbidden!r}"
