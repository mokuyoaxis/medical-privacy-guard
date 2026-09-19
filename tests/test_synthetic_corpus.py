"""Self-checks for the synthetic Chinese clinical note corpus.

The corpus is the ruler every detection claim is measured against, so it must
be validated independently of the detectors:

- structure: 7 document types, >= 20 documents each, text/sidecar pairs;
- annotation integrity: spans align with the document text;
- coverage: all supported fact types appear, plus a no-identifier subset that
  exercises the ASK path;
- synthetic-only guarantee: no real-looking subscriber numbers, no non-example
  domains, only RFC 5737 address space;
- reproducibility: regenerating with the same seed yields identical bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from tools.generate_synthetic_cn_notes import (
    DEFAULT_NEGATIVES_PER_TYPE,
    DEFAULT_PER_TYPE,
    DEFAULT_SEED,
    DOC_TYPES,
    generate_corpus,
)

CORPUS = Path(__file__).resolve().parent / "fixtures" / "synthetic_cn_notes"
GENERATOR = Path(__file__).resolve().parents[1] / "tools" / "generate_synthetic_cn_notes.py"

SUPPORTED_FACT_TYPES = {
    # v0.1 baseline
    "PHONE",
    "EMAIL",
    "URL",
    "IP_ADDRESS",
    "PERSON_NAME",
    "GOVERNMENT_ID",
    "MEDICAL_RECORD_NUMBER",
    "EXACT_DATE",
    "PRECISE_LOCATION",
    # v0.2 clinical narrative and institution context
    "AGE",
    "SEX",
    "HOSPITAL_NAME",
    "DEPARTMENT",
    "WARD",
    "BED_NUMBER",
    "DOCTOR_NAME",
    "NURSE_NAME",
    "RELATIVE_NAME",
    "SPECIMEN_ID",
    "ACCESSION_NUMBER",
    "LANDLINE",
    "POSTAL_CODE",
    "SOCIAL_MEDIA_ID",
    "RARE_CONTEXT",
}


def _sidecars() -> list[Path]:
    return sorted(CORPUS.glob("*.spans.json"))


def _load(sidecar: Path) -> tuple[str, dict]:
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    text = sidecar.with_name(sidecar.name[: -len(".spans.json")] + ".txt").read_text(
        encoding="utf-8"
    )
    return text, meta


@pytest.fixture(scope="module")
def corpus() -> list[tuple[str, dict]]:
    documents = _sidecars()
    assert documents, f"corpus is empty: {CORPUS} (run tools/generate_synthetic_cn_notes.py)"
    return [_load(s) for s in documents]


# -- structure --------------------------------------------------------------


def test_corpus_has_seven_document_types(corpus):
    types = {meta["document_type"] for _, meta in corpus}
    assert types == set(DOC_TYPES)


def test_each_document_type_meets_minimum_count(corpus):
    counts: dict[str, int] = {}
    for _, meta in corpus:
        counts[meta["document_type"]] = counts.get(meta["document_type"], 0) + 1
    for doc_type in DOC_TYPES:
        assert counts.get(doc_type, 0) >= DEFAULT_PER_TYPE, doc_type


def test_every_text_has_a_sidecar(corpus):
    texts = {p.name[: -len(".txt")] for p in CORPUS.glob("*.txt")}
    sidecars = {p.name[: -len(".spans.json")] for p in _sidecars()}
    assert texts == sidecars


def test_documents_use_multiple_departments(corpus):
    departments = {meta["department"] for _, meta in corpus}
    assert len(departments) >= 5


# -- annotation integrity ---------------------------------------------------


def test_span_offsets_align_with_text(corpus):
    for text, meta in corpus:
        for span in meta["spans"]:
            start, end = span["start"], span["end"]
            assert 0 <= start < end <= len(text), (meta["doc_id"], span)
            assert text[start:end].strip(), (meta["doc_id"], span)


def test_span_types_are_supported(corpus):
    seen = {s["type"] for _, meta in corpus for s in meta["spans"]}
    assert seen <= SUPPORTED_FACT_TYPES, seen - SUPPORTED_FACT_TYPES


def test_expected_verdict_follows_the_declared_rule(corpus):
    """The declared verdict must come from the document, not from the guard.

    Stated independently of the generator so that a change to either the rule
    or the corpus is caught: identifier-free content needs no transformation;
    a rare-context re-identification claim needs human review; anything else
    must have its identifiers transformed before release.
    """
    for _, meta in corpus:
        rare = any(s["type"] == "RARE_CONTEXT" for s in meta["spans"])
        if not meta["spans"]:
            expected = "ALLOW"
        elif rare:
            expected = "ASK"
        else:
            expected = "SANITIZE"
        assert meta["expected_verdict"] == expected, meta["doc_id"]


def test_expected_verdict_covers_all_three_outcomes(corpus):
    """A corpus that only ever declares one verdict cannot detect a policy drift."""
    declared = {meta["expected_verdict"] for _, meta in corpus}
    assert declared == {"SANITIZE", "ASK", "ALLOW"}


def test_corpus_covers_all_supported_fact_types(corpus):
    seen = {s["type"] for _, meta in corpus for s in meta["spans"]}
    assert seen == SUPPORTED_FACT_TYPES, SUPPORTED_FACT_TYPES - seen


def test_corpus_includes_no_identifier_documents(corpus):
    no_identifier = [meta for _, meta in corpus if not meta["spans"]]
    assert no_identifier, "corpus must exercise the ALLOW path"
    # Every document type should contribute one such document.
    assert {meta["document_type"] for meta in no_identifier} == set(DOC_TYPES)


def test_span_values_are_unique_per_document(corpus):
    """Identical adjacent spans would make alignment scoring ambiguous."""
    for text, meta in corpus:
        seen: set[tuple[int, int, str]] = set()
        for span in meta["spans"]:
            key = (span["start"], span["end"], span["type"])
            assert key not in seen, (meta["doc_id"], key)
            seen.add(key)


# -- synthetic-only guarantee ----------------------------------------------


def test_mobile_numbers_use_placeholder_prefix(corpus):
    for text, meta in corpus:
        for span in meta["spans"]:
            if span["type"] != "PHONE":
                continue
            value = text[span["start"] : span["end"]]
            assert re.fullmatch(r"1[3-9]\d{9}", value), value
            assert value.startswith("138000"), value


def test_network_identifiers_use_reserved_ranges(corpus):
    for text, meta in corpus:
        for span in meta["spans"]:
            value = text[span["start"] : span["end"]]
            if span["type"] == "IP_ADDRESS":
                assert value.startswith(("192.0.2.", "198.51.100.")), value
            elif span["type"] == "EMAIL":
                assert value.split("@", 1)[1] in {"example.com", "example.org"}, value
            elif span["type"] == "URL":
                assert value.startswith(("https://example.com/", "https://example.org/")), value


def test_resident_ids_have_valid_check_digit(corpus):
    from detectors.cn_identifiers import validate_id18

    checked = 0
    for text, meta in corpus:
        for span in meta["spans"]:
            if span["type"] != "GOVERNMENT_ID":
                continue
            value = text[span["start"] : span["end"]]
            assert validate_id18(value), value
            checked += 1
    assert checked > 0


def test_no_document_is_marked_real(corpus):
    for _, meta in corpus:
        assert meta["synthetic"] is True
        assert meta["text_policy"] == "do_not_store_in_audit"


# -- negative corpus --------------------------------------------------------


def test_corpus_has_expected_role_split(corpus):
    roles = Counter(meta["corpus_role"] for _, meta in corpus)
    assert roles["positive"] == len(DOC_TYPES) * DEFAULT_PER_TYPE
    assert roles["negative"] == len(DOC_TYPES) * DEFAULT_NEGATIVES_PER_TYPE


def test_negative_documents_declare_no_spans(corpus):
    for _, meta in corpus:
        if meta["corpus_role"] == "negative":
            assert meta["spans"] == [], meta["doc_id"]


def test_positive_documents_declare_spans(corpus):
    for _, meta in corpus:
        if meta["corpus_role"] == "positive":
            assert meta["spans"], meta["doc_id"]


def test_negative_documents_have_no_detectable_identifier(corpus):
    """The negative corpus must be genuinely identifier-free.

    If a detector fires here, either the detector over-reaches or the document
    smuggled in an identifier. Both make the corpus lie about what it measures,
    so this fails fast instead of waiting for the full benchmark.
    """
    from core.benchmark import NON_SPAN_FACT_TYPES
    from detectors import detect_all

    for text, meta in corpus:
        if meta["corpus_role"] != "negative":
            continue
        found = sorted({f.type for f in detect_all(text)} - NON_SPAN_FACT_TYPES)
        assert not found, f"{meta['doc_id']}: {found}"


def test_negative_documents_contain_adversarial_material(corpus):
    """The negative half is only useful if it actually looks like identifiers."""
    text = "\n".join(t for t, m in corpus if m["corpus_role"] == "negative")
    for phrase in (
        "男病房",
        "男女比例",
        "主任医师",
        "责任护士",
        "床位紧张",
        "三级甲等医院",
        "50岁以上人群",
        "罕见病诊疗管理",
        "本病区",
    ):
        assert phrase in text, phrase


# -- reproducibility --------------------------------------------------------


def _tree_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.iterdir()):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_generation_is_independent_of_hash_seed(tmp_path):
    """Byte-exact reproducibility must not depend on PYTHONHASHSEED.

    Iterating a set into a tuple follows hash order, which varies per process:
    the corpus would then differ between the machine that generated it and any
    machine that regenerates it. A same-process comparison cannot catch that,
    so the generator runs in two subprocesses with different seeds.
    """
    digests = []
    for seed in ("0", "1"):
        out = tmp_path / f"corpus_{seed}"
        subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--out",
                str(out),
                "--per-type",
                "1",
                "--negatives-per-type",
                "1",
            ],
            check=True,
            capture_output=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        digests.append(_tree_digest(out))
    assert digests[0] == digests[1]


def test_regeneration_is_byte_identical(tmp_path):
    generate_corpus(tmp_path, per_type=2, seed=DEFAULT_SEED)
    for sidecar in sorted(tmp_path.glob("*.spans.json")):
        original = CORPUS / sidecar.name
        assert original.is_file(), f"{sidecar.name} missing from committed corpus"
        assert sidecar.read_text(encoding="utf-8") == original.read_text(encoding="utf-8")
        text_name = sidecar.name[: -len(".spans.json")] + ".txt"
        assert (tmp_path / text_name).read_text(encoding="utf-8") == (
            CORPUS / text_name
        ).read_text(encoding="utf-8")


def test_committed_corpus_matches_generator(tmp_path):
    """The committed corpus must be exactly what the generator produces."""
    generate_corpus(tmp_path, per_type=DEFAULT_PER_TYPE, seed=DEFAULT_SEED)
    expected = {p.name for p in tmp_path.iterdir()}
    actual = {p.name for p in CORPUS.iterdir()}
    assert actual == expected, (actual - expected, expected - actual)
