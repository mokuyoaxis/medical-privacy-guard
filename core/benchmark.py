"""Strict one-to-one span scoring and per-document release/audit safety gates.

Exact type and code-point boundaries are required for a true positive.
Released labels must be wholly covered by planned transformations; this
conservative residual check also catches partially detected identifiers whose
full original value no longer occurs in the output. Actual execution is checked
by the Guard verifier, not inferred from output offsets.

Reports contain only metadata and counts. ``sanitized_documents`` retains its
legacy meaning of all released documents; use ``sanitized_verified_documents``
for successful SANITIZE releases and ``allowed_original_documents`` for ALLOW.
"""

from __future__ import annotations

import json
import math
import re
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from core.errors import GuardError
from core.model import DetectedFact, Purpose, Recipient, TrustLevel, Verdict
from core.policy import CONTEXT_ONLY_TYPES
from detectors import detect_all
from medical_privacy_guard import Guard

DEFAULT_PROFILE = "external-ai-strict"
# The corpus models disclosure to an institution-approved external endpoint:
# that is the recipient for which "de-identify, then send" is the expected
# outcome. An unknown external recipient gets ASK for any note carrying
# medical content (core/policy.py), so under EXTERNAL_UNKNOWN no document ever
# reaches the sanitize path and the residual/verification gates are vacuous.
DEFAULT_RECIPIENT = "external_approved"
DEFAULT_PURPOSE = "EXTERNAL_AI_ASSISTANCE"

# Fact types that describe a document-level classification rather than a
# replaceable span. They are excluded from span recall/precision but still
# flow through policy.
NON_SPAN_FACT_TYPES = frozenset({"MEDICAL_CONTENT", "PARSER_FAILURE", "UNSUPPORTED_FORMAT"})

# Context types that policy deliberately does not transform: sex, medical
# content and rare-context signals carry risk but have no span to rewrite.
# Their values legitimately survive into the released payload, so they must
# not be counted as residual PHI. Derived from the policy allow-list so the
# benchmark and the verifier cannot drift apart on which types survive.
NON_TRANSFORMABLE_TYPES = CONTEXT_ONLY_TYPES | {"RARE_CONDITION"}


@dataclass
class CorpusDocument:
    """One labelled document loaded from the corpus directory."""

    doc_id: str
    document_type: str
    department: str
    text: str
    spans: tuple[Mapping[str, Any], ...]
    expected_verdict: str


@dataclass
class DocumentOutcome:
    """Internal outcome; audit_text may contain injected leaks and is never exported."""

    doc_id: str
    document_type: str
    expected_verdict: str
    actual_verdict: str
    true_positives: int
    false_negatives: int
    false_positives: int
    residual_spans: int
    verification_failed: bool
    verification_ran: bool
    released: bool
    audit_leaks: int
    latency_ms: float
    error: str | None = None
    lifecycle_failed: bool = False
    allowed_original: bool = False
    sanitized_verified: bool = False
    audit_failure: str | None = None
    audit_text: str = field(default="", repr=False)

    @property
    def labelled_spans(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def verdict_matches(self) -> bool:
        return self.actual_verdict == self.expected_verdict


@dataclass
class BenchmarkReport:
    """Aggregate benchmark result. Safe to print or persist."""

    profile: str
    recipient: str
    purpose: str
    documents: int
    span_documents: int
    clean_documents: int
    labelled_spans: int
    true_positives: int
    false_negatives: int
    false_positives: int
    false_positives_on_clean_documents: int
    false_allow_count: int
    residual_phi_count: int
    verification_failure_count: int
    verification_runs: int
    sanitized_documents: int  # Legacy total released, including unchanged ALLOW.
    released_documents: int
    allowed_original_documents: int
    sanitized_verified_documents: int
    ask_documents: int
    blocked_documents: int
    lifecycle_failure_count: int
    audit_failure_count: int
    audit_missing_count: int
    audit_invalid_count: int
    audit_mismatch_count: int
    audit_read_error_count: int
    verdict_mismatch_count: int
    audit_raw_leak_count: int
    errors: int
    span_recall: float
    span_precision: float
    p50_latency_ms: float
    p95_latency_ms: float
    by_fact_type: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    by_document_type: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "recipient": self.recipient,
            "purpose": self.purpose,
            "documents": self.documents,
            "span_documents": self.span_documents,
            "clean_documents": self.clean_documents,
            "labelled_spans": self.labelled_spans,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "false_positives_on_clean_documents": self.false_positives_on_clean_documents,
            "span_recall": round(self.span_recall, 4),
            "span_precision": round(self.span_precision, 4),
            "false_allow_count": self.false_allow_count,
            "residual_phi_count": self.residual_phi_count,
            "verification_failure_count": self.verification_failure_count,
            "verification_runs": self.verification_runs,
            "sanitized_documents": self.sanitized_documents,
            "sanitized_documents_semantics": "legacy alias for released_documents (ALLOW + SANITIZE)",
            "released_documents": self.released_documents,
            "allowed_original_documents": self.allowed_original_documents,
            "sanitized_verified_documents": self.sanitized_verified_documents,
            "ask_documents": self.ask_documents,
            "blocked_documents": self.blocked_documents,
            "lifecycle_failure_count": self.lifecycle_failure_count,
            "audit_failure_count": self.audit_failure_count,
            "audit_missing_count": self.audit_missing_count,
            "audit_invalid_count": self.audit_invalid_count,
            "audit_mismatch_count": self.audit_mismatch_count,
            "audit_read_error_count": self.audit_read_error_count,
            "verdict_mismatch_count": self.verdict_mismatch_count,
            "audit_raw_leak_count": self.audit_raw_leak_count,
            "errors": self.errors,
            "p50_latency_ms": round(self.p50_latency_ms, 3),
            "p95_latency_ms": round(self.p95_latency_ms, 3),
            "by_fact_type": {k: dict(v) for k, v in sorted(self.by_fact_type.items())},
            "by_document_type": {k: dict(v) for k, v in sorted(self.by_document_type.items())},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def gates_passed(self) -> bool:
        """True when safety, per-document lifecycle and audit checks succeed."""
        return not set(self.gate_failures()) - {"verdict_mismatch", "false_positive"}

    def verdict_gates_passed(self) -> bool:
        """True when every document reached the verdict the corpus declares.

        The corpus expectation is hand-written from the document's own content
        (see ``_expected_verdict`` in the generator), so a mismatch means the
        policy disagreed with an independently stated expectation rather than
        with itself.
        """
        return self.verdict_mismatch_count == 0

    def precision_gates_passed(self) -> bool:
        """True when no detector produced a span the corpus does not account for.

        Over-redaction is not a safety failure — it errs toward withholding —
        so this is a quality gate reported alongside, not inside,
        :meth:`gates_passed`. It still has to stay at zero: a spurious span
        silently strips clinical meaning out of the released text.
        """
        return self.false_positives == 0

    def gate_failures(self) -> tuple[str, ...]:
        """Names of every gate that failed, for CLI output and test messages."""
        failures: list[str] = []
        if self.false_allow_count:
            failures.append("false_allow")
        if self.residual_phi_count:
            failures.append("residual_phi")
        if self.audit_raw_leak_count:
            failures.append("audit_raw_leak")
        if self.errors:
            failures.append("errors")
        if self.verification_failure_count:
            failures.append("verification_failure")
        if self.lifecycle_failure_count:
            failures.append("lifecycle_failure")
        if self.audit_failure_count:
            failures.append("audit_failure")
        if self.false_negatives:
            failures.append("incomplete_span_coverage")
        if self.sanitized_verified_documents == 0 or self.verification_runs == 0:
            failures.append("sanitize_path_not_exercised")
        if self.verdict_mismatch_count:
            failures.append("verdict_mismatch")
        if self.false_positives:
            failures.append("false_positive")
        return tuple(failures)

    def passed(self) -> bool:
        """True when safety, verdict and precision gates all hold."""
        return not self.gate_failures()


# -- corpus loading ---------------------------------------------------------


def load_corpus(corpus_dir: str | Path, limit: int | None = None) -> list[CorpusDocument]:
    """Load ``*.spans.json`` sidecars and their sibling ``.txt`` documents."""
    directory = Path(corpus_dir).resolve()
    if not directory.is_dir():
        raise GuardError(f"corpus directory not found: {directory}")
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise GuardError("corpus limit must be a positive integer")

    documents: list[CorpusDocument] = []
    seen_ids: set[str] = set()
    for sidecar in sorted(directory.glob("*.spans.json")):
        text_path = sidecar.with_name(sidecar.name[: -len(".spans.json")] + ".txt")
        if sidecar.resolve().parent != directory or text_path.resolve().parent != directory:
            raise GuardError("corpus files must remain within the corpus directory")
        try:
            meta = json.loads(sidecar.read_text(encoding="utf-8"))
            text = text_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise GuardError(f"cannot read corpus document {sidecar.name}") from exc
        if not isinstance(meta, dict) or not isinstance(meta.get("spans"), list):
            raise GuardError(f"{sidecar.name}: expected an object with a spans list")
        expected = meta.get("expected_verdict")
        if not isinstance(expected, str) or expected not in {v.value for v in Verdict}:
            raise GuardError(f"{sidecar.name}: invalid or missing expected_verdict")
        doc_id = meta.get("doc_id", text_path.stem)
        if (
            not isinstance(doc_id, str) or not doc_id or doc_id in {".", ".."}
            or any(c in doc_id for c in ("/", "\\", "\x00")) or doc_id in seen_ids
        ):
            raise GuardError(f"{sidecar.name}: invalid or duplicate doc_id")
        seen_ids.add(doc_id)
        doc = CorpusDocument(
            doc_id=doc_id,
            document_type=str(meta.get("document_type", "unknown")),
            department=str(meta.get("department", "unknown")),
            text=text,
            spans=tuple(meta["spans"]),
            expected_verdict=expected,
        )
        _validate_spans(doc, text_path)
        documents.append(doc)

    if not documents:
        raise GuardError("corpus contains no annotated documents")
    return documents if limit is None else documents[:limit]


def _validate_spans(doc: CorpusDocument, path: Path) -> None:
    """Fail loudly on a mis-annotated corpus rather than silently mis-scoring."""
    seen: set[tuple[str, int, int]] = set()
    for span in doc.spans:
        if not isinstance(span, dict):
            raise GuardError(f"{path.name}: malformed span")
        start, end, ftype = span.get("start"), span.get("end"), span.get("type")
        if (
            type(start) is not int or type(end) is not int
            or not isinstance(ftype, str) or not ftype or ftype in NON_SPAN_FACT_TYPES
            or not 0 <= start < end <= len(doc.text)
        ):
            raise GuardError(f"{path.name}: invalid span type or boundaries")
        key = (ftype, start, end)
        if key in seen:
            raise GuardError(f"{path.name}: duplicate span")
        seen.add(key)


# -- alignment --------------------------------------------------------------


def _align_indices(
    facts: Sequence[DetectedFact], spans: Sequence[Mapping[str, Any]]
) -> tuple[set[int], set[int]]:
    """Match exact type and boundaries one-to-one, including duplicate facts."""
    matched_spans: set[int] = set()
    matched_facts: set[int] = set()
    for fi, fact in enumerate(facts):
        if fact.type in NON_SPAN_FACT_TYPES:
            continue
        for si, span in enumerate(spans):
            if (
                si not in matched_spans and fact.type == span["type"]
                and (fact.start, fact.end) == (span["start"], span["end"])
            ):
                matched_spans.add(si)
                matched_facts.add(fi)
                break
    return matched_spans, matched_facts


def _false_positive_facts(
    facts: Sequence[DetectedFact], spans: Sequence[Mapping[str, Any]]
) -> list[DetectedFact]:
    _, matched = _align_indices(facts, spans)
    return [f for i, f in enumerate(facts) if i not in matched and f.type not in NON_SPAN_FACT_TYPES]


def align_document(
    facts: Sequence[DetectedFact], spans: Sequence[Mapping[str, Any]]
) -> tuple[int, int, int]:
    """Return strict one-to-one (true positives, false negatives, false positives)."""
    matched_spans, matched_facts = _align_indices(facts, spans)
    scored = sum(f.type not in NON_SPAN_FACT_TYPES for f in facts)
    return len(matched_spans), len(spans) - len(matched_spans), scored - len(matched_facts)


def _type_stats(
    stats: dict[str, dict[str, int]], fact_type: str
) -> dict[str, int]:
    return stats.setdefault(
        fact_type, {"labelled": 0, "detected": 0, "residual": 0, "false_positive": 0}
    )


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


# -- evaluation -------------------------------------------------------------


def run_benchmark(
    corpus_dir: str | Path,
    profile: str = DEFAULT_PROFILE,
    recipient: str = DEFAULT_RECIPIENT,
    purpose: str = DEFAULT_PURPOSE,
    limit: int | None = None,
) -> BenchmarkReport:
    """Drive every corpus document through the full guard pipeline.

    Sanitization uses a temporary audit directory that is scanned for raw
    labelled values and then discarded.
    """
    documents = load_corpus(corpus_dir, limit=limit)
    guard = Guard(profile=profile)
    recipient_obj = Recipient(kind="benchmark", trust_level=TrustLevel(recipient.upper()))
    purpose_obj = _coerce_purpose(purpose)

    outcomes: list[DocumentOutcome] = []
    fact_type_stats: dict[str, dict[str, int]] = {}

    with tempfile.TemporaryDirectory(prefix="mpg-benchmark-") as audit_root:
        audit_dir = Path(audit_root)
        for index, doc in enumerate(documents):
            outcomes.append(
                _evaluate_document(
                    guard, doc, recipient_obj, purpose_obj,
                    audit_dir / str(index), fact_type_stats,
                )
            )
        event_ids: set[str] = set()
        for outcome in outcomes:
            if outcome.audit_failure is None:
                event_id = json.loads(outcome.audit_text)["event_id"]
                if event_id in event_ids:
                    outcome.audit_failure = "invalid"
                event_ids.add(event_id)
        audit_text = "\n".join(outcome.audit_text for outcome in outcomes)

    return _aggregate(
        outcomes, fact_type_stats, audit_text, documents, profile, recipient_obj, purpose_obj
    )


def _coerce_purpose(purpose: str) -> Purpose:
    try:
        return Purpose(purpose.upper())
    except ValueError:
        return Purpose.UNKNOWN


# A residual value must survive as a whole token. Naive substring containment
# is both too strict and too loose: 89岁 is "contained" in the generalized band
# 80-89岁, and 2026-01 is contained in 2026-01-03 — neither is a leak, because
# the value was transformed and the hit is a fragment of a longer number or
# range. These sets decide whether an occurrence is such a fragment.
_FRAGMENT_BEFORE = frozenset("0123456789.-–—~～")
_FRAGMENT_AFTER = frozenset("0123456789")

# Band and threshold qualifiers. 90岁 is a fragment of the generalized band
# 90岁及以上, 50岁 of the population statement 50岁以上人群, and 1岁 of the
# band 不足1岁; in each the value is qualified rather than disclosed, so none
# is a residual. Mirrors the qualifiers the AGE detector itself excludes.
_BAND_SUFFIXES = ("及以上", "及以下", "以上", "以下", "左右", "上下")
_BAND_PREFIXES = ("不足",)


def _survives_as_token(value: str, released: str) -> bool:
    """True when *value* appears in *released* as a standalone token."""
    start = 0
    while (index := released.find(value, start)) != -1:
        before = released[index - 1] if index else ""
        end = index + len(value)
        after = released[end] if end < len(released) else ""
        if (
            before not in _FRAGMENT_BEFORE
            and after not in _FRAGMENT_AFTER
            and not released.startswith(_BAND_SUFFIXES, end)
            and not released[:index].endswith(_BAND_PREFIXES)
        ):
            return True
        start = index + 1
    return False


def _evaluate_document(
    guard: Guard,
    doc: CorpusDocument,
    recipient: Recipient,
    purpose: Purpose,
    audit_dir: Path,
    fact_type_stats: dict[str, dict[str, int]],
) -> DocumentOutcome:
    started = time.perf_counter()
    facts = detect_all(doc.text)
    true_positives, false_negatives, false_positives = align_document(facts, doc.spans)
    matched_spans, _ = _align_indices(facts, doc.spans)
    for index, span in enumerate(doc.spans):
        stats = _type_stats(fact_type_stats, span["type"])
        stats["labelled"] += 1
        if index in matched_spans:
            stats["detected"] += 1
    for fact in _false_positive_facts(facts, doc.spans):
        _type_stats(fact_type_stats, fact.type)["false_positive"] += 1

    try:
        result = guard.sanitize(doc.text, recipient, purpose, audit_dir=str(audit_dir))
    except GuardError as exc:
        audit_failure, audit_text = _check_audit(audit_dir, None)
        return DocumentOutcome(
            doc_id=doc.doc_id,
            document_type=doc.document_type,
            expected_verdict=doc.expected_verdict,
            actual_verdict="ERROR",
            true_positives=true_positives,
            false_negatives=false_negatives,
            false_positives=false_positives,
            residual_spans=0,
            verification_failed=False,
            verification_ran=False,
            released=False,
            audit_leaks=0,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            error=type(exc).__name__,
            lifecycle_failed=True,
            audit_failure=audit_failure,
            audit_text=audit_text,
        )
    latency_ms = (time.perf_counter() - started) * 1000.0
    decision = result.decision_before
    verdict = decision.verdict.value
    verification_ran = result.verification is not None
    verification_failed = verification_ran and result.verification.passed is not True
    released = result.sanitized_payload is not None
    allowed_original = (
        verdict == "ALLOW" and released and not verification_ran
        and result.sanitized_payload.kind == "text"
        and result.sanitized_payload.content == doc.text
    )
    sanitized_verified = (
        verdict == "SANITIZE" and released and verification_ran and not verification_failed
        and result.sanitized_payload.kind == "text"
        and isinstance(result.sanitized_payload.content, str)
    )
    lifecycle_ok = verdict == doc.expected_verdict and (
        (doc.expected_verdict == "SANITIZE" and sanitized_verified)
        or (doc.expected_verdict == "ALLOW" and allowed_original)
        or (doc.expected_verdict in {"ASK", "BLOCK"} and not released and not verification_ran)
    )
    status = "FAIL" if verification_failed else "PASS" if verification_ran else (
        "N/A (ALLOW)" if verdict == "ALLOW" else "N/A"
    )
    operations = decision.plan.operations if decision.plan else ()
    expected_audit = {
        "decision": verdict,
        "reason_codes": [reason.value for reason in decision.reason_codes],
        "entity_counts": dict(Counter(f.type for f in facts)),
        "risk_level": decision.risk.level.value,
        "risk_score": decision.risk.score,
        "recipient_class": recipient.trust_level.value,
        "purpose": purpose.value,
        "policy_profile": guard.profile.policy_version.split("/", 1)[0],
        "policy_version": guard.profile.policy_version,
        "transformations": [f"{op.op}_{op.entity_type or op.target}" for op in operations],
        "verification": status,
    }
    audit_failure, audit_text = _check_audit(audit_dir, expected_audit)

    residual_spans = 0
    if released and isinstance(result.sanitized_payload.content, str):
        for span in doc.spans:
            if span["type"] in NON_TRANSFORMABLE_TYPES:
                continue
            value = doc.text[span["start"] : span["end"]]
            covered = any(
                fact.type == span["type"] and fact.start <= span["start"]
                and fact.end >= span["end"]
                and any(op.target == fact.type and op.op != "KEEP" for op in operations)
                for fact in facts
            )
            if not covered or _survives_as_token(value, result.sanitized_payload.content):
                residual_spans += 1
                _type_stats(fact_type_stats, span["type"])["residual"] += 1

    return DocumentOutcome(
        doc_id=doc.doc_id,
        document_type=doc.document_type,
        expected_verdict=doc.expected_verdict,
        actual_verdict=verdict,
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
        residual_spans=residual_spans,
        verification_failed=verification_failed,
        verification_ran=verification_ran,
        released=released,
        audit_leaks=0,
        latency_ms=latency_ms,
        lifecycle_failed=not lifecycle_ok,
        allowed_original=allowed_original,
        sanitized_verified=sanitized_verified,
        audit_failure=audit_failure,
        audit_text=audit_text,
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _check_audit(
    audit_dir: Path, expected: Mapping[str, Any] | None,
) -> tuple[str | None, str]:
    """Require exactly one metadata-only event for this isolated request."""
    try:
        content = (audit_dir / "events.jsonl").read_text(encoding="utf-8")
    except FileNotFoundError:
        return "missing", ""
    except (OSError, UnicodeError):
        return "read_error", ""
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        return "missing", content
    if len(lines) != 1:
        return "invalid", content
    try:
        event = json.loads(lines[0], object_pairs_hook=_unique_json_object)
    except (ValueError, TypeError):
        return "invalid", content
    if not isinstance(event, dict):
        return "invalid", content
    # The exact field set is checked on purpose: an audit record that grows an
    # unexpected field is a schema change, and this gate must be updated
    # deliberately rather than silently accept it. prev_hash / event_hash are
    # the chained-integrity fields; both must be non-empty on a chained record.
    fields = {
        "event_id", "timestamp", "decision", "reason_codes", "entity_counts",
        "risk_level", "risk_score", "recipient_class", "purpose", "policy_profile",
        "policy_version", "transformations", "verification",
        "prev_hash", "event_hash",
    }
    string_fields = fields - {"reason_codes", "entity_counts", "risk_score", "transformations"}
    if (
        set(event) != fields
        or any(not isinstance(event[k], str) or not event[k] for k in string_fields)
        or type(event["risk_score"]) is not int
        or not isinstance(event["entity_counts"], dict)
        or any(not isinstance(k, str) or type(v) is not int or v < 0
               for k, v in event["entity_counts"].items())
        or any(not isinstance(event[k], list) or any(not isinstance(v, str) for v in event[k])
               for k in ("reason_codes", "transformations"))
    ):
        return "invalid", content
    try:
        datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return "invalid", content
    event.pop("timestamp")
    audit_text = json.dumps(event, ensure_ascii=False, sort_keys=True)
    if expected is None or any(event[k] != value for k, value in expected.items()):
        return "mismatch", audit_text
    return None, audit_text


def _aggregate(
    outcomes: Sequence[DocumentOutcome],
    fact_type_stats: dict[str, dict[str, int]],
    audit_text: str,
    documents: Sequence[CorpusDocument],
    profile: str,
    recipient: Recipient,
    purpose: Purpose,
) -> BenchmarkReport:
    labelled = [o for o in outcomes if o.labelled_spans > 0]
    clean = [o for o in outcomes if o.labelled_spans == 0]
    tp = sum(o.true_positives for o in outcomes)
    fn = sum(o.false_negatives for o in outcomes)
    fp = sum(o.false_positives for o in outcomes)
    fp_clean = sum(o.false_positives for o in clean)

    false_allow = sum(
        1 for o in outcomes if o.actual_verdict == Verdict.ALLOW.value
        and o.expected_verdict != Verdict.ALLOW.value
    )
    residual = sum(o.residual_spans for o in outcomes)
    verification_failures = sum(1 for o in outcomes if o.verification_failed)
    verification_runs = sum(1 for o in outcomes if o.verification_ran)
    sanitized = sum(1 for o in outcomes if o.released)
    verdict_mismatches = sum(1 for o in outcomes if not o.verdict_matches)
    errors = sum(1 for o in outcomes if o.error is not None)

    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0

    latencies = [o.latency_ms for o in outcomes]
    by_doc_type: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[DocumentOutcome]] = {}
    for outcome in outcomes:
        grouped.setdefault(outcome.document_type, []).append(outcome)
    for doc_type, group in sorted(grouped.items()):
        g_tp = sum(o.true_positives for o in group)
        g_fn = sum(o.false_negatives for o in group)
        g_fp = sum(o.false_positives for o in group)
        by_doc_type[doc_type] = {
            "documents": len(group),
            "clean_documents": sum(1 for o in group if o.labelled_spans == 0),
            "labeled_spans": g_tp + g_fn,
            "recall": round(g_tp / (g_tp + g_fn), 4) if (g_tp + g_fn) else 1.0,
            "precision": round(g_tp / (g_tp + g_fp), 4) if (g_tp + g_fp) else 1.0,
            "false_positives": g_fp,
            "residual_phi": sum(o.residual_spans for o in group),
            "sanitized_documents": sum(1 for o in group if o.released),
            "released_documents": sum(o.released for o in group),
            "allowed_original_documents": sum(o.allowed_original for o in group),
            "sanitized_verified_documents": sum(o.sanitized_verified for o in group),
            "lifecycle_failure_count": sum(o.lifecycle_failed for o in group),
            "audit_failure_count": sum(o.audit_failure is not None for o in group),
            "verdict_mismatch": sum(1 for o in group if not o.verdict_matches),
            "false_allow": sum(
                1
                for o in group
                if o.actual_verdict == Verdict.ALLOW.value
                and o.expected_verdict != Verdict.ALLOW.value
            ),
        }

    audit_leaks = _count_audit_leaks(documents, audit_text)

    return BenchmarkReport(
        profile=guard_profile_label(profile),
        recipient=recipient.trust_level.value,
        purpose=purpose.value,
        documents=len(outcomes),
        span_documents=len(labelled),
        clean_documents=len(clean),
        labelled_spans=tp + fn,
        true_positives=tp,
        false_negatives=fn,
        false_positives=fp,
        false_positives_on_clean_documents=fp_clean,
        false_allow_count=false_allow,
        residual_phi_count=residual,
        verification_failure_count=verification_failures,
        verification_runs=verification_runs,
        sanitized_documents=sanitized,
        released_documents=sanitized,
        allowed_original_documents=sum(o.allowed_original for o in outcomes),
        sanitized_verified_documents=sum(o.sanitized_verified for o in outcomes),
        ask_documents=sum(o.actual_verdict == "ASK" for o in outcomes),
        blocked_documents=sum(o.actual_verdict == "BLOCK" for o in outcomes),
        lifecycle_failure_count=sum(o.lifecycle_failed for o in outcomes),
        audit_failure_count=sum(o.audit_failure is not None for o in outcomes),
        audit_missing_count=sum(o.audit_failure == "missing" for o in outcomes),
        audit_invalid_count=sum(o.audit_failure == "invalid" for o in outcomes),
        audit_mismatch_count=sum(o.audit_failure == "mismatch" for o in outcomes),
        audit_read_error_count=sum(o.audit_failure == "read_error" for o in outcomes),
        verdict_mismatch_count=verdict_mismatches,
        audit_raw_leak_count=audit_leaks,
        errors=errors,
        span_recall=recall,
        span_precision=precision,
        p50_latency_ms=_percentile(latencies, 0.50),
        p95_latency_ms=_percentile(latencies, 0.95),
        by_fact_type=fact_type_stats,
        by_document_type=by_doc_type,
    )


#: Audit fields whose values are random hex rather than payload-derived.
#: ``event_id`` is a UUID and the chain hashes are SHA-256 digests, so a short
#: labelled value can occur inside one by chance: the postal code 730908 was
#: found inside a 64-character event_hash. This gate is absolute (must be 0), so
#: a spurious hit failed the whole run intermittently. The fields carry no
#: payload, so removing them removes the false positive without weakening the
#: check — a real leak lives in a semantic field and is still caught.
_RANDOM_AUDIT_FIELD_RE = re.compile(r'"(?:event_id|prev_hash|event_hash)"\s*:\s*"[^"]*"')


def _count_audit_leaks(
    documents: Sequence[CorpusDocument], audit_text: str
) -> int:
    """Count raw labelled values appearing anywhere in the audit stream.

    The audit must never become a disclosure source, so this is an absolute
    gate (must be 0) rather than a rate. Values are read from the corpus on
    the fly and never stored in the report. Random identifier fields are
    stripped first; see ``_RANDOM_AUDIT_FIELD_RE``.
    """
    if not audit_text:
        return 0
    scan_text = _RANDOM_AUDIT_FIELD_RE.sub("", audit_text)
    leaks = 0
    seen: set[str] = set()
    for doc in documents:
        for span in doc.spans:
            value = doc.text[span["start"] : span["end"]]
            if len(value) < 2 or value in seen:
                continue
            seen.add(value)
            if value in scan_text:
                leaks += 1
    return leaks


def guard_profile_label(profile: str) -> str:
    """Return the loaded profile's versioned label (e.g. external-ai-strict/1)."""
    try:
        from core.policy import load_builtin_profile

        return load_builtin_profile(profile).policy_version
    except GuardError:
        return profile
