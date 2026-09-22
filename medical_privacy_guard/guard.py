"""Public Python API for medical-privacy-guard.

The Guard class is the single entry point for embedding this library in
pipelines and agents:

    from medical_privacy_guard import Guard

    guard = Guard(profile="external-ai-strict")
    result = guard.evaluate(
        payload="患者：张三",
        recipient="external-ai",
        purpose="EXTERNAL_AI_ASSISTANCE",
    )
"""

from __future__ import annotations

import os
from typing import Sequence

from core.audit import AuditError, AuditWriter, build_audit_event
from core.dictionary import load_dictionary
from core.errors import ParserError
from core.model import (
    Decision,
    DetectedFact,
    EnvironmentContext,
    EvaluationResult,
    Payload,
    Purpose,
    ReasonCode,
    Recipient,
    RiskFactor,
    RiskLevel,
    RiskSummary,
    SanitizationResult,
    TrustLevel,
    Verdict,
    VerificationResult,
)
from core.policy import PolicyEvaluator, PolicyProfile, load_builtin_profile
from core.verify import verify_sanitized
from detectors import detect_all
from detectors import registry as detector_registry
from detectors.dictionary import DictionaryDetector
from formats import dumps, from_document, parse_json_payload, rebuild
from transformers import apply_plan

__all__ = ["Guard"]


#: Separator between leaf values when a structured payload is flattened for the
#: text pipeline. NUL cannot occur in a JSON string, and no detector's character
#: classes or whitespace escapes match it, so two adjacent leaves can never form
#: a pattern that exists in neither of them.
_LEAF_SEPARATOR = "\x00"

#: Environment variable holding the optional audit HMAC key. Read from the
#: environment rather than a parameter default so a key never lands in argv.
_AUDIT_KEY_ENV = "MEDICAL_PRIVACY_GUARD_AUDIT_KEY"


def _env_audit_key() -> bytes | None:
    """Return the configured audit HMAC key, if any.

    Without a key the audit chain still detects deleted, reordered and edited
    records, but anyone able to write the log can recompute the whole chain.
    """
    raw = os.environ.get(_AUDIT_KEY_ENV)
    return raw.encode("utf-8") if raw else None


def _coerce_payload(payload: str | Payload) -> Payload:
    if isinstance(payload, Payload):
        return payload
    if isinstance(payload, str):
        return Payload(kind="text", content=payload)
    raise TypeError(f"payload must be str or Payload, got {type(payload).__name__}")


def _coerce_recipient(recipient: str | Recipient) -> Recipient:
    if isinstance(recipient, Recipient):
        return recipient
    if isinstance(recipient, str):
        normalized = recipient.lower().replace("-", "_")
        for trust in TrustLevel:
            if trust.value.lower() == normalized:
                return Recipient(kind="api", trust_level=trust)
        # Unknown endpoint descriptors default to EXTERNAL_UNKNOWN (never trust).
        return Recipient(kind="api", trust_level=TrustLevel.EXTERNAL_UNKNOWN)
    raise TypeError(f"recipient must be str or Recipient, got {type(recipient).__name__}")


def _coerce_purpose(purpose: str | Purpose) -> Purpose:
    if isinstance(purpose, Purpose):
        return purpose
    if isinstance(purpose, str):
        try:
            return Purpose(purpose.upper())
        except ValueError:
            return Purpose.UNKNOWN
    raise TypeError(f"purpose must be str or Purpose, got {type(purpose).__name__}")


def _coerce_environment(environment: EnvironmentContext | None) -> EnvironmentContext | None:
    if environment is None or isinstance(environment, EnvironmentContext):
        return environment
    raise TypeError(
        f"environment must be EnvironmentContext or None, got {type(environment).__name__}"
    )


def _flatten(leaves) -> tuple[str, list[tuple[int, int, object]]]:
    """Join leaf values into one text; return it and each leaf's span."""
    parts: list[str] = []
    spans: list[tuple[int, int, object]] = []
    offset = 0
    for leaf in leaves:
        parts.append(leaf.text)
        spans.append((offset, offset + len(leaf.text), leaf))
        offset += len(leaf.text) + len(_LEAF_SEPARATOR)
    return _LEAF_SEPARATOR.join(parts), spans


def _detect_leaves(
    leaves, spans: list[tuple[int, int, object]], detectors
) -> tuple:
    """Detect over each leaf, offsetting the facts into the flattened text.

    A leaf whose key implies a field label is probed as "label：value" so the
    label-driven detectors apply, and the label's own span is discarded. The
    flattened text itself carries no labels, so the transformation never sees
    them.
    """
    from dataclasses import replace as _replace

    facts: list[DetectedFact] = []
    for leaf, (start, end, _) in zip(leaves, spans):
        if leaf.label:
            probe = f"{leaf.label}：{leaf.text}"
            offset = len(leaf.label) + 1
        else:
            probe, offset = leaf.text, 0
        for fact in detect_all(probe, detectors):
            if fact.start < offset:
                continue
            facts.append(
                _replace(
                    fact,
                    start=fact.start - offset + start,
                    end=fact.end - offset + start,
                )
            )
    return tuple(facts)


def _split(
    text: str,
    output: str,
    spans: list[tuple[int, int, object]],
    evidence,
) -> dict[str, str]:
    """Map each leaf to its sanitized value.

    The transformation guarantees untargeted context is byte-identical, so a
    leaf's output span is its input span shifted by the net length change of
    every replacement before it.
    """
    def net(record) -> int:
        return (record.output_end - record.output_start) - (record.end - record.start)

    replacements: dict[str, str] = {}
    for start, end, leaf in spans:
        inner = [r for r in evidence if start <= r.start < end]
        before = sum(net(r) for r in evidence if r.start < start)
        out_start = start + before
        out_end = out_start + (end - start) + sum(net(r) for r in inner)
        replacements[leaf.path] = output[out_start:out_end]
    return replacements


class Guard:
    """Privacy guard for one policy profile.

    Thin, deterministic facade over the core pipeline:
    detect → evaluate → (sanitize → verify) → optional audit.
    """

    def __init__(
        self,
        profile: str = "external-ai-strict",
        profile_path: str | None = None,
        audit_dir: str | None = None,
        audit_key: bytes | None = None,
        dictionary_path: str | None = None,
        detectors: Sequence | None = None,
    ) -> None:
        """Create a Guard bound to one policy profile.

        Args:
            profile: builtin profile name (external-ai-strict, research, ...).
            profile_path: optional explicit path to a custom profile YAML.
            audit_dir: optional directory for append-only audit events.
            audit_key: optional HMAC key for the audit chain. When omitted, the
                ``MEDICAL_PRIVACY_GUARD_AUDIT_KEY`` environment variable is
                used if set; otherwise the chain is unkeyed.
            dictionary_path: optional ``.csv`` or ``.json`` institution
                vocabulary. Its terms are detected alongside the built-in
                rules and give verification a signal independent of them.
            detectors: optional replacement detector set. Supplied detectors
                may only extend recall; they must return ``DetectedFact`` and
                must not decide verdicts, bypass verification or write audit.
        """
        self.profile: PolicyProfile = (
            PolicyProfile.load(profile_path) if profile_path else load_builtin_profile(profile)
        )
        self._evaluator = PolicyEvaluator(self.profile)
        self.audit_dir = audit_dir
        self.audit_key = audit_key if audit_key is not None else _env_audit_key()
        self.dictionary = load_dictionary(dictionary_path) if dictionary_path else None
        # The dictionary is a detector like any other, so detection and
        # verification always see the same set — a mismatch there is how a
        # fact gets transformed but not verified, or vice versa.
        # Read the registry attribute at call time rather than binding the name
        # at import time, so a caller (or a test) that replaces the default set
        # is actually honoured.
        base = (
            tuple(detectors)
            if detectors is not None
            else tuple(detector_registry.DEFAULT_DETECTORS)
        )
        if self.dictionary is not None and not self.dictionary.is_empty():
            base = base + (DictionaryDetector(self.dictionary),)
        self._detectors = base

    def _parse_structured(self, content):
        """Parse a structured payload, or None when it cannot be parsed.

        Accepts either serialised text or an already-decoded object, so a caller
        holding a document does not have to serialise it to hand it back.
        """
        if isinstance(content, (dict, list)):
            return from_document(content)
        if not isinstance(content, str):
            return None
        try:
            return parse_json_payload(content)
        except ParserError:
            return None

    # -- detection ----------------------------------------------------------

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        """Run all detectors; returns internal facts (may contain raw values)."""
        if not isinstance(text, str):
            raise TypeError(f"detect expects str, got {type(text).__name__}")
        return detect_all(text, self._detectors)

    # -- evaluation ---------------------------------------------------------

    def evaluate(
        self,
        payload: str | Payload,
        recipient: str | Recipient,
        purpose: str | Purpose,
        environment: EnvironmentContext | None = None,
    ) -> EvaluationResult:
        """Detect and decide without modifying data.

        The returned EvaluationResult carries DetectedFact objects which may
        contain raw values; use `result.public_facts` for logging or audit.
        """
        request_payload = _coerce_payload(payload)
        recipient_obj = _coerce_recipient(recipient)
        purpose_obj = _coerce_purpose(purpose)
        env = _coerce_environment(environment)

        text = request_payload.content
        if request_payload.kind == "json":
            parsed = self._parse_structured(text)
            if parsed is None:
                return EvaluationResult(
                    decision=self._decision_fail_closed(ReasonCode.PARSER_FAILURE), facts=()
                )
            _, spans = _flatten(parsed.leaves)
            facts = _detect_leaves(parsed.leaves, spans, self._detectors)
            decision = self._evaluator.evaluate(facts, recipient_obj, purpose_obj, env)
            return EvaluationResult(decision=decision, facts=facts)
        if request_payload.kind != "text" or not isinstance(text, str):
            decision = self._decision_fail_closed(ReasonCode.UNSUPPORTED_FORMAT)
            return EvaluationResult(decision=decision, facts=())

        facts = detect_all(text, self._detectors)
        decision = self._evaluator.evaluate(facts, recipient_obj, purpose_obj, env)
        return EvaluationResult(decision=decision, facts=facts)

    def _decision_fail_closed(self, reason_code: ReasonCode) -> Decision:
        return Decision(
            verdict=Verdict.BLOCK,
            reason_codes=(reason_code,),
            explanation="Unsupported payload kind; blocked (fail closed).",
            risk=RiskSummary(
                level=RiskLevel.CRITICAL,
                score=100,
                factors=(RiskFactor(code=reason_code.value, description="unsupported format", score=100),),
            ),
            plan=None,
            policy_version=self.profile.policy_version,
        )

    # -- sanitization -------------------------------------------------------

    def sanitize(
        self,
        payload: str | Payload,
        recipient: str | Recipient,
        purpose: str | Purpose,
        environment: EnvironmentContext | None = None,
        audit_dir: str | None = None,
    ) -> SanitizationResult:
        """Run the full pipeline: evaluate → transform → verify → (audit).

        Returns a SanitizationResult; `sanitized_payload` is None when the
        verdict is BLOCK/ASK or verification failed (nothing to release).
        """
        request_payload = _coerce_payload(payload)
        recipient_obj = _coerce_recipient(recipient)
        purpose_obj = _coerce_purpose(purpose)
        env = _coerce_environment(environment)
        text = request_payload.content

        if request_payload.kind == "json":
            return self._sanitize_structured(
                request_payload,
                recipient_obj,
                purpose_obj,
                env,
                audit_dir or self.audit_dir,
            )

        if request_payload.kind != "text" or not isinstance(text, str):
            decision = self._decision_fail_closed(ReasonCode.UNSUPPORTED_FORMAT)
            self._maybe_audit(
                audit_dir or self.audit_dir, decision, (), recipient_obj, purpose_obj, None
            )
            return SanitizationResult(
                decision_before=decision,
                sanitized_payload=None,
                verification=None,
                decision_after=None,
            )

        facts = detect_all(text, self._detectors)
        decision = self._evaluator.evaluate(facts, recipient_obj, purpose_obj, env)
        verification: VerificationResult | None = None
        sanitized: Payload | None = None
        decision_after: Decision | None = None

        if decision.verdict is Verdict.ALLOW:
            sanitized = request_payload
        elif decision.verdict is Verdict.SANITIZE and decision.plan is not None:
            outcome = apply_plan(text, facts, decision.plan)
            verification = verify_sanitized(
                profile=self.profile,
                sanitized_text=outcome.text,
                original_facts=facts,
                recipient=recipient_obj,
                purpose=purpose_obj,
                original_text=text,
                plan=decision.plan,
                outcome=outcome,
                detectors=self._detectors,
                dictionary=self.dictionary,
            )
            if verification.passed:
                sanitized = Payload(
                    kind=request_payload.kind,
                    content=outcome.text,
                    provenance=request_payload.provenance,
                )
                residual = detect_all(outcome.text, self._detectors)
                decision_after = self._evaluator.evaluate(
                    residual, recipient_obj, purpose_obj, env
                )
        # BLOCK / ASK: nothing to release.

        self._maybe_audit(
            audit_dir or self.audit_dir,
            decision,
            facts,
            recipient_obj,
            purpose_obj,
            verification,
        )
        return SanitizationResult(
            decision_before=decision,
            sanitized_payload=sanitized,
            verification=verification,
            decision_after=decision_after,
        )

    def _sanitize_structured(
        self,
        payload: Payload,
        recipient: Recipient,
        purpose: Purpose,
        env: EnvironmentContext | None,
        audit_dir: str | None,
    ) -> SanitizationResult:
        """Sanitize a structured payload: one decision, per-leaf transformation.

        The leaves are flattened into a single text so detection, transformation
        and verification all run unchanged; the result is split back and written
        into a copy of the original structure. The verdict covers the whole
        document, not individual fields — a single direct identifier withholds
        the record, because a partially released record is exactly where
        cross-field quasi-identifiers do their damage.
        """
        parsed = self._parse_structured(payload.content)
        if parsed is None:
            decision = self._decision_fail_closed(ReasonCode.PARSER_FAILURE)
            self._maybe_audit(audit_dir, decision, (), recipient, purpose, None)
            return SanitizationResult(
                decision_before=decision,
                sanitized_payload=None,
                verification=None,
                decision_after=None,
            )

        text, spans = _flatten(parsed.leaves)
        facts = _detect_leaves(parsed.leaves, spans, self._detectors)
        decision = self._evaluator.evaluate(facts, recipient, purpose, env)
        verification: VerificationResult | None = None
        sanitized: Payload | None = None
        decision_after: Decision | None = None

        if decision.verdict is Verdict.ALLOW:
            sanitized = payload
        elif decision.verdict is Verdict.SANITIZE and decision.plan is not None:
            outcome = apply_plan(text, facts, decision.plan)
            verification = verify_sanitized(
                profile=self.profile,
                sanitized_text=outcome.text,
                original_facts=facts,
                recipient=recipient,
                purpose=purpose,
                original_text=text,
                plan=decision.plan,
                outcome=outcome,
                detectors=self._detectors,
                dictionary=self.dictionary,
            )
            if verification.passed:
                replacements = _split(text, outcome.text, spans, outcome._evidence)
                serialized = dumps(rebuild(parsed.document, replacements))
                sanitized = Payload(
                    kind="json", content=serialized, provenance=payload.provenance
                )
                reparsed = parse_json_payload(serialized)
                residual_spans = _flatten(reparsed.leaves)[1]
                residual = _detect_leaves(reparsed.leaves, residual_spans, self._detectors)
                decision_after = self._evaluator.evaluate(residual, recipient, purpose, env)

        self._maybe_audit(audit_dir, decision, facts, recipient, purpose, verification)
        return SanitizationResult(
            decision_before=decision,
            sanitized_payload=sanitized,
            verification=verification,
            decision_after=decision_after,
        )

    # -- audit --------------------------------------------------------------

    def _maybe_audit(
        self,
        audit_dir: str | None,
        decision: Decision,
        facts: tuple[DetectedFact, ...],
        recipient: Recipient,
        purpose: Purpose,
        verification: VerificationResult | None,
    ) -> None:
        if not audit_dir:
            return
        status = "N/A"
        if verification is not None:
            status = "PASS" if verification.passed else "FAIL"
        elif decision.verdict is Verdict.ALLOW:
            status = "N/A (ALLOW)"
        try:
            writer = AuditWriter(audit_dir, key=self.audit_key)
            event = build_audit_event(
                decision,
                facts,
                recipient,
                purpose,
                verification=status,
                dictionary_loaded=self.dictionary is not None,
                dictionary_entries=len(self.dictionary) if self.dictionary else 0,
            )
            writer.record(event)
        except AuditError:
            # Audit is part of the fail-closed contract for sanitize; surface
            # it rather than silently dropping the record.
            raise
