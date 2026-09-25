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
from core.policy import (
    CONTEXT_ONLY_TYPES,
    PolicyEvaluator,
    PolicyProfile,
    load_builtin_profile,
)
from core.textnorm import strip_invisible
from core.verify import verify_sanitized
from detectors import detect_all
from detectors import registry as detector_registry
from detectors.dictionary import DictionaryDetector
from formats import (
    UnsupportedInput,
    dumps,
    dumps_csv,
    from_document,
    parse_csv_payload,
    parse_json_payload,
    payload_for_text,
    rebuild,
    rebuild_csv,
    reject_if_binary,
)
from transformers import apply_plan

__all__ = ["Guard"]


#: Separator between leaf values when a structured payload is flattened for the
#: text pipeline. Two things make it safe to join leaves with it:
#:
#: - Detection runs one leaf at a time (see ``_detect_leaves``), so no rule is
#:   ever given the joined text and no pattern can span the separator. The
#:   character class a detector happens to use is therefore irrelevant; a NUL
#:   that reaches a leaf is refused before the leaf exists, by
#:   ``formats.admission.reject_if_binary``.
#: - A NUL cannot occur in a JSON string, so a value the caller sent cannot be
#:   mistaken for the join.
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
    """Turn a caller's payload into the form the guard will actually scan.

    A string is *classified*, never trusted. The detectors are label-driven, so
    a JSON document scanned as prose loses the keys that supply its field
    labels: ``{"name": "张三"}`` yields no fact at all, reaches ALLOW and is
    released with the name intact. The rule is the shared one in
    ``formats.admission`` -- the same rule the CLI and the adapters use -- so
    one piece of content cannot be plain text to this entry point and a
    structured document to the others.

    Content that is recognisably not text the guard can read is declared
    unsupported rather than guessed at, which fails closed.
    """
    if isinstance(payload, Payload):
        return payload
    if isinstance(payload, str):
        try:
            reject_if_binary(payload)
        except UnsupportedInput:
            return Payload(kind="unsupported", content="")
        return payload_for_text(strip_invisible(payload))
    if isinstance(payload, (dict, list)):
        # A decoded document is already structured, so it is declared as such.
        # The adapters accept this shape; an entry point that refused it would
        # be the divergence this module exists to prevent.
        return Payload(kind="json", content=payload)
    raise TypeError(f"payload must be str or Payload, got {type(payload).__name__}")


def _strip_text_payload(payload: Payload) -> Payload:
    """Remove characters that render as nothing from a declared text payload.

    An explicit ``Payload(kind="text")`` bypasses classification but not the
    normalisation: a caller that declares plain text is still describing text a
    human would read, and a zero-width character is not part of what that
    reader sees. The strip happens here, before any detection, so the string
    that is scanned, transformed, verified and released is the same one
    throughout.
    """
    if payload.kind != "text" or not isinstance(payload.content, str):
        return payload
    stripped = strip_invisible(payload.content)
    if stripped == payload.content:
        return payload
    return Payload(kind="text", content=stripped, provenance=payload.provenance)


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


def _rebuild_payload(parsed, replacements: dict[str, str]):
    """Write replacements back into the document and re-read the result.

    The re-read is *not* what verification runs over: verification sees the
    flattened text, which is a different string from the serialised document
    that would be released. That is why the caller re-decides policy on the
    rebuilt document before releasing it -- the gap between "the text we
    checked" and "the document we send" has to be closed by a check, not by an
    assumption about the rebuild being faithful.
    """
    if parsed.kind == "csv":
        serialized = dumps_csv(rebuild_csv(parsed.document, replacements))
        return serialized, parse_csv_payload(serialized)
    serialized = dumps(rebuild(parsed.document, replacements))
    return serialized, parse_json_payload(serialized)


def _detect_leaves(
    leaves, spans: list[tuple[int, int, object]], detectors
) -> tuple:
    """Detect over each leaf, offsetting the facts into the flattened text.

    A leaf whose key implies a field label is probed as "label：value" so the
    label-driven detectors apply, and the label's own span is discarded. The
    flattened text itself carries no labels, so the transformation never sees
    them.

    Every spelling the key implies is probed, not only the Chinese label. An
    English key is translated so the Chinese rules apply, but the translation
    would otherwise hide the value from the English rules -- they look for
    ``name:``/``patient:`` and find neither in ``姓名：John Smith`` -- and
    ``{"name": "John Smith"}`` was released with the name intact. The passes are
    merged, so a value that both spellings match is still one fact.
    """
    from dataclasses import replace as _replace

    facts: list[DetectedFact] = []
    for leaf, (start, end, _) in zip(leaves, spans):
        probes = leaf.probes or ((leaf.label,) if leaf.label else ())
        if not probes:
            # No label to prepend, so the offsets are the leaf's own -- but the
            # leaf still starts somewhere in the flattened text, and a fact left
            # at its leaf-local offset lands on an unrelated value: it is then
            # either merged away as an overlap or transformed in the wrong place.
            for fact in detect_all(leaf.text, detectors):
                facts.append(
                    _replace(
                        fact,
                        start=fact.start + start,
                        end=fact.end + start,
                        read_only=leaf.read_only,
                    )
                )
            continue
        for probe_label in probes:
            # A half-width colon: every label-driven rule accepts it
            # (``field_syntax.FIELD_SEP`` matches ``[:：=]``), and the English
            # rules accept only it or a space. The full-width form used here
            # before meant an English key's probe could not reach the English
            # rules at all.
            probe = f"{probe_label}:{leaf.text}"
            offset = len(probe_label) + 1
            for fact in detect_all(probe, detectors):
                if fact.start < offset:
                    continue
                facts.append(
                    _replace(
                        fact,
                        start=fact.start - offset + start,
                        end=fact.end - offset + start,
                        read_only=leaf.read_only,
                    )
                )
    return detector_registry.merge_facts(facts)


#: Actions that leave a fact in the output on purpose. A residual of one of
#: these types was produced by the plan and was verified against its execution
#: evidence; every other type is a value the transformation failed to remove.
_REBUILD_TRANSFORM_ACTIONS = frozenset({"GENERALIZE", "DATE_SHIFT"})


def _rebuilt_document_releasable(
    profile: PolicyProfile, decision: Decision, residual: tuple[DetectedFact, ...]
) -> bool:
    """True when the rebuilt document may still be released.

    ALLOW is releasable. SANITIZE is releasable only when every residual fact is
    either a context-only signal or one whose configured action leaves it in
    place by design (a generalised date or age band, a shifted date). ASK and
    BLOCK never are. This mirrors the policy re-run inside verification, so the
    two checks cannot disagree about what "releasable" means.
    """
    if decision.verdict is Verdict.ALLOW:
        return True
    if decision.verdict is not Verdict.SANITIZE or not residual:
        return False
    return all(
        profile.action_for(fact.type) in _REBUILD_TRANSFORM_ACTIONS
        for fact in residual
        if fact.type not in CONTEXT_ONLY_TYPES
    )


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
        if leaf.read_only:
            # The policy refuses SANITIZE whenever a read-only leaf carries a
            # fact, so no plan should ever reach here with one as a target.
            # Skipping it keeps the value byte-identical instead of writing a
            # string over a number and changing the document's type. Offsets
            # for the other leaves are unaffected: ``before`` sums over the
            # evidence, not over the spans visited so far.
            continue
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
        if (
            self.dictionary is not None
            and not self.dictionary.is_empty()
            and not any(isinstance(d, DictionaryDetector) for d in base)
        ):
            # A caller that supplied its own detector set may already carry a
            # dictionary detector. Registering a second one would only duplicate
            # every fact it reports, and the registry's merge would then have to
            # pick between two identical claims.
            base = base + (DictionaryDetector(self.dictionary),)
        self._detectors = base

    def _parse_structured(self, content, kind: str = "json"):
        """Parse a structured payload, or None when it cannot be parsed.

        Accepts either serialised text or an already-decoded object, so a caller
        holding a document does not have to serialise it to hand it back.
        """
        if kind == "csv":
            if not isinstance(content, str):
                return None
            try:
                return parse_csv_payload(content)
            except ParserError:
                return None
        if isinstance(content, (dict, list)):
            # A decoded document is inspected here rather than at rebuild time.
            # A value the guard cannot read or address (a non-string key, a
            # value JSON cannot carry) is an admission failure, not a crash
            # from inside the transformation: the three routes into this method
            # must fail the same way.
            try:
                return from_document(content)
            except ParserError:
                return None
        if not isinstance(content, str):
            return None
        try:
            return parse_json_payload(content)
        except ParserError:
            return None

    # -- detection ----------------------------------------------------------

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        """Run all detectors; returns internal facts (may contain raw values).

        Invisible format characters are removed first, so a caller reaching for
        this method directly gets the same reading as one going through
        :meth:`evaluate`.
        """
        if not isinstance(text, str):
            raise TypeError(f"detect expects str, got {type(text).__name__}")
        return detect_all(strip_invisible(text), self._detectors)

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
        request_payload = _strip_text_payload(_coerce_payload(payload))
        recipient_obj = _coerce_recipient(recipient)
        purpose_obj = _coerce_purpose(purpose)
        env = _coerce_environment(environment)

        text = request_payload.content
        if request_payload.kind in {"json", "csv"}:
            parsed = self._parse_structured(text, request_payload.kind)
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
        request_payload = _strip_text_payload(_coerce_payload(payload))
        recipient_obj = _coerce_recipient(recipient)
        purpose_obj = _coerce_purpose(purpose)
        env = _coerce_environment(environment)
        text = request_payload.content

        if request_payload.kind in {"json", "csv"}:
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
        parsed = self._parse_structured(payload.content, payload.kind)
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
                serialized, reparsed = _rebuild_payload(parsed, replacements)
                residual_spans = _flatten(reparsed.leaves)[1]
                residual = _detect_leaves(reparsed.leaves, residual_spans, self._detectors)
                decision_after = self._evaluator.evaluate(residual, recipient, purpose, env)
                # The document that would be released is the rebuilt one, and
                # it is a different string from the flattened text verification
                # approved. Re-deciding on it turns "the transformation ran" and
                # "the payload is releasable" into the same claim: a rebuild
                # that dropped, mis-keyed or reintroduced a value shows up here
                # as a verdict that is not releasable, and the release is
                # withheld rather than reported as verified.
                if _rebuilt_document_releasable(self.profile, decision_after, residual):
                    sanitized = Payload(
                        kind=payload.kind, content=serialized, provenance=payload.provenance
                    )
                else:
                    verification = VerificationResult(
                        passed=False,
                        reason_codes=(ReasonCode.VERIFICATION_FAILED,),
                        details=(
                            "the rebuilt document does not satisfy policy "
                            f"({decision_after.verdict.value}); release withheld"
                        ),
                    )

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
