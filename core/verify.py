"""Post-transformation verification loop.

The sanitizer is not trusted to succeed: after transforming, we re-run the
detectors on the output and re-run policy. Residual erase-type identifiers or
an unsatisfied policy ⇒ VERIFICATION_FAILED ⇒ release must be blocked. No
fallback to the original payload is ever produced here.

Checks:
- V1: no erase-type identifier residuals (REMOVE/MASK/TOKENIZE targets must
  be gone).
- V2: no new sensitive types appeared that were absent from the input.
- Execution: exact target coverage, unchanged context, matching operation
  parameters and independent type-specific postconditions. Full dates may
  remain only at verified DATE_SHIFT output spans.
- V4: policy re-run must be ALLOW, or SANITIZE with verified shifted dates
  and context-only signals.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import date
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from transformers.base import TransformOutcome

from .errors import GuardError
from .model import (
    Decision,
    DetectedFact,
    DisclosurePlan,
    Purpose,
    ReasonCode,
    Recipient,
    TransformationOp,
    Verdict,
    VerificationResult,
)
from .policy import CONTEXT_ONLY_TYPES, PolicyEvaluator, PolicyProfile


@dataclass(frozen=True)
class _CheckFailure(GuardError):
    """Internal: carries the reason detail for a failed verification check.

    Inherits GuardError so the unified error hierarchy holds, even though
    callers normally convert it into a VerificationResult.
    """

    detail: str


#: Actions whose intent is to ERASE the identifier entirely; residuals of
#: these types are always verification failures (V1).
_ERASE_ACTIONS = frozenset({"REMOVE", "MASK", "TOKENIZE"})

#: Precision-reducing or shifting actions require execution evidence.
#: Only verified DATE_SHIFT output spans may remain as full-date residuals.
_TRANSFORM_ACTIONS = frozenset({"GENERALIZE", "DATE_SHIFT"})

#: Fact types whose span must cover a whole personal name. A span that stops
#: before a name character releases the remainder of the name, and re-detection
#: cannot see it: the orphaned character no longer matches a name pattern, so
#: verification used to report success on a partially redacted name.
_NAME_FACT_TYPES = frozenset(
    {"PERSON_NAME", "DOCTOR_NAME", "NURSE_NAME", "RELATIVE_NAME"}
)


class Verifier:
    """Verifies that a sanitized payload is safe to release under a profile."""

    def __init__(
        self,
        profile: PolicyProfile,
        detectors: Sequence | None = None,
    ) -> None:
        self.profile = profile
        # Imported lazily to keep core/ free of a hard detectors dependency at
        # module import time; detectors only import core.model, so this is safe.
        from detectors import DEFAULT_DETECTORS, detect_all

        self._detectors = detectors if detectors is not None else DEFAULT_DETECTORS
        self._detect_all = detect_all
        self._evaluator = PolicyEvaluator(profile)
        # Characters that continue a personal name. Kept here rather than at
        # module import so core/ keeps no hard detectors dependency.
        from detectors.surnames import GIVEN_CHARS, NAME_FOLLOW_BOUNDARY

        self._name_continuation = frozenset(GIVEN_CHARS + "一二三四五六七八九十")
        self._name_boundary = re.compile(NAME_FOLLOW_BOUNDARY)

    # -- public API ---------------------------------------------------------

    def verify(
        self,
        *,
        sanitized_text: str,
        original_facts: Sequence[DetectedFact],
        recipient: Recipient,
        purpose: Purpose,
        original_text: str | None = None,
        plan: DisclosurePlan | None = None,
        outcome: TransformOutcome | None = None,
    ) -> VerificationResult:
        """Verify execution evidence, residual detection and policy.

        Legacy calls without evidence support erase-only checks; transformation
        targets require all three optional execution arguments to prove completion.
        """
        residual = self._detect_all(sanitized_text, self._detectors)

        try:
            self._check_v1_no_residual(residual)
            self._check_v2_no_new_types(original_facts, residual)
            self._check_execution(sanitized_text, original_facts, original_text, plan, outcome)
            for fact in residual:
                if self.profile.action_for(fact.type) not in _TRANSFORM_ACTIONS:
                    continue
                if outcome is None or not any(
                    record.operation.target == fact.type and
                    record.operation.op == "DATE_SHIFT" and
                    (record.output_start, record.output_end) == (fact.start, fact.end)
                    for record in outcome._evidence
                ):
                    raise _CheckFailure("unverified transform-type residual span")
            decision_after = self._check_v4_policy_satisfied(residual, recipient, purpose)
        except _CheckFailure as failure:
            return VerificationResult(
                passed=False,
                reason_codes=(ReasonCode.VERIFICATION_FAILED,),
                details=failure.detail,
            )

        return VerificationResult(
            passed=True,
            reason_codes=(),
            details=f"verified: transformation checks satisfied; policy re-run → {decision_after.verdict.value}",
        )

    def _check_execution(
        self,
        sanitized: str,
        facts: Sequence[DetectedFact],
        original: str | None,
        plan: DisclosurePlan | None,
        outcome: TransformOutcome | None,
    ) -> None:
        targets = [f for f in facts if self.profile.action_for(f.type) in
                   _ERASE_ACTIONS | _TRANSFORM_ACTIONS]
        if original is None and plan is None and outcome is None:
            if any(self.profile.action_for(f.type) in _TRANSFORM_ACTIONS for f in targets):
                raise _CheckFailure("transformation execution evidence is required")
            if any(not f.value or f.value in sanitized for f in targets):
                raise _CheckFailure("erase target completion cannot be verified")
            return
        if original is None or plan is None or outcome is None:
            raise _CheckFailure("incomplete transformation execution evidence")
        if outcome.text != sanitized:
            raise _CheckFailure("execution output does not match verified text")

        expected: list[tuple[DetectedFact, TransformationOp]] = []
        for op in plan.operations:
            if op.op != self.profile.action_for(op.target):
                raise _CheckFailure("planned action does not match policy")
            if op.entity_type not in (None, op.target):
                raise _CheckFailure("planned entity type does not match target")
            allowed = {"shift_days", "_seed"} if op.op == "DATE_SHIFT" else set()
            if set(op.parameters) - allowed:
                raise _CheckFailure("unsupported transformation parameters")
            matches = [f for f in targets if f.type == op.target]
            if not matches:
                raise _CheckFailure("planned operation has no target spans")
            effective = op
            if op.op == "DATE_SHIFT" and "shift_days" not in op.parameters:
                seed = int(hashlib.sha256(original.encode("utf-8")).hexdigest()[:8], 16)
                days = (seed % 730) - 365 or 365
                effective = replace(op, parameters={**op.parameters, "_seed": days})
            expected.extend((f, effective) for f in matches)
        expected.sort(key=lambda pair: pair[0].start)
        if len(expected) != len(targets) or any(
            sum(f == candidate for candidate, _ in expected) != 1 for f in targets
        ):
            raise _CheckFailure("plan does not cover every target exactly once")
        records = outcome._evidence
        if len(records) != len(expected):
            raise _CheckFailure("execution evidence does not cover every target")
        applied: list[TransformationOp] = []
        for record in reversed(records):
            if record.operation not in applied:
                applied.append(record.operation)
        if tuple(applied) != outcome.applied:
            raise _CheckFailure("applied operations disagree with execution evidence")

        cursor = output_cursor = 0
        tokens: dict[tuple[str, str], str] = {}
        token_values: dict[str, tuple[str, str]] = {}
        shift: int | None = None
        for (fact, op), record in zip(expected, records):
            if not (cursor <= fact.start < fact.end <= len(original)):
                raise _CheckFailure("invalid or overlapping original target spans")
            raw = original[fact.start:fact.end]
            if fact.value is not None and fact.value != raw:
                raise _CheckFailure("original target does not match detected value")
            start = output_cursor + fact.start - cursor
            end = start + len(record.replacement)
            if (record.start, record.end, record.output_start, record.output_end) != (
                fact.start, fact.end, start, end
            ) or record.operation != op:
                raise _CheckFailure("execution spans or operation parameters do not match plan")
            if sanitized[output_cursor:start] != original[cursor:fact.start]:
                raise _CheckFailure("transformation changed untargeted context")
            if sanitized[start:end] != record.replacement:
                raise _CheckFailure("execution replacement does not match output span")
            self._check_postcondition(fact.type, raw, record.replacement, op)
            self._check_name_span_boundary(fact.type, raw, original, fact.end)
            if op.op == "TOKENIZE":
                key = (fact.type, raw)
                token = record.replacement
                if tokens.get(key, token) != token or token_values.get(token, key) != key:
                    raise _CheckFailure("inconsistent token mapping")
                tokens[key] = token
                token_values[token] = key
            if op.op == "DATE_SHIFT":
                days = op.parameters.get("shift_days", op.parameters.get("_seed"))
                if shift is not None and shift != days:
                    raise _CheckFailure("inconsistent date offsets within payload")
                shift = days
            cursor, output_cursor = fact.end, end
        if sanitized[output_cursor:] != original[cursor:]:
            raise _CheckFailure("transformation changed untargeted context")

    def _check_name_span_boundary(
        self, kind: str, raw: str, original: str, end: int
    ) -> None:
        """A name span must not stop inside the name.

        The detectors bound a name with a character inventory or a boundary
        word, and neither can be complete. When the bound is wrong the capture
        stops at the surname and the rest of the name survives into the
        released text ("责任护士：郑爽" released "爽"). Re-detection cannot see
        this — the orphaned character no longer matches a name pattern — so the
        check reads the original text instead.

        A name may be followed by punctuation, the end of the text, or a word
        that legitimately follows a name (a clinical verb, a connective, the
        next field's label). Anything else is text the detector never
        explained, and part of the name may be hiding in it, so release is
        withheld rather than silently truncated.
        """
        if kind not in _NAME_FACT_TYPES or not raw or end >= len(original):
            return
        following = original[end]
        if not ("\u4e00" <= following <= "\u9fff"):
            return
        if following in self._name_continuation:
            raise _CheckFailure(
                f"{kind} span ends inside a name; the remainder would be released"
            )
        if not self._name_boundary.match(original, end):
            raise _CheckFailure(
                f"{kind} span is followed by unexplained text "
                f"({original[end:end + 4]!r}); the name may be truncated"
            )

    @staticmethod
    def _date(value: str) -> date:
        match = re.fullmatch(r"(\d{4})([-/.])(\d{1,2})\2(\d{1,2})", value)
        if match:
            parts = (match[1], match[3], match[4])
        else:
            match = re.fullmatch(r"(\d{4})年(\d{1,2})月(\d{1,2})日", value)
            if match:
                parts = match.groups()
            else:
                match = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", value)
                if not match:
                    raise _CheckFailure("invalid date in transformation evidence")
                parts = (match[3], match[1], match[2])
        try:
            return date(*(int(part) for part in parts))
        except ValueError:
            raise _CheckFailure("invalid date in transformation evidence") from None

    @classmethod
    def _check_postcondition(cls, kind: str, raw: str, output: str, op: TransformationOp) -> None:
        valid = False
        if raw == output:
            raise _CheckFailure("target span was not transformed")
        if op.op == "REMOVE":
            valid = output == "[REDACTED]"
        elif op.op == "MASK":
            valid = output == "*" * len(raw)
        elif op.op == "TOKENIZE":
            valid = bool(re.fullmatch(r"\[" + re.escape(kind) + r"_[0-9]{3,}\]", output))
        elif op.op == "DATE_SHIFT" and kind == "EXACT_DATE":
            days = op.parameters.get("shift_days", op.parameters.get("_seed"))
            valid = (type(days) is int and days != 0 and
                     (cls._date(output) - cls._date(raw)).days == days)
        elif op.op == "GENERALIZE":
            markers = {
                "PRECISE_LOCATION": "[LOCATION_GENERALIZED]",
                "HOSPITAL_NAME": "[INSTITUTION_GENERALIZED]",
                "DEPARTMENT": "[DEPARTMENT_GENERALIZED]",
                "WARD": "[WARD_GENERALIZED]",
            }
            if kind in markers:
                valid = output == markers[kind]
            elif kind == "EXACT_DATE":
                original_date = cls._date(raw)
                month = re.fullmatch(r"(\d{4})[-/.](\d{1,2})", output)
                if not month:
                    month = re.fullmatch(r"(\d{4})年(\d{1,2})月", output)
                valid = bool(month and (int(month[1]), int(month[2])) ==
                             (original_date.year, original_date.month))
            elif kind in {"AGE", "AGE_90_PLUS"}:
                # A month-age fact carries its whole token ("6个月").
                month_match = re.fullmatch(r"(\d{1,2})\s*个?月(?:龄|大)?", raw)
                if month_match:
                    valid = 1 <= int(month_match.group(1)) <= 36 and output in (
                        "不足1岁", "1-9岁"
                    )
                else:
                    age_match = re.fullmatch(r"(\d{1,3})\s*(?:岁|周岁)", raw)
                    if age_match:
                        age = int(age_match[1])
                        if kind == "AGE_90_PLUS" and age < 90:
                            raise _CheckFailure(
                                "invalid age category in transformation evidence"
                            )
                        if age == 0:
                            valid = output == "不足1岁"
                        elif age < 10:
                            valid = output == "1-9岁"
                        elif age < 90:
                            band = re.fullmatch(r"(\d{2})-(\d{2})岁", output)
                            valid = bool(band and int(band[1]) % 10 == 0 and
                                         int(band[2]) == int(band[1]) + 9 and
                                         int(band[1]) <= age <= int(band[2]))
                        elif age <= 200:
                            valid = output == "90岁及以上"
        if not valid:
            raise _CheckFailure("transformation violates type-specific postcondition")

    # -- checks -------------------------------------------------------------

    def _check_v1_no_residual(self, residual: Sequence[DetectedFact]) -> None:
        """V1: erase-type identifiers (REMOVE/MASK/TOKENIZE) must not remain.

        Transform-type residuals are checked separately against execution
        evidence; this check does not grant them a release exemption.
        """
        residues = [
            f
            for f in residual
            if self.profile.action_for(f.type) in _ERASE_ACTIONS
        ]
        if residues:
            kinds = sorted({f.type for f in residues})
            raise _CheckFailure(
                f"residual identifiers after transformation: {', '.join(kinds)}"
            )

    @staticmethod
    def _check_v2_no_new_types(
        original_facts: Sequence[DetectedFact],
        residual: Sequence[DetectedFact],
    ) -> None:
        """V2: transformation must not create new sensitive types."""
        original_types = {f.type for f in original_facts}
        new_types = {f.type for f in residual} - original_types
        if new_types:
            raise _CheckFailure(
                f"transformation introduced new sensitive types: {', '.join(sorted(new_types))}"
            )

    def _check_v4_policy_satisfied(
        self,
        residual: Sequence[DetectedFact],
        recipient: Recipient,
        purpose: Purpose,
    ) -> Decision:
        """Re-run policy after execution and residual-span checks.

        ALLOW passes. SANITIZE permits only already-verified DATE_SHIFT spans
        and context-only signals; ASK and BLOCK always fail.
        """
        decision = self._evaluator.evaluate(residual, recipient, purpose)
        if decision.verdict is Verdict.ALLOW:
            return decision
        if decision.verdict is Verdict.SANITIZE and residual:
            transformable = [f for f in residual if f.type not in CONTEXT_ONLY_TYPES]
            if all(
                self.profile.action_for(f.type) in _TRANSFORM_ACTIONS
                for f in transformable
            ):
                return decision
        raise _CheckFailure(
            f"policy re-run on sanitized output yielded {decision.verdict.value}; "
            "release not allowed"
        )


def verify_sanitized(
    *,
    profile: PolicyProfile,
    sanitized_text: str,
    original_facts: Sequence[DetectedFact],
    recipient: Recipient,
    purpose: Purpose,
    original_text: str | None = None,
    plan: DisclosurePlan | None = None,
    outcome: TransformOutcome | None = None,
) -> VerificationResult:
    """Convenience wrapper constructing a Verifier for *profile*."""
    return Verifier(profile).verify(
        sanitized_text=sanitized_text,
        original_facts=original_facts,
        recipient=recipient,
        purpose=purpose,
        original_text=original_text,
        plan=plan,
        outcome=outcome,
    )
