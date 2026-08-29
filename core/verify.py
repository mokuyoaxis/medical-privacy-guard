"""Post-transformation verification loop (plan.md §11).

The sanitizer is not trusted to succeed: after transforming, we re-run the
detectors on the output and re-run policy. Residual erase-type identifiers or
an unsatisfied policy ⇒ VERIFICATION_FAILED ⇒ release must be blocked. No
fallback to the original payload is ever produced here.

Checks:
- V1: no erase-type identifier residuals (REMOVE/MASK/TOKENIZE targets must
  be gone). Transform-type facts (GENERALIZE/DATE_SHIFT) may remain — the
  profile's intent is to shift/generalize them, not delete them.
- V2: no new sensitive types appeared that were absent from the input.
- V4: policy re-run on the sanitized output must be ALLOW, or SANITIZE with
  only transform-type residuals (transformation complete).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .errors import GuardError
from .model import (
    Decision,
    DetectedFact,
    Purpose,
    ReasonCode,
    Recipient,
    Verdict,
    VerificationResult,
)
from .policy import PolicyEvaluator, PolicyProfile


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

#: Actions whose intent is to TRANSFORM the value while keeping it (dates
#: shift/generalize rather than disappear); residuals of these types are the
#: expected output of a completed transformation, not failures.
_TRANSFORM_ACTIONS = frozenset({"GENERALIZE", "DATE_SHIFT"})


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

    # -- public API ---------------------------------------------------------

    def verify(
        self,
        *,
        sanitized_text: str,
        original_facts: Sequence[DetectedFact],
        recipient: Recipient,
        purpose: Purpose,
    ) -> VerificationResult:
        """Check the sanitized output; return passed or VERIFICATION_FAILED.

        Raises VerificationError only on internal configuration problems, not
        on verification failure (which is a result, not an exception).
        """
        residual = self._detect_all(sanitized_text, self._detectors)

        try:
            self._check_v1_no_residual(residual)
            self._check_v2_no_new_types(original_facts, residual)
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
            details=f"verified: no residual identifiers; policy re-run → {decision_after.verdict.value}",
        )

    # -- checks -------------------------------------------------------------

    def _check_v1_no_residual(self, residual: Sequence[DetectedFact]) -> None:
        """V1: erase-type identifiers (REMOVE/MASK/TOKENIZE) must not remain.

        Transform-type facts (GENERALIZE/DATE_SHIFT) may remain: the profile's
        intent is to shift/generalize them, not delete them.
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
        """V4: re-run policy; ALLOW passes, and SANITIZE passes only when every
        residual is transform-type (the profile's transformation is complete)."""
        decision = self._evaluator.evaluate(residual, recipient, purpose)
        if decision.verdict is Verdict.ALLOW:
            return decision
        if decision.verdict is Verdict.SANITIZE and residual:
            if all(self.profile.action_for(f.type) in _TRANSFORM_ACTIONS for f in residual):
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
) -> VerificationResult:
    """Convenience wrapper constructing a Verifier for *profile*."""
    return Verifier(profile).verify(
        sanitized_text=sanitized_text,
        original_facts=original_facts,
        recipient=recipient,
        purpose=purpose,
    )
