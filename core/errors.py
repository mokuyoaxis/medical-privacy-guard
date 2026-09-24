"""Base errors for medical-privacy-guard.

All guard-specific errors inherit from GuardError so callers can catch a single
exception type while still inspecting more specific variants.

The last three classes are different in kind from the rest: they carry a Guard
verdict to an adapter, rather than reporting that something inside the guard
went wrong. See the section comment above them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Decision


class GuardError(Exception):
    """Base exception for all guard-internal failures."""


class ParserError(GuardError):
    """Raised when an input cannot be parsed.

    Per the fail-closed invariant, parsing failures should lead to a BLOCK
    decision unless an explicit policy overrides the behavior.
    """


class PolicyError(GuardError):
    """Raised when policy configuration is invalid, missing, or inconsistent."""


class VerificationError(GuardError):
    """Raised when post-sanitization verification fails."""


class AuditError(GuardError):
    """Raised when the audit writer cannot record an event.

    In strict profiles this is treated as a BLOCK condition.
    """


class TransformerError(GuardError):
    """Raised when a transformation operation is unknown or cannot be applied."""


class DictionaryError(GuardError):
    """Raised when an institution dictionary cannot be loaded or is invalid.

    Fail closed, for the same reason policy configuration does: a dictionary
    the deployment believes is active but which silently loaded nothing is
    worse than no dictionary at all.
    """


# -- verdict exceptions -----------------------------------------------------
#
# These three carry a decision outward instead of reporting an internal fault.
# A caller must not retry them, fall back to an unguarded path, or read them as
# transient: they are the answer, not a hiccup on the way to one. They stay in
# this module so a single ``except GuardError`` still catches everything the
# guard can raise.


def _verdict_summary(outcome: str, decision: Decision) -> str:
    """Describe a decision without quoting any detected value.

    Reason codes and risk scores are safe by construction; raw spans are not.
    This message may end up in a log the guard does not control.
    """
    codes = ", ".join(code.value for code in decision.reason_codes) or "no reason code"
    return f"disclosure {outcome}: {codes} (risk {decision.risk.level.value}/{decision.risk.score})"


class DisclosureBlocked(GuardError):
    """Raised when the guard returns BLOCK for a disclosure.

    Nothing may be sent. BLOCK is a policy decision rather than a failure to
    retry, so a caller that catches this and sends anyway has moved the trust
    boundary instead of respecting it.
    """

    def __init__(self, decision: Decision, message: str | None = None) -> None:
        self.decision = decision
        super().__init__(message or _verdict_summary("blocked", decision))


class HumanApprovalRequired(GuardError):
    """Raised when the guard returns ASK: a human must authorize this disclosure.

    ASK is neither a refusal nor an approval. A declared purpose, an earlier
    approval for a similar request, or a retry is not consent; the payload must
    not be sent until a grant scoped to this request exists.
    """

    def __init__(self, decision: Decision, message: str | None = None) -> None:
        self.decision = decision
        super().__init__(message or _verdict_summary("requires human approval", decision))


class VerificationFailed(VerificationError):
    """Raised when a SANITIZE decision produced nothing that may be released.

    Distinct from :class:`DisclosureBlocked`: policy permitted a sanitization
    and the failure is in executing or checking it. The input must not be sent
    instead — releasing unverified output is exactly what verification exists
    to prevent.
    """

    def __init__(
        self,
        decision: Decision,
        details: str | None = None,
        message: str | None = None,
    ) -> None:
        self.decision = decision
        #: Local diagnostic detail. It can quote fragments of the payload, so it
        #: must not be written to a log the guard does not control or returned
        #: to an external caller. The exception message deliberately omits it.
        self.details = details
        super().__init__(message or _verdict_summary("verification failed", decision))
