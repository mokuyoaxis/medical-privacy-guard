"""The rule every adapter follows: nothing leaves without a guard decision.

An adapter translates one external egress path into a ``DisclosureRequest``,
hands it to the Guard, and then either sends what came back or raises. This
module holds the second half of that contract, so the mapping from verdict to
caller behaviour is written once instead of once per vendor SDK::

    result = guard.sanitize(text, recipient, purpose)
    payload = release_or_raise(result)
    send(payload.content)

Adapters do not implement policy. They must not widen a verdict, retry a BLOCK,
or send the input when verification failed.
"""

from __future__ import annotations

from core.errors import DisclosureBlocked, HumanApprovalRequired, VerificationFailed
from core.model import Payload, SanitizationResult, Verdict

__all__ = ["release_or_raise", "verification_details"]


def release_or_raise(result: SanitizationResult) -> Payload:
    """Return the payload an adapter may send, or raise the matching exception.

    ALLOW returns the original payload unchanged and SANITIZE returns the
    verified replacement. BLOCK and ASK raise. A SANITIZE with nothing verified
    to send raises :class:`VerificationFailed` rather than falling back to the
    input.
    """
    decision = result.decision_before
    verdict = decision.verdict

    if verdict is Verdict.BLOCK:
        raise DisclosureBlocked(decision)
    if verdict is Verdict.ASK:
        raise HumanApprovalRequired(decision)

    payload = result.sanitized_payload
    if payload is None:
        # A SANITIZE whose transformation did not verify, or a verdict and
        # payload that disagree. Either way nothing verified exists to send, and
        # sending the input instead would be the disclosure this guard exists to
        # prevent.
        raise VerificationFailed(decision, verification_details(result))
    if verdict is Verdict.SANITIZE and not _verified(result):
        raise VerificationFailed(decision, verification_details(result))
    return payload


def _verified(result: SanitizationResult) -> bool:
    return result.verification is not None and result.verification.passed


def verification_details(result: SanitizationResult) -> str | None:
    """Diagnostic detail for a failed verification, for local use only.

    It can quote fragments of the payload, so it belongs in a local operator's
    view: not in a log sink the guard does not control, and not in a response to
    an external caller.
    """
    verification = result.verification
    if verification is None:
        return None
    codes = ", ".join(code.value for code in verification.reason_codes) or "no reason code"
    return f"{codes}: {verification.details}"
