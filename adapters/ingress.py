"""The other half of an adapter: turning an external call into a payload.

``egress`` decides what may leave. This decides what the guard is looking at
while it decides, and it exists because the caller cannot be relied on to get it
right. An LLM message content arrives as ``str``; tool arguments arrive as a
``dict``. Handing the first to the guard as plain text is not a small mistake:
the detectors are label-driven, so ``{"name": "张三"}`` scanned as prose yields no
fact at all — the key is not a Chinese label, and a bare name is deliberately not
detected — and the call goes through. The same content declared as JSON is
sanitized.

So the adapter classifies and the caller does not. The rules are shared with the
CLI rather than written again here: see ``formats.admission``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.model import (
    EnvironmentContext,
    EvaluationResult,
    Payload,
    Purpose,
    Recipient,
    SanitizationResult,
)
from formats.admission import UnsupportedInput, payload_for_text, reject_if_binary

if TYPE_CHECKING:
    from medical_privacy_guard import Guard

__all__ = ["evaluate_call", "payload_for", "sanitize_call"]


def payload_for(content: Any) -> Payload:
    """Build the payload an external call's content should be scanned as.

    A decoded container is already structured, so it is declared as such. A
    string is classified, because a JSON document inside a string is still a JSON
    document and scanning it as prose would drop its field labels. Anything else
    — bytes, a stream, an image handle — is a kind the guard cannot inspect, so
    it is declared unsupported and fails closed rather than guessed at.
    """
    if isinstance(content, (dict, list)):
        return Payload(kind="json", content=content)
    if not isinstance(content, str):
        return Payload(kind="unsupported", content="")
    try:
        reject_if_binary(content)
    except UnsupportedInput:
        # The content is not text the guard can read. Report it as an
        # unsupported payload so the caller gets a decision and an audit record,
        # rather than an exception it has to remember to catch.
        return Payload(kind="unsupported", content="")
    return payload_for_text(content)


def evaluate_call(
    guard: Guard,
    content: Any,
    recipient: str | Recipient,
    purpose: str | Purpose,
    environment: EnvironmentContext | None = None,
) -> EvaluationResult:
    """Evaluate an external call's content without modifying it."""
    return guard.evaluate(payload_for(content), recipient, purpose, environment)


def sanitize_call(
    guard: Guard,
    content: Any,
    recipient: str | Recipient,
    purpose: str | Purpose,
    environment: EnvironmentContext | None = None,
    audit_dir: str | None = None,
) -> SanitizationResult:
    """Sanitize an external call's content; one decision covers the whole call."""
    return guard.sanitize(payload_for(content), recipient, purpose, environment, audit_dir)
