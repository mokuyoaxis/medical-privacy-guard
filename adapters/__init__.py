"""Adapters that put the guard in front of an external egress path.

v0.4 skeleton. A vendor module (OpenAI-compatible, Anthropic, MCP stdio) has two
jobs and no others: turn the call into a payload with :mod:`adapters.ingress`,
and act on the decision with :mod:`adapters.egress`. No vendor transport is
implemented yet.

An adapter must not contain privacy rules. It translates and enforces the core
result; it does not decide, widen or re-derive it.
"""

from .egress import release_or_raise, verification_details
from .ingress import evaluate_call, payload_for, sanitize_call

__all__ = [
    "evaluate_call",
    "payload_for",
    "release_or_raise",
    "sanitize_call",
    "verification_details",
]
