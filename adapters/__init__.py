"""Adapters that put the guard in front of an external egress path.

A vendor module has two jobs and no others: turn the call into a payload with
:mod:`adapters.ingress`, and act on the decision with :mod:`adapters.egress`.
Three transports ship: the MCP stdio gateway and the OpenAI-compatible and
Anthropic client wrappers. All three call the same ingress/egress pair.

An adapter must not contain privacy rules. It translates and enforces the core
result; it does not decide, widen or re-derive it.
"""

from .anthropic_compat import AnthropicGuard
from .egress import release_or_raise, verification_details
from .ingress import evaluate_call, payload_for, sanitize_call
from .mcp_gateway import REFUSED_CODE, GatewayError, GatewaySettings, McpGateway
from .openai_compat import OpenAIGuard

__all__ = [
    "REFUSED_CODE",
    "GatewayError",
    "GatewaySettings",
    "AnthropicGuard",
    "McpGateway",
    "OpenAIGuard",
    "evaluate_call",
    "payload_for",
    "release_or_raise",
    "sanitize_call",
    "verification_details",
]
