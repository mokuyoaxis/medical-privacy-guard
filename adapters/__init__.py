"""Adapters that put the guard in front of an external egress path.

A vendor module has two jobs and no others: turn the call into a payload with
:mod:`adapters.ingress`, and act on the decision with :mod:`adapters.egress`.
:mod:`adapters.mcp_gateway` is the first working transport — a stdio proxy that
sits between an MCP client and an MCP server. The vendor SDK wrappers
(OpenAI-compatible, Anthropic) are not started.

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
