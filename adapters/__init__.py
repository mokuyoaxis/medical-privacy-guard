"""Adapters that put the guard in front of an external egress path.

v0.4 skeleton. The shared release semantics live in :mod:`adapters.egress`; a
vendor module (OpenAI-compatible, Anthropic, MCP stdio) only has to translate a
call into a ``DisclosureRequest`` and then use ``release_or_raise``. No vendor
transport is implemented yet.

An adapter must not contain privacy rules. It translates and enforces the core
result; it does not decide, widen or re-derive it.
"""

from .egress import release_or_raise, verification_details

__all__ = ["release_or_raise", "verification_details"]
