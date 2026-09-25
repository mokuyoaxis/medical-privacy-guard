"""An OpenAI-compatible chat client with the guard on its egress path.

The MCP gateway stands between a client and a server on stdio; this wrapper
stands between an application and an OpenAI-compatible HTTP API. The shape is
the same -- every field that can carry caller-supplied content is evaluated
before the request leaves, and nothing on the response side is inspected
(``docs/scope.md`` records that boundary) -- but the mechanics differ: there is
no wire protocol to re-frame, only a kwargs mapping to rewrite, so the wrapper
intercepts at the SDK call itself.

    guard = Guard(profile="external-ai-strict")
    client = OpenAIGuard(real_client, guard, recipient="external_unknown")
    client.chat.completions.create(model=..., messages=[...])

What is inspected, and how:

- ``messages[].content`` -- the data channel. A string is sanitized as text; a
  content-part list has each text part sanitized in place and non-text parts
  (images) declared unsupported, which fails closed; a list of tool-call
  messages has its ``arguments`` evaluated as JSON.
- ``tools[].function`` -- an interface description the caller wrote, not a
  data channel. It is evaluated but never rewritten: a schema that names a
  hospital cannot be paraphrased safely, and the caller's own SDK call is the
  place to fix it. A BLOCK verdict raises; an ALLOW or SANITIZE verdict passes
  the description through unchanged.
- ``metadata`` -- evaluated as a JSON payload, rewritten on SANITIZE, refused
  on BLOCK/ASK. Keys are free-form, so a key can carry PHI too.
- ``user`` -- a end-user identifier, evaluated as text, never rewritten: the
  field is defined as an opaque identifier and rewriting it would break the
  caller's accounting. BLOCK raises.

A verdict of SANITIZE with nothing verified to send raises
:class:`VerificationFailed` through :func:`release_or_raise`, exactly as every
other adapter; there is no fallback to the original content.

The transport is duck-typed: anything with a
``chat.completions.create(**kwargs)`` works, which is what the tests stub.
Credentials stay with the caller's own client; this module never sees them.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping, Sequence

from adapters.egress import release_or_raise
from adapters.ingress import payload_for
from core.errors import GuardError
from core.model import Payload, Purpose, Recipient, SanitizationResult, TrustLevel
from medical_privacy_guard import Guard

__all__ = ["OpenAIGuard"]


class OpenAIGuard:
    """Wrap an OpenAI-compatible client so no request leaves unaudited."""

    def __init__(
        self,
        client: Any,
        guard: Guard,
        recipient: str | Recipient = "external_unknown",
        purpose: str | Purpose = "EXTERNAL_AI_ASSISTANCE",
        audit_dir: str | None = None,
    ) -> None:
        if isinstance(recipient, str):
            recipient = Recipient(kind="llm", trust_level=_trust(recipient))
        if isinstance(purpose, str):
            purpose = Purpose(purpose.upper())
        self._client = client
        self._guard = guard
        self._recipient = recipient
        self._purpose = purpose
        self._audit_dir = audit_dir
        # Same attribute chain as the SDK: client.chat.completions.create().
        self.chat = _Chat(self)

    # -- entry points --------------------------------------------------------
    # (completions_create is reached through _Chat below)

    def completions_create(self, **kwargs: Any) -> Any:
        """Evaluate one chat-completions call and forward, rewrite or refuse."""
        inspected = copy.deepcopy(kwargs)
        if "messages" in inspected:
            inspected["messages"] = self._messages(inspected["messages"])
        if "metadata" in inspected and inspected["metadata"] is not None:
            inspected["metadata"] = self._mapping_field("metadata", inspected["metadata"])
        if "user" in inspected and inspected["user"] is not None:
            self._opaque("user", inspected["user"])
        if "tools" in inspected:
            self._tools(inspected["tools"])
        return self._client.chat.completions.create(**inspected)

    # -- per-field evaluation -------------------------------------------------

    def _messages(self, messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for message in messages:
            if not isinstance(message, Mapping):
                raise GuardError("messages must be mappings")
            message = dict(message)
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = self._text_field(str(message.get("role", "message")), content)
            elif isinstance(content, Sequence) and not isinstance(content, (str, bytes)):
                message["content"] = [self._content_part(p) for p in content]
            tool_calls = message.get("tool_calls")
            if tool_calls:
                message["tool_calls"] = self._tool_calls(tool_calls)
            out.append(message)
        return out

    def _content_part(self, part: Mapping[str, Any]) -> dict[str, Any]:
        part = dict(part)
        if part.get("type") == "text" and isinstance(part.get("text"), str):
            part["text"] = self._text_field("content_part", part["text"])
        elif part.get("type") in ("image_url", "input_image", "image"):
            # Multimodal content is declared out of scope for v0.4 and fails
            # closed: an image the guard cannot read must not ride along with
            # sanitized text.
            payload = Payload(kind="unsupported", content="")
            result = self._guard.sanitize(payload, self._recipient, self._purpose, audit_dir=self._audit_dir)
            release_or_raise(result)
        return part

    def _tool_calls(self, tool_calls: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for call in tool_calls:
            call = dict(call)
            fn = call.get("function")
            if isinstance(fn, Mapping) and isinstance(fn.get("arguments"), str):
                fn = dict(fn)
                fn["arguments"] = self._json_field("tool_arguments", fn["arguments"])
                call["function"] = fn
            out.append(call)
        return out

    def _tools(self, tools: Sequence[Mapping[str, Any]]) -> None:
        for tool in tools:
            fn = tool.get("function") if isinstance(tool, Mapping) else None
            description = fn.get("description") if isinstance(fn, Mapping) else None
            if isinstance(description, str) and description:
                self._evaluate_only("tool_description", description)

    def _mapping_field(self, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
        result = self._sanitize(Payload(kind="json", content=copy.deepcopy(dict(value))))
        release_or_raise(result)
        assert result.sanitized_payload is not None
        return json.loads(result.sanitized_payload.content)

    def _json_field(self, name: str, value: str) -> str:
        result = self._sanitize(Payload(kind="json", content=value))
        released = release_or_raise(result)
        assert released.content is not None
        return released.content

    def _text_field(self, name: str, value: str) -> str:
        result = self._sanitize(payload_for(value))
        released = release_or_raise(result)
        assert released.content is not None
        return released.content

    def _opaque(self, name: str, value: str) -> None:
        """Evaluate a field that may never be rewritten, only refused."""
        result = self._guard.evaluate(payload_for(value), self._recipient, self._purpose)
        if result.decision.verdict.value == "BLOCK":
            from core.errors import DisclosureBlocked

            raise DisclosureBlocked(result.decision)

    def _evaluate_only(self, name: str, value: str) -> None:
        """Evaluate a caller-authored description; refuse BLOCK, never rewrite."""
        result = self._guard.evaluate(payload_for(value), self._recipient, self._purpose)
        if result.decision.verdict.value == "BLOCK":
            from core.errors import DisclosureBlocked

            raise DisclosureBlocked(result.decision)

    def _sanitize(self, payload: Payload) -> SanitizationResult:
        return self._guard.sanitize(
            payload, self._recipient, self._purpose, audit_dir=self._audit_dir
        )


class _Chat:
    """Duck-typed stand-in for ``client.chat``."""

    def __init__(self, outer: OpenAIGuard) -> None:
        self.completions = _Completions(outer)


class _Completions:
    """Duck-typed stand-in for ``client.chat.completions``."""

    def __init__(self, outer: OpenAIGuard) -> None:
        self._outer = outer

    def create(self, **kwargs: Any) -> Any:
        return self._outer.completions_create(**kwargs)


def _trust(value: str) -> TrustLevel:
    try:
        return TrustLevel(value.upper().replace("-", "_"))
    except ValueError as exc:
        raise GuardError(f"unknown recipient trust level {value!r}") from exc
