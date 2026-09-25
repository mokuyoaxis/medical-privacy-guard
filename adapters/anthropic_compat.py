"""An Anthropic Messages API client with the guard on its egress path.

The sibling of :mod:`adapters.openai_compat`, for the same trust boundary and
the same verdict semantics: every field that can carry caller-supplied content
is evaluated before the SDK call leaves, SANITIZE rewrites in place, BLOCK and
ASK raise, responses are not inspected (``docs/scope.md``). What differs is the
request shape, and each difference is a decision:

- **``system`` is a top-level field**, not a message. In a medical deployment a
  system prompt routinely names the clinic, the department or the treating
  physician, so it is a data channel and is sanitized like any other text. A
  block-list form (``[{"type": "text", "text": ...}]``) has each block handled
  as such.
- **Message content is a block list.** ``text`` blocks are sanitized;
  ``tool_use.input`` is a JSON payload and is sanitized as one; ``tool_result``
  content -- the tool's output replayed back to the model -- is data going out
  just the same and is sanitized as text or blocks; ``image`` and ``document``
  blocks are formats the guard cannot read and fail closed, so an image cannot
  ride along with sanitized prose.
- **``tools[].description`` is caller-authored** and evaluated but never
  rewritten, as with OpenAI: an interface description that names a hospital
  cannot be safely paraphrased. A BLOCK verdict refuses the call.
- **``metadata.user_id`` is an opaque identifier** and only ever evaluated:
  rewriting it would break the caller's accounting. BLOCK raises.
- **``model``, ``max_tokens`` and the sampling fields** are not content; they
  are forwarded untouched.

The transport is duck-typed -- anything with
``messages.create(**kwargs)`` works, which is what the tests stub -- and the
wrapper never holds credentials: it receives the caller's own configured
client.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping, Sequence

from adapters.egress import release_or_raise
from adapters.ingress import payload_for
from core.errors import DisclosureBlocked, GuardError
from core.model import Payload, Purpose, Recipient, TrustLevel
from medical_privacy_guard import Guard

__all__ = ["AnthropicGuard"]

_TEXTUAL_BLOCKS = ("text",)
_REFUSED_BLOCKS = ("image", "document")


class AnthropicGuard:
    """Wrap an Anthropic Messages client so no request leaves unaudited."""

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
        self.messages = _Messages(self)

    # -- entry point ---------------------------------------------------------

    def messages_create(self, **kwargs: Any) -> Any:
        """Evaluate one Messages API call and forward, rewrite or refuse."""
        inspected = copy.deepcopy(kwargs)
        if isinstance(inspected.get("system"), str):
            inspected["system"] = self._text_field("system", inspected["system"])
        elif isinstance(inspected.get("system"), Sequence) and not isinstance(
            inspected.get("system"), (str, bytes)
        ):
            inspected["system"] = [self._content_block(b) for b in inspected["system"]]
        if isinstance(inspected.get("messages"), Sequence):
            inspected["messages"] = self._messages(inspected["messages"])
        if isinstance(inspected.get("metadata"), Mapping):
            user_id = inspected["metadata"].get("user_id")
            if isinstance(user_id, str):
                self._opaque("metadata.user_id", user_id)
        if isinstance(inspected.get("tools"), Sequence):
            self._tools(inspected["tools"])
        return self._client.messages.create(**inspected)

    # -- per-field evaluation --------------------------------------------------

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
                message["content"] = [self._content_block(b) for b in content]
            out.append(message)
        return out

    def _content_block(self, block: Mapping[str, Any]) -> dict[str, Any]:
        block = dict(block)
        kind = block.get("type")
        if kind in _TEXTUAL_BLOCKS and isinstance(block.get("text"), str):
            block["text"] = self._text_field(f"{kind}_block", block["text"])
        elif kind == "tool_use" and isinstance(block.get("input"), Mapping):
            block["input"] = self._mapping_field("tool_use.input", block["input"])
        elif kind == "tool_result":
            inner = block.get("content")
            if isinstance(inner, str):
                block["content"] = self._text_field("tool_result", inner)
            elif isinstance(inner, Sequence) and not isinstance(inner, (str, bytes)):
                block["content"] = [self._content_block(b) for b in inner]
        elif kind in _REFUSED_BLOCKS:
            # An image or document the guard cannot read must not ride along
            # with sanitized text: the part is declared unsupported and the
            # verdict machinery refuses the call.
            result = self._sanitize(Payload(kind="unsupported", content=""))
            release_or_raise(result)
        return block

    def _tools(self, tools: Sequence[Mapping[str, Any]]) -> None:
        for tool in tools:
            if not isinstance(tool, Mapping):
                continue
            description = tool.get("description")
            if isinstance(description, str) and description:
                self._evaluate_only("tool_description", description)

    def _mapping_field(self, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
        result = self._sanitize(Payload(kind="json", content=copy.deepcopy(dict(value))))
        release_or_raise(result)
        assert result.sanitized_payload is not None
        return json.loads(result.sanitized_payload.content)

    def _text_field(self, name: str, value: str) -> str:
        result = self._sanitize(payload_for(value))
        released = release_or_raise(result)
        assert released.content is not None
        return released.content

    def _opaque(self, name: str, value: str) -> None:
        """Evaluate a field that may never be rewritten, only refused."""
        result = self._guard.evaluate(payload_for(value), self._recipient, self._purpose)
        if result.decision.verdict.value == "BLOCK":
            raise DisclosureBlocked(result.decision)

    def _evaluate_only(self, name: str, value: str) -> None:
        """Evaluate a caller-authored description; refuse BLOCK, never rewrite."""
        result = self._guard.evaluate(payload_for(value), self._recipient, self._purpose)
        if result.decision.verdict.value == "BLOCK":
            raise DisclosureBlocked(result.decision)

    def _sanitize(self, payload: Payload):
        return self._guard.sanitize(
            payload, self._recipient, self._purpose, audit_dir=self._audit_dir
        )


class _Messages:
    """Duck-typed stand-in for ``client.messages``."""

    def __init__(self, outer: AnthropicGuard) -> None:
        self._outer = outer

    def create(self, **kwargs: Any) -> Any:
        return self._outer.messages_create(**kwargs)


def _trust(value: str) -> TrustLevel:
    try:
        return TrustLevel(value.upper().replace("-", "_"))
    except ValueError as exc:
        raise GuardError(f"unknown recipient trust level {value!r}") from exc
