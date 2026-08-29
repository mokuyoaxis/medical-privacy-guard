"""Text transformers: REMOVE, MASK, TOKENIZE.

- REMOVE:   replace the span with a fixed redaction marker.
- MASK:     replace every character with `*` (length preserved).
- TOKENIZE: replace with a stable per-value token ([TYPE_001]); the same raw
            value always maps to the same token within one run.
"""

from __future__ import annotations

from core.errors import TransformerError
from core.model import DetectedFact, TransformationOp

from .base import TokenRegistry, Transformer

_REDACTED = "[REDACTED]"


class TextTransformer(Transformer):
    """Handles REMOVE / MASK / TOKENIZE for any entity type."""

    handles = ("REMOVE", "MASK", "TOKENIZE")

    def apply(
        self,
        fact: DetectedFact,
        op: TransformationOp,
        tokens: TokenRegistry,
    ) -> str:
        if op.op == "REMOVE":
            return _REDACTED
        if op.op == "MASK":
            value = fact.value or ""
            return "*" * max(len(value), 1)
        if op.op == "TOKENIZE":
            entity_type = op.entity_type or fact.type
            value = fact.value or ""
            if not value:
                raise TransformerError(
                    f"TOKENIZE requires a raw value; none recorded for {fact.type} span"
                )
            return tokens.token_for(entity_type, value)
        raise TransformerError(f"op '{op.op}' not handled by {type(self).__name__}")
