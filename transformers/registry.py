"""Transformer registry: applies a DisclosurePlan to text.

`apply_plan` walks the plan's operations, collects the DetectedFacts that each
operation targets, and replaces spans right-to-left so earlier edits do not
shift later span offsets. It derives a payload-consistent DATE_SHIFT seed from
the text so all dates in one payload move together (plan.md §10.1).
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Sequence

from core.errors import TransformerError
from core.model import DetectedFact, DisclosurePlan, TransformationOp

from .base import TokenRegistry, Transformer, TransformOutcome
from .dates import DateTransformer
from .text import TextTransformer

DEFAULT_TRANSFORMERS: tuple[Transformer, ...] = (
    TextTransformer(),
    DateTransformer(),
)


class TransformerRegistry:
    """Maps op names to Transformer instances."""

    def __init__(self, transformers: Sequence[Transformer] = DEFAULT_TRANSFORMERS) -> None:
        self._by_op: dict[str, Transformer] = {}
        for transformer in transformers:
            for op_name in transformer.handles:
                if op_name in self._by_op:
                    raise ValueError(f"duplicate transformer for op '{op_name}'")
                self._by_op[op_name] = transformer

    def get(self, op_name: str) -> Transformer:
        transformer = self._by_op.get(op_name)
        if transformer is None:
            raise TransformerError(f"unknown transformation op '{op_name}'")
        return transformer

    def apply_plan(
        self,
        text: str,
        facts: Sequence[DetectedFact],
        plan: DisclosurePlan,
        tokens: TokenRegistry | None = None,
    ) -> TransformOutcome:
        """Apply every operation in the plan; return the sanitized text."""
        token_registry = tokens or TokenRegistry()
        ops = self._with_seed(text, plan.operations)

        # Collect (fact, op, replacement) triples, ordered by span start desc.
        replacements: list[tuple[DetectedFact, TransformationOp, str]] = []
        for op in ops:
            transformer = self.get(op.op)
            for fact in facts:
                if fact.type != op.target:
                    continue
                replacement = transformer.apply(fact, op, token_registry)
                replacements.append((fact, op, replacement))

        result = text
        applied: list[TransformationOp] = []
        for fact, op, replacement in sorted(
            replacements, key=lambda r: r[0].start, reverse=True
        ):
            result = result[: fact.start] + replacement + result[fact.end :]
            if op not in applied:
                applied.append(op)
        return TransformOutcome(text=result, applied=tuple(applied))

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _with_seed(
        text: str, ops: Sequence[TransformationOp]
    ) -> tuple[TransformationOp, ...]:
        """Inject a payload-derived DATE_SHIFT seed when not already configured."""
        if not any(op.op == "DATE_SHIFT" for op in ops):
            return tuple(ops)
        seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)
        shift_days = (seed % 730) - 365  # deterministic per payload, -365..364
        return tuple(
            replace(op, parameters={**op.parameters, "_seed": shift_days})
            if op.op == "DATE_SHIFT" and "shift_days" not in op.parameters
            else op
            for op in ops
        )


# Convenience singleton for the common case.
_registry = TransformerRegistry()


def apply_plan(
    text: str,
    facts: Sequence[DetectedFact],
    plan: DisclosurePlan,
    tokens: TokenRegistry | None = None,
    registry: TransformerRegistry | None = None,
) -> TransformOutcome:
    """Apply a DisclosurePlan to text using the default transformer registry."""
    return (registry or _registry).apply_plan(text, facts, plan, tokens)
