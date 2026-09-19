"""Transformer registry: applies a DisclosurePlan to text.

`apply_plan` walks the plan's operations, collects the DetectedFacts that each
operation targets, and replaces spans right-to-left so earlier edits do not
shift later span offsets. It derives a payload-consistent DATE_SHIFT seed from
the text so all dates in one payload move together.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Sequence

from core.errors import TransformerError
from core.model import DetectedFact, DisclosurePlan, TransformationOp

from .base import TokenRegistry, Transformer, TransformOutcome
from .dates import DateTransformer
from .generalize import GeneralizeTransformer
from .text import TextTransformer

DEFAULT_TRANSFORMERS: tuple[Transformer, ...] = (
    TextTransformer(),
    GeneralizeTransformer(),
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
        token_registry = tokens if tokens is not None else TokenRegistry()
        ops = self._with_seed(text, plan.operations)

        replacements: list[tuple[DetectedFact, TransformationOp, str]] = []
        for op in ops:
            transformer = self.get(op.op)
            for fact in facts:
                if fact.type != op.target:
                    continue
                replacement = transformer.apply(fact, op, token_registry)
                replacements.append((fact, op, replacement))

        from .base import _SpanEvidence

        evidence: list[_SpanEvidence] = []
        cursor = 0
        delta = 0
        for fact, op, replacement in sorted(replacements, key=lambda r: r[0].start):
            if not (cursor <= fact.start < fact.end <= len(text)):
                raise TransformerError("invalid or overlapping transformation spans")
            if fact.value is not None and text[fact.start:fact.end] != fact.value:
                raise TransformerError("transformation span does not match detected value")
            if not isinstance(replacement, str):
                raise TransformerError("transformation replacement must be text")
            output_start = fact.start + delta
            evidence.append(_SpanEvidence(
                fact.start, fact.end, output_start, output_start + len(replacement),
                replace(op, parameters=dict(op.parameters)), replacement,
            ))
            delta += len(replacement) - (fact.end - fact.start)
            cursor = fact.end

        result = text
        applied: list[TransformationOp] = []
        for record in reversed(evidence):
            result = result[:record.start] + record.replacement + result[record.end:]
            if record.operation not in applied:
                applied.append(record.operation)
        return TransformOutcome(text=result, applied=tuple(applied), _evidence=tuple(evidence))

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _with_seed(
        text: str, ops: Sequence[TransformationOp]
    ) -> tuple[TransformationOp, ...]:
        """Inject a payload-derived DATE_SHIFT seed when not already configured."""
        if not any(op.op == "DATE_SHIFT" for op in ops):
            return tuple(ops)
        seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)
        shift_days = (seed % 730) - 365 or 365  # nonzero, -365..365
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
