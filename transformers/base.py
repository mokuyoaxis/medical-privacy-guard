"""Transformer base classes and shared state.

Design (plan.md §10): a transformer turns one matched span (DetectedFact)
into a replacement string. `apply_plan` in registry.py drives the whole
DisclosurePlan, applying operations right-to-left so earlier replacements do
not shift later spans.

TokenRegistry keeps entity-to-token mapping in memory for one sanitization
run so TOKENIZE is stable within a payload (张伟 → [PERSON_NAME_001] wherever
it appears) and the map is never written to audit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.model import DetectedFact, TransformationOp


class TokenRegistry:
    """In-memory map from (entity_type, value) to a stable pseudo-token."""

    def __init__(self) -> None:
        self._map: dict[tuple[str, str], str] = {}
        self._count: int = 0

    def token_for(self, entity_type: str, value: str) -> str:
        key = (entity_type, value)
        token = self._map.get(key)
        if token is None:
            self._count += 1
            token = f"[{entity_type}_{self._count:03d}]"
            self._map[key] = token
        return token

    def __len__(self) -> int:
        return len(self._map)


@dataclass(frozen=True)
class TransformOutcome:
    """Result of applying a DisclosurePlan to text.

    `applied` lists the operations that actually replaced at least one span.
    The outcome never contains raw sensitive values.
    """

    text: str
    applied: tuple[TransformationOp, ...] = ()


class Transformer(ABC):
    """One transformer implements one or more transformation op types."""

    #: Op names this transformer can apply (e.g. ("REMOVE", "MASK")).
    handles: tuple[str, ...] = ()

    @abstractmethod
    def apply(
        self,
        fact: DetectedFact,
        op: TransformationOp,
        tokens: TokenRegistry,
    ) -> str:
        """Return the replacement string for one detected fact span.

        Raises TransformerError when the operation cannot be applied safely.
        """
        raise NotImplementedError

    @property
    def op_names(self) -> tuple[str, ...]:
        return self.handles
