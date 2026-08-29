"""Detector base classes.

Design: classifiers produce facts, not policy (see plan.md §9). A Detector
turns raw text into a tuple of immutable DetectedFact objects. Detectors never
decide the verdict — that is the policy engine's job.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Pattern

from core.model import DetectedFact


class Detector(ABC):
    """Base class for all detectors."""

    #: Stable identifier for this detector, used in DetectedFact.source.
    name: str = "base"

    @abstractmethod
    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        """Return every fact found in *text*, in any order (registry sorts)."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"


class RegexDetector(Detector):
    """A detector built from a single compiled regex pattern.

    Subclasses set `pattern`, `fact_type`, and `confidence`. Named groups are
    allowed; the whole match is reported unless `value_group` selects a group.
    """

    name: str = "regex"
    pattern: Pattern[str] = re.compile(r"(?!)")  # never matches by default
    fact_type: str = "UNKNOWN"
    confidence: float = 1.0
    #: Optional named group whose text becomes the fact value.
    value_group: str | None = None

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for match in self.pattern.finditer(text):
            value = match.group(0)
            if self.value_group is not None:
                try:
                    value = match.group(self.value_group) or value
                except (IndexError, KeyError):
                    pass
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=value,
                )
            )
        return tuple(facts)
