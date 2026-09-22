"""Vocabulary-backed detection.

A term in the deployment's institution dictionary is a fact even when no
built-in rule matches its shape — that is the point of loading one. The
detector emits the same fact types the rule-based detectors do, so policy needs
no new rules, and it reports higher confidence because an institution's own
records are stronger evidence than a shape match.
"""

from __future__ import annotations

import re

from core.dictionary import CATEGORY_FACT_TYPES, InstitutionDictionary
from core.model import DetectedFact

from .base import Detector

#: Contexts where a department or institution name denotes a service rather
#: than something attributed to this patient. docs/scope.md lists these as
#: deliberate non-detection ("建议神经内科会诊" names a service, not the patient's
#: department), and a dictionary must not overturn that judgement merely because
#: it happens to contain the word.
#: "由" is deliberately absent: it marks the agent as often as the source
#: ("患者由王建国医师接诊" names the treating physician, who must be detected).
_REFERRAL_BEFORE_RE = re.compile(r"(?:建议|转诊至|转至|转往|请|至|到)$")


class DictionaryDetector(Detector):
    """Reports every dictionary term that occurs in the text.

    Longest terms are tried first and matches are consumed, so "神内二病区"
    wins over a shorter overlapping entry rather than producing two facts for
    the same span.
    """

    name = "institution_dictionary"
    #: High: an institution's own records outrank a shape match. The registry
    #: keeps the higher-confidence fact when spans overlap.
    confidence = 0.97

    def __init__(self, dictionary: InstitutionDictionary) -> None:
        self.dictionary = dictionary
        self._entries = dictionary.entries()

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        consumed: list[tuple[int, int]] = []
        for term, category in self._entries:
            start = text.find(term)
            while start != -1:
                end = start + len(term)
                if not _REFERRAL_BEFORE_RE.search(text[max(0, start - 4) : start]) and not any(
                    prior < end and start < after for prior, after in consumed
                ):
                    facts.append(
                        DetectedFact(
                            type=CATEGORY_FACT_TYPES[category],
                            start=start,
                            end=end,
                            confidence=self.confidence,
                            source=f"dictionary.{category}",
                            value=term,
                        )
                    )
                    consumed.append((start, end))
                start = text.find(term, start + 1)
        return tuple(facts)
