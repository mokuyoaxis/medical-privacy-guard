"""Independent recall guard for narrative identifiers.

The verifier re-runs the *same* detector set that produced the original facts,
so a miss in the first pass is invisible to verification as well. Worse, a
payload the primary detectors find nothing in short-circuits to ALLOW and never
reaches verification at all — "张伟，男，67岁，因脑梗死入院" was released with the
name intact while the system reported success.

This module is a second opinion written from a different angle. The primary
name detector is anchored on a field label (``姓名：``/``患者``); these rules key
on *adjacent clinical context* instead — a surname+given-name run immediately
followed by a gender marker — so a blind spot in the labelled form does not
automatically reproduce here.

Scope is deliberately narrow and empirically bounded. Only patterns measured to
be zero-false-positive on the committed corpus are included, because a recall
guard that fires on ordinary clinical prose would block the release path the
way detector false positives once did (see docs/evaluation.md). This is a
safety net with a known mesh size, not a second complete detector set.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector
from .surnames import SURNAME_CLASS

#: Narrative name confidence. Below the labelled-field detectors (0.95) so that
#: when both fire on the same span the labelled fact wins the merge, and low
#: enough to reflect that this is contextual inference rather than a label.
NARRATIVE_NAME_CONFIDENCE = 0.6

# A name immediately followed by a gender marker — "张伟，男，67岁" — the
# standard Chinese clinical-note opener. The primary PERSON_NAME detector needs
# an explicit 患者/姓名/病人 label and misses this form entirely.
#
# The lookahead requires the gender character to be followed by a separator or
# end of string, which is what separates "男，67岁" (a patient) from "男病房" /
# "男护士" (a room, a role). An optional bracketed age may sit between the name
# and the marker ("张伟（67岁，男）").
_NARRATIVE_NAME_RE = re.compile(
    rf"(?P<name>{SURNAME_CLASS}[\u4e00-\u9fff]{{1,2}})"
    r"(?=[，,、\s（(]*(?:\d{1,3}\s*岁[，,、\s]*)?(?:男|女)(?:性)?(?:[，,）、。；;\s]|$))"
)


class NarrativeNameDetector(Detector):
    """Detects ``姓名，性别`` narrative openers without a field label."""

    name = "recall_narrative_name"
    fact_type = "PERSON_NAME"
    confidence = NARRATIVE_NAME_CONFIDENCE

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        return tuple(
            DetectedFact(
                type=self.fact_type,
                start=m.start("name"),
                end=m.end("name"),
                confidence=self.confidence,
                source=f"regex.{self.name}",
                value=m.group("name"),
            )
            for m in _NARRATIVE_NAME_RE.finditer(text)
        )
