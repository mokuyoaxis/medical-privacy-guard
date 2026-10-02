"""Independent recall guard for narrative identifiers.

The verifier re-runs the *same* detector set that produced the original facts,
so a miss in the first pass is invisible to verification as well. Worse, a
payload the primary detectors find nothing in short-circuits to ALLOW and never
reaches verification at all — "张伟，男，67岁，因脑梗死入院" was released with the
name intact while the system reported success.

This module is a second opinion written from a different angle. The primary
name detector is anchored on a field label (``姓名：``/``患者``); these rules key
on *adjacent clinical context* instead, so a blind spot in the labelled form
does not automatically reproduce here. Three narrative shapes are covered:

- a name followed by a gender marker — ``张伟，男，67岁``, the standard note
  opener;
- a name followed by a complaint verb — ``陈曦诉头晕`` / ``潘婷主诉腹痛``;
- a name followed by a connective — ``汪洋由急诊科转入`` / ``陈曦因胸痛入院``.

The anchors differ in strength and the rules are tuned to match. A gender
marker is unambiguous, so its name may use any ideograph run. A complaint
verb (诉/主诉/自诉/自述) is strong but still needs the given name to come from
the name-character inventory, so a surname-like word is not read as a person.
A connective (因/由/以) is the weakest of the three — 高峰, 文明 and 白云 all
have the shape of a surname plus a given-name character — so it additionally
requires the name to sit at a clause boundary. The residual case (a common
word of that shape opening a clause) is named in the rule comment and in
docs/scope.md rather than left implicit.

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
from .surnames import (
    COMPOUND_SURNAME_CLASS,
    GIVEN_NAME_CLASS,
    SURNAME_CLASS,
)

#: Narrative name confidence. Below the labelled-field detectors (0.95) so that
#: when both fire on the same span the labelled fact wins the merge, and low
#: enough to reflect that this is contextual inference rather than a label.
NARRATIVE_NAME_CONFIDENCE = 0.6

# A name immediately followed by a gender marker — "张伟，男，67岁" — the
# standard Chinese clinical-note opener. The primary PERSON_NAME detector needs
# an explicit 患者/姓名/病人 label and misses this form entirely.
#
# The given name is any ideograph run, not an inventory: a 男/女 marker directly
# after the name is such a strong anchor that an uncommon given character (杨帆)
# must still be captured, and the lookahead's gender requirement is what keeps
# ordinary prose out.
#
# The lookahead requires the gender character to be followed by a separator or
# end of string, which is what separates "男，67岁" (a patient) from "男病房" /
# "男护士" (a room, a role). An optional bracketed age may sit between the name
# and the marker ("张伟（67岁，男）").
_NARRATIVE_NAME_RE = re.compile(
    rf"(?P<name>{SURNAME_CLASS}[\u4e00-\u9fff]{{1,2}})"
    r"(?=[，,、\s（(]*(?:\d{1,3}\s*岁[，,、\s]*)?(?:男|女)(?:性)?(?:[，,）、。；;\s]|$))"
)

# A name immediately followed by a complaint verb — "陈曦诉头晕" /
# "潘婷主诉腹痛" / "赵六自述头晕". This is the narrative form the gender opener
# cannot see: no field label, no 男/女 marker, so before this rule the name was
# released verbatim under an approved recipient.
#
# 诉 is a strong anchor: it attributes a complaint to the person named in front
# of it, and no ordinary clinical noun ends that way (the words that do —
# 上诉/申诉/投诉 — do not have a name shape in front). The given name must still
# come from the inventory, so a surname-like word followed by an unrelated
# character is not read as a person.
_NARRATIVE_SU_NAME_RE = re.compile(
    r"(?P<name>"
    r"(?:" + COMPOUND_SURNAME_CLASS + r")" + GIVEN_NAME_CLASS +
    r"|" + SURNAME_CLASS + GIVEN_NAME_CLASS +
    r")"
    r"(?=(?:主诉|自诉|自述|诉)[\u4e00-\u9fff])"
)

# A name immediately followed by a connective — "汪洋由急诊科转入" /
# "陈曦因胸痛入院" / "张伟以发热为主诉". The connective is a weaker anchor than
# a complaint verb, because ordinary words have this shape too: 高峰, 文明,
# 白云 and 石林 are all [surname][given-name-character] pairs. The name is
# therefore required to sit at a clause boundary, which keeps an embedded word
# out ("就诊高峰因…" no longer matches) while a name introduced by a comma or
# at the start of a sentence still does.
#
# Known residual: a common word of this shape at the start of a clause
# ("文明因交流而多彩") is still read as a person. That is the price of covering
# the connective form without a field label; it is recorded in docs/scope.md
# and pinned by negative tests for the shapes that do not fire.
_NARRATIVE_CONNECTIVE_NAME_RE = re.compile(
    r"(?:(?<=[，,。；;、！？!?\s\n])|^)"
    r"(?P<name>"
    r"(?:" + COMPOUND_SURNAME_CLASS + r")" + GIVEN_NAME_CLASS +
    r"|" + SURNAME_CLASS + GIVEN_NAME_CLASS +
    r")"
    r"(?=(?:因|由|以)[\u4e00-\u9fff])"
)


class NarrativeNameDetector(Detector):
    """Detects narrative names without a field label.

    Every shape is reported as ``PERSON_NAME`` with the same confidence, so
    policy and transformation treat them exactly like a labelled name.
    """

    name = "recall_narrative_name"
    fact_type = "PERSON_NAME"
    confidence = NARRATIVE_NAME_CONFIDENCE

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for pattern in (
            _NARRATIVE_NAME_RE,
            _NARRATIVE_SU_NAME_RE,
            _NARRATIVE_CONNECTIVE_NAME_RE,
        ):
            for match in pattern.finditer(text):
                name = match.group("name")
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=match.start("name"),
                        end=match.end("name"),
                        confidence=self.confidence,
                        source=f"regex.{self.name}",
                        value=name,
                    )
                )
        # Two rules can only overlap on a name followed by both a gender marker
        # and a verb, which no note writes; deduplicate anyway so the detector
        # never reports one span twice.
        unique: dict[tuple[int, int], DetectedFact] = {}
        for fact in facts:
            unique.setdefault((fact.start, fact.end), fact)
        return tuple(unique.values())
