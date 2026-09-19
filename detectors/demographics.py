"""Demographic detectors: AGE and SEX.

Both are quasi-identifiers rather than direct identifiers: on their own they
identify nobody, but combined with district, date and rare diagnosis they
narrow a population quickly. They are therefore detected (so policy can count
the re-identification risk) without necessarily being erased.

SEX is deliberately conservative. A bare 男/女 is extremely common in
non-clinical text ("男病房", "男女比例", "男友"), so a fact is only emitted
when the character appears in a clinical context:

- an explicit field label (``性别：男``, ``性别男``);
- a structured enumeration (``男，67岁``, ``女，45岁``);
- an attributive form (``男性患者``, ``女性``).

``SEX`` is a non-transformable context type in policy: it contributes risk but
has no span transformation, so it never blocks a release on its own.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector
from .field_syntax import FIELD_SEP

# An age must be a plausible human age and must not be part of a longer digit
# run (IDs and phone numbers contain digit sequences that end in 岁-less text,
# but a leading-digit guard keeps partial matches out of "1380000012岁").
#
# An age is only a quasi-identifier when it is attributed to the patient.
# Thresholds and population statements — "多见于50岁以上人群", "纳入18岁以上
# 成人" — carry an age-like number that must not be redacted: the number
# describes a population, not a person, and rewriting it garbles the sentence.
#
# A generalized band is likewise not a patient age. The transformer rewrites
# 44岁 to 40-49岁, and the trailing 49 of that band is an age-shaped token; so
# is the 90 of 90岁及以上 and the 1 of 不足1岁. Re-detecting the pipeline's own
# output would make the policy re-run report SANITIZE forever and the note
# would never be released. Range separators and band markers are therefore
# excluded on both sides.
_AGE_RE = re.compile(
    r"(?<![\d.\-–—~～])"
    r"(?<!不足)"
    r"(?P<age>\d{1,3})\s*(?:岁|周岁)"
    r"(?!(?:及)?(?:以上|以下)|左右|上下)"
)
_AGE_GENERIC_BEFORE_RE = re.compile(
    r"(?:多见于|多发于|好发于|高发于|见于|纳入|选取|年龄在|超过|大于|小于|"
    r"至少|多为|大于等于|小于等于|一般在)$"
)
_AGE_MIN = 1
_AGE_MAX = 120

# Explicit field label: 性别：男 / 性别 男 / 性别男 / 性别=男
_SEX_FIELD_RE = re.compile(r"性别" + FIELD_SEP + r"(?P<sex>男|女)")
# Patient enumeration, the most common clinical form: 患者男，67岁 / 病人女,45岁
_SEX_PATIENT_RE = re.compile(
    r"(?:患者|病人|患儿|伤者)\s*(?P<sex>男|女)(?=[，,、。；;\s)]|\d)"
)
# Structured enumeration: 男，67岁 / 女,45岁
_SEX_ENUM_RE = re.compile(
    r"(?<![\u4e00-\u9fff])(?P<sex>男|女)\s*[，,、]\s*\d{1,3}\s*(?:岁|周岁)"
)
# Attributive: 男性患者 / 女性 / 男性病人
_SEX_ATTR_RE = re.compile(r"(?P<sex>男|女)性(?=患者|病人|病例|住院|就诊|体检|受检)")


class AgeDetector(Detector):
    """Detects explicit ages written with 岁 / 周岁."""

    name = "age"
    fact_type = "AGE"
    confidence = 0.95

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for m in _AGE_RE.finditer(text):
            age = int(m.group("age"))
            if not _AGE_MIN <= age <= _AGE_MAX:
                continue
            if _AGE_GENERIC_BEFORE_RE.search(text[max(0, m.start() - 8) : m.start()]):
                continue
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start(),
                    end=m.end(),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=m.group(0),
                )
            )
        return tuple(facts)


class SexDetector(Detector):
    """Detects sex only in a clinical context (field, enumeration or attribute)."""

    name = "sex"
    fact_type = "SEX"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        spans: dict[tuple[int, int], DetectedFact] = {}
        for pattern in (_SEX_FIELD_RE, _SEX_PATIENT_RE, _SEX_ENUM_RE, _SEX_ATTR_RE):
            for m in pattern.finditer(text):
                # Report the sex character itself, not the surrounding label,
                # so a transformation (if a profile configures one) removes
                # exactly the identifying token.
                start, end = m.start("sex"), m.end("sex")
                spans[(start, end)] = DetectedFact(
                    type=self.fact_type,
                    start=start,
                    end=end,
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=m.group("sex"),
                )
        ordered = sorted(spans.values(), key=lambda f: (f.start, f.end))
        return tuple(ordered)
