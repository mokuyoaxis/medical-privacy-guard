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
from typing import Mapping

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
# Month-based age: the primary form for infants, and more re-identifying than a
# year band because so few patients share a given month-age. 岁/周岁 never
# matches it, so "患儿6个月" previously produced no AGE fact at all.
#
# An explicit age context is required. Bare "3个月" is far more often a duration
# ("反复头痛3个月加重1周"), and the committed corpus contains that phrasing in
# documents whose ALLOW path is pinned by the precision gate.
_MONTH_AGE_RE = re.compile(
    r"(?:月龄|患儿|出生后|婴儿|幼儿)\s*(?P<v1>\d{1,2}\s*个?月(?:龄|大)?)"
    r"|(?:年龄|月龄)\s*[:：=]?\s*(?P<v2>\d{1,2}\s*个?月(?:龄|大)?)"
    r"|(?P<v3>\d{1,2}\s*个月大)"
)
# Chinese numerals are how ages are often written in narrative notes
# ("五十岁", "六十七岁"). Without them the age is invisible, and so is the sex
# beside it: "患者，女，五十六岁。" produced no fact at all and was released
# unchanged, while "患者，女，67岁。" was sanitized. Same sentence, different
# digits, opposite outcome.
_CN_DIGITS: Mapping[str, int] = {
    "零": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4,
    "五": 5, "六": 6, "七": 7, "八": 8, "九": 9,
}
_CN_AGE_RE = re.compile(
    r"(?<![\d一二三四五六七八九十两])"
    r"(?P<age>[一二两三四五六七八九十]{1,3})\s*(?:岁|周岁)"
    r"(?!(?:及)?(?:以上|以下)|左右|上下|年代|时期)"
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
# A comma often sits between the patient word and the sex character
# ("患者，女，56岁"), which the earlier adjacent-only form missed; the same
# sentence with digits after the sex still matched, so the gap was invisible.
# The lookahead keeps "患者，女性家属" out: 性 is not a following boundary.
_SEX_PATIENT_RE = re.compile(
    r"(?:患者|病人|患儿|伤者)[\s，,、]*(?P<sex>男|女)(?=[，,、。；;\s)]|\d|$)"
)
# Structured enumeration: 男，67岁 / 女,45岁
_SEX_ENUM_RE = re.compile(
    r"(?<![\u4e00-\u9fff])(?P<sex>男|女)\s*[，,、]\s*\d{1,3}\s*(?:岁|周岁)"
)
# Attributive: 男性患者 / 女性 / 男性病人
_SEX_ATTR_RE = re.compile(r"(?P<sex>男|女)性(?=患者|病人|病例|住院|就诊|体检|受检)")


def parse_cn_numeral(token: str) -> int | None:
    """Parse a Chinese numeral of the form the age rule can produce.

    Handles 一–九, 十, 十五, 二十 and 五十六. Returns None for anything else,
    so an implausible token is dropped rather than guessed at.
    """
    if not token:
        return None
    if "十" not in token:
        return _CN_DIGITS.get(token) if len(token) == 1 else None
    head, _, tail = token.partition("十")
    if head == "零":
        return None
    if head and head not in _CN_DIGITS:
        return None
    if tail and tail not in _CN_DIGITS:
        return None
    tens = _CN_DIGITS[head] if head else 1
    return tens * 10 + (_CN_DIGITS[tail] if tail else 0)


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
        facts.extend(self._month_ages(text))
        facts.extend(self._numeral_ages(text))
        return tuple(facts)

    def _numeral_ages(self, text: str) -> list[DetectedFact]:
        facts: list[DetectedFact] = []
        for match in _CN_AGE_RE.finditer(text):
            age = parse_cn_numeral(match.group("age"))
            if age is None or not _AGE_MIN <= age <= _AGE_MAX:
                continue
            if _AGE_GENERIC_BEFORE_RE.search(text[max(0, match.start() - 8) : match.start()]):
                continue
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=self.confidence,
                    source=f"regex.{self.name}.numeral",
                    value=match.group(0),
                )
            )
        return facts

    def _month_ages(self, text: str) -> list[DetectedFact]:
        facts: list[DetectedFact] = []
        for m in _MONTH_AGE_RE.finditer(text):
            group = next(g for g in ("v1", "v2", "v3") if m.group(g) is not None)
            token = m.group(group)
            months = int(re.match(r"\d{1,2}", token).group(0))
            # A month-age is an infant's age; anything beyond the toddler years
            # is a duration or a data error rather than a patient age.
            if not 1 <= months <= 36:
                continue
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start(group),
                    end=m.end(group),
                    confidence=self.confidence,
                    source=f"regex.{self.name}.month",
                    value=token,
                )
            )
        return facts


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
