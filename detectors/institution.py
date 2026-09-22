"""Institution and location-within-institution detectors.

Covers institution-specific identity that a patient note carries implicitly:

- ``HOSPITAL_NAME``  — 示例医院 / 医科大学附属医院
- ``DEPARTMENT``     — 神经内科 / 检验科 / ICU
- ``WARD``           — 神内二病区 / 三病区
- ``BED_NUMBER``     — 12床 / A03床

Departments use an explicit dictionary rather than a suffix pattern. A
suffix rule ("内科") matches ordinary prose such as "患者在内科就诊" and
silently swallows the preceding characters; a dictionary keeps precision high
and is the seed for the local institution dictionary planned for a later
version.

The hospital pattern is anchored on institution suffixes, which have no
common non-institutional meaning in clinical text.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector
from .field_syntax import label_with_value

# Common department names. Kept as an explicit set because a generic
# "…科" pattern produces unacceptable false positives on ordinary words
# (学科, 本科, 外科手术 as a phrase, …).
_DEPARTMENTS: frozenset[str] = frozenset(
    {
        "神经内科", "神经外科", "心内科", "心血管内科", "呼吸内科", "消化内科",
        "内分泌科", "肾内科", "血液科", "风湿免疫科", "感染科", "肿瘤科",
        "普通外科", "普外科", "骨科", "创伤骨科", "脊柱外科", "泌尿外科",
        "胸外科", "心脏外科", "神经外科", "肝胆外科", "血管外科", "肛肠科",
        "妇产科", "妇科", "产科", "儿科", "新生儿科", "眼科", "耳鼻咽喉科",
        "口腔科", "皮肤科", "精神科", "心理科", "康复科", "中医科", "针灸科",
        "急诊科", "重症医学科", "麻醉科", "疼痛科", "影像科", "放射科",
        "超声科", "检验科", "病理科", "输血科", "营养科", "药剂科",
        "门诊部", "住院部", "手术室", "导管室", "内镜中心", "血液净化中心",
    }
)

# A department name is patient-related identity only when it is the patient's
# own department, so a field label or a patient-movement verb must sit next to
# it. This keeps referral targets out: "建议神经内科会诊" is clinical content,
# and redacting it strips the meaning of the referral while revealing nothing
# the diagnosis in the same note does not already imply.
_DEPARTMENT_BEFORE_RE = re.compile(
    r"(?:科室|部门|病区|病房)\s*[:：]?\s*$"
    r"|(?:转入|转至|转往|收入|收治|入住|收住)\s*$"
)
_DEPARTMENT_AFTER_RE = re.compile(r"(?:门诊|病房|病区|住院)")

# Institutional suffixes. These are specific enough that a preceding Chinese
# run is reliably part of the institution name. The pattern deliberately stays
# anchored to the Han-character range (no \w, which would cross newlines and
# swallow the preceding line).
_HOSPITAL_SUFFIXES = tuple(
    sorted(
        ("附属医院", "医疗中心", "医学中心", "卫生院", "医科大学", "医学院", "医院"),
        key=len,
        reverse=True,
    )
)
_HOSPITAL_RE = re.compile(r"[\u4e00-\u9fff]{2,12}?(?:" + "|".join(_HOSPITAL_SUFFIXES) + r")")

# Verb/preposition lead-ins that are never part of an institution name.
# Longest first so 建议转诊至 is stripped as a unit rather than as 转.
_HOSPITAL_VERB_PREFIXES = tuple(
    sorted(
        (
            "建议转诊至", "建议转诊", "建议转往", "建议转入", "建议转",
            "就诊于", "转诊至", "转诊到", "转往", "转入", "转出",
            "送往", "送至", "前往", "赴", "就诊", "转诊",
            "于", "至", "在", "到", "转", "送",
        ),
        key=len,
        reverse=True,
    )
)

# Words that describe a hospital's type or grade rather than name it. A match
# whose name part is one of these is a generic reference ("上级医院",
# "三级甲等医院"), not an institution identifier.
_HOSPITAL_GENERIC_QUALIFIERS = frozenset(
    {
        "三级甲等", "三级乙等", "三甲", "三乙", "二甲", "二乙",
        "三级", "二级", "一级", "甲等", "乙等",
        "上级", "下级", "当地", "本地", "外地", "外院", "该院", "本院",
        "我院", "贵院", "综合", "专科", "社区", "基层", "定点", "公立",
        "民营", "中心", "有关", "相关", "各级", "各类", "其他", "同一",
    }
)

# Characters that never occur inside a proper name. Their presence means the
# match swallowed a sentence fragment ("该院为三级甲等医院"). 和/协 are absent
# on purpose: real names contain them (仁和医院, 协和医院).
_HOSPITAL_REJECT_CHARS = frozenset("为是在的于到至往转送等其并就而则")


def _strip_hospital_verb_prefix(value: str, start: int) -> tuple[str, int]:
    for prefix in _HOSPITAL_VERB_PREFIXES:
        if value.startswith(prefix) and len(value) > len(prefix):
            return value[len(prefix) :], start + len(prefix)
    return value, start


def _strip_hospital_reject_chars(value: str, start: int) -> tuple[str, int]:
    """Drop the sentence fragment preceding the real name.

    A reject character means the match swallowed text that cannot belong to a
    name — "患者在宣武医院" is a name preceded by ordinary narration. Dropping
    the whole match (the previous behaviour) meant "患者曾在X医院住院", one of
    the most natural clinical sentences, produced no fact at all and released
    the institution name verbatim.

    Cutting at the *last* reject character keeps the name while discarding the
    fragment, so the generic cases the reject set exists for are still removed:
    "该院为三级甲等医院" cuts at 为 and leaves "三级甲等医院", which the
    generic-qualifier check then rejects.
    """
    cut = -1
    for index, char in enumerate(value):
        if char in _HOSPITAL_REJECT_CHARS:
            cut = index
    if cut >= 0:
        return value[cut + 1 :], start + cut + 1
    return value, start


def _strip_hospital_suffix(value: str) -> str:
    for suffix in _HOSPITAL_SUFFIXES:
        if value.endswith(suffix):
            return value[: -len(suffix)]
    return value

_WARD_RE = re.compile(r"(?<![\dA-Za-z])(?:[\u4e00-\u9fff]{0,6}?)?(?P<ward>\d{1,2}|[一二三四五六七八九十]{1,2})病区")

# Generic references to a ward are not identifiers. At the start of a line the
# preceding-character lookbehind cannot help, so "本病区" would otherwise be
# captured as a ward name. A real designation ("神内二病区", "三病区") never
# starts with one of these.
_WARD_GENERIC_PREFIXES = (
    "各科", "全科", "所有", "部分", "其他", "上述", "同一",
    "本", "该", "各", "全", "此", "每",
)
_WARD_GENERIC_RE = "|".join(sorted(_WARD_GENERIC_PREFIXES, key=len, reverse=True))
_WARD_NAMED_RE = re.compile(
    rf"(?<![\u4e00-\u9fff])(?!(?:{_WARD_GENERIC_RE})病区)(?P<ward>[\u4e00-\u9fff]{{1,4}}病区)"
)

_BED_RE = re.compile(r"(?<![A-Za-z0-9])(?P<bed>[A-Z]?\d{1,3})\s*床(?!位)")

# The labelled form ("床号 12") is at least as common as the suffix form and
# was not covered at all. 床位 is deliberately not a label: it is a capacity
# concept ("床位紧张"), not an identifier.
_BED_LABEL_RE = re.compile(label_with_value(r"床号|床位号", r"[A-Z]?\d{1,3}") + r"(?!\d)")


class HospitalNameDetector(Detector):
    """Detects institution names by their institutional suffix."""

    name = "hospital_name"
    fact_type = "HOSPITAL_NAME"
    confidence = 0.85

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for m in _HOSPITAL_RE.finditer(text):
            value, start = _strip_hospital_verb_prefix(m.group(0), m.start())
            value, start = _strip_hospital_reject_chars(value, start)
            name_part = _strip_hospital_suffix(value)
            # A generic reference ("上级医院") names no institution.
            if not name_part or name_part in _HOSPITAL_GENERIC_QUALIFIERS:
                continue
            # A function word means the match swallowed a phrase.
            if any(ch in _HOSPITAL_REJECT_CHARS for ch in name_part):
                continue
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=start,
                    end=start + len(value),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=value,
                )
            )
        return tuple(facts)


class DepartmentDetector(Detector):
    """Detects department names from an explicit dictionary."""

    name = "department"
    fact_type = "DEPARTMENT"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        # Longest-match-first so 神经内科 is not shadowed by a shorter entry.
        for name in sorted(_DEPARTMENTS, key=len, reverse=True):
            start = 0
            while (index := text.find(name, start)) != -1:
                start = index + len(name)
                if not _in_department_context(text, index, start):
                    continue
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=index,
                        end=start,
                        confidence=self.confidence,
                        source=f"dictionary.{self.name}",
                        value=name,
                    )
                )
        return tuple(facts)


def _in_department_context(text: str, start: int, end: int) -> bool:
    """True when a department name refers to this patient's own department."""
    if _DEPARTMENT_BEFORE_RE.search(text[max(0, start - 10) : start]):
        return True
    return bool(_DEPARTMENT_AFTER_RE.match(text[end : end + 3]))


class WardDetector(Detector):
    """Detects ward designations such as 神内二病区 / 三病区."""

    name = "ward"
    fact_type = "WARD"
    confidence = 0.85

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for pattern in (_WARD_NAMED_RE, _WARD_RE):
            for m in pattern.finditer(text):
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


class BedNumberDetector(Detector):
    """Detects bed numbers such as 12床 / A03床."""

    name = "bed_number"
    fact_type = "BED_NUMBER"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for match in _BED_RE.finditer(text):
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=match.group(0),
                )
            )
        for match in _BED_LABEL_RE.finditer(text):
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=match.start("value"),
                    end=match.end("value"),
                    confidence=self.confidence,
                    source=f"regex.{self.name}.label",
                    value=match.group("value"),
                )
            )
        return tuple(facts)
