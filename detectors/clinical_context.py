"""Clinical-context detectors.

Covers the identifiers that appear inside clinical narrative rather than in a
dedicated demographic field:

- ``DOCTOR_NAME`` / ``NURSE_NAME``  — staff names in narrative or signature
- ``RELATIVE_NAME``                 — family members named in the history
- ``SPECIMEN_ID`` / ``ACCESSION_NUMBER`` — lab and imaging accession identifiers
- ``LANDLINE`` / ``POSTAL_CODE``    — contact and geography identifiers
- ``SOCIAL_MEDIA_ID``               — WeChat / QQ handles
- ``RARE_CONTEXT``                  — narrative re-identification signals

Two of these need explicit restraint to stay usable:

``POSTAL_CODE`` is only reported after an explicit label. A bare six-digit
number is ubiquitous in clinical text (doses, counts, reference ranges,
dates without separators), so an unlabelled rule would flood the pipeline
with false positives.

``RARE_CONTEXT`` marks narrative phrases that can single out a patient even
with every direct identifier removed ("本县唯一", "罕见病"). It is not
transformable and exists so policy can require human review.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector
from .surnames import GIVEN_CLASS, SURNAME_CLASS

# -- staff and family names -------------------------------------------------

# Name patterns are anchored on common surnames (see surnames.py). Without the
# anchor the suffix rule "…医生" matches the measure word in "共12名医生", and
# relative rules match ordinary words. The given-name part is non-greedy so a
# trailing verb is not swallowed ("其妻王芳陪同" must not capture "王芳陪").
# The negative lookbehinds stop the suffix rule from matching *inside* a title
# word: "主任医师" contains "任医师" (任 is a surname) and "责任护士" contains
# "任护士". Without them, sanitizing a title form leaves a residual match and
# verification correctly rejects the result.
_DOCTOR_SUFFIX_RE = re.compile(
    rf"(?<!主)(?<!责)(?P<name>{SURNAME_CLASS}{GIVEN_CLASS})(?:医生|医师|大夫)"
)
# "主治医师李某" / "主任医师王某某": title first, name after. The given-name
# part uses the shared name inventory so the match stops before a following
# verb ("责任护士王芳执行医嘱" must not capture 王芳执).
_DOCTOR_TITLE_RE = re.compile(
    r"(?:主任医师|副主任医师|主治医师|住院医师|主管医师|经治医师|接诊医师|手术医师|会诊医师)"
    rf"\s*[:：]?\s*(?P<name>{SURNAME_CLASS}{GIVEN_CLASS})"
)
_NURSE_RE = re.compile(
    rf"(?<!责)(?<!主)(?P<name>{SURNAME_CLASS}{GIVEN_CLASS})护士"
    r"|(?:责任护士|值班护士|接诊护士|主管护师|护士长)\s*[:：]?\s*"
    rf"(?P<title_name>{SURNAME_CLASS}{GIVEN_CLASS})"
)

_RELATIVE_KINDS = (
    "其妻", "其夫", "其子", "其女", "其父", "其母", "其兄", "其弟",
    "父亲", "母亲", "儿子", "女儿", "丈夫", "妻子", "配偶", "家属",
    "哥哥", "姐姐", "弟弟", "妹妹", "祖父", "祖母", "外祖父", "外祖母",
)
_RELATIVE_RE = re.compile(
    r"(?:" + "|".join(_RELATIVE_KINDS) + rf")\s*(?P<name>{SURNAME_CLASS}{GIVEN_CLASS})"
)

# -- accession and specimen identifiers -------------------------------------

_SPECIMEN_RE = re.compile(
    r"(?:标本号|标本编号|样本号|样本编号)\s*[:：]?\s*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9_\-]{2,31})(?![A-Za-z0-9_\-])"
)
_ACCESSION_RE = re.compile(
    r"(?:检查号|影像号|申请号|检查编号|影像编号|报告编号)\s*[:：]?\s*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9_\-]{2,31})(?![A-Za-z0-9_\-])"
)

# -- contact and geography --------------------------------------------------

# Landline: area code starting with 0 (010, 021, 0755, …) plus 7-8 digits.
_LANDLINE_RE = re.compile(r"(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)")

# Postal code: only after an explicit label. A bare 6-digit run is far too
# common in clinical text to be treated as a postal code.
_POSTAL_RE = re.compile(
    r"(?:邮政编码|邮编|postal\s*code)\s*[:：]?\s*(?P<value>\d{6})(?!\d)"
)

_SOCIAL_RE = re.compile(
    r"(?:微信号|微信|QQ号|QQ|企鹅号)\s*[:：]?\s*"
    r"(?P<value>[A-Za-z][A-Za-z0-9_\-]{4,31})(?![A-Za-z0-9_\-])"
)

# -- narrative re-identification signals ------------------------------------

# A rare-disease term is a re-identification signal only when it is predicated
# of this patient. "加强罕见病诊疗管理" and "完善罕见病病例登记" are policy
# language that names no one, so the term needs a case reference to count.
_RARE_CASE_ANCHOR = r"(?:本例|该例|此例|本患者|该患者|此患者|本病例|该病例|患者|患儿|病人)"

_RARE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?P<rare>本(?:县|市|区|地区|省)唯一)"),
    re.compile(r"(?P<rare>全(?:国|省|市|县|区)唯一)"),
    re.compile(
        rf"(?:{_RARE_CASE_ANCHOR}[为系是]?\s*)"
        r"(?P<rare>(?:极|超)?罕见(?:变异(?:型病例)?|病例|疾病|病|综合征))"
    ),
    re.compile(r"(?P<rare>世界首例|国内首例|本院首例|首例报道)"),
    re.compile(r"(?P<rare>(?<!\d)1[0-2]\d\s*岁(?:以上|高龄))"),
)


class DoctorNameDetector(Detector):
    """Detects physician names in suffix ("张医生") or title ("主治医师李某") form."""

    name = "doctor_name"
    fact_type = "DOCTOR_NAME"
    confidence = 0.8

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for m in _DOCTOR_SUFFIX_RE.finditer(text):
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start("name"),
                    end=m.end("name"),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=m.group("name"),
                )
            )
        for m in _DOCTOR_TITLE_RE.finditer(text):
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start("name"),
                    end=m.end("name"),
                    confidence=self.confidence,
                    source=f"regex.{self.name}.title",
                    value=m.group("name"),
                )
            )
        return tuple(facts)


class NurseNameDetector(Detector):
    """Detects nurse names in suffix ("王护士") or title ("责任护士李某") form."""

    name = "nurse_name"
    fact_type = "NURSE_NAME"
    confidence = 0.8

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for m in _NURSE_RE.finditer(text):
            group = "name" if m.group("name") else "title_name"
            facts.append(
                DetectedFact(
                    type=self.fact_type,
                    start=m.start(group),
                    end=m.end(group),
                    confidence=self.confidence,
                    source=f"regex.{self.name}",
                    value=m.group(group),
                )
            )
        return tuple(facts)


class RelativeNameDetector(Detector):
    """Detects family members named relative to the patient ("其妻王某")."""

    name = "relative_name"
    fact_type = "RELATIVE_NAME"
    confidence = 0.75

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
            for m in _RELATIVE_RE.finditer(text)
        )


class SpecimenIdDetector(Detector):
    """Detects specimen identifiers after their label."""

    name = "specimen_id"
    fact_type = "SPECIMEN_ID"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        return tuple(
            DetectedFact(
                type=self.fact_type,
                start=m.start("value"),
                end=m.end("value"),
                confidence=self.confidence,
                source=f"regex.{self.name}",
                value=m.group("value"),
            )
            for m in _SPECIMEN_RE.finditer(text)
        )


class AccessionNumberDetector(Detector):
    """Detects imaging/report accession numbers after their label."""

    name = "accession_number"
    fact_type = "ACCESSION_NUMBER"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        return tuple(
            DetectedFact(
                type=self.fact_type,
                start=m.start("value"),
                end=m.end("value"),
                confidence=self.confidence,
                source=f"regex.{self.name}",
                value=m.group("value"),
            )
            for m in _ACCESSION_RE.finditer(text)
        )


class LandlineDetector(Detector):
    """Detects landline numbers (area code + local number)."""

    name = "landline"
    fact_type = "LANDLINE"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        return tuple(
            DetectedFact(
                type=self.fact_type,
                start=m.start(),
                end=m.end(),
                confidence=self.confidence,
                source=f"regex.{self.name}",
                value=m.group(0),
            )
            for m in _LANDLINE_RE.finditer(text)
        )


class PostalCodeDetector(Detector):
    """Detects postal codes only after an explicit label."""

    name = "postal_code"
    fact_type = "POSTAL_CODE"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        return tuple(
            DetectedFact(
                type=self.fact_type,
                start=m.start("value"),
                end=m.end("value"),
                confidence=self.confidence,
                source=f"regex.{self.name}",
                value=m.group("value"),
            )
            for m in _POSTAL_RE.finditer(text)
        )


class SocialMediaIdDetector(Detector):
    """Detects WeChat / QQ handles after their label."""

    name = "social_media_id"
    fact_type = "SOCIAL_MEDIA_ID"
    confidence = 0.9

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        return tuple(
            DetectedFact(
                type=self.fact_type,
                start=m.start("value"),
                end=m.end("value"),
                confidence=self.confidence,
                source=f"regex.{self.name}",
                value=m.group("value"),
            )
            for m in _SOCIAL_RE.finditer(text)
        )


class RareContextDetector(Detector):
    """Detects narrative phrases that can single out a patient."""

    name = "rare_context"
    fact_type = "RARE_CONTEXT"
    confidence = 0.7

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        seen: set[tuple[int, int]] = set()
        for pattern in _RARE_PATTERNS:
            for m in pattern.finditer(text):
                # Report the rare phrase itself, not the case reference that
                # anchors it, so the span stays on the identifying words.
                start, end = m.start("rare"), m.end("rare")
                key = (start, end)
                if key in seen:
                    continue
                seen.add(key)
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=start,
                        end=end,
                        confidence=self.confidence,
                        source=f"regex.{self.name}",
                        value=m.group("rare"),
                    )
                )
        return tuple(sorted(facts, key=lambda f: (f.start, f.end)))
