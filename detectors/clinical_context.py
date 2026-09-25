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
from core.textnorm import INVISIBLE_CLASS

from .base import Detector
from .field_syntax import FIELD_SEP_REQUIRED, label_with_value
from .surnames import (
    COMPOUND_SURNAME_CLASS,
    GIVEN_NAME_CLASS,
    NAME_FOLLOW_BOUNDARY,
    NAME_MARKS,
    NUMERAL_GIVEN_CLASS,
    SURNAME_CLASS,
)

# -- staff and family names -------------------------------------------------

# Two shapes carry a personal name, and they need different end conditions.
#
# Labelled ("责任护士：郑爽", "家属 郑爽", "主治医师：王建国"): an explicit
# separator bounds the value, so the surname anchors the start and a boundary
# word or punctuation ends it. No character inventory is involved, which is
# what lets a name outside the inventory survive whole. 郑爽, 王鑫 and 李曦 are
# ordinary names; an inventory-bounded capture stopped at 郑 and released "爽"
# as residual PHI while verification still reported success.
#
# Adjacent ("责任护士王芳执行医嘱", "其妻张伟签字"): nothing separates the label
# from the name and nothing follows it but prose, so the given-name part must
# come from the shared inventory. A looser rule here reads prose as people
# ("责任护士每班交接" must not yield 每班交接).
#
# Both shapes stay anchored on a surname. Without that anchor the label alone
# matches prose ("家属表示理解").
_NAME_AFTER_LABEL = (
    r"[（(【\[]?"
    r"(?P<name>"
    r"(?:" + COMPOUND_SURNAME_CLASS + r")[" + NAME_MARKS + r"]{0,2}?"
    r"|" + SURNAME_CLASS + r"[" + NAME_MARKS + r"]{0,2}?"
    r")"
    r"(?=[，,。；;、\s" + INVISIBLE_CLASS + r"\u2e2f）)】\]（(【\[]|$|"
    + NAME_FOLLOW_BOUNDARY + r")"
)

_NAME_ADJACENT = (
    r"(?P<name>"
    r"(?:" + COMPOUND_SURNAME_CLASS + r")" + GIVEN_NAME_CLASS +
    r"|" + SURNAME_CLASS + GIVEN_NAME_CLASS +
    r"|" + SURNAME_CLASS + NUMERAL_GIVEN_CLASS +
    r")"
)

# Titles that introduce a physician's name, longest first: the alternation is
# ordered, so 主任医师 is tried before 医师.
_DOCTOR_TITLES = (
    r"主任医师|副主任医师|主治医师|住院医师|主管医师|经治医师|"
    r"接诊医师|手术医师|会诊医师|主刀医生|管床医生|手术医生|"
    r"接诊医生|经治医生|值班医生|"
    # Signature and assistant lines are standard in surgical and outpatient
    # notes: 医师签名：王强 / 助手：邓超.
    r"医师签名|医生签名|签名|一助|二助|手术助手|助手|"
    r"医生|医师|大夫"
)

# "张医生" / "王大夫": the title follows the name, so a bare surname is a
# complete match and the given name may legitimately be empty. The negative
# lookbehinds stop the rule from matching inside a title word: 主任医师
# contains 任医师 (任 is a surname) and 责任护士 contains 任护士. Without them,
# sanitizing a title form leaves a residual match and verification rejects it.
#
# The given name is a lazy 0-2 characters here rather than the name inventory:
# the title already supplies the end boundary, so the inventory only causes
# misses. 郑沫医生 and 欧阳修远医生 were both undetected because 沫 and 修 are
# outside it, while the same names behind a labelled field were captured.
_DOCTOR_SUFFIX_RE = re.compile(
    rf"(?<!主)(?<!责)(?P<name>"
    rf"(?:{COMPOUND_SURNAME_CLASS})[{NAME_MARKS}]{{0,2}}?"
    rf"|{SURNAME_CLASS}[{NAME_MARKS}]{{0,2}}?"
    r")(?:医生|医师|大夫)"
)
_DOCTOR_TITLE_SEP_RE = re.compile(
    r"(?:" + _DOCTOR_TITLES + r")" + FIELD_SEP_REQUIRED + _NAME_AFTER_LABEL
)
_DOCTOR_TITLE_ADJACENT_RE = re.compile(
    r"(?:" + _DOCTOR_TITLES + r")" + _NAME_ADJACENT
)

_NURSE_TITLES = r"责任护士|值班护士|接诊护士|主管护师|护士长|护士|护师"
_NURSE_SUFFIX_RE = re.compile(
    rf"(?<!责)(?<!主)(?P<name>"
    rf"(?:{COMPOUND_SURNAME_CLASS})[\u3400-\u9fff]{{0,2}}?"
    rf"|{SURNAME_CLASS}[\u3400-\u9fff]{{0,2}}?"
    r")护士"
)
_NURSE_TITLE_SEP_RE = re.compile(
    r"(?:" + _NURSE_TITLES + r")" + FIELD_SEP_REQUIRED + _NAME_AFTER_LABEL
)
_NURSE_TITLE_ADJACENT_RE = re.compile(
    r"(?:" + _NURSE_TITLES + r")" + _NAME_ADJACENT
)

_RELATIVE_KINDS = (
    "其妻", "其夫", "其子", "其女", "其父", "其母", "其兄", "其弟",
    "父亲", "母亲", "儿子", "女儿", "丈夫", "妻子", "配偶", "家属",
    "哥哥", "姐姐", "弟弟", "妹妹", "祖父", "祖母", "外祖父", "外祖母",
)
# Kinship terms are written both adjacent ("其子张伟") and labelled
# ("父亲：张伟"), so the same two shapes apply here.
_RELATIVE_KINDS_RE = r"(?:" + "|".join(_RELATIVE_KINDS) + r")"
# The value may repeat the kinship term after the label — "家属：其妻白洁陪同"
# is a common way to write it, and without the optional prefix the name is
# missed because 其 is not a surname.
_RELATIVE_SEP_RE = re.compile(
    _RELATIVE_KINDS_RE
    + FIELD_SEP_REQUIRED
    + r"(?:" + _RELATIVE_KINDS_RE + r")?"
    + _NAME_AFTER_LABEL
)
_RELATIVE_ADJACENT_RE = re.compile(
    _RELATIVE_KINDS_RE + _NAME_ADJACENT
)

# -- accession and specimen identifiers -------------------------------------

_SPECIMEN_RE = re.compile(
    label_with_value(r"标本号|标本编号|样本号|样本编号", r"[A-Za-z0-9][A-Za-z0-9_\-]{1,31}")
    + r"(?![A-Za-z0-9_\-])"
)
_ACCESSION_RE = re.compile(
    label_with_value(
        r"检查号|影像号|申请号|检查编号|影像编号|报告编号", r"[A-Za-z0-9][A-Za-z0-9_\-]{1,31}"
    )
    + r"(?![A-Za-z0-9_\-])"
)

# -- contact and geography --------------------------------------------------

# Landline: area code starting with 0 (010, 021, 0755, …) plus 7-8 digits.
_LANDLINE_RE = re.compile(r"(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)")

# Postal code: only after an explicit label. A bare 6-digit run is far too
# common in clinical text to be treated as a postal code.
_POSTAL_RE = re.compile(
    label_with_value(r"邮政编码|邮编|postal\s*code", r"\d{6}") + r"(?!\d)"
)

_SOCIAL_RE = re.compile(
    label_with_value(r"微信号|微信|QQ号|QQ|企鹅号", r"[A-Za-z0-9][A-Za-z0-9_\-]{4,31}")
    + r"(?![A-Za-z0-9_\-])"
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
        for pattern, source in (
            (_DOCTOR_SUFFIX_RE, f"regex.{self.name}"),
            (_DOCTOR_TITLE_SEP_RE, f"regex.{self.name}.title"),
            (_DOCTOR_TITLE_ADJACENT_RE, f"regex.{self.name}.title_adjacent"),
        ):
            for m in pattern.finditer(text):
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=m.start("name"),
                        end=m.end("name"),
                        confidence=self.confidence,
                        source=source,
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
        for pattern in (_NURSE_SUFFIX_RE, _NURSE_TITLE_SEP_RE, _NURSE_TITLE_ADJACENT_RE):
            for m in pattern.finditer(text):
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
            for pattern in (_RELATIVE_SEP_RE, _RELATIVE_ADJACENT_RE)
            for m in pattern.finditer(text)
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
