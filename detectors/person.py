"""Person-name detector based on explicit field markers.

This is a Layer 2 dictionary/rule detector: a name is only
reported when it appears in a labelled field such as "患者：" / "姓名：" /
"Patient:" / "Name:". Bare name tokens are deliberately not detected — the
false-positive rate on free text would be unacceptable, and policy will only
see facts with meaningful confidence.

Two field shapes are supported:

- separated: ``患者：张三`` / ``姓名 张三`` — an explicit delimiter bounds the
  value, so uncommon/compound/synthetic names are captured whole.
- adjacent:  ``患者张三`` — common in real notes. This form requires the name
  to start with a known surname, otherwise "患者住院号" would be read as a
  person called 住院号. It is additionally capped at four characters and must
  not contain institution words, so clinical phrases like "于协和医院住院"
  are not absorbed into the name.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector
from .surnames import (
    COMPOUND_SURNAME_CLASS,
    GIVEN_NAME_CLASS,
    NUMERAL_GIVEN_CLASS,
    SURNAME_CLASS,
)

# Chinese: a field label followed by either an explicit delimiter or a known
# surname. Capture the whole field value up to punctuation/newline instead of
# silently truncating uncommon/compound or synthetic names at four characters.
_CN_SEPARATED_RE = re.compile(
    r"(?:患者姓名|病人姓名|患者名字|患者|病人|姓名|名字)"
    r"(?:\s*[:：]\s*|\s+)"
    r"(?P<name>[\u3400-\u9fff·]{2,20}?)"
    r"(?=(?:电话|手机|邮箱|身份证号?|证件号?|病历号|住院号|就诊号|"
    r"地址|住址|诊断|症状|用药|治疗)\s*[:：]?|[,，。；;\s]|$)"
)

# Adjacent form: a field label directly followed by a known surname and no
# delimiter (e.g. "患者张三"). Without a delimiter nothing bounds the capture,
# so this form must stay tight: the name is capped at four characters (compound
# surname + two-character given name) and institution words are excluded, which
# otherwise swallows clinical phrases such as "于协和医院住院".
_CN_ADJACENT_RE = re.compile(
    r"(?:患者姓名|病人姓名|患者名字|患者|病人|姓名|名字)"
    r"(?P<name>"
    r"(?:" + COMPOUND_SURNAME_CLASS + r")" + GIVEN_NAME_CLASS +
    r"|" + SURNAME_CLASS + GIVEN_NAME_CLASS +
    r"|" + SURNAME_CLASS + NUMERAL_GIVEN_CLASS +
    r")"
    r"(?=[,，。；;、\s]|$|"
    r"(?:入院|出院|就诊|住院|治疗|复查|随访|主诉|既往|收入|转入|转科|查房|病情|"
    r"因|于|诉|在|自|伴|拟|"
    r"电话|手机|邮箱|身份证号?|证件号?|病历号|住院号|就诊号|地址|住址|诊断|症状|用药))"
)

# English: support multi-part and hyphenated names, but stop at field
# punctuation/newline so a suffix can never survive sanitization unnoticed.
_EN_FIELD_RE = re.compile(
    r"\b(?:patient|patient's name|name)\b(?:\s*:\s*|\s+)"
    r"(?P<name>[A-Za-z][A-Za-z'\-]*(?:\s+[A-Za-z][A-Za-z'\-]*){0,5})"
    r"(?=[,;\n\r]|$)",
    re.IGNORECASE,
)


class PersonNameDetector(Detector):
    """Detects names that appear after an explicit person-field marker.

    Only the name span itself is reported (labels like "患者：" stay in the
    text), so transformers replace exactly the identifying token.
    """

    name = "person_field"
    fact_type = "PERSON_NAME"
    confidence = 0.95

    def detect(self, text: str) -> tuple[DetectedFact, ...]:
        facts: list[DetectedFact] = []
        for pattern in (_CN_SEPARATED_RE, _CN_ADJACENT_RE, _EN_FIELD_RE):
            for m in pattern.finditer(text):
                name = m.group("name")
                start = m.end() - len(name)
                facts.append(
                    DetectedFact(
                        type=self.fact_type,
                        start=start,
                        end=m.end(),
                        confidence=self.confidence,
                        source=f"regex.{self.name}",
                        value=name,
                    )
                )
        return tuple(facts)
