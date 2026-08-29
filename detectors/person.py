"""Person-name detector based on explicit field markers.

This is a Layer 2 dictionary/rule detector (plan.md §9.2): a name is only
reported when it appears in a labelled field such as "患者：" / "姓名：" /
"Patient:" / "Name:". Bare name tokens are deliberately not detected — the
false-positive rate on free text would be unacceptable, and policy will only
see facts with meaningful confidence.
"""

from __future__ import annotations

import re

from core.model import DetectedFact

from .base import Detector

# Chinese: a field label must be followed by a real delimiter.  Requiring a
# colon or whitespace avoids treating words such as ``患者住址`` as a name.
# Capture the whole field value up to punctuation/newline instead of silently
# truncating uncommon/compound or synthetic names at four characters.
_CN_FIELD_RE = re.compile(
    r"(?:患者姓名|病人姓名|患者名字|患者|病人|姓名|名字)"
    r"(?:\s*[:：]\s*|\s+)"
    r"(?P<name>[\u3400-\u9fff·]{2,20}?)"
    r"(?=(?:电话|手机|邮箱|身份证号?|证件号?|病历号|住院号|就诊号|"
    r"地址|住址|诊断|症状|用药|治疗)\s*[:：]?|[,，。；;\s]|$)"
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
        for pattern in (_CN_FIELD_RE, _EN_FIELD_RE):
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
