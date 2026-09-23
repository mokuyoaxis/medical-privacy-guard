"""Audit the project's shared contracts for "declared but not wired".

This project has repeatedly hit the same failure shape: a shared module defines
a capability, and one consumer keeps its own hand-rolled version, so behaviour
diverges silently. Three instances so far:

- v0.2.1: ``person.py`` was fixed for name spans, ``clinical_context.py`` was not;
- v0.2.4: Chinese numeral ages were detected but the transformer could not
  execute them, turning a silent release into a raised error;
- v0.2.6+: ``person.py`` never adopted ``field_syntax``, so ``姓名=张伟`` was
  missed while every other field accepted the equals sign.

Run this after touching detectors, transformers or policy: it is cheap and it
catches the class of defect that unit tests miss, because each consumer is
tested against its own convention.

    python tools/audit_contracts.py
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.errors import GuardError  # noqa: E402
from core.model import Purpose, Recipient, TrustLevel  # noqa: E402
from detectors import detect_all  # noqa: E402
from medical_privacy_guard import Guard  # noqa: E402

#: (label, value, expected fact type) — one field per detector family.
FIELDS = (
    ("姓名", "张伟", "PERSON_NAME"),
    ("电话", "13800000000", "PHONE"),
    ("地址", "北京市朝阳区建国路1号", "PRECISE_LOCATION"),
    ("病历号", "ZY2026001", "MEDICAL_RECORD_NUMBER"),
    ("科室", "神经内科", "DEPARTMENT"),
    ("年龄", "67岁", "AGE"),
    ("标本号", "SP123456", "SPECIMEN_ID"),
    ("邮编", "100020", "POSTAL_CODE"),
)

#: Separator spellings field_syntax claims to unify.
SEPARATORS = (
    ("full-width colon", "{}：{}"),
    ("ascii colon", "{}:{}"),
    ("equals", "{}={}"),
    ("space", "{} {}"),
    ("ideographic space", "{}\u3000{}"),
    ("none", "{}{}"),
    ("brackets", "{}（{}）"),
)

SAMPLES = {
    "PHONE": "电话 13800000000",
    "LANDLINE": "电话 010-66668888",
    "EMAIL": "邮箱 a@example.com",
    "URL": "网址 https://example.com/x",
    "IP_ADDRESS": "IP 10.0.0.1",
    "PERSON_NAME": "患者姓名：张伟",
    "MEDICAL_RECORD_NUMBER": "病历号 ZY2026001",
    "SPECIMEN_ID": "标本号 SP123456",
    "ACCESSION_NUMBER": "检查号 IM2026001",
    "POSTAL_CODE": "邮编 100020",
    "SOCIAL_MEDIA_ID": "微信 zhangsan2026",
    "PRECISE_LOCATION": "住址：北京市朝阳区建国路1号",
    "HOSPITAL_NAME": "患者在协和医院住院",
    "WARD": "患者神内二病区住院",
    "BED_NUMBER": "床号 12",
    "DOCTOR_NAME": "主治医师：张伟",
    "NURSE_NAME": "责任护士：李娜",
    "RELATIVE_NAME": "家属：王强陪同",
    "AGE": "患者 67岁",
    "EXACT_DATE": "就诊日期 2026年3月12日",
    "GOVERNMENT_ID": "身份证号 110101199003078888",
}


def separator_matrix() -> list[str]:
    """Fields whose detection depends on how the separator is spelled."""
    problems = []
    for label, value, expected in FIELDS:
        marks = []
        for name, template in SEPARATORS:
            types = {f.type for f in detect_all(template.format(label, value))}
            marks.append((name, expected in types))
        failed = [name for name, ok in marks if not ok]
        if failed:
            problems.append(f"  {label} ({expected}): not detected with {', '.join(failed)}")
    return problems


def fact_type_coverage() -> list[str]:
    """Fact types emitted by detectors but absent from the policy tables."""
    policy = (ROOT / "core/policy.py").read_text(encoding="utf-8")
    reason_block = policy.split("_FACT_REASON_CODES")[1].split("}")[0]
    known = set(re.findall(r'"([A-Z_0-9]+)"\s*:', reason_block))

    produced: set[str] = set()
    for path in sorted((ROOT / "detectors").glob("*.py")):
        produced |= set(re.findall(r'fact_type\s*[:=]\s*"([A-Z_0-9]+)"', path.read_text(encoding="utf-8")))
    # The dictionary detector derives its types from the category table.
    produced |= set(re.findall(r'"([A-Z_0-9]{3,})"', (ROOT / "core/dictionary.py").read_text(encoding="utf-8")))
    produced.discard("CATEGORY_FACT_TYPES")

    missing = sorted(t for t in produced if t not in known)
    return [f"  {t}: emitted by a detector, absent from _FACT_REASON_CODES (fails closed to BLOCK)" for t in missing]


def transformation_coverage() -> list[str]:
    """Fact types that policy plans to transform but no transformer can execute."""
    guard = Guard(profile="external-ai-strict")
    recipient = Recipient(kind="audit", trust_level=TrustLevel("EXTERNAL_APPROVED"))
    problems = []
    for fact_type, text in sorted(SAMPLES.items()):
        try:
            result = guard.sanitize(text, recipient, Purpose.EXTERNAL_AI_ASSISTANCE)
        except GuardError as exc:
            problems.append(f"  {fact_type}: raised {type(exc).__name__}: {exc}")
            continue
        if result.decision_before.verdict.value == "SANITIZE" and (
            result.verification is None or not result.verification.passed
        ):
            detail = result.verification.details if result.verification else "no verification"
            problems.append(f"  {fact_type}: planned a transformation but verification failed ({detail})")
    return problems


def main() -> int:
    sections = collections.OrderedDict(
        (
            ("Separator spelling (field_syntax)", separator_matrix()),
            ("Fact types vs policy tables", fact_type_coverage()),
            ("Detection vs transformation", transformation_coverage()),
        )
    )
    failed = False
    for title, problems in sections.items():
        print(f"== {title} ==")
        if problems:
            failed = True
            print("\n".join(problems))
        else:
            print("  consistent")
        print()
    print("FAIL" if failed else "OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
