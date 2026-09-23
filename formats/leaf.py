"""Shared vocabulary for structured payloads.

JSON and CSV both flatten to addressable string leaves, and both rely on the
same idea: a key or column name says what its value is, so the label-driven
detectors can apply. That vocabulary lives here rather than in either parser.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

#: Key or column names that label their own value. In ``{"name": "张三"}`` or a
#: ``姓名`` column the key says what the value is, so the value needs no label
#: inside the text — but the detectors are label-driven, so without this the
#: name would be treated as bare prose and deliberately not detected.
#:
#: Lookup is case-insensitive and ignores separators, so ``patient_name``,
#: ``patientName`` and ``Patient Name`` all resolve.
LABEL_KEYS: Mapping[str, str] = {
    "name": "姓名",
    "patientname": "患者姓名",
    "patient": "患者",
    "phone": "电话",
    "tel": "电话",
    "telephone": "电话",
    "mobile": "手机",
    "phonenumber": "电话",
    "email": "邮箱",
    "idcard": "身份证号",
    "idnumber": "身份证号",
    "nationalid": "身份证号",
    "governmentid": "身份证号",
    "mrn": "病历号",
    "medicalrecordnumber": "病历号",
    "recordnumber": "病历号",
    "address": "住址",
    "homeaddress": "住址",
    "postalcode": "邮编",
    "zipcode": "邮编",
    "wechat": "微信",
    "qq": "QQ号",
    "birthdate": "出生日期",
    "dateofbirth": "出生日期",
    "dob": "出生日期",
    "date": "日期",
    "age": "年龄",
    "sex": "性别",
    "gender": "性别",
    "department": "科室",
    "ward": "病区",
    "bed": "床号",
    "bednumber": "床号",
    "institution": "机构",
    "hospital": "医院",
    "doctor": "医生",
    "physician": "医师",
    "nurse": "护士",
    # Chinese headers, matched literally.
    "姓名": "姓名",
    "患者姓名": "患者姓名",
    "患者": "患者",
    "电话": "电话",
    "手机": "手机",
    "邮箱": "邮箱",
    "身份证号": "身份证号",
    "身份证": "身份证号",
    "病历号": "病历号",
    "住院号": "住院号",
    "住址": "住址",
    "地址": "住址",
    "邮编": "邮编",
    "微信": "微信",
    "出生日期": "出生日期",
    "年龄": "年龄",
    "性别": "性别",
    "科室": "科室",
    "病区": "病区",
    "床号": "床号",
    "医院": "医院",
    "医生": "医生",
    "医师": "医师",
    "护士": "护士",
}


def label_for(key: str) -> str | None:
    """Return the field label a key or column name implies, or None."""
    normalized = key.strip().lower()
    for separator in ("_", "-", " "):
        normalized = normalized.replace(separator, "")
    if normalized in LABEL_KEYS:
        return LABEL_KEYS[normalized]
    # Chinese headers carry no separators and are matched as written.
    return LABEL_KEYS.get(key.strip())


@dataclass(frozen=True)
class Leaf:
    """One string value inside a structured payload."""

    path: str
    text: str
    #: Field label implied by the key or column holding this value, if any.
    label: str | None = None


@dataclass(frozen=True)
class StructuredPayload:
    """A parsed document plus the leaves the pipeline will run over."""

    kind: str
    document: object
    leaves: tuple[Leaf, ...]
