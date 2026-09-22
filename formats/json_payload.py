"""JSON payload traversal.

A JSON document is flattened into its string leaves so the existing text
pipeline can run over them, then rebuilt from a copy of the original structure.
Nothing here decides anything: parsing produces leaves, rebuilding writes
replacement values back.

Scope note: only *string* leaves are extracted. A numeric value that happens to
be an identifier (``{"phone": 13800000000}``) is left alone, because rewriting it
would change its JSON type and silently break the consumer. That boundary is
recorded in ``docs/scope.md`` rather than left implicit.

Paths are JSON Pointers (RFC 6901), so ``~0`` and ``~1`` escaping is handled and
a key containing ``/`` still addresses the right leaf.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Mapping

from core.errors import ParserError

#: Key names that label their own value. In ``{"name": "张三"}`` the key says
#: what the value is, so the value needs no label inside the text — but the
#: detectors are label-driven, so without this the name would be treated as bare
#: prose and deliberately not detected. Keys are matched case-insensitively with
#: separators removed, so ``patient_name``, ``patientName`` and ``PatientName``
#: all resolve.
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
}


def label_for(key: str) -> str | None:
    """Return the field label a JSON key implies, or None.

    The lookup is case-insensitive and ignores underscores, hyphens and spaces,
    because the same field is written ``patient_name``, ``patientName`` and
    ``Patient Name`` across systems.
    """
    normalized = key.strip().lower()
    for separator in ("_", "-", " "):
        normalized = normalized.replace(separator, "")
    return LABEL_KEYS.get(normalized)


@dataclass(frozen=True)
class Leaf:
    """One string value inside a structured payload."""

    path: str
    text: str
    #: Field label implied by the key that holds this value, if any. Detection
    #: runs over "label：value" so the label-driven detectors apply.
    label: str | None = None


@dataclass(frozen=True)
class StructuredPayload:
    """A parsed document plus the leaves the pipeline will run over."""

    kind: str
    document: Any
    leaves: tuple[Leaf, ...]


def escape_token(token: str) -> str:
    """RFC 6901 escaping: ``~`` becomes ``~0`` and ``/`` becomes ``~1``."""
    return token.replace("~", "~0").replace("/", "~1")


def _collect_leaves(document: Any) -> list[Leaf]:
    """Collect string leaves with an explicit stack.

    Deliberately not recursive: nesting depth is attacker-controlled, and a
    payload of a few thousand brackets overflows Python's recursion limit
    before any size limit applies. The stack preserves document order.
    """
    leaves: list[Leaf] = []
    stack: list[tuple[Any, str, str | None]] = [(document, "", None)]
    while stack:
        node, path, inherited = stack.pop()
        if isinstance(node, str):
            leaves.append(Leaf(path=path, text=node, label=inherited))
        elif isinstance(node, dict):
            # Every child goes on the stack, strings included: appending a
            # string leaf here would place it before the descendants of an
            # earlier key and break document order.
            for key, value in reversed(list(node.items())):
                stack.append(
                    (value, f"{path}/{escape_token(str(key))}", label_for(str(key)))
                )
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((node[index], f"{path}/{index}", inherited))
        # Numbers, booleans and null are not text: see the module docstring.
    return leaves


def parse_json_payload(text: str) -> StructuredPayload:
    """Parse *text* as a JSON object or array and collect its string leaves.

    Raises ``ParserError`` when the text is not a JSON container. Scalars are
    rejected: a bare string or number is not a structured payload, and treating
    one as such would let a caller bypass the plain-text path.
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ParserError(f"cannot parse JSON payload: {exc}") from exc
    return from_document(document)


def from_document(document: Any) -> StructuredPayload:
    """Build a structured payload from an already-parsed object or array.

    Callers that hold a decoded document should not have to serialise it just
    to hand it back to the guard.
    """
    if not isinstance(document, (dict, list)):
        raise ParserError("JSON payload must be an object or an array")
    return StructuredPayload(
        kind="json", document=document, leaves=tuple(_collect_leaves(document))
    )


def rebuild(document: Any, replacements: Mapping[str, str]) -> Any:
    """Return a deep copy of *document* with each path's string replaced.

    Keys, array lengths, ordering and every non-string value are preserved: the
    transformation may only touch the values it was planned for.
    """
    try:
        clone = copy.deepcopy(document)
    except RecursionError as exc:
        raise ParserError("JSON payload nests too deeply to rebuild") from exc
    for path, value in replacements.items():
        _assign(clone, path, value)
    return clone


def _assign(document: Any, path: str, value: str) -> None:
    tokens = _parse_pointer(path)
    if not tokens:
        raise ParserError("cannot replace the document root")
    node = document
    for token in tokens[:-1]:
        node = node[int(token)] if isinstance(node, list) else node[token]
    last = tokens[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


def _parse_pointer(path: str) -> list[str]:
    if not path:
        return []
    if not path.startswith("/"):
        raise ParserError(f"invalid JSON Pointer {path!r}")
    return [token.replace("~1", "/").replace("~0", "~") for token in path[1:].split("/")]


def dumps(document: Any) -> str:
    """Serialise a rebuilt document with its structure intact."""
    return json.dumps(document, ensure_ascii=False, indent=2)
