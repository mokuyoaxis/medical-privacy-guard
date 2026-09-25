"""JSON payload traversal.

A JSON document is flattened into its string leaves so the existing text
pipeline can run over them, then rebuilt from a copy of the original structure.
Nothing here decides anything: parsing produces leaves, rebuilding writes
replacement values back.

Scope note: string leaves can be rewritten; numeric leaves are collected as
*read-only*. A number can be an identifier (``{"phone": 13800000000}``), but
writing a string back over it would change the document's JSON type, so the
transformation layer must leave it alone. It is still detected, and a payload
carrying one can never be released as SANITIZE — the policy sends it to human
review instead of reporting a sanitization that quietly left the number in
place. That boundary is recorded in ``docs/scope.md`` rather than left
implicit.

Paths are JSON Pointers (RFC 6901), so ``~0`` and ``~1`` escaping is handled and
a key containing ``/`` still addresses the right leaf.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping

from core.errors import ParserError
from core.textnorm import strip_invisible

from .admission import reject_if_binary
from .leaf import LABEL_KEYS, Leaf, StructuredPayload, label_for, probe_labels_for


def escape_token(token: str) -> str:
    """RFC 6901 escaping: ``~`` becomes ``~0`` and ``/`` becomes ``~1``."""
    return token.replace("~", "~0").replace("/", "~1")


def _collect_leaves(document: Any) -> list[Leaf]:
    """Collect string leaves with an explicit stack.

    Deliberately not recursive: nesting depth is attacker-controlled, and a
    payload of a few thousand brackets overflows Python's recursion limit
    before any size limit applies. The stack preserves document order.

    Each string leaf is normalised and admitted before it becomes a leaf:

    - Characters that render as nothing are removed. ``"\u0000"`` and
      ``"\u200b"`` are both legal JSON escapes, so a file whose bytes contain
      no control character at all can still hide a name from a label-anchored
      detector -- the value is bounded by punctuation, whitespace or a boundary
      word, and neither character is any of those.
    - Control characters are refused. A NUL arriving inside a leaf is a value
      the caller did not intend to send, exactly as it is on the text path;
      there it is refused by ``reject_if_binary``, and a structured payload
      must not be the way around that check.
    - Object keys must be strings, and every value must be something JSON can
      represent. A key of another type is not addressable by a JSON Pointer
      (the pointer is built from ``str(key)``), so writing a replacement back
      would add a key instead of replacing the value and release the original
      untouched.
    """
    leaves: list[Leaf] = []
    stack: list[tuple[Any, str, tuple[str, ...]]] = [(document, "", ())]
    while stack:
        node, path, inherited = stack.pop()
        if isinstance(node, str):
            text = strip_invisible(node)
            reject_if_binary(text)
            leaves.append(
                Leaf(
                    path=path,
                    text=text,
                    label=inherited[0] if inherited else None,
                    probes=inherited,
                )
            )
        elif isinstance(node, dict):
            # Every child goes on the stack, strings included: appending a
            # string leaf here would place it before the descendants of an
            # earlier key and break document order.
            for key, value in reversed(list(node.items())):
                if not isinstance(key, str):
                    raise ParserError(
                        "JSON object keys must be strings; a key of another type "
                        "cannot be addressed for replacement"
                    )
                stack.append(
                    (value, f"{path}/{escape_token(key)}", probe_labels_for(key))
                )
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((node[index], f"{path}/{index}", inherited))
        elif isinstance(node, bool):
            # A boolean is never an identifier, and ``bool`` is an ``int``
            # subclass, so it has to be excluded before the numeric branch.
            continue
        elif isinstance(node, (int, float)):
            # ``str`` is exact for the integers a JSON document actually
            # carries: Python ints are arbitrary precision, so an 18-digit ID
            # survives the round trip unmangled. The probes come from the key
            # exactly as they do for a string leaf: a number under ``mrn`` is
            # still an MRN, and that is what sends it to human review instead of
            # releasing it.
            leaves.append(
                Leaf(
                    path=path,
                    text=str(node),
                    label=inherited[0] if inherited else None,
                    probes=inherited,
                    read_only=True,
                )
            )
        elif node is None:
            # Null has no text to inspect.
            continue
        else:
            # A value the guard can neither inspect nor serialise. Detecting
            # nothing in it and rebuilding the document anyway would report a
            # sanitization that never looked at that value.
            raise ParserError(
                f"JSON payload contains a value the guard cannot inspect "
                f"({type(node).__name__})"
            )
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
    to hand it back to the guard. The document is inspected here rather than at
    rebuild time, so a value the guard cannot read is reported as an admission
    failure (a BLOCK) instead of surfacing later as a serialisation error from
    inside the transformation.
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


__all__ = [
    "LABEL_KEYS",
    "Leaf",
    "StructuredPayload",
    "dumps",
    "from_document",
    "label_for",
    "parse_json_payload",
    "rebuild",
]
