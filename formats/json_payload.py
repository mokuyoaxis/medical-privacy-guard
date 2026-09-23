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
from typing import Any, Mapping

from core.errors import ParserError

from .leaf import LABEL_KEYS, Leaf, StructuredPayload, label_for


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
