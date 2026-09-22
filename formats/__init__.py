"""Structured-payload parsers.

Each parser flattens a document into addressable string leaves, so the text
pipeline can run unchanged and the result can be written back into a copy of
the original structure.
"""

from .json_payload import (
    Leaf,
    StructuredPayload,
    dumps,
    from_document,
    parse_json_payload,
    rebuild,
)

__all__ = [
    "Leaf",
    "StructuredPayload",
    "dumps",
    "from_document",
    "parse_json_payload",
    "rebuild",
]
