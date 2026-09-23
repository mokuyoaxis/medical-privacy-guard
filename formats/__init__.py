"""Structured-payload parsers.

Each parser flattens a document into addressable string leaves, so the text
pipeline can run unchanged and the result can be written back into a copy of
the original structure.
"""

from .csv_payload import CsvTable, parse_csv_payload
from .csv_payload import dumps as dumps_csv
from .csv_payload import rebuild as rebuild_csv
from .json_payload import dumps, from_document, parse_json_payload, rebuild
from .leaf import LABEL_KEYS, Leaf, StructuredPayload, label_for

__all__ = [
    "LABEL_KEYS",
    "CsvTable",
    "Leaf",
    "StructuredPayload",
    "dumps",
    "dumps_csv",
    "from_document",
    "label_for",
    "parse_csv_payload",
    "parse_json_payload",
    "rebuild",
    "rebuild_csv",
]
