"""Payload admission: what a piece of content is, before it is scanned.

Both ways into the guard have to answer the same question first. The CLI reads a
file; an adapter receives an external call. Either may be holding plain text, a
structured document, or something the guard must refuse, and the answer has to
be identical in both places.

It matters because a structured payload treated as prose loses its field labels,
and the detectors are label-driven. ``{"name": "张三"}`` scanned as text yields
nothing at all: the key is not a Chinese label, and a bare name is deliberately
not detected. The same document handed over as a JSON payload is sanitized. A
caller that guesses wrong is not merely less accurate; it releases.

The rules live here so the two entry points cannot drift apart.
``tools/audit_contracts.py`` checks that the classification has exactly one
implementation and that both entry points use it.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.errors import ParserError
from core.model import Payload

__all__ = [
    "UNSUPPORTED_SUFFIXES",
    "UnsupportedInput",
    "classify_text",
    "payload_for_text",
    "read_text_file",
    "reject_if_binary",
]

#: Extensions whose content is never plain clinical text. The list names formats
#: the guard cannot inspect; it does not attempt to identify a disguised one.
UNSUPPORTED_SUFFIXES = frozenset(
    {
        ".jsonl", ".ndjson", ".tsv", ".xls", ".xlsx", ".xlsm",
        ".ods", ".pdf", ".doc", ".docx", ".odt", ".rtf", ".fhir", ".xml",
        ".hl7", ".dcm", ".dicom", ".bin", ".zip", ".gz", ".png", ".jpg",
        ".jpeg", ".gif", ".tif", ".tiff", ".wav", ".mp3", ".mp4",
    }
)

#: Byte prefixes of containers the guard cannot inspect.
_BINARY_MAGIC = (b"PK\x03\x04", b"GIF87a", b"GIF89a")

#: Text prefixes of document formats that are not clinical prose.
_DOCUMENT_MAGIC = ("%PDF-", "{\\rtf", "<?xml", "<fhir:")


class UnsupportedInput(ParserError):
    """Raised when content is recognisably not plain text.

    A ``ParserError`` so callers that already handle parse failures keep working,
    and a distinct type so an entry point can report a refused format rather
    than a read error.
    """


def reject_if_binary(text: str) -> None:
    """Raise :class:`UnsupportedInput` when *text* carries binary markers.

    Control characters other than tab, CR and LF do not occur in clinical prose
    and do occur in a mis-decoded or disguised container. The structured
    pipeline also joins its leaves with NUL, so a NUL arriving on the text path
    is a value the caller did not intend to send.
    """
    if any(
        (ord(char) < 32 and char not in "\t\r\n") or 127 <= ord(char) <= 159
        for char in text
    ):
        raise UnsupportedInput("unsupported binary or document format")
    if text.lstrip().startswith(_DOCUMENT_MAGIC):
        raise UnsupportedInput("unsupported binary or document format")


def classify_text(text: str) -> str:
    """Return ``"json"``, ``"text"`` or ``"unsupported"`` for *text*.

    Something that looks like a container but does not parse as one is not
    quietly demoted to prose: a truncated or double-wrapped JSON file is a
    format problem, and treating it as clinical text would release its contents
    as if they had been inspected properly.
    """
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return "text"
    try:
        container = json.loads(stripped)
    except (json.JSONDecodeError, RecursionError, ValueError):
        # Not a complete document. It is only a broken payload if a valid JSON
        # value parses and leaves content behind (a truncated or double-wrapped
        # file); otherwise the braces are ordinary text, and "[随访] 记录" must
        # not be blocked merely for starting with a bracket.
        try:
            value, end = json.JSONDecoder().raw_decode(stripped)
        except (json.JSONDecodeError, RecursionError, ValueError):
            return "text"
        if isinstance(value, (dict, list)) and stripped[end:].strip():
            return "unsupported"
        return "text"
    return "json" if isinstance(container, (dict, list)) else "unsupported"


def payload_for_text(text: str, *, is_csv: bool = False) -> Payload:
    """Build the payload a classified input should take through the guard.

    CSV is named by the caller rather than detected: no byte pattern marks a CSV
    file, and any text can be read as one.
    """
    if is_csv:
        return Payload(kind="csv", content=text)
    kind = classify_text(text)
    if kind == "json":
        return Payload(kind="json", content=text)
    if kind == "unsupported":
        return Payload(kind="unsupported", content="")
    return Payload(kind="text", content=text)


def read_text_file(path: str, encoding: str = "utf-8-sig") -> str:
    """Read *path* as text, refusing known formats and binary content.

    The encoding is stated by the caller and never guessed. A wrong codec is
    reported rather than silently retried with another one: mojibake that reaches
    a model is worse than an error that reaches the operator.
    """
    source = Path(path)
    try:
        suffixes = source.suffixes + source.resolve().suffixes
        if any(suffix.lower() in UNSUPPORTED_SUFFIXES for suffix in suffixes):
            raise UnsupportedInput("unsupported input format; UTF-8 plain text required")
        data = source.read_bytes()
    except (OSError, RuntimeError) as exc:
        raise ParserError("cannot read input file") from exc
    try:
        text = data.decode(encoding)
    except LookupError as exc:
        raise ParserError(f"unknown encoding {encoding!r}") from exc
    except UnicodeDecodeError as exc:
        raise UnsupportedInput(
            f"cannot decode input as {encoding}; state the correct --encoding"
        ) from exc
    if data.startswith(_BINARY_MAGIC) or data[128:132] == b"DICM":
        raise UnsupportedInput("unsupported binary or document format")
    reject_if_binary(text)
    return text
