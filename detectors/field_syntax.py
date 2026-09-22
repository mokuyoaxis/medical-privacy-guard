"""Shared field-label syntax for label-anchored detectors.

Chinese clinical notes write a labelled field in several equally common ways:

    住院号：1234567      full-width colon
    住院号:1234567       ASCII colon
    住院号=1234567       equals sign
    住院号 （1234567）   value wrapped in brackets
    住院号 1234567       whitespace only
    住院号1234567        no separator at all

Each detector used to spell out its own ``\\s*[:：]?\\s*``, so the same field
was detected with a colon and missed with an equals sign, and a bracketed
value was missed entirely. Centralising the separator keeps the whole family
consistent: fixing it here fixes every label-anchored detector at once.

``FIELD_SEP`` is the separator between a label and its value. It never
consumes a newline, so a label on one line cannot capture a value on the next.
``VALUE_OPEN`` / ``VALUE_CLOSE`` let a value be optionally bracketed; the
bracket is part of the match but never part of the reported value span.
"""

from __future__ import annotations

#: Label/value separator: whitespace, an optional colon/equals, more
#: whitespace. Bracket-openers are deliberately excluded so ``[`` can start a
#: transformer marker without being read as a separator.
FIELD_SEP = r"[ \t\u3000]*[:：=]?[ \t\u3000]*"

#: A mandatory label/value separator: an explicit colon/equals, or at least one
#: space. ``FIELD_SEP`` also matches the empty string, which is what makes the
#: adjacent forms ("住院号123") work; a value that needs a real end boundary
#: uses this one, so the two shapes can be handled by different rules instead
#: of one permissive rule that has to guess.
FIELD_SEP_REQUIRED = r"(?:[ \t\u3000]*[:：=][ \t\u3000]*|[ \t\u3000]+)"

#: An optional opening bracket before the value itself.
VALUE_OPEN = r"[（(]?"

#: The matching optional closing bracket.
VALUE_CLOSE = r"[）)]?"

#: Full optional wrapper around a value: ``(value)`` or ``（value）``.
WRAP_OPEN = VALUE_OPEN
WRAP_CLOSE = VALUE_CLOSE


def label_with_value(label: str, value: str) -> str:
    """Compose ``label + separator + optional bracket + value + optional bracket``.

    The value regex must contain no bracket characters of its own.
    """
    return rf"(?:{label}){FIELD_SEP}{VALUE_OPEN}(?P<value>{value}){VALUE_CLOSE}"
