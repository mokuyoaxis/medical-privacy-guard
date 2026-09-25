"""Invisible-character normalisation for text entering the guard.

A character the reader cannot see must not change what the guard detects. The
name detectors end a captured value on punctuation, whitespace or a boundary
word, and Unicode's format characters (``Cf``) are none of those. One U+200B
after a name made every name detector miss, while verification -- which re-runs
the same detectors -- reported success, and the payload was released with the
name intact. The same character placed *inside* the name worked just as well.

``strip_invisible`` removes those characters before detection. It runs once, at
the entry to the pipeline, so the string that is detected, transformed, verified
and released is the same string throughout and no span offset has to be
remapped. Removing them is not a loss of content: they are formatting controls
with no rendered glyph, and their only effect here was to hide a value from the
rules meant to find it.

Control characters (C0/C1, DEL) are deliberately *not* handled here. They mark a
payload as unreadable rather than hiding part of one, so
``formats.admission.reject_if_binary`` refuses them instead.
"""

from __future__ import annotations

import re

#: Characters that render as nothing and carry no clinical meaning: format
#: characters, variation selectors and the tag block. Ordinary whitespace is
#: not included -- the detectors already treat it as a boundary, and it is
#: content the reader can see.
INVISIBLE_RANGES: tuple[str, ...] = (
    "\u00ad",  # soft hyphen
    "\u061c",  # Arabic letter mark
    "\u180e",  # Mongolian vowel separator
    "\u200b-\u200f",  # zero-width space/joiners, LRM, RLM
    "\u202a-\u202e",  # bidirectional embedding and override
    "\u2060-\u2064",  # word joiner, invisible operators
    "\u2066-\u206f",  # bidirectional isolates, deprecated format characters
    "\ufe00-\ufe0f",  # variation selectors
    "\ufeff",  # zero-width no-break space (BOM)
    "\ufff9-\ufffb",  # interlinear annotation
    "\U0001d173-\U0001d17a",
    "\U000e0000-\U000e007f",  # tag characters
    "\U000e0100-\U000e01ef",  # variation selectors supplement
)

#: The character class form, shared with the detectors' end conditions so a
#: rule that reads text directly (without passing through the guard entry
#: points) still cannot be blinded by one of these characters.
INVISIBLE_CLASS: str = "".join(INVISIBLE_RANGES)

_INVISIBLE_RE = re.compile(f"[{INVISIBLE_CLASS}]+")


def strip_invisible(text: str) -> str:
    """Return *text* without characters that render as nothing.

    A non-``str`` value is returned unchanged, so a caller holding a decoded
    document can pass every leaf through without a type check of its own.
    """
    if not isinstance(text, str) or not text:
        return text
    return _INVISIBLE_RE.sub("", text)


def has_invisible(text: str) -> bool:
    """True when *text* contains at least one character that renders as nothing."""
    return isinstance(text, str) and _INVISIBLE_RE.search(text) is not None


__all__ = ["INVISIBLE_CLASS", "INVISIBLE_RANGES", "has_invisible", "strip_invisible"]
