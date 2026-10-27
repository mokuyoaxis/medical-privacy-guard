"""Local institution vocabulary.

A deployment-supplied list of institutions, departments, wards and staff names.
It does two jobs:

- **detection**: a term in the dictionary is a fact even when no built-in rule
  matches its shape — that is the point of loading one;
- **verification**: a term that survives into the released text is a residual
  the rule-based re-scan cannot see, because the rule never knew the word. This
  is the only genuinely independent verification signal in the project: it comes
  from the deployment's own records rather than from the detector regexes, so it
  can answer "we do not recognise this word" instead of merely agreeing with the
  rules that produced it.

The vocabulary is a sensitive asset — it names real institutions and real
staff. Nothing here writes an entry to an audit record, a log line or an error
message; callers report counts only.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .errors import DictionaryError

#: Accepted category names, in the order the loaders normalise them.
CATEGORIES: tuple[str, ...] = ("institution", "department", "ward", "staff")

#: Category → the fact type a matching term is reported as. These are the same
#: types the rule-based detectors emit, so policy needs no new rules.
CATEGORY_FACT_TYPES: Mapping[str, str] = {
    "institution": "HOSPITAL_NAME",
    "department": "DEPARTMENT",
    "ward": "WARD",
    "staff": "DOCTOR_NAME",
}

#: Category → dataclass field name. "staff" is both singular and plural, so a
#: naive f"{category}s" would look for a field that does not exist.
_FIELD_FOR_CATEGORY: Mapping[str, str] = {
    "institution": "institutions",
    "department": "departments",
    "ward": "wards",
    "staff": "staff",
}

_CSV_HEADER = ("category", "name")


@dataclass(frozen=True)
class InstitutionDictionary:
    """An immutable local vocabulary. Contains raw institution data."""

    institutions: frozenset[str] = frozenset()
    departments: frozenset[str] = frozenset()
    wards: frozenset[str] = frozenset()
    staff: frozenset[str] = frozenset()
    source: str = "<memory>"

    def __len__(self) -> int:
        return (
            len(self.institutions)
            + len(self.departments)
            + len(self.wards)
            + len(self.staff)
        )

    def is_empty(self) -> bool:
        return len(self) == 0

    def entries(self) -> tuple[tuple[str, str], ...]:
        """``(term, category)`` pairs, longest term first.

        Longest first so a compound term wins over a prefix of itself, and so
        the detector's first match at a position is the most specific one.
        """
        pairs: list[tuple[str, str]] = []
        for category in CATEGORIES:
            for term in self.terms(category):
                pairs.append((term, category))
        return tuple(sorted(pairs, key=lambda pair: (-len(pair[0]), pair[0], pair[1])))

    def terms(self, category: str) -> frozenset[str]:
        """Terms of one category. Raises on an unknown category."""
        if category not in CATEGORIES:
            raise DictionaryError(f"unknown dictionary category {category!r}")
        return getattr(self, _FIELD_FOR_CATEGORY[category])


def load_dictionary(path: str | Path) -> InstitutionDictionary:
    """Load a dictionary from a ``.csv`` or ``.json`` file.

    Every failure is explicit: an unreadable file, a missing header, an unknown
    category or an empty term raises ``DictionaryError`` rather than being
    skipped, so a deployment never believes a vocabulary is active when it is
    not.
    """
    source = Path(path)
    try:
        raw = source.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise DictionaryError(f"cannot read dictionary {source}: {exc}") from exc

    suffix = source.suffix.lower()
    if suffix == ".csv":
        buckets = _parse_csv(raw, source)
    elif suffix == ".json":
        buckets = _parse_json(raw, source)
    else:
        raise DictionaryError(
            f"unsupported dictionary format {suffix or '<none>'!r}; use .csv or .json"
        )
    return InstitutionDictionary(
        source=str(source),
        **{_FIELD_FOR_CATEGORY[category]: terms for category, terms in buckets.items()},
    )


def _parse_csv(raw: str, source: Path) -> dict[str, frozenset[str]]:
    rows = [
        row
        for row in csv.reader(io.StringIO(raw))
        if row and not row[0].lstrip().startswith("#")
    ]
    if not rows:
        raise DictionaryError(f"dictionary {source} is empty")
    header = tuple(cell.strip().lower() for cell in rows[0][:2])
    if header != _CSV_HEADER:
        raise DictionaryError(
            f"dictionary {source} must start with a '{','.join(_CSV_HEADER)}' header"
        )
    buckets: dict[str, set[str]] = {category: set() for category in CATEGORIES}
    for number, row in enumerate(rows[1:], start=2):
        if len(row) < 2:
            raise DictionaryError(
                f"dictionary {source} line {number}: expected two columns"
            )
        category = row[0].strip().lower()
        term = row[1].strip()
        if category not in buckets:
            raise DictionaryError(
                f"dictionary {source} line {number}: unknown category {category!r}"
            )
        if not term:
            raise DictionaryError(f"dictionary {source} line {number}: empty name")
        buckets[category].add(term)
    return {category: frozenset(terms) for category, terms in buckets.items()}


def _parse_json(raw: str, source: Path) -> dict[str, frozenset[str]]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DictionaryError(f"invalid JSON in dictionary {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise DictionaryError(f"dictionary {source} must be a JSON object")
    unknown = sorted(set(payload) - set(CATEGORIES))
    if unknown:
        raise DictionaryError(f"dictionary {source}: unknown keys {unknown}")
    buckets: dict[str, frozenset[str]] = {}
    for category in CATEGORIES:
        values = payload.get(category, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise DictionaryError(
                f"dictionary {source}: '{category}' must be a list of strings"
            )
        terms = [v.strip() for v in values]
        if any(not term for term in terms):
            raise DictionaryError(f"dictionary {source}: '{category}' has empty entries")
        buckets[category] = frozenset(terms)
    return buckets
