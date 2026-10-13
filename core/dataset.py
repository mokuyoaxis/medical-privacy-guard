"""Batch-scoped tokens and aggregate quasi-identifier engineering measurements.

Reports count rows, not distinct people, and never authorize disclosure.
Raw combinations and token-to-original maps stay in local memory.
"""

from __future__ import annotations

import csv
import io
import json
import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.errors import ParserError
from core.model import Payload, Purpose, Recipient, SanitizationResult
from formats.admission import read_text_file
from transformers import TokenRegistry


@dataclass(frozen=True)
class DatasetRiskReport:
    quasi_identifiers: tuple[str, ...]
    row_count: int
    group_count: int
    smallest_group: int
    largest_group: int
    singleton_rows: int
    small_group_rows: int
    threshold: int
    size_histogram: tuple[tuple[int, int], ...]

    def to_dict(self) -> dict:
        return {
            "engineering_only": True,
            "quasi_identifiers": list(self.quasi_identifiers),
            "row_count": self.row_count, "group_count": self.group_count,
            "smallest_group": self.smallest_group, "largest_group": self.largest_group,
            "singleton_rows": self.singleton_rows,
            "singleton_fraction": self.singleton_rows / self.row_count if self.row_count else 0.0,
            "small_group_rows": self.small_group_rows,
            "small_group_fraction": self.small_group_rows / self.row_count if self.row_count else 0.0,
            "threshold": self.threshold,
            "size_histogram": [{"rows_per_group": size, "groups": count}
                               for size, count in self.size_histogram],
        }


def _cell(value: Any) -> tuple[str, str]:
    if value is None:
        return ("null", "")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise ParserError("dataset contains invalid text") from exc
        return ("scalar", value)
    if type(value) in (int, float, bool):
        try:
            return ("scalar", json.dumps(value, allow_nan=False))
        except ValueError as exc:
            raise ParserError("dataset contains an unsupported numeric value") from exc
    raise ParserError("selected quasi-identifier values must be scalar")


def analyze_dataset(
    rows: Iterable[Mapping[str, Any]], quasi_identifiers: Sequence[str], *, min_group_size: int = 2,
) -> DatasetRiskReport:
    """Count exact combinations across the supplied batch; serialize no values.

    CSV text and JSON scalar renderings can match ("40" and 40). JSON null is
    distinct from text, including an empty CSV cell. No implicit trimming,
    age binning, identity resolution or external-population estimation occurs.
    """
    columns = tuple(quasi_identifiers)
    if (not columns or any(not isinstance(name, str) or not name for name in columns)
            or len(set(columns)) != len(columns)):
        raise ParserError("select distinct non-empty quasi-identifier column names")
    if type(min_group_size) is not int or min_group_size < 2:
        raise ParserError("minimum group size must be an integer of at least 2")
    groups: Counter = Counter()
    total = 0
    for row in rows:
        if not isinstance(row, Mapping) or any(name not in row for name in columns):
            raise ParserError("dataset row is missing a selected quasi-identifier column")
        groups[tuple(_cell(row[name]) for name in columns)] += 1
        total += 1
    sizes = Counter(groups.values())
    return DatasetRiskReport(
        columns, total, len(groups), min(sizes, default=0), max(sizes, default=0),
        sizes.get(1, 0), sum(size * count for size, count in sizes.items() if size < min_group_size),
        min_group_size, tuple(sorted(sizes.items())),
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ParserError("dataset JSON contains duplicate object keys")
        result[name] = value
    return result


def _nonfinite(value: str) -> None:
    raise ParserError("dataset JSON contains unsupported numeric constants")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ParserError("dataset JSON contains an unsupported numeric value")
    return number


def read_dataset_file(path: str | Path, encoding: str = "utf-8-sig") -> tuple[Payload, list[dict]]:
    """Read CSV with a unique header or a JSON object/array of row objects."""
    source = Path(path)
    text = read_text_file(str(source), encoding)
    if source.suffix.lower() == ".csv":
        try:
            table = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        except csv.Error as exc:
            raise ParserError("dataset CSV cannot be parsed") from exc
        if not table or not table[0] or any(not name for name in table[0]):
            raise ParserError("dataset CSV requires a non-empty header")
        header = table[0]
        if len(set(header)) != len(header) or any(len(row) != len(header) for row in table[1:]):
            raise ParserError("dataset CSV has duplicate columns or uneven rows")
        rows = [dict(zip(header, row)) for row in table[1:]]
        return Payload(kind="csv", content=text), rows
    if source.suffix.lower() != ".json":
        raise ParserError("dataset input must be a CSV or JSON file")
    try:
        document = json.loads(text, object_pairs_hook=_unique_object,
                              parse_constant=_nonfinite, parse_float=_finite_float)
    except (ValueError, RecursionError) as exc:
        raise ParserError("dataset JSON cannot be parsed") from exc
    rows = document if isinstance(document, list) else [document]
    if any(not isinstance(row, dict) for row in rows):
        raise ParserError("dataset JSON must contain row objects")
    return Payload(kind="json", content=text), rows


@dataclass(frozen=True)
class DatasetSanitizationResult:
    results: tuple[SanitizationResult, ...] = field(repr=False)
    token_count: int

    def summary(self) -> dict:
        return {"token_count": self.token_count, "files": [
            {"index": index, "decision": result.decision_before.verdict.value,
             "released": result.sanitized_payload is not None,
             "verification": result.verification.passed if result.verification else None}
            for index, result in enumerate(self.results, 1)
        ]}


def sanitize_dataset(
    payloads: Sequence[Payload], recipient: str | Recipient, purpose: str | Purpose, *,
    profile: str = "external-ai-strict", dictionary_path: str | None = None,
    audit_dir: str | None = None,
) -> DatasetSanitizationResult:
    """Share tokens only within this serial batch; apply normal Guard gates per file."""
    from medical_privacy_guard import Guard

    if any(payload.kind not in {"csv", "json"} for payload in payloads):
        raise ParserError("dataset sanitizer supports CSV and JSON payloads")
    tokens = TokenRegistry()
    guard = Guard(profile=profile, dictionary_path=dictionary_path, audit_dir=audit_dir,
                  token_registry=tokens)
    results = tuple(guard.sanitize(payload, recipient, purpose) for payload in payloads)
    return DatasetSanitizationResult(results, len(tokens))
