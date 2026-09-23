"""CSV payload traversal.

A CSV file is flattened into its cell values so the existing text pipeline can
run over them, then rebuilt with the table structure intact.

Column detection is deliberately two-sided, because neither half is sufficient
on its own:

- **Column names** supply the field label, which is what makes a value
  detectable at all (``姓名`` says the value is a name, ``name`` likewise). A
  table whose headers are unconventional simply gets no labels.
- **Cell scanning** is the source of truth for facts. A header can be wrong,
  missing, or duplicated; the value is still whatever it is.

Encoding is *not* guessed. The caller states it, and a decode failure is
reported rather than silently retried with another codec — mojibake that
reaches a model is worse than an error that reaches the operator.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass

from core.errors import ParserError

from .leaf import Leaf, StructuredPayload, label_for

#: ``row[3].col[2]`` — indices only, so rebuilding needs no header.
_PATH_RE = re.compile(r"^row\[(\d+)\]\.col\[(\d+)\]$")


@dataclass(frozen=True)
class CsvTable:
    """A parsed CSV file: an optional header plus its data rows."""

    header: tuple[str, ...] | None
    rows: tuple[tuple[str, ...], ...]


def parse_csv_payload(text: str) -> StructuredPayload:
    """Parse CSV text and collect its cell values as leaves.

    A first row is treated as a header when any of its cells is a recognised
    field name; otherwise every row is data. That heuristic can misread a data
    row whose first cell happens to be a field name, so callers with unusual
    files should not rely on header-based labelling.
    """
    reader = csv.reader(io.StringIO(text))
    try:
        raw = [tuple(cell for cell in row) for row in reader]
    except csv.Error as exc:
        raise ParserError(f"cannot parse CSV payload: {exc}") from exc
    if not raw or all(not any(cell.strip() for cell in row) for row in raw):
        # A file of blank lines parses to rows of empty cells; it holds nothing
        # to sanitize, and reporting it as empty is more honest than releasing
        # a table that was never inspected.
        raise ParserError("CSV payload is empty")

    header: tuple[str, ...] | None = None
    data = raw
    if any(label_for(cell) for cell in raw[0]):
        header = raw[0]
        data = raw[1:]

    leaves: list[Leaf] = []
    for row_index, row in enumerate(data):
        for col_index, cell in enumerate(row):
            label = None
            if header is not None and col_index < len(header):
                label = label_for(header[col_index])
            leaves.append(
                Leaf(
                    path=f"row[{row_index}].col[{col_index}]",
                    text=cell,
                    label=label,
                )
            )
    return StructuredPayload(
        kind="csv", document=CsvTable(header=header, rows=tuple(data)), leaves=tuple(leaves)
    )


def rebuild(table: CsvTable, replacements: dict[str, str]) -> CsvTable:
    """Return a copy of *table* with each addressed cell replaced.

    Row and column counts never change: only values do. A path that addresses a
    cell outside the table is an error rather than a silent no-op, because that
    would mean the plan and the document had diverged.
    """
    rows = [list(row) for row in table.rows]
    for path, value in replacements.items():
        row_index, col_index = _parse_path(path)
        if row_index >= len(rows) or col_index >= len(rows[row_index]):
            raise ParserError(f"CSV path {path} addresses no cell")
        rows[row_index][col_index] = value
    return CsvTable(header=table.header, rows=tuple(tuple(row) for row in rows))


def _parse_path(path: str) -> tuple[int, int]:
    match = _PATH_RE.fullmatch(path)
    if not match:
        raise ParserError(f"invalid CSV path {path!r}")
    return int(match.group(1)), int(match.group(2))


def dumps(table: CsvTable) -> str:
    """Serialise a rebuilt table.

    Quoting follows the csv module's minimal rule, so a field is quoted only
    when it contains a delimiter, a quote or a newline. An input file that
    quoted every field will come back minimally quoted: the data is identical,
    the bytes are not.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    if table.header is not None:
        writer.writerow(table.header)
    writer.writerows(table.rows)
    return buffer.getvalue()
