"""Evaluate the guard against the hand-written simulation corpus.

Reports generalisation: which labelled values survive into released output, and
which values that should have been kept were removed. This is a measurement, not
a gate — the corpus is deliberately not tuned to the detectors, so a low score
is information rather than a build failure.

    python tools/evaluate_simulation.py [--json] [--recipient T]

Findings live in ``.internal/simulation-evaluation-2026-09-23.md``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.model import Purpose, Recipient, TrustLevel  # noqa: E402
from medical_privacy_guard import Guard  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests" / "fixtures"))
from simulation.cases import CASES  # noqa: E402


def still_present(value: str, released: str) -> bool:
    """True when *value* survives as a standalone token.

    A generalized age band (``20-29岁``) still contains the digits, so plain
    substring containment would report a correctly transformed value as a leak.
    """
    age = re.fullmatch(r"(\d{1,3})岁", value)
    if age:
        return bool(re.search(rf"(?<![-\d]){age.group(1)}岁", released))
    return value in released


def evaluate(recipient_name: str) -> dict:
    guard = Guard(profile="external-ai-strict")
    recipient = Recipient(kind="simulation", trust_level=TrustLevel(recipient_name.upper()))
    rows = []
    for case in CASES:
        result = guard.sanitize(case["text"], recipient, Purpose.EXTERNAL_AI_ASSISTANCE)
        released = result.sanitized_payload.content if result.sanitized_payload else None
        if released is None:
            rows.append(
                {
                    "id": case["id"],
                    "type": case["type"],
                    "verdict": result.decision_before.verdict.value,
                    "released": False,
                    "missed": [],
                    "over_redacted": [],
                }
            )
            continue
        rows.append(
            {
                "id": case["id"],
                "type": case["type"],
                "verdict": result.decision_before.verdict.value,
                "released": True,
                "missed": [v for v in case["phi"] if still_present(v, released)],
                "over_redacted": [v for v in case["clean"] if v not in released],
            }
        )
    phi_total = sum(len(c["phi"]) for c in CASES)
    clean_total = sum(len(c["clean"]) for c in CASES)
    missed = sum(len(r["missed"]) for r in rows)
    over = sum(len(r["over_redacted"]) for r in rows)
    return {
        "documents": len(CASES),
        "labelled_values": phi_total,
        "kept_values": clean_total,
        "missed": missed,
        "over_redacted": over,
        "miss_rate": missed / phi_total if phi_total else 0.0,
        "over_redaction_rate": over / clean_total if clean_total else 0.0,
        "withheld_documents": sum(1 for r in rows if not r["released"]),
        "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--recipient", default="external_approved")
    args = parser.parse_args(argv)

    report = evaluate(args.recipient)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print(f"{'case':<10} {'type':<10} {'verdict':<9} missed / over-redacted")
    print("-" * 76)
    for row in report["cases"]:
        if not row["released"]:
            print(f"{row['id']:<10} {row['type']:<10} {row['verdict']:<9} WITHHELD")
            continue
        mark = "  <--" if row["missed"] or row["over_redacted"] else ""
        print(
            f"{row['id']:<10} {row['type']:<10} {row['verdict']:<9} "
            f"missed={row['missed']} over={row['over_redacted']}{mark}"
        )
    print()
    print(f"labelled values : {report['labelled_values']}, "
          f"missed {report['missed']} ({report['miss_rate']:.1%})")
    print(f"values to keep  : {report['kept_values']}, "
          f"over-redacted {report['over_redacted']} ({report['over_redaction_rate']:.1%})")
    print(f"withheld        : {report['withheld_documents']}/{report['documents']}")
    print()
    print("This corpus is not tuned to the detectors; the number is a")
    print("generalisation measurement, not a build gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
