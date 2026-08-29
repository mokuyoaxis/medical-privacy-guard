"""Command-line interface for medical-privacy-guard.

Commands:
    inspect   <file> [--json] [--profile P] [--recipient T] [--purpose U]
    sanitize  <file> [-o OUT] [--profile P] [--recipient T] [--purpose U]
              [--audit-dir DIR]

Exit codes (act.md Step 6):
    0  ALLOW, or SANITIZE that passed verification
    2  BLOCK (or verification failure — no output is produced)
    3  ASK
    4  internal / parser / configuration error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

from core.errors import GuardError, ParserError
from core.model import (
    Decision,
    DetectedFact,
    Purpose,
    Recipient,
    TrustLevel,
    Verdict,
)
from medical_privacy_guard import Guard

EXIT_OK = 0
EXIT_BLOCK = 2
EXIT_ASK = 3
EXIT_ERROR = 4

DEFAULT_PROFILE = "external-ai-strict"

_TRUST_LEVELS = {t.value.lower(): t for t in TrustLevel}
_PURPOSES = {p.value.lower(): p for p in Purpose}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="medical-privacy-guard",
        description="Local-first privacy guardrails for medical data.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="Detect and evaluate without modifying data.")
    p_inspect.add_argument("file", help="UTF-8 text file to inspect")
    p_inspect.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _add_common(p_inspect)

    p_sanitize = sub.add_parser("sanitize", help="Sanitize a file and write the result.")
    p_sanitize.add_argument("file", help="UTF-8 text file to sanitize")
    p_sanitize.add_argument("-o", "--output", default=None, help="Output path (default: stdout)")
    p_sanitize.add_argument("--audit-dir", default=None, help="Append audit events to this directory")
    _add_common(p_sanitize)
    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="Policy profile name")
    parser.add_argument(
        "--recipient",
        default="external_unknown",
        choices=sorted(_TRUST_LEVELS),
        help="Recipient trust level",
    )
    parser.add_argument(
        "--purpose",
        default="external_ai_assistance",
        choices=sorted(_PURPOSES),
        help="Declared disclosure purpose",
    )


# -- context helpers ---------------------------------------------------------


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ParserError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ParserError(f"{path} is not valid UTF-8 text: {exc}") from exc


def _exit_for_verdict(verdict: Verdict) -> int:
    if verdict is Verdict.BLOCK:
        return EXIT_BLOCK
    if verdict is Verdict.ASK:
        return EXIT_ASK
    return EXIT_OK


# -- output formatting -------------------------------------------------------


def _human_decision(decision: Decision, counts: Mapping[str, int]) -> str:
    lines = [f"Decision: {decision.verdict.value}", f"Risk: {decision.risk.level.value}"]
    if decision.reason_codes:
        lines.append("Reason codes:")
        lines.extend(f"  - {rc.value}" for rc in decision.reason_codes)
    if counts:
        lines.append("Entity counts:")
        lines.extend(f"  - {kind}: {count}" for kind, count in sorted(counts.items()))
    if decision.plan and decision.plan.operations:
        lines.append("Plan:")
        lines.extend(f"  - {op.op} {op.entity_type or op.target}" for op in decision.plan.operations)
    return "\n".join(lines)


def _json_decision(
    decision: Decision,
    counts: Mapping[str, int],
    public_facts: Sequence,
    sanitized: str | None = None,
    verification: str | None = None,
) -> str:
    payload: dict = {
        "decision": decision.verdict.value,
        "risk": {"level": decision.risk.level.value, "score": decision.risk.score},
        "reason_codes": [rc.value for rc in decision.reason_codes],
        "counts": dict(counts),
        "facts": [
            {"type": f.type, "start": f.start, "end": f.end, "confidence": f.confidence}
            for f in public_facts
        ],
    }
    if decision.plan is not None:
        payload["plan"] = {
            "operations": [
                f"{op.op}_{op.entity_type or op.target}" for op in decision.plan.operations
            ]
        }
    if sanitized is not None:
        payload["sanitized"] = sanitized
    if verification is not None:
        payload["verification"] = verification
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _counts(facts: Sequence[DetectedFact]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in facts:
        counts[f.type] = counts.get(f.type, 0) + 1
    return counts


# -- commands ----------------------------------------------------------------


def _cmd_inspect(args: argparse.Namespace) -> int:
    text = _read_text(args.file)
    recipient = Recipient(kind="cli", trust_level=_TRUST_LEVELS[args.recipient])
    purpose = _PURPOSES[args.purpose]
    result = Guard(profile=args.profile).evaluate(text, recipient, purpose)
    facts = result.facts
    decision = result.decision
    counts = _counts(facts)

    if args.json:
        print(_json_decision(decision, counts, result.public_facts))
    else:
        print(_human_decision(decision, counts))
    return _exit_for_verdict(decision.verdict)


def _cmd_sanitize(args: argparse.Namespace) -> int:
    text = _read_text(args.file)
    recipient = Recipient(kind="cli", trust_level=_TRUST_LEVELS[args.recipient])
    purpose = _PURPOSES[args.purpose]
    # Guard owns detect → decide → transform → verify → audit.  In particular,
    # audit completes before this function writes/reveals the output.
    result = Guard(profile=args.profile).sanitize(
        text,
        recipient,
        purpose,
        audit_dir=args.audit_dir,
    )
    decision = result.decision_before

    if decision.verdict is Verdict.BLOCK:
        print(f"BLOCK: {decision.explanation}", file=sys.stderr)
        return EXIT_BLOCK
    if decision.verdict is Verdict.ASK:
        print(f"ASK: {decision.explanation}", file=sys.stderr)
        return EXIT_ASK

    if result.verification is not None and not result.verification.passed:
        print(f"VERIFICATION FAILED: {result.verification.details}", file=sys.stderr)
        return EXIT_BLOCK
    if result.sanitized_payload is None:
        print("BLOCK: no verified payload is available for release", file=sys.stderr)
        return EXIT_BLOCK

    _write_output(args.output, args.file, result.sanitized_payload.content)
    return EXIT_OK


def _write_output(output: str | None, input_file: str, content: str) -> None:
    if output is None:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
        return
    out_path = Path(output)
    if out_path.resolve() == Path(input_file).resolve():
        raise GuardError("refusing to overwrite the input file in place")
    try:
        out_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise GuardError(f"cannot write {output}: {exc}") from exc


# -- entry point -------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse: usage errors exit 2, --help exits 0. Remap usage errors
        # to EXIT_ERROR so exit code 2 stays unambiguous (= BLOCK).
        if exc.code == 2:
            return EXIT_ERROR
        raise
    try:
        if args.command == "inspect":
            return _cmd_inspect(args)
        if args.command == "sanitize":
            return _cmd_sanitize(args)
        parser.error(f"unknown command: {args.command}")
    except SystemExit:
        raise
    except GuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
