"""Command-line interface for medical-privacy-guard.

Commands:
    inspect   <file> [--json] [--profile P] [--recipient T] [--purpose U]
    sanitize  <file> [-o OUT] [--profile P] [--recipient T] [--purpose U]
              [--audit-dir DIR]
    benchmark <corpus_dir> [--json] [--profile P] [--limit N]
    audit-verify <audit_dir> [--json] [--key-env VAR]

Exit codes:
    0  ALLOW, or SANITIZE that passed verification; for audit-verify, an intact chain
    2  BLOCK (or verification failure — no output is produced); for
       audit-verify, a broken chain
    3  ASK
    4  internal / parser / configuration error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Mapping, Sequence

from core.audit import read_events, verify_chain
from core.benchmark import run_benchmark
from core.errors import AuditError, GuardError, ParserError
from core.model import (
    Decision,
    DetectedFact,
    Payload,
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
#: Environment variable holding the optional audit HMAC key. A key is read from
#: the environment rather than argv so it never lands in a process listing.
DEFAULT_AUDIT_KEY_ENV = "MEDICAL_PRIVACY_GUARD_AUDIT_KEY"
# Kept in step with core.benchmark.DEFAULT_RECIPIENT: the corpus expects its
# positive documents to be sanitized and released, which only an approved
# endpoint allows.
DEFAULT_BENCHMARK_RECIPIENT = "external_approved"

_TRUST_LEVELS = {t.value.lower(): t for t in TrustLevel}
_PURPOSES = {p.value.lower(): p for p in Purpose}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="medical-privacy-guard",
        description="Local-first privacy guardrails for medical data.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    format_boundary = (
        "UTF-8 plain text and JSON objects/arrays are supported. Known "
        "unsupported suffixes and binary markers are blocked; arbitrary "
        "disguised formats cannot be detected."
    )
    p_inspect = sub.add_parser(
        "inspect", help="Detect and evaluate without modifying data.", epilog=format_boundary,
    )
    p_inspect.add_argument("file", help="UTF-8 text file to inspect")
    p_inspect.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_inspect.add_argument(
        "--dictionary", default=None,
        help="Optional .csv or .json institution vocabulary (local-only)",
    )
    _add_common(p_inspect)

    p_sanitize = sub.add_parser(
        "sanitize", help="Sanitize a file and write the result.",
        epilog=(format_boundary + " Use trusted directories: path preflight is not "
                "protection against concurrent directory or audit-path replacement. "
                "Failed output writes may leave an incomplete owner-only file."),
    )
    p_sanitize.add_argument("file", help="UTF-8 text file to sanitize")
    p_sanitize.add_argument(
        "-o", "--output", default=None,
        help="New owner-only output file; existing paths are refused (default: stdout)",
    )
    p_sanitize.add_argument("--audit-dir", default=None, help="Append audit events to this directory")
    p_sanitize.add_argument(
        "--dictionary", default=None,
        help="Optional .csv or .json institution vocabulary (local-only)",
    )
    _add_common(p_sanitize)

    p_benchmark = sub.add_parser(
        "benchmark",
        help="Evaluate the guard against an annotated synthetic corpus.",
    )
    p_benchmark.add_argument("corpus", help="Corpus directory containing *.txt and *.spans.json")
    p_benchmark.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_benchmark.add_argument("--limit", type=int, default=None, help="Evaluate only the first N documents")
    # The corpus declares its expected verdicts for an approved endpoint; under
    # the conservative default no note would ever reach the sanitize path and
    # the benchmark would report a pass over zero measurements.
    _add_common(p_benchmark, recipient_default=DEFAULT_BENCHMARK_RECIPIENT)

    p_audit = sub.add_parser(
        "audit-verify",
        help="Verify the integrity chain of an audit log.",
        epilog=(
            "Exit codes: 0 intact, 2 broken, 4 unreadable. Tail truncation and "
            "whole-chain rewriting are not detectable without a key or an "
            "external anchor."
        ),
    )
    p_audit.add_argument("audit_dir", help="Directory holding events.jsonl")
    p_audit.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_audit.add_argument(
        "--key-env",
        default=None,
        help="Environment variable holding the HMAC key (kept out of argv)",
    )
    return parser


def _add_common(
    parser: argparse.ArgumentParser, recipient_default: str = "external_unknown"
) -> None:
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="Policy profile name")
    parser.add_argument(
        "--recipient",
        default=recipient_default,
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


_UNSUPPORTED_SUFFIXES = {
    ".jsonl", ".ndjson", ".csv", ".tsv", ".xls", ".xlsx", ".xlsm",
    ".ods", ".pdf", ".doc", ".docx", ".odt", ".rtf", ".fhir", ".xml",
    ".hl7", ".dcm", ".dicom", ".bin", ".zip", ".gz", ".png", ".jpg",
    ".jpeg", ".gif", ".tif", ".tiff", ".wav", ".mp3", ".mp4",
}


class _UnsupportedInput(ParserError):
    pass


def _read_text(path: str) -> str:
    """Reject known formats, not arbitrary formats disguised as clinical text."""
    source = Path(path)
    try:
        suffixes = source.suffixes + source.resolve().suffixes
        if any(suffix.lower() in _UNSUPPORTED_SUFFIXES for suffix in suffixes):
            raise _UnsupportedInput("unsupported input format; UTF-8 plain text required")
        data = source.read_bytes()
    except (OSError, RuntimeError) as exc:
        raise ParserError("cannot read input file") from exc
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _UnsupportedInput("unsupported input encoding; UTF-8 plain text required") from exc
    if (
        any((ord(char) < 32 and char not in "\t\r\n") or 127 <= ord(char) <= 159
            for char in text)
        or text.lstrip().startswith(("%PDF-", "{\\rtf", "<?xml", "<fhir:"))
        or data.startswith((b"PK\x03\x04", b"GIF87a", b"GIF89a"))
        or data[128:132] == b"DICM"
    ):
        raise _UnsupportedInput("unsupported binary or document format")
    return text


def _classify(text: str) -> str:
    """Classify the input as ``json``, ``text`` or ``unsupported``.

    Something that looks like a container but does not parse as one is not
    quietly demoted to prose: a truncated or double-wrapped JSON file is a
    format problem, and treating it as clinical text would release its
    contents as if they had been inspected properly.
    """
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return "text"
    try:
        container = json.loads(stripped)
    except (json.JSONDecodeError, RecursionError, ValueError):
        # Not a complete document. It is only a broken payload if a valid JSON
        # value parses and leaves content behind (a truncated or double-wrapped
        # file); otherwise the braces are ordinary text, and "[随访] 记录"
        # must not be blocked merely for starting with a bracket.
        try:
            value, end = json.JSONDecoder().raw_decode(stripped)
        except (json.JSONDecodeError, RecursionError, ValueError):
            return "text"
        if isinstance(value, (dict, list)) and stripped[end:].strip():
            return "unsupported"
        return "text"
    return "json" if isinstance(container, (dict, list)) else "unsupported"


def _payload_for(text: str) -> str | Payload:
    """Build the payload a classified input should take through the guard."""
    kind = _classify(text)
    if kind == "json":
        return Payload(kind="json", content=text)
    if kind == "unsupported":
        return Payload(kind="unsupported", content="")
    return text


def _check_paths(input_file: str, output: str | None, audit_dir: str | None) -> None:
    """Preflight aliases in trusted directories; not a directory-race sandbox."""
    paths = [Path(input_file)]
    if output is not None:
        paths.append(Path(output))
    if audit_dir:
        paths.append(Path(audit_dir) / "events.jsonl")
    try:
        resolved = [path.resolve() for path in paths]
        identities = []
        for path in paths:
            try:
                info = path.stat()
            except FileNotFoundError:
                identities.append(None)
            else:
                identities.append((info.st_dev, info.st_ino))
        for index, path in enumerate(resolved):
            for other in range(index):
                if path == resolved[other] or (
                    identities[index] is not None
                    and identities[index] == identities[other]
                ):
                    raise GuardError("input, output and audit log must be distinct files")
        if output is not None and os.path.lexists(output):
            raise GuardError("refusing to overwrite an existing output path")
    except (OSError, RuntimeError) as exc:
        raise GuardError("cannot validate input, output and audit log paths") from exc


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
    if _classify(text) == "unsupported":
        # Admission failure, not a policy verdict: keep it off stdout so the
        # two are distinguishable, exactly as sanitize does.
        print("BLOCK: unsupported structured input", file=sys.stderr)
        return EXIT_BLOCK
    payload = _payload_for(text)
    result = Guard(
        profile=args.profile, dictionary_path=args.dictionary
    ).evaluate(payload, recipient, purpose)
    facts = result.facts
    decision = result.decision
    counts = _counts(facts)

    if args.json:
        print(_json_decision(decision, counts, result.public_facts))
    else:
        print(_human_decision(decision, counts))
    return _exit_for_verdict(decision.verdict)


def _cmd_sanitize(args: argparse.Namespace) -> int:
    _check_paths(args.file, args.output, args.audit_dir)
    try:
        text = _read_text(args.file)
    except _UnsupportedInput:
        payload: str | Payload = Payload(kind="unsupported", content="")
    else:
        payload = _payload_for(text)
    recipient = Recipient(kind="cli", trust_level=_TRUST_LEVELS[args.recipient])
    purpose = _PURPOSES[args.purpose]
    # Guard owns detect → decide → transform → verify → audit.  In particular,
    # audit completes before this function writes/reveals the output.
    result = Guard(profile=args.profile, dictionary_path=args.dictionary).sanitize(
        payload,
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


def _cmd_benchmark(args: argparse.Namespace) -> int:
    report = run_benchmark(
        args.corpus,
        profile=args.profile,
        recipient=args.recipient,
        purpose=args.purpose,
        limit=args.limit,
    )
    if args.json:
        print(report.to_json())
    else:
        print(_human_benchmark(report))
    # A failed gate is a blocking result: exit 2 keeps the CLI contract
    # ("2 = BLOCK") meaningful for CI usage. Every gate counts, including the
    # precision gate (an over-redaction regression) and the non-vacuity clause
    # (a run that never reached the sanitize path measured nothing).
    return EXIT_OK if report.passed() else EXIT_BLOCK


def _audit_key(key_env: str | None) -> bytes | None:
    """Resolve the optional audit HMAC key from the environment.

    An explicitly named variable that is unset is an error: silently verifying
    an unkeyed chain would report success on a log the caller expects to be
    authenticated.
    """
    name = key_env or DEFAULT_AUDIT_KEY_ENV
    raw = os.environ.get(name)
    if raw is None:
        if key_env:
            raise GuardError(f"environment variable {key_env} is not set")
        return None
    return raw.encode("utf-8")


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    key = _audit_key(args.key_env)
    log = Path(args.audit_dir) / "events.jsonl"
    if not log.is_file():
        # An absent log proves nothing about integrity; reporting an empty chain
        # as INTACT would turn a mistyped path into a passing verification.
        print(f"error: no audit log at {log}", file=sys.stderr)
        return EXIT_ERROR
    events = read_events(log)
    report = verify_chain(events, key)

    if args.json:
        print(
            json.dumps(
                {
                    "log": str(log),
                    "total": report.total,
                    "chained": report.chained,
                    "unchained": report.unchained,
                    "verified": report.verified,
                    "failures": list(report.failures),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"Audit log: {log}")
        print(
            f"Records: {report.total} "
            f"(chained {report.chained}, pre-chain {report.unchained})"
        )
        if report.verified:
            print("Result: INTACT")
        else:
            print("Result: BROKEN")
            for failure in report.failures:
                print(f"  - {failure}")
    return EXIT_OK if report.verified else EXIT_BLOCK


def _human_benchmark(report) -> str:
    lines = [
        f"Corpus: {report.documents} documents "
        f"({report.span_documents} with labelled spans, "
        f"{report.clean_documents} identifier-free)",
        f"Policy: {report.profile}  recipient={report.recipient}  purpose={report.purpose}",
        f"Span recall:    {report.span_recall:.4f}  ({report.true_positives}/{report.labelled_spans})",
        f"Span precision: {report.span_precision:.4f}  ({report.false_positives} false positives)",
        "Safety gates:",
        f"  false allows:        {report.false_allow_count}",
        f"  residual PHI:        {report.residual_phi_count}",
        f"  audit raw leaks:     {report.audit_raw_leak_count}",
        f"  verification fails:  {report.verification_failure_count}",
        f"  lifecycle failures:  {report.lifecycle_failure_count}",
        f"  audit failures:      {report.audit_failure_count}",
        f"  errors:              {report.errors}",
        "Verdict gate:",
        f"  verdict mismatches:  {report.verdict_mismatch_count}",
        "Detection gates (exact one-to-one spans):",
        f"  false negatives:     {report.false_negatives}",
        f"  false positives on identifier-free documents: "
        f"{report.false_positives_on_clean_documents}",
        "Coverage (a gate that was never exercised cannot pass):",
        f"  documents released:  {report.released_documents}",
        f"  unchanged ALLOW:     {report.allowed_original_documents}",
        f"  verified SANITIZE:   {report.sanitized_verified_documents}",
        f"  ASK / BLOCK:         {report.ask_documents} / {report.blocked_documents}",
        f"  verifications run:   {report.verification_runs}",
        f"Latency: p50 {report.p50_latency_ms:.2f} ms, p95 {report.p95_latency_ms:.2f} ms",
    ]
    failures = report.gate_failures()
    lines.append(
        "Result: PASS" if not failures else f"Result: FAIL ({', '.join(failures)})"
    )
    return "\n".join(lines)


def _write_output(output: str | None, input_file: str, content: str) -> None:
    if output is None:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
        return
    _check_paths(input_file, output, None)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            data = content.encode("utf-8")
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("output write made no progress")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise GuardError("cannot write output file; an incomplete output may remain") from exc


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
        if args.command == "benchmark":
            return _cmd_benchmark(args)
        if args.command == "audit-verify":
            return _cmd_audit_verify(args)
        parser.error(f"unknown command: {args.command}")
    except SystemExit:
        raise
    except _UnsupportedInput as exc:
        print(f"BLOCK: {exc}", file=sys.stderr)
        return EXIT_BLOCK
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except GuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
