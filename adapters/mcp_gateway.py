"""A transparent privacy proxy in front of a stdio MCP server.

The gateway is the first place in this project where disclosure is not merely
checked but *structurally* prevented: an MCP client is configured to launch the
gateway instead of the server, so nothing reaches the server without passing
through it.

    medical-privacy-guard mcp-gateway --recipient external_unknown \
        -- python -m some_mcp_server

What it does, and deliberately does not do:

- It forwards newline-delimited JSON-RPC in both directions, unchanged.
- It intercepts ``tools/call`` and holds the request back, rewrites it, or
  refuses it, according to the guard's verdict.
- It does **not** participate in protocol negotiation. The protocol is stateless
  (2026-07-28: "There is no negotiation handshake"), so a modern client's
  ``server/discover`` probe and a legacy client's ``initialize`` are forwarded
  untouched. The server's era is the server's business.
- It does **not** inspect responses. v0.4 is an egress guard; what comes back
  from the server is out of scope and recorded as such in ``docs/scope.md``.

The verdict that matters most is neither ALLOW nor BLOCK. A ``SANITIZE`` verdict
means the call may proceed only with rewritten arguments, and treating that as
permission is how a raw phone number reaches a tool: the first draft of this
design did exactly that. See :meth:`McpGateway._decide`.

Two static-analysis findings are suppressed below, both because they describe
what this module is for rather than a mistake in it. ``B404`` warns about
importing ``subprocess`` at all; launching and mediating a subprocess is the
gateway's entire job. ``B603`` asks the caller to confirm that an executed
command is trustworthy; the command is the operator's own argv from the CLI,
passed as a list with ``shell=False``, so nothing is re-parsed by a shell.
"""

from __future__ import annotations

import json
import signal
import subprocess  # nosec B404
import sys
import threading
from dataclasses import dataclass
from typing import IO, Any, Sequence

from adapters.ingress import sanitize_call
from core.errors import GuardError
from core.model import Verdict
from medical_privacy_guard import Guard

__all__ = ["REFUSED_CODE", "GatewayError", "GatewaySettings", "McpGateway"]

#: Application-defined JSON-RPC error code for a refusal.
#:
#: The specification reserves ``-32020..-32099`` for itself and marks
#: ``-32000..-32019`` legacy, saying new codes SHOULD be allocated outside the
#: JSON-RPC reserved range (``-32768..-32000``) altogether. A positive code is
#: therefore the only safe choice; ``-32001`` would collide with a legacy
#: allocation.
REFUSED_CODE = 4001

#: Request parameter fields that carry caller-supplied content. ``arguments`` is
#: the ordinary tool call; ``inputResponses`` carries the user's answers on a
#: multi-round-trip retry, and can hold the same identifiers.
_INSPECTED_FIELDS = ("arguments", "inputResponses")


class GatewayError(GuardError):
    """Raised when the wrapped server cannot be started.

    A ``GuardError`` so the CLI reports it as a configuration error with exit
    code 4 instead of surfacing a traceback and exiting 1.
    """


@dataclass(frozen=True)
class GatewaySettings:
    """Everything the gateway needs to decide, and nothing else."""

    profile: str = "external-ai-strict"
    recipient: str = "external_unknown"
    purpose: str = "external_ai_assistance"
    dictionary_path: str | None = None
    audit_dir: str | None = None


def _parse(raw: bytes) -> dict[str, Any] | list[Any] | None:
    """Parse one NDJSON line into a JSON object or array, else None.

    An array is returned rather than discarded, because a JSON-RPC batch is the
    one shape that can hide a ``tools/call`` from a check that only looks at
    objects. A line the gateway cannot parse is not repaired: it is forwarded and
    left to the upstream server, which owns the protocol.
    """
    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return message if isinstance(message, (dict, list)) else None


def _restore(original: Any, sanitized: str) -> Any:
    """Put a sanitized value back into the shape the caller used.

    A structured payload comes back from the guard as serialized text; a string
    argument comes back as a string.
    """
    if isinstance(original, (dict, list)):
        return json.loads(sanitized)
    return sanitized


class McpGateway:
    """Spawns an MCP server and mediates one stdio session with it."""

    def __init__(
        self,
        server_command: Sequence[str],
        settings: GatewaySettings,
        *,
        stdin: IO[bytes] | None = None,
        stdout: IO[bytes] | None = None,
    ) -> None:
        self._server_command = list(server_command)
        self._settings = settings
        # Byte streams throughout. The wire format is newline-delimited JSON, and
        # a text stream would translate "\n" to the platform line ending on the
        # way out — a stray CR is a parse error for the peer — and would accept a
        # foreign line ending on the way in. Neither is acceptable in a proxy
        # that promises to forward messages unchanged.
        self._stdin = stdin if stdin is not None else sys.stdin.buffer
        self._stdout = stdout if stdout is not None else sys.stdout.buffer
        # Two writers share stdout: the upstream reader thread and a refusal
        # written from this thread. Without the lock their lines can interleave.
        self._write_lock = threading.Lock()
        self._guard = Guard(
            profile=settings.profile,
            dictionary_path=settings.dictionary_path,
            audit_dir=settings.audit_dir,
        )
        self.intercepted = 0
        self.rewritten = 0
        self.refused = 0

    # -- process lifecycle --------------------------------------------------

    def run(self) -> int:
        """Proxy until the client stops sending; return the server's exit code.

        The upstream exit code is propagated rather than swallowed. A gateway
        that restarted a dead server would be making a decision that belongs to
        the client, and would hide the failure while doing it.
        """
        # argv as a list, never a shell string: the command is the operator's own
        # (it comes from the CLI's argv after --), and shell=False keeps it from
        # being re-parsed. B603 asks the caller to confirm exactly this.
        try:
            process = subprocess.Popen(  # nosec B603
                self._server_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                # Inherit stderr so the server's logging reaches the operator with
                # no code of ours in the path. The specification permits the
                # server to write anything it likes there.
                stderr=None,
                # Binary, so no newline translation happens in either direction.
                bufsize=0,
            )
        except OSError as exc:
            # A missing or unexecutable command is an operator error, and should
            # read like one rather than like a crash.
            raise GatewayError(f"cannot start the MCP server: {exc}") from exc
        reader = threading.Thread(target=self._pump_upstream, args=(process,), daemon=True)
        reader.start()

        def _on_terminate(signum, _frame):
            # SIGTERM's default action kills the gateway and leaves the wrapped
            # server running, holding the upstream connection. Route it through
            # the same path as Ctrl+C so the server is taken down with us.
            raise KeyboardInterrupt

        previous = None
        try:
            previous = signal.signal(signal.SIGTERM, _on_terminate)
        except ValueError:
            # Not on the main thread, so the caller owns signal handling.
            pass

        interrupted = False
        try:
            self._pump_client(process)
        except (BrokenPipeError, OSError):
            # The server exited mid-session. Its exit code is the answer.
            pass
        except KeyboardInterrupt:
            interrupted = True
        finally:
            if previous is not None:
                signal.signal(signal.SIGTERM, previous)
            # Closing stdin is the protocol's own shutdown signal; a server is
            # expected to exit on it.
            try:
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            if interrupted and process.poll() is None:
                process.terminate()

        try:
            code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # A server that ignores both stdin EOF and SIGTERM does not get to
            # keep the gateway alive.
            process.kill()
            code = process.wait()
        # Let the reader drain the server's last lines before returning, so a
        # caller that captured stdout sees the whole session.
        reader.join(timeout=5)
        return code

    def _pump_client(self, process: subprocess.Popen) -> None:
        """Client to server, inspecting every message on the way."""
        for line in self._stdin:
            if not line.strip():
                continue
            self._handle(line, process)

    def _pump_upstream(self, process: subprocess.Popen) -> None:
        """Server to client, untouched."""
        if process.stdout is None:
            return
        try:
            for line in process.stdout:
                self._write(line)
        except (BrokenPipeError, OSError):
            # The client went away. There is nobody left to forward to, and the
            # main thread discovers the same thing when its own stdin ends.
            # Without this the reader dies with a traceback on stderr, which
            # reads like a crash rather than a disconnect.
            pass

    # -- forwarding ---------------------------------------------------------

    def _write(self, raw: bytes) -> None:
        with self._write_lock:
            self._stdout.write(raw)
            self._stdout.flush()

    def _forward(self, raw: bytes, process: subprocess.Popen) -> None:
        if process.stdin is None:
            return
        process.stdin.write(raw if raw.endswith(b"\n") else raw + b"\n")
        process.stdin.flush()

    @staticmethod
    def _encode(message: dict[str, Any]) -> bytes:
        return json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"

    # -- interception -------------------------------------------------------

    def _handle(self, raw: bytes, process: subprocess.Popen) -> None:
        message = _parse(raw)
        if isinstance(message, list):
            self._handle_batch(raw, message, process)
            return
        if message is None or message.get("method") != "tools/call":
            # Everything else — server/discover, initialize, notifications,
            # resources/read — is forwarded verbatim, byte for byte. The gateway
            # has no opinion about the protocol, only about what a tool call
            # would disclose.
            self._forward(raw, process)
            return
        self._intercept(raw, message, process)

    def _handle_batch(
        self, raw: bytes, batch: list[Any], process: subprocess.Popen
    ) -> None:
        """Refuse a batch that carries a tool call; forward any other batch.

        MCP does not define JSON-RPC batching, so a batch is already outside the
        protocol. A batch cannot be rewritten in part without changing its
        meaning, so the only safe answer for one containing ``tools/call`` is to
        refuse the whole thing. Forwarding it would let a call reach the server
        unchecked — the same fail-open shape as the read-only leaf defect, one
        layer further out.
        """
        for item in batch:
            if isinstance(item, dict) and item.get("method") == "tools/call":
                self.refused += 1
                self._refuse(None, "batch requests carrying tools/call are not supported")
                return
        self._forward(raw, process)

    def _intercept(
        self, raw: bytes, message: dict[str, Any], process: subprocess.Popen
    ) -> None:
        self.intercepted += 1
        params = message.get("params")
        if not isinstance(params, dict):
            self._forward(raw, process)
            return

        for field in _INSPECTED_FIELDS:
            if field not in params:
                continue
            action, value, reason = self._decide(params[field])
            if action == "refuse":
                self.refused += 1
                if "id" in message:
                    self._refuse(message["id"], reason)
                # A tools/call without an id is a notification, and JSON-RPC
                # forbids replying to one. The call was not forwarded, so the
                # refusal is complete without a reply.
                return
            if action == "rewrite":
                self.rewritten += 1
                # ``params`` is the mapping ``message`` already holds, so the
                # rewrite is visible to the serialization below.
                params[field] = value

        self._forward(self._encode(message), process)

    def _decide(self, value: Any) -> tuple[str, Any, str | None]:
        """Return ``(action, rewritten_value, reason)`` for one parameter field.

        Three actions, not two. ``ALLOW`` forwards, ``SANITIZE`` rewrites, and
        anything else is refused. Collapsing SANITIZE into "allowed" is the
        defect this method exists to prevent: the verdict means the call may
        proceed *only* with the identifiers removed.
        """
        if value is None:
            return "forward", None, None
        try:
            result = sanitize_call(self._guard, value, self._settings.recipient, self._settings.purpose)
        except GuardError as exc:
            return "refuse", None, f"guard could not evaluate the call ({type(exc).__name__})"

        verdict = result.decision_before.verdict
        if verdict is Verdict.ALLOW:
            return "forward", None, None
        if verdict is Verdict.SANITIZE:
            payload = result.sanitized_payload
            if payload is None:
                return "refuse", None, "sanitization did not verify"
            return "rewrite", _restore(value, payload.content), None
        return "refuse", None, f"disclosure withheld ({verdict.value})"

    def _refuse(self, request_id: Any, reason: str | None) -> None:
        self._write(
            self._encode(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": REFUSED_CODE,
                        "message": reason or "disclosure withheld",
                    },
                }
            )
        )
