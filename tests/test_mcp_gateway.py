"""The MCP stdio gateway.

The behaviour these tests pin, in order of how much it matters:

1. A SANITIZE verdict rewrites the arguments rather than letting them through.
   The first draft of this design treated SANITIZE as permission and forwarded a
   raw phone number to the tool; the upstream echo in these tests is what makes
   that visible.
2. A refusal reaches the client as a JSON-RPC error and never reaches the
   server, and the stream keeps working afterwards.
3. Everything that is not tools/call is forwarded byte-for-byte, because the
   gateway has no opinion about the protocol.

The upstream server echoes back the arguments it received, so every test can
assert on what actually crossed the boundary rather than on what the gateway
intended to send.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from adapters.mcp_gateway import REFUSED_CODE, GatewayError, GatewaySettings, McpGateway

#: An upstream MCP server that reports what it was given.
UPSTREAM = r"""
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        # A real server would answer with a parse error. The test server only has
        # to prove the gateway forwarded the line rather than swallowing it.
        print("upstream: unparseable line", file=sys.stderr)
        continue
    if isinstance(msg, list):
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": "batch",
                                     "result": {"received": len(msg)}}) + "\n")
        sys.stdout.flush()
        continue
    if not isinstance(msg, dict) or "id" not in msg:
        continue
    method = msg.get("method")
    if method == "tools/call":
        params = msg.get("params")
        received = {}
        if isinstance(params, dict):
            received = {k: params.get(k) for k in ("arguments", "inputResponses") if k in params}
        result = {"resultType": "complete", "isError": False,
                  "content": [{"type": "text", "text": json.dumps(received, ensure_ascii=False)}]}
    else:
        result = {"echo": method}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


def _call(request_id, arguments, name="tool", **extra):
    params = {"name": name, "arguments": arguments}
    params.update(extra)
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


def run_gateway(messages, *, recipient="external_unknown", profile="external-ai-strict"):
    """Run one session and return (exit code, parsed client-visible lines, gateway).

    The streams are bytes on purpose: that is what the gateway talks, and it is
    the only way a test can see exactly what crossed the boundary.
    """
    payload = ("\n".join(json.dumps(m, ensure_ascii=False) for m in messages) + "\n").encode("utf-8")
    stdout = io.BytesIO()
    gateway = McpGateway(
        [sys.executable, "-c", UPSTREAM],
        GatewaySettings(recipient=recipient, profile=profile),
        stdin=io.BytesIO(payload),
        stdout=stdout,
    )
    code = gateway.run()
    text = stdout.getvalue().decode("utf-8")
    lines = [json.loads(line) for line in text.splitlines() if line.strip()]
    return code, lines, gateway


def by_id(lines):
    return {line.get("id"): line for line in lines if line.get("id") is not None}


def upstream_saw(lines, request_id):
    """The arguments the upstream server reported receiving for one request."""
    text = by_id(lines)[request_id]["result"]["content"][0]["text"]
    return json.loads(text)


# -- the three actions -------------------------------------------------------


class TestThreeWayDecision:
    def test_allow_is_forwarded_unchanged(self):
        _, lines, gateway = run_gateway([_call(1, {"note": "普通随访"})])
        assert gateway.intercepted == 1
        assert gateway.rewritten == 0 and gateway.refused == 0
        assert upstream_saw(lines, 1)["arguments"] == {"note": "普通随访"}

    def test_sanitize_rewrites_before_forwarding(self):
        """The defect this module exists to prevent.

        SANITIZE is not permission. If the gateway forwards the original
        arguments here, the phone number crosses the boundary and the upstream
        echo shows it.
        """
        _, lines, gateway = run_gateway([_call(1, {"note": "联系电话13800000000"})])
        assert gateway.rewritten == 1 and gateway.refused == 0
        forwarded = upstream_saw(lines, 1)["arguments"]
        assert "13800000000" not in json.dumps(forwarded, ensure_ascii=False)
        assert forwarded != {"note": "联系电话13800000000"}

    def test_a_refusal_never_reaches_the_server(self):
        _, lines, gateway = run_gateway([_call(1, {"mrn": 1234567})])
        assert gateway.refused == 1
        entry = by_id(lines)[1]
        assert "error" in entry
        assert entry["error"]["code"] == REFUSED_CODE
        # Nothing came back from upstream, so the call was held at the gateway.
        assert "result" not in entry

    def test_the_refusal_code_is_not_a_legacy_allocation(self):
        """-32000..-32019 is legacy and -32020..-32099 belongs to the spec.

        The specification says new codes SHOULD be allocated outside the JSON-RPC
        reserved range entirely, so -32001 would have been wrong.
        """
        assert REFUSED_CODE > 0
        assert not (-32768 <= REFUSED_CODE <= -32000)


# -- the stream --------------------------------------------------------------


class TestStreamIntegrity:
    def test_a_refusal_does_not_break_the_session(self):
        _, lines, gateway = run_gateway([
            _call(1, {"mrn": 1234567}),          # refused
            _call(2, {"note": "普通随访"}),       # still works
        ])
        assert gateway.refused == 1
        assert "error" in by_id(lines)[1]
        assert by_id(lines)[2]["result"]["resultType"] == "complete"

    def test_non_tool_methods_are_forwarded(self):
        _, lines, gateway = run_gateway([
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
        ])
        assert gateway.intercepted == 0
        assert by_id(lines)[1]["result"] == {"echo": "server/discover"}

    def test_an_unparseable_line_is_forwarded(self):
        """The gateway does not repair the stream; the server owns the protocol."""
        payload = b"not json at all\n"
        stdout = io.BytesIO()
        gateway = McpGateway(
            [sys.executable, "-c", UPSTREAM],
            GatewaySettings(),
            stdin=io.BytesIO(payload),
            stdout=stdout,
        )
        code = gateway.run()
        assert code == 0
        assert gateway.intercepted == 0

    def test_notifications_are_forwarded(self):
        _, lines, gateway = run_gateway([
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
        ])
        assert gateway.intercepted == 0
        # A notification has no id, so nothing comes back; the session still ends.
        assert lines == []

    def test_the_exit_code_is_propagated(self):
        code, _, _ = run_gateway([_call(1, {"note": "普通随访"})])
        assert code == 0


# -- multi-round-trip retries ------------------------------------------------


class TestInputResponses:
    def test_input_responses_are_inspected_too(self):
        """A retry carries the user's answers, which can hold the same identifiers."""
        _, lines, gateway = run_gateway([
            _call(1, {"query": "普通"}, inputResponses={"note": "联系电话13800000000"}),
        ])
        assert gateway.rewritten == 1
        forwarded = upstream_saw(lines, 1)["inputResponses"]
        assert "13800000000" not in json.dumps(forwarded, ensure_ascii=False)

    def test_a_refusal_covers_either_field(self):
        _, lines, gateway = run_gateway([
            _call(1, {"query": "普通"}, inputResponses={"mrn": 1234567}),
        ])
        assert gateway.refused == 1
        assert "error" in by_id(lines)[1]


# -- degenerate input --------------------------------------------------------


class TestMalformedCalls:
    @pytest.mark.parametrize(
        "params",
        [None, "not-a-mapping", 42, []],
    )
    def test_non_mapping_params_are_forwarded(self, params):
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
        _, lines, gateway = run_gateway([message])
        assert gateway.refused == 0
        assert by_id(lines)[1]["result"]["resultType"] == "complete"

    def test_a_call_without_arguments_is_forwarded(self):
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "ping"}}
        _, lines, gateway = run_gateway([message])
        assert gateway.intercepted == 1
        assert gateway.refused == 0 and gateway.rewritten == 0
        assert by_id(lines)[1]["result"]["resultType"] == "complete"


# -- batches -----------------------------------------------------------------


class TestBatches:
    """MCP does not define JSON-RPC batching, so a batch is already out of protocol.

    The gateway's first draft inspected objects only, so a tools/call inside an
    array reached the server with its arguments untouched — the same fail-open
    shape as the read-only leaf defect, one layer further out. A batch cannot be
    rewritten in part without changing its meaning, so one carrying a tool call
    is refused whole.
    """

    def test_a_batch_carrying_a_tool_call_is_refused(self):
        _, lines, gateway = run_gateway([[_call(1, {"body": "联系电话13800000000"})]])
        assert gateway.refused == 1
        assert gateway.intercepted == 0
        assert lines[0]["error"]["code"] == REFUSED_CODE
        # Nothing came back from upstream: the batch never left the gateway.
        assert "result" not in lines[0]

    def test_a_batch_without_a_tool_call_is_forwarded(self):
        batch = [{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}]
        _, lines, gateway = run_gateway([batch])
        assert gateway.refused == 0
        assert lines[0]["result"] == {"received": 1}

    def test_a_tool_call_hidden_among_other_calls_is_refused(self):
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
            _call(2, {"body": "联系电话13800000000"}),
        ]
        _, lines, gateway = run_gateway([batch])
        assert gateway.refused == 1
        assert "error" in lines[0]


# -- operator errors ---------------------------------------------------------


class TestStartupFailure:
    def test_a_missing_server_command_raises_a_guard_error(self):
        """An unstartable command is an operator error, not a crash.

        Without this the CLI surfaced a traceback and exited 1, which is neither
        the documented configuration-error code nor readable.
        """
        gateway = McpGateway(
            ["/nonexistent/mcp-server"], GatewaySettings(),
            stdin=io.BytesIO(b""), stdout=io.BytesIO(),
        )
        with pytest.raises(GatewayError, match="cannot start the MCP server"):
            gateway.run()

    def test_the_cli_reports_it_as_a_configuration_error(self, capsys):
        from cli.main import EXIT_ERROR, main

        rc = main(["mcp-gateway", "--recipient", "external_unknown",
                   "--", "/nonexistent/mcp-server"])
        assert rc == EXIT_ERROR
        assert "cannot start the MCP server" in capsys.readouterr().err


# -- failure paths found by adversarial review -------------------------------


class _DeadPipe(io.RawIOBase):
    """A stdout that fails the way a disconnected client does."""

    def __init__(self):
        self.attempts = 0

    def writable(self):
        return True

    def write(self, _data):
        self.attempts += 1
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self):
        pass


class TestDisconnectedClient:
    def test_a_broken_client_stdout_does_not_kill_the_reader(self):
        """The reader thread used to die with a traceback on stderr.

        A disconnected client is a disconnect, not a crash, and the main thread
        already learns the same thing when its own stdin ends.
        """
        sink = _DeadPipe()
        gateway = McpGateway(
            [sys.executable, "-c", UPSTREAM], GatewaySettings(recipient="external_unknown"),
            stdin=io.BytesIO(
                (json.dumps(_call(1, {"note": "普通随访"})) + "\n").encode("utf-8")
            ),
            stdout=sink,
        )
        assert gateway.run() == 0
        assert sink.attempts >= 1


class TestNotifications:
    def test_a_tools_call_without_an_id_is_refused_without_a_reply(self):
        """JSON-RPC forbids replying to a notification.

        The call is still not forwarded: a tools/call sent as a notification
        would otherwise execute a tool with whatever arguments it carried.
        """
        message = {"jsonrpc": "2.0", "method": "tools/call",
                   "params": {"name": "t", "arguments": {"mrn": 1234567}}}
        _, lines, gateway = run_gateway([message])
        assert gateway.refused == 1
        assert lines == []

    def test_a_notification_without_sensitive_arguments_is_forwarded(self):
        message = {"jsonrpc": "2.0", "method": "tools/call",
                   "params": {"name": "t", "arguments": {"note": "普通随访"}}}
        _, _, gateway = run_gateway([message])
        assert gateway.refused == 0
