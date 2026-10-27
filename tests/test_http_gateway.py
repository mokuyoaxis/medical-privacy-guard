"""Zero-code HTTP gateway integration tests with a synthetic upstream."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from medical_privacy_guard.adapters.http_gateway import HttpGateway, HttpGatewaySettings
from medical_privacy_guard.core.errors import GuardError


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        body = json.loads(raw)
        self.server.requests.append(  # type: ignore[attr-defined]
            {"path": self.path, "headers": dict(self.headers), "body": body}
        )
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n')
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            return
        payload = json.dumps(
            {"id": "synthetic-response", "choices": [{"message": {"content": "ok"}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.fixture()
def gateway_server(upstream):
    settings = HttpGatewaySettings(
        upstream=f"http://127.0.0.1:{upstream.server_address[1]}",
        port=0,
        timeout=3,
    )
    server = HttpGateway(settings).server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _post(server, path: str, body: dict, *, headers: dict | None = None) -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_address[1]}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _post_raw(server, path: str, body: bytes) -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_address[1]}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_healthz(gateway_server):
    request = urllib.request.Request(
        f"http://127.0.0.1:{gateway_server.server_address[1]}/healthz"
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        body = json.loads(response.read())
    assert response.status == 200
    assert body["status"] == "ok"
    assert "upstream" not in body


def test_openai_request_is_sanitized_before_upstream(gateway_server, upstream):
    status, _ = _post(
        gateway_server,
        "/v1/chat/completions",
        {
            "model": "synthetic-model",
            "messages": [{"role": "user", "content": "电话13800000000"}],
        },
        headers={"Authorization": "Bearer synthetic-key"},
    )
    assert status == 200
    assert len(upstream.requests) == 1
    sent = upstream.requests[0]
    assert sent["path"] == "/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer synthetic-key"
    assert "13800000000" not in json.dumps(sent["body"], ensure_ascii=False)


def test_anthropic_system_and_message_are_sanitized(gateway_server, upstream):
    status, _ = _post(
        gateway_server,
        "/v1/messages",
        {
            "model": "synthetic-model",
            "system": "医院：测试医院，电话13800000000",
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "患者电话13800000000"}],
                }
            ],
        },
    )
    assert status == 200
    sent = upstream.requests[0]
    assert sent["path"] == "/v1/messages"
    assert "13800000000" not in json.dumps(sent["body"], ensure_ascii=False)


def test_block_is_returned_without_upstream_call(gateway_server, upstream):
    status, body = _post(
        gateway_server,
        "/v1/chat/completions",
        {
            "model": "synthetic-model",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {"url": "https://example.invalid/image.png"},
                        }
                    ],
                }
            ],
        },
    )
    assert status == 403
    assert b"privacy_guard_block" in body
    assert upstream.requests == []


def test_ask_is_withheld_without_raw_values(gateway_server, upstream):
    status, body = _post(
        gateway_server,
        "/v1/chat/completions",
        {
            "model": "synthetic-model",
            "messages": [{"role": "user", "content": "诊断：HIV感染；当前用药多替拉韦"}],
        },
    )
    assert status == 403
    assert b"privacy_guard_ask" in body
    assert b"HIV" not in body
    assert upstream.requests == []


def test_invalid_json_returns_400(gateway_server, upstream):
    status, body = _post_raw(gateway_server, "/v1/chat/completions", b"{")
    assert status == 400
    assert b"invalid_request_error" in body
    assert upstream.requests == []


def test_unknown_path_returns_404(gateway_server):
    status, body = _post(gateway_server, "/v1/unknown", {})
    assert status == 404
    assert b"not_found" in body


def test_oversized_body_is_rejected():
    settings = HttpGatewaySettings(
        upstream="http://127.0.0.1:1", port=0, max_body_bytes=10
    )
    server = HttpGateway(settings).server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = _post_raw(
            server, "/v1/chat/completions", b'{"messages":["too long"]}'
        )
        assert status == 413
        assert b"request_too_large" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_streaming_response_is_passed_through(gateway_server):
    request = urllib.request.Request(
        f"http://127.0.0.1:{gateway_server.server_address[1]}/v1/chat/completions",
        data=json.dumps(
            {
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": "电话13800000000"}],
                "stream": True,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read()
        assert response.headers.get_content_type() == "text/event-stream"
    assert b"data: [DONE]" in body


def test_non_loopback_binding_requires_explicit_opt_in():
    with pytest.raises(GuardError):
        HttpGateway(
            HttpGatewaySettings(upstream="http://127.0.0.1:1", host="0.0.0.0", port=0)
        )
