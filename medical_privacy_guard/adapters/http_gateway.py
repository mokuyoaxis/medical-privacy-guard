"""Zero-code HTTP gateway for OpenAI-compatible and Anthropic clients.

The gateway is a local HTTP reverse proxy. An application points its existing
SDK at the gateway's ``base_url``; the gateway evaluates and rewrites the
request body with the same ``OpenAIGuard``/``AnthropicGuard`` logic used by the
in-process wrappers, then forwards it to one configured upstream. Responses
are passed through unchanged: this is an egress guard, not a response scanner.

Only two request paths are accepted:

- ``POST /v1/chat/completions`` (OpenAI-compatible chat completions)
- ``POST /v1/messages`` (Anthropic Messages API)

``GET /healthz`` is unauthenticated and returns no configuration details.

Security boundaries:

- the upstream is fixed at startup; a request cannot select an arbitrary host;
- the default listen address is ``127.0.0.1``; non-loopback binding requires
  an explicit ``allow_remote`` setting;
- request bodies are size-limited and must be JSON objects with Content-Length;
- caller credentials are forwarded, never stored or echoed;
- error responses contain reason codes and risk metadata, never payload text.
"""

from __future__ import annotations

import http.client
import json
import socket
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from medical_privacy_guard import Guard, __version__
from medical_privacy_guard.adapters.anthropic_compat import AnthropicGuard
from medical_privacy_guard.adapters.openai_compat import OpenAIGuard
from medical_privacy_guard.core.errors import (
    DisclosureBlocked,
    GuardError,
    HumanApprovalRequired,
    VerificationFailed,
)

__all__ = ["HttpGateway", "HttpGatewaySettings"]

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_REQUEST_SKIP = _HOP_BY_HOP | {"content-length", "host"}

_ROUTES = ("/v1/chat/completions", "/v1/messages")


@dataclass(frozen=True)
class HttpGatewaySettings:
    """Configuration for the local HTTP gateway."""

    upstream: str
    host: str = "127.0.0.1"
    port: int = 8787
    profile: str = "external-ai-strict"
    recipient: str = "external_unknown"
    purpose: str = "EXTERNAL_AI_ASSISTANCE"
    audit_dir: str | None = None
    dictionary_path: str | None = None
    timeout: float = 60.0
    max_body_bytes: int = 10 * 1024 * 1024
    allow_remote: bool = False


class _ClientError(Exception):
    def __init__(self, status: int, error_type: str, message: str) -> None:
        self.status = status
        self.error_type = error_type
        self.message = message
        super().__init__(message)


class _CaptureClient:
    """Duck-typed client that captures the adapter's sanitized request."""

    def __init__(self) -> None:
        self.request: dict[str, Any] | None = None
        self.chat = _ChatCapture(self)
        self.messages = _MessagesCapture(self)


class _ChatCapture:
    def __init__(self, owner: _CaptureClient) -> None:
        self.completions = _CompletionsCapture(owner)


class _CompletionsCapture:
    def __init__(self, owner: _CaptureClient) -> None:
        self._owner = owner

    def create(self, **kwargs: Any) -> dict[str, Any]:
        self._owner.request = kwargs
        return kwargs


class _MessagesCapture:
    def __init__(self, owner: _CaptureClient) -> None:
        self._owner = owner

    def create(self, **kwargs: Any) -> dict[str, Any]:
        self._owner.request = kwargs
        return kwargs


class HttpGateway:
    """A local reverse proxy that applies the guard before forwarding."""

    def __init__(self, settings: HttpGatewaySettings) -> None:
        if settings.max_body_bytes <= 0:
            raise GuardError("max_body_bytes must be positive")
        if settings.timeout <= 0:
            raise GuardError("timeout must be positive")
        self.settings = settings
        self._upstream = _parse_upstream(settings.upstream)
        if not settings.allow_remote and settings.host not in {
            "127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1",
        }:
            raise GuardError(
                "refusing to bind the HTTP gateway to a non-loopback address "
                "without allow_remote"
            )
        self._guard = Guard(
            profile=settings.profile,
            dictionary_path=settings.dictionary_path,
            audit_dir=settings.audit_dir,
        )

    def server(self) -> ThreadingHTTPServer:
        """Create the listening server without starting it (useful for tests)."""
        httpd = ThreadingHTTPServer((self.settings.host, self.settings.port), _RequestHandler)
        httpd.daemon_threads = True
        httpd.gateway = self  # type: ignore[attr-defined]
        return httpd

    def serve_forever(self) -> None:
        httpd = self.server()
        host, port = httpd.server_address[:2]
        print(
            f"medical-privacy-guard gateway listening on http://{host}:{port} "
            f"-> {self.settings.upstream}",
            file=sys.stderr,
        )
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()

    def sanitize_request(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """Run the matching adapter and return its rewritten request body."""
        capture = _CaptureClient()
        if path == "/v1/chat/completions":
            OpenAIGuard(
                capture,
                self._guard,
                recipient=self.settings.recipient,
                purpose=self.settings.purpose,
                audit_dir=self.settings.audit_dir,
            ).completions_create(**dict(body))
        elif path == "/v1/messages":
            AnthropicGuard(
                capture,
                self._guard,
                recipient=self.settings.recipient,
                purpose=self.settings.purpose,
                audit_dir=self.settings.audit_dir,
            ).messages_create(**dict(body))
        else:
            raise _ClientError(404, "not_found", "unknown gateway path")
        if capture.request is None:
            raise GuardError("adapter produced no request")
        return capture.request

    def target_url(self, request_path: str) -> str:
        """Build the fixed upstream URL for a request path and query."""
        request = urlsplit(request_path)
        base = self._upstream
        base_path = base.path.rstrip("/")
        if base_path and request.path.startswith(base_path + "/"):
            path = request.path
        else:
            path = base_path + request.path
        return urlunsplit((base.scheme, base.netloc, path, request.query, ""))


def _parse_upstream(raw: str):
    parsed = urlsplit(raw)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GuardError(
            "upstream must be an http(s) origin such as https://api.openai.com"
        )
    return parsed


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"medical-privacy-guard/{__version__}"

    @property
    def gateway(self) -> HttpGateway:
        return self.server.gateway  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        # Never log request bodies, authorization headers or response content.
        sys.stderr.write(f"{self.address_string()} - {format % args}\n")

    def do_GET(self) -> None:  # noqa: N802
        if urlsplit(self.path).path == "/healthz":
            self._send_json(200, {"status": "ok", "service": "medical-privacy-guard"})
        else:
            self._send_json(404, _error_body("not_found", "unknown gateway path"))

    def do_HEAD(self) -> None:  # noqa: N802
        if urlsplit(self.path).path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in _ROUTES:
            self._send_json(404, _error_body("not_found", "unknown gateway path"))
            return
        try:
            body = self._read_body()
        except _ClientError as exc:
            self._send_json(exc.status, _error_body(exc.error_type, exc.message))
            return
        try:
            sanitized = self.gateway.sanitize_request(path, body)
        except DisclosureBlocked as exc:
            self._send_json(403, _decision_error("BLOCK", "privacy_guard_block", exc.decision))
            return
        except HumanApprovalRequired as exc:
            self._send_json(403, _decision_error("ASK", "privacy_guard_ask", exc.decision))
            return
        except VerificationFailed as exc:
            self._send_json(
                422,
                _decision_error(
                    "SANITIZE_FAILED", "privacy_guard_verification_failed", exc.decision
                ),
            )
            return
        except GuardError as exc:
            sys.stderr.write(f"gateway guard error: {type(exc).__name__}\n")
            self._send_json(
                400,
                _error_body(
                    "invalid_request_error", "request rejected by the privacy guard"
                ),
            )
            return
        self._forward(path, sanitized)

    def _read_body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise _ClientError(411, "length_required", "Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise _ClientError(400, "invalid_request_error", "invalid Content-Length") from exc
        if length < 0:
            raise _ClientError(400, "invalid_request_error", "invalid Content-Length")
        if length > self.gateway.settings.max_body_bytes:
            raise _ClientError(413, "request_too_large", "request body exceeds the gateway limit")
        data = self.rfile.read(length)
        if len(data) != length:
            raise _ClientError(400, "invalid_request_error", "incomplete request body")
        try:
            body = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _ClientError(400, "invalid_request_error", "request body must be UTF-8 JSON") from exc
        if not isinstance(body, dict):
            raise _ClientError(400, "invalid_request_error", "request body must be a JSON object")
        return body

    def _forward_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        for name, value in self.headers.items():
            if name.lower() in _REQUEST_SKIP:
                continue
            headers[name] = value
        headers["Content-Type"] = "application/json"
        headers["Connection"] = "close"
        return headers

    def _forward(self, path: str, body: Mapping[str, Any]) -> None:
        target = self.gateway.target_url(path)
        parsed = urlsplit(target)
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        connection_class = (
            http.client.HTTPSConnection if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_class(parsed.netloc, timeout=self.gateway.settings.timeout)
        try:
            connection.request(
                "POST",
                urlunsplit(("", "", parsed.path, parsed.query, "")),
                body=payload,
                headers=self._forward_headers(),
            )
            response = connection.getresponse()
        except (OSError, socket.timeout, http.client.HTTPException) as exc:
            connection.close()
            self._send_json(502, _error_body("upstream_error", str(exc) or "upstream request failed"))
            return
        try:
            self._send_upstream(response, streaming=bool(body.get("stream")))
        finally:
            response.close()
            connection.close()
            self.close_connection = True

    def _send_upstream(self, response: http.client.HTTPResponse, *, streaming: bool) -> None:
        headers = [
            (name, value)
            for name, value in response.getheaders()
            if name.lower() not in _HOP_BY_HOP
            and name.lower() not in {"content-length", "connection"}
        ]
        content_type = response.getheader("Content-Type", "")
        streaming = streaming or content_type.lower().startswith("text/event-stream")
        if streaming:
            self.send_response(response.status, response.reason)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        else:
            data = response.read()
            self.send_response(response.status, response.reason)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

    def _send_json(self, status: int, body: Mapping[str, Any]) -> None:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True


def _decision_error(code: str, error_type: str, decision) -> dict[str, Any]:
    return {
        "error": {
            "message": f"Request withheld by medical privacy guard ({code})",
            "type": error_type,
            "code": code,
            "reason_codes": [reason.value for reason in decision.reason_codes],
            "risk_level": decision.risk.level.value,
            "risk_score": decision.risk.score,
            "policy_version": decision.policy_version,
        }
    }


def _error_body(error_type: str, message: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": error_type, "code": error_type}}
