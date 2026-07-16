"""Loopback-only HTTP adapter over the typed synthetic scenario protocol."""

from __future__ import annotations

import re
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from typing import Any
from urllib.parse import unquote, urlsplit

from simulator.corpus import canonical_json
from simulator.engine import ScenarioEngine
from simulator.mail import InMemoryMailCapture
from simulator.protocol import (
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
    ResourceLimitError,
    ScenarioName,
    ScenarioState,
    SimulatorProtocolError,
)

LOOPBACK_ADDRESS = "127.0.0.1"
MAX_PATH_BYTES = 512
ROUTE = re.compile(
    r"/v1/scenarios/(?P<scenario>[a-z_]+)/sessions/"
    r"(?P<session>[a-z0-9-]+)/next/(?P<expected>[a-z_]+)"
)


@dataclass(frozen=True, slots=True)
class WebRequest:
    method: str
    path: str
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class WebResponse:
    status_code: int
    body: bytes
    content_type: str = "application/json"


def _error(status_code: int, code: str) -> WebResponse:
    return WebResponse(status_code, canonical_json({"error": code}))


class LocalWebSimulator:
    def __init__(self, engine: ScenarioEngine, mail: InMemoryMailCapture) -> None:
        self._engine = engine
        self._mail = mail

    def handle(self, request: WebRequest) -> WebResponse:
        if len(request.body) > MAX_REQUEST_BODY_BYTES:
            return _error(413, "request_too_large")
        if request.method != "GET" or request.body:
            return _error(405, "closed_fixture_method")
        if len(request.path.encode("utf-8")) > MAX_PATH_BYTES:
            return _error(414, "path_too_large")
        parsed = urlsplit(request.path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            return _error(400, "noncanonical_path")
        decoded = unquote(parsed.path)
        if "\\" in decoded or "\x00" in decoded or ".." in decoded.split("/"):
            return _error(400, "noncanonical_path")
        match = ROUTE.fullmatch(decoded)
        if match is None:
            return _error(404, "unknown_fixture_route")
        try:
            scenario = ScenarioName(match.group("scenario"))
            expected = ScenarioState(match.group("expected"))
            result = self._engine.advance(
                scenario_name=scenario,
                session_id=match.group("session"),
                expected_state=expected,
            )
            if result.mail is not None:
                self._mail.capture(result.mail)
        except ValueError:
            return _error(400, "unknown_fixture_value")
        except ResourceLimitError:
            return _error(429, "fixture_resource_limit")
        except SimulatorProtocolError:
            return _error(409, "fixture_transition_denied")

        body = canonical_json(
            {
                "body": result.body.decode("utf-8"),
                "evidence": result.evidence.decode("utf-8"),
                "occurred_at": result.occurred_at,
                "scenario": result.scenario.value,
                "state": result.state.value,
            }
        )
        if len(body) > MAX_RESPONSE_BODY_BYTES:
            return _error(500, "fixture_response_limit")
        return WebResponse(result.status_code, body)


class LoopbackHTTPServer(ThreadingHTTPServer):
    """HTTP server whose bind path never performs hostname lookup."""

    allow_reuse_address = False

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        if host != LOOPBACK_ADDRESS:
            raise RuntimeError("simulator server did not bind the fixed loopback address")
        self.server_name = LOOPBACK_ADDRESS
        self.server_port = port


def _handler_for(fixture: LocalWebSimulator) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "MyCogniSyntheticFixture/1"
        sys_version = ""

        def do_GET(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
            self._dispatch()

        def _dispatch(self) -> None:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError:
                self._write(_error(400, "invalid_content_length"))
                return
            if not 0 <= length <= MAX_REQUEST_BODY_BYTES:
                self._write(_error(413, "request_too_large"))
                return
            response = fixture.handle(
                WebRequest(method=self.command, path=self.path, body=self.rfile.read(length))
            )
            self._write(response)

        def _write(self, response: WebResponse) -> None:
            self.send_response(response.status_code)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(response.body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def create_loopback_server(
    fixture: LocalWebSimulator,
    *,
    port: int = 0,
) -> LoopbackHTTPServer:
    if not 0 <= port <= 65_535:
        raise ValueError("invalid loopback fixture port")
    return LoopbackHTTPServer((LOOPBACK_ADDRESS, port), _handler_for(fixture))
