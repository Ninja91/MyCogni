"""Transactional loopback-only HTTP adapter over the synthetic protocol."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from threading import BoundedSemaphore, RLock
from typing import Any
from urllib.parse import unquote, urlsplit

from simulator.corpus import canonical_json
from simulator.engine import EnginePlan, ScenarioEngine
from simulator.mail import InMemoryMailCapture, MailReservation
from simulator.protocol import (
    MAX_CONCURRENT_REQUESTS,
    MAX_HTTP_RESPONSE_BYTES,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
    ResourceLimitError,
    ScenarioName,
    ScenarioState,
    SimulatorProtocolError,
    UnknownDeliveryError,
)

LOOPBACK_ADDRESS = "127.0.0.1"
HTTP_SCHEME = "http"
MAX_PATH_BYTES = 512
SOCKET_TIMEOUT_SECONDS = 2.0
CONTENT_LENGTH = re.compile(r"0|[1-9][0-9]{0,5}")
ROUTE = re.compile(
    r"/v1/scenarios/(?P<scenario>[a-z_]+)/sessions/"
    r"(?P<session>[a-z0-9-]+)/next/(?P<expected>[a-z_]+)"
)
REASONS = {
    200: "OK",
    206: "Partial Content",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Content Too Large",
    414: "URI Too Long",
    422: "Unprocessable Content",
    429: "Too Many Requests",
    500: "Internal Server Error",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


@dataclass(frozen=True, slots=True)
class WebRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class WebResponse:
    status_code: int
    body: bytes
    content_type: str = "application/json"


def _error(status_code: int, code: str) -> WebResponse:
    return WebResponse(status_code, canonical_json({"error": code}))


def _header_values(headers: tuple[tuple[str, str], ...], name: str) -> list[str]:
    lowered = name.lower()
    return [value for key, value in headers if key.lower() == lowered]


def _validate_envelope(request: WebRequest, expected_authority: str) -> WebResponse | None:
    if request.method != "GET":
        return _error(405, "closed_fixture_method")
    transfer_encoding = _header_values(request.headers, "Transfer-Encoding")
    if transfer_encoding:
        return _error(400, "transfer_encoding_denied")
    hosts = _header_values(request.headers, "Host")
    origins = _header_values(request.headers, "Origin")
    lengths = _header_values(request.headers, "Content-Length")
    if len(hosts) != 1 or hosts[0] != expected_authority:
        return _error(400, "loopback_host_required")
    if len(origins) != 1 or origins[0] != f"{HTTP_SCHEME}://{expected_authority}":
        return _error(403, "same_loopback_origin_required")
    if len(lengths) != 1 or CONTENT_LENGTH.fullmatch(lengths[0]) is None:
        return _error(400, "single_content_length_required")
    declared = int(lengths[0])
    if declared > MAX_REQUEST_BODY_BYTES:
        return _error(413, "request_too_large")
    if declared != len(request.body):
        return _error(400, "content_length_mismatch")
    if request.body:
        return _error(405, "closed_fixture_method")
    return None


class LocalWebSimulator:
    def __init__(self, engine: ScenarioEngine, mail: InMemoryMailCapture) -> None:
        self._engine = engine
        self._mail = mail

    def _prepare(
        self,
        request: WebRequest,
        *,
        expected_authority: str = LOOPBACK_ADDRESS,
    ) -> tuple[WebResponse, EnginePlan | None, MailReservation | None]:
        envelope_error = _validate_envelope(request, expected_authority)
        if envelope_error is not None:
            return envelope_error, None, None
        if len(request.path.encode("utf-8")) > MAX_PATH_BYTES:
            return _error(414, "path_too_large"), None, None
        parsed = urlsplit(request.path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            return _error(400, "noncanonical_path"), None, None
        decoded = unquote(parsed.path)
        if "\\" in decoded or "\x00" in decoded or ".." in decoded.split("/"):
            return _error(400, "noncanonical_path"), None, None
        match = ROUTE.fullmatch(decoded)
        if match is None:
            return _error(404, "unknown_fixture_route"), None, None

        plan: EnginePlan | None = None
        mail_reservation: MailReservation | None = None
        try:
            scenario = ScenarioName(match.group("scenario"))
            expected = ScenarioState(match.group("expected"))
            plan = self._engine._reserve(
                scenario_name=scenario,
                session_id=match.group("session"),
                expected_state=expected,
            )
            if plan.result.mail is not None:
                mail_reservation = self._mail._reserve(plan.result.mail)
            body = self._render_result(plan)
            if len(body) > MAX_RESPONSE_BODY_BYTES:
                raise ResourceLimitError("rendered response exceeds hard cap")
            response = WebResponse(plan.result.status_code, body)
            if len(_wire_response(response)) > MAX_HTTP_RESPONSE_BYTES:
                raise ResourceLimitError("aggregate HTTP response exceeds hard cap")
        except ValueError:
            self._cancel(plan, mail_reservation)
            return _error(400, "unknown_fixture_value"), None, None
        except ResourceLimitError:
            self._cancel(plan, mail_reservation)
            return _error(429, "fixture_resource_limit"), None, None
        except SimulatorProtocolError:
            self._cancel(plan, mail_reservation)
            return _error(409, "fixture_transition_denied"), None, None
        except Exception:
            self._cancel(plan, mail_reservation)
            return _error(500, "fixture_render_failed"), None, None
        return response, plan, mail_reservation

    def _render_result(self, plan: EnginePlan) -> bytes:
        return canonical_json(
            {
                "body": plan.result.body.decode("utf-8"),
                "evidence": plan.result.evidence.decode("utf-8"),
                "occurred_at": plan.result.occurred_at,
                "scenario": plan.result.scenario.value,
                "state": plan.result.state.value,
            }
        )

    def _cancel(
        self,
        engine_plan: EnginePlan | None,
        mail_reservation: MailReservation | None,
    ) -> None:
        try:
            if mail_reservation is not None:
                self._mail.rollback(mail_reservation)
        finally:
            if engine_plan is not None:
                self._engine.rollback(engine_plan)

    def _commit_internal(
        self,
        engine_plan: EnginePlan,
        mail_reservation: MailReservation | None,
    ) -> None:
        engine_snapshot = None
        engine_snapshot_taken = False
        mail_snapshot: int | None = None
        with self._engine.transaction_lock(), self._mail.transaction_lock():
            try:
                self._engine.validate_reservation_locked(engine_plan)
                if mail_reservation is not None:
                    self._mail.validate_reservation_locked(mail_reservation)
                engine_snapshot = self._engine.snapshot_locked(engine_plan)
                engine_snapshot_taken = True
                if mail_reservation is not None:
                    mail_snapshot = self._mail.snapshot_locked(mail_reservation)
                self._engine.commit_reservation_locked(engine_plan)
                if mail_reservation is not None:
                    self._mail.commit_reservation_locked(mail_reservation)
                self._engine.finalize_reservation_locked(engine_plan)
                if mail_reservation is not None:
                    self._mail.finalize_reservation_locked(mail_reservation)
            except BaseException:
                if engine_snapshot_taken:
                    self._engine.restore_snapshot_locked(engine_plan, engine_snapshot)
                if mail_snapshot is not None:
                    self._mail.restore_snapshot_locked(mail_snapshot)
                self._engine.cancel_reservation_locked(engine_plan)
                if mail_reservation is not None:
                    self._mail.cancel_reservation_locked(mail_reservation)
                raise

    def deliver(
        self,
        request: WebRequest,
        writer: Callable[[bytes], Any],
        *,
        expected_authority: str = LOOPBACK_ADDRESS,
    ) -> WebResponse:
        response, engine_plan, mail_reservation = self._prepare(
            request,
            expected_authority=expected_authority,
        )
        try:
            wire = _wire_response(response)
        except BaseException:
            self._cancel(engine_plan, mail_reservation)
            raise
        if engine_plan is not None:
            self._commit_internal(engine_plan, mail_reservation)
        try:
            writer(wire)
        except BaseException as error:
            raise UnknownDeliveryError(
                "writer was invoked; response byte delivery is unknowable"
            ) from error
        return response

    def handle(
        self,
        request: WebRequest,
        *,
        expected_authority: str = LOOPBACK_ADDRESS,
    ) -> WebResponse:
        return self.deliver(request, lambda _: None, expected_authority=expected_authority)


def _wire_response(response: WebResponse) -> bytes:
    reason = REASONS.get(response.status_code)
    if reason is None or len(response.body) > MAX_RESPONSE_BODY_BYTES:
        raise ValueError("response cannot be represented by finite HTTP fixture protocol")
    head = (
        f"HTTP/1.1 {response.status_code} {reason}\r\n"
        f"Content-Type: {response.content_type}\r\n"
        f"Content-Length: {len(response.body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return head + response.body


class LoopbackHTTPServer(ThreadingHTTPServer):
    """Bounded HTTP server whose bind path never performs hostname lookup."""

    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = MAX_CONCURRENT_REQUESTS

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        self._request_slots = BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self._active_requests = 0
        self._active_lock = RLock()
        super().__init__(server_address, handler)

    @property
    def active_request_count(self) -> int:
        with self._active_lock:
            return self._active_requests

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        if host != LOOPBACK_ADDRESS:
            raise RuntimeError("simulator server did not bind the fixed loopback address")
        self.server_name = LOOPBACK_ADDRESS
        self.server_port = port

    def get_request(self) -> tuple[Any, Any]:
        request, address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, address

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(_wire_response(_error(503, "fixture_concurrency_limit")))
            finally:
                self.shutdown_request(request)
            return
        with self._active_lock:
            self._active_requests += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._active_lock:
                self._active_requests -= 1
            self._request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active_requests -= 1
            self._request_slots.release()


def _handler_for(fixture: LocalWebSimulator) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self._dispatch()

        do_POST = do_GET
        do_PUT = do_GET
        do_DELETE = do_GET
        do_PATCH = do_GET
        do_HEAD = do_GET
        do_OPTIONS = do_GET
        do_CONNECT = do_GET
        do_TRACE = do_GET

        def _dispatch(self) -> None:
            if self.request_version != "HTTP/1.1":
                self.wfile.write(_wire_response(_error(400, "http_1_1_required")))
                self.close_connection = True
                return
            raw_headers = tuple(self.headers.raw_items())
            if not isinstance(self.server, LoopbackHTTPServer):
                raise RuntimeError("unexpected simulator server type")
            authority = f"{LOOPBACK_ADDRESS}:{self.server.server_port}"
            fixture.deliver(
                WebRequest(self.command, self.path, raw_headers, b""),
                self.wfile.write,
                expected_authority=authority,
            )
            self.close_connection = True

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            self.wfile.write(_wire_response(_error(405, "unsupported_http_method")))
            self.close_connection = True

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
