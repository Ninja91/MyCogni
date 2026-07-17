from __future__ import annotations

import json
import socket
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Thread

import pytest

from simulator.clock import ControllableClock
from simulator.engine import ScenarioEngine
from simulator.mail import InMemoryMailCapture, MailReservation
from simulator.protocol import (
    MAX_CONCURRENT_REQUESTS,
    MAX_MAIL_BODY_BYTES,
    MAX_MAIL_MESSAGES,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
    MailFixture,
    ResourceLimitError,
    ScenarioDefinition,
    ScenarioName,
    ScenarioState,
    ScenarioStep,
    UnknownDeliveryError,
    UnknownTransitionError,
)
from simulator.safety import (
    assert_deterministic_source,
    assert_no_outbound_network_source,
    assert_simulator_tree,
)
from simulator.web import (
    LOOPBACK_ADDRESS,
    LocalWebSimulator,
    LoopbackHTTPServer,
    WebRequest,
    create_loopback_server,
)

SIMULATOR_ROOT = Path(__file__).parents[2] / "simulator"
README = SIMULATOR_ROOT / "README.md"


def _http_origin(authority: str) -> str:
    return "http" + "://" + authority


def _fixture(
    *, scenarios: tuple[ScenarioDefinition, ...] | None = None
) -> tuple[LocalWebSimulator, InMemoryMailCapture, ScenarioEngine]:
    mail = InMemoryMailCapture()
    engine = ScenarioEngine(clock=ControllableClock(), scenarios=scenarios)
    return LocalWebSimulator(engine, mail), mail, engine


def _request(
    path: str = "/v1/scenarios/happy/sessions/web-happy/next/start",
    *,
    method: str = "GET",
    body: bytes = b"",
    authority: str = LOOPBACK_ADDRESS,
    headers: tuple[tuple[str, str], ...] | None = None,
) -> WebRequest:
    canonical_headers = (
        ("Host", authority),
        ("Origin", _http_origin(authority)),
        ("Content-Length", str(len(body))),
    )
    return WebRequest(method, path, canonical_headers if headers is None else headers, body)


def test_typed_web_boundary_commits_scenario_and_mail_after_local_write() -> None:
    fixture, mail, engine = _fixture()
    response = fixture.handle(_request())
    assert response.status_code == 200
    assert json.loads(response.body)["state"] == "candidate"
    assert engine.state("web-happy") is ScenarioState.CANDIDATE
    assert len(mail.messages) == 1


@pytest.mark.parametrize("consumption", ["before", "partial", "complete"])
def test_write_failure_is_typed_unknown_and_never_rolls_back_or_retries(
    consumption: str,
) -> None:
    fixture, mail, engine = _fixture()
    calls = 0
    consumed = bytearray()

    def fail_write(data: bytes) -> None:
        nonlocal calls
        calls += 1
        if consumption == "partial":
            consumed.extend(data[: len(data) // 2])
        elif consumption == "complete":
            consumed.extend(data)
        raise OSError("injected write failure")

    with pytest.raises(UnknownDeliveryError, match="delivery is unknowable") as raised:
        fixture.deliver(_request(), fail_write)
    assert raised.value.code == "UNKNOWN_DELIVERY"
    assert isinstance(raised.value.__cause__, OSError)
    assert calls == 1
    assert bool(consumed) is (consumption != "before")
    assert engine.state("web-happy") is ScenarioState.CANDIDATE
    assert len(mail.messages) == 1

    retry_wire: list[bytes] = []
    retry = fixture.deliver(_request(), retry_wire.append)
    assert retry.status_code == 409
    assert len(retry_wire) == 1
    assert b'"error":"fixture_transition_denied"' in retry_wire[0]
    assert calls == 1
    assert engine.state("web-happy") is ScenarioState.CANDIDATE
    assert len(mail.messages) == 1


class FailCommitMail(InMemoryMailCapture):
    def __init__(self) -> None:
        super().__init__()
        self._fail_once = True

    def commit_reservation_locked(self, reservation: MailReservation) -> None:
        super().commit_reservation_locked(reservation)
        if self._fail_once:
            self._fail_once = False
            raise RuntimeError("injected mail commit edge")


def test_fail_commit_mail_rolls_back_both_without_wire_then_retries() -> None:
    mail = FailCommitMail()
    engine = ScenarioEngine(clock=ControllableClock())
    fixture = LocalWebSimulator(engine, mail)
    written: list[bytes] = []
    with pytest.raises(RuntimeError, match="mail commit edge"):
        fixture.deliver(_request(), written.append)
    assert written == []
    assert mail.messages == ()
    with pytest.raises(UnknownTransitionError):
        engine.state("web-happy")

    fixture.deliver(_request(), written.append)
    assert len(written) == 1
    assert len(mail.messages) == 1
    assert engine.state("web-happy") is ScenarioState.CANDIDATE


@pytest.mark.parametrize(
    ("target_name", "method_name"),
    [
        ("engine", "validate_reservation_locked"),
        ("mail", "validate_reservation_locked"),
        ("engine", "snapshot_locked"),
        ("mail", "snapshot_locked"),
        ("engine", "commit_reservation_locked"),
        ("mail", "commit_reservation_locked"),
        ("engine", "finalize_reservation_locked"),
        ("mail", "finalize_reservation_locked"),
    ],
)
def test_each_atomic_commit_edge_rolls_back_without_wire_and_retries(
    monkeypatch: pytest.MonkeyPatch,
    target_name: str,
    method_name: str,
) -> None:
    fixture, mail, engine = _fixture()
    target = engine if target_name == "engine" else mail
    original = getattr(target, method_name)
    failed = False

    def fail_once(*args: object) -> object:
        nonlocal failed
        result = original(*args)
        if not failed:
            failed = True
            raise RuntimeError(f"injected {target_name} {method_name}")
        return result

    monkeypatch.setattr(target, method_name, fail_once)
    written: list[bytes] = []
    with pytest.raises(RuntimeError, match="injected"):
        fixture.deliver(_request(), written.append)
    assert written == []
    assert mail.messages == ()
    with pytest.raises(UnknownTransitionError):
        engine.state("web-happy")

    fixture.deliver(_request(), written.append)
    assert len(written) == 1
    assert len(mail.messages) == 1
    assert engine.state("web-happy") is ScenarioState.CANDIDATE


def test_no_public_prepare_or_prepared_response_can_abandon_reservations() -> None:
    fixture, _, engine = _fixture()
    assert not hasattr(fixture, "prepare")
    assert not hasattr(engine, "prepare")
    assert not hasattr(InMemoryMailCapture(), "reserve")
    assert "PreparedWebResponse" not in __import__("simulator").__all__


def test_render_failure_rolls_back_then_retry_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, mail, engine = _fixture()
    original = fixture._render_result

    def fail_render(plan: object) -> bytes:
        raise RuntimeError("injected renderer failure")

    monkeypatch.setattr(fixture, "_render_result", fail_render)
    assert fixture.handle(_request()).status_code == 500
    with pytest.raises(UnknownTransitionError):
        engine.state("web-happy")
    assert mail.messages == ()

    monkeypatch.setattr(fixture, "_render_result", original)
    assert fixture.handle(_request()).status_code == 200
    assert engine.state("web-happy") is ScenarioState.CANDIDATE


def test_mail_capacity_failure_does_not_advance_and_retry_is_safe() -> None:
    fixture, mail, engine = _fixture()
    filler = MailFixture("filler@notices.test", "Fixture", "Fixture")
    for _ in range(MAX_MAIL_MESSAGES):
        mail.capture(filler)
    assert fixture.handle(_request()).status_code == 429
    with pytest.raises(UnknownTransitionError):
        engine.state("web-happy")
    mail.clear()
    assert fixture.handle(_request()).status_code == 200
    assert engine.state("web-happy") is ScenarioState.CANDIDATE


def test_response_expansion_failure_does_not_advance_state() -> None:
    body = b'{"fixture":"' + (b"x" * (MAX_RESPONSE_BODY_BYTES - 30)) + b'"}'
    scenario = ScenarioDefinition(
        ScenarioName.HAPPY,
        (ScenarioStep(ScenarioState.START, ScenarioState.COMPLETE, 200, body),),
    )
    fixture, _, engine = _fixture(scenarios=(scenario,))
    response = fixture.handle(_request())
    assert response.status_code == 429
    with pytest.raises(UnknownTransitionError):
        engine.state("web-happy")


def test_same_session_web_race_commits_once_and_captures_one_mail() -> None:
    fixture, mail, engine = _fixture()
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: fixture.handle(_request()).status_code, range(2)))
    assert statuses.count(200) == 1
    assert len(mail.messages) == 1
    assert engine.state("web-happy") is ScenarioState.CANDIDATE


def test_mail_cap_is_race_safe() -> None:
    capture = InMemoryMailCapture()
    message = MailFixture("fixture@notices.test", "Fixture", "Fixture")

    def capture_once(_: int) -> str:
        try:
            capture.capture(message)
            return "captured"
        except ResourceLimitError:
            return "denied"

    with ThreadPoolExecutor(max_workers=MAX_MAIL_MESSAGES * 2) as pool:
        outcomes = list(pool.map(capture_once, range(MAX_MAIL_MESSAGES * 2)))
    assert outcomes.count("captured") == MAX_MAIL_MESSAGES
    assert outcomes.count("denied") == MAX_MAIL_MESSAGES
    assert len(capture.messages) == MAX_MAIL_MESSAGES


@pytest.mark.parametrize(
    "path",
    [
        "/v1/scenarios/happy/sessions/../next/start",
        "/v1/scenarios/happy/sessions/%2e%2e/next/start",
        "/v1/scenarios/happy/sessions/good%5cbad/next/start",
        "//outside.test/v1/scenarios/happy/sessions/good/next/start",
    ],
)
def test_path_traversal_and_authority_paths_fail_closed(path: str) -> None:
    fixture, _, _ = _fixture()
    assert fixture.handle(_request(path)).status_code == 400


def test_oversized_request_body_fails_before_scenario_execution() -> None:
    fixture, _, engine = _fixture()
    response = fixture.handle(_request(body=b"x" * (MAX_REQUEST_BODY_BYTES + 1)))
    assert response.status_code == 413
    with pytest.raises(UnknownTransitionError):
        engine.state("web-happy")


@pytest.mark.parametrize(
    "mailbox",
    [
        "fixture@" + "public" + ".com",
        "fixture@-bad.test",
        "fixture@bad-.test",
        "fixture@two..test",
        "fixture@under_score.test",
        "two@@identity.test",
    ],
)
def test_mail_boundary_rejects_non_reserved_or_invalid_dns_labels(mailbox: str) -> None:
    with pytest.raises(ValueError, match="strict reserved-domain"):
        MailFixture(mailbox, "Mutation", "Mutation")
    with pytest.raises(ResourceLimitError, match="body exceeds hard cap"):
        MailFixture("fixture@notices.test", "Mutation", "x" * (MAX_MAIL_BODY_BYTES + 1))


@contextmanager
def _running_server() -> Iterator[tuple[LocalWebSimulator, ScenarioEngine, LoopbackHTTPServer]]:
    fixture, _, engine = _fixture()
    server = create_loopback_server(fixture)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield fixture, engine, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _raw_request(port: int, request: bytes) -> bytes:
    with socket.create_connection((LOOPBACK_ADDRESS, port), timeout=2) as client:
        client.settimeout(4)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while chunk := client.recv(65_536):
            chunks.append(chunk)
    return b"".join(chunks)


def _raw_valid(port: int, *, method: str = "GET", extra: bytes = b"") -> bytes:
    origin = _http_origin(f"{LOOPBACK_ADDRESS}:{port}")
    return (
        (
            f"{method} /v1/scenarios/happy/sessions/raw/next/start HTTP/1.1\r\n"
            f"Host: {LOOPBACK_ADDRESS}:{port}\r\n"
            f"Origin: {origin}\r\n"
            "Content-Length: 0\r\n"
        ).encode()
        + extra
        + b"\r\n"
    )


@pytest.mark.simulator_loopback
def test_raw_http_success_has_deterministic_headers_without_date() -> None:
    with _running_server() as (_, engine, server):
        port = server.server_port
        response = _raw_request(port, _raw_valid(port))
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"\r\nDate:" not in response
    assert b"\r\nServer:" not in response
    assert engine.state("raw") is ScenarioState.CANDIDATE


@pytest.mark.parametrize(
    ("request_builder", "status"),
    [
        (
            lambda port: (
                "GET / HTTP/1.1\r\nOrigin: "
                + _http_origin("127.0.0.1")
                + "\r\nContent-Length: 0\r\n\r\n"
            ).encode(),
            400,
        ),
        (
            lambda port: (
                "GET / HTTP/1.1\r\nHost: outside.test\r\nOrigin: "
                + _http_origin("outside.test")
                + "\r\nContent-Length: 0\r\n\r\n"
            ).encode(),
            400,
        ),
        (
            lambda port: (
                f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 0\r\n\r\n".encode()
            ),
            403,
        ),
        (
            lambda port: (
                f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: "
                + _http_origin("outside.test")
                + "\r\nContent-Length: 0\r\n\r\n"
            ).encode(),
            403,
        ),
        (lambda port: _raw_valid(port, extra=f"Host: 127.0.0.1:{port}\r\n".encode()), 400),
        (
            lambda port: (
                f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: "
                + _http_origin(f"127.0.0.1:{port}")
                + "\r\n\r\n"
            ).encode(),
            400,
        ),
        (lambda port: _raw_valid(port, extra=b"Content-Length: 0\r\n"), 400),
        (lambda port: _raw_valid(port, extra=b"Transfer-Encoding: chunked\r\n"), 400),
        (lambda port: _raw_valid(port, method="POST"), 405),
        (
            lambda port: (
                f"GET / HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nOrigin: "
                + _http_origin(f"127.0.0.1:{port}")
                + "\r\nContent-Length: 0\r\n\r\n"
            ).encode(),
            400,
        ),
    ],
)
@pytest.mark.simulator_loopback
def test_raw_http_mutations_fail_closed(request_builder: object, status: int) -> None:
    builder = request_builder
    assert callable(builder)
    with _running_server() as (_, _, server):
        port = server.server_port
        response = _raw_request(port, builder(port))
    assert response.startswith(f"HTTP/1.1 {status} ".encode())
    assert b"\r\nDate:" not in response


@pytest.mark.simulator_loopback
def test_raw_http_concurrency_is_bounded() -> None:
    with _running_server() as (_, _, server):
        port = server.server_port
        clients = [
            socket.create_connection((LOOPBACK_ADDRESS, port), timeout=2)
            for _ in range(MAX_CONCURRENT_REQUESTS)
        ]
        try:
            for client in clients:
                client.sendall(b"GET / HTTP/1.1\r\n")
            deadline = time.monotonic() + 1
            while (
                server.active_request_count < MAX_CONCURRENT_REQUESTS
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            assert server.active_request_count == MAX_CONCURRENT_REQUESTS
            with socket.create_connection((LOOPBACK_ADDRESS, port), timeout=2) as probe:
                probe.settimeout(2)
                response = probe.recv(4096)
            assert response.startswith(b"HTTP/1.1 503")
        finally:
            for client in clients:
                client.close()


@pytest.mark.simulator_loopback
def test_incomplete_raw_request_is_closed_by_read_timeout() -> None:
    with (
        _running_server() as (_, _, server),
        socket.create_connection((LOOPBACK_ADDRESS, server.server_port), timeout=2) as client,
    ):
        client.settimeout(4)
        client.sendall(b"GET / HTTP/1.1\r\nHost: incomplete")
        started = time.monotonic()
        assert client.recv(4096) == b""
        assert time.monotonic() - started < 3.5


def test_server_binds_fixed_numeric_loopback_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSocket:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.bound: tuple[str, int] | None = None

        def setsockopt(self, *args: object) -> None:
            return

        def bind(self, address: tuple[str, int]) -> None:
            assert address[0] == LOOPBACK_ADDRESS
            self.bound = (address[0], 43123 if address[1] == 0 else address[1])

        def getsockname(self) -> tuple[str, int]:
            assert self.bound is not None
            return self.bound

        def listen(self, backlog: int) -> None:
            return

        def close(self) -> None:
            return

    def deny_dns(*args: object, **kwargs: object) -> None:
        raise AssertionError("DNS lookup attempted")

    monkeypatch.setattr(socket, "getaddrinfo", deny_dns)
    monkeypatch.setattr(socket, "gethostbyaddr", deny_dns)
    monkeypatch.setattr(socket, "socket", FakeSocket)
    fixture, _, _ = _fixture()
    server = create_loopback_server(fixture)
    try:
        assert server.server_address[0] == LOOPBACK_ADDRESS
    finally:
        server.server_close()


def test_recursive_simulator_tree_has_structural_import_boundary() -> None:
    assert_simulator_tree(SIMULATOR_ROOT)


def test_recursive_from_import_reaches_nested_escape_mutation(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "__init__.py").write_text("from . import nested\n", encoding="utf-8")
    (nested / "__init__.py").write_text("from . import escape\n", encoding="utf-8")
    (nested / "escape.py").write_text("import subprocess\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="process/network escape import denied"):
        assert_simulator_tree(root, package="fixture")


def test_recursive_tree_rejects_nested_symlink_directory(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    nested = root / "nested"
    target = tmp_path / "escaped"
    nested.mkdir(parents=True)
    target.mkdir()
    (root / "__init__.py").write_text("", encoding="utf-8")
    (target / "escape.py").write_text("import subprocess\n", encoding="utf-8")
    (nested / "linked").symlink_to(target, target_is_directory=True)

    with pytest.raises(AssertionError, match="simulator source symlink denied"):
        assert_simulator_tree(root, package="fixture")


@pytest.mark.parametrize(
    "source",
    [
        "import socket\n",
        "import subprocess\n",
        "import os\nos.system('fixture')\n",
        "import asyncio\nasyncio.create_subprocess_shell('fixture')\n",
        "import ctypes\n",
        "import importlib\n",
        "import builtins\n",
        "from urllib import request\nrequest.urlopen('fixture')\n",
        "import urllib as u\nu.request.urlopen('fixture')\n",
        "eval('fixture')\n",
        "exec('fixture')\n",
        "compile('fixture', 'fixture', 'exec')\n",
        "__import__('socket')\n",
    ],
)
def test_process_network_and_dynamic_escape_mutations_fail_guard(
    tmp_path: Path, source: str
) -> None:
    mutation = tmp_path / "escape.py"
    mutation.write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="escape"):
        assert_no_outbound_network_source(mutation)


def test_nondeterministic_and_wall_clock_mutations_fail_guard(tmp_path: Path) -> None:
    random_mutation = tmp_path / "nondeterministic.py"
    random_mutation.write_text("import secrets\nsecrets.token_hex(8)\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="nondeterministic"):
        assert_deterministic_source(random_mutation)
    clock_mutation = tmp_path / "wall_clock.py"
    clock_mutation.write_text(
        "from datetime import datetime as moment\nmoment.now()\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="wall-clock"):
        assert_deterministic_source(clock_mutation)


def test_deterministic_modules_pass_source_guard_and_nonclaim_is_explicit() -> None:
    for name in ("clock.py", "corpus.py", "engine.py"):
        assert_deterministic_source(SIMULATOR_ROOT / name)
    readme = README.read_text(encoding="utf-8")
    assert "not an operating-system sandbox" in readme
    assert "deliberate language-level bypass" in readme
