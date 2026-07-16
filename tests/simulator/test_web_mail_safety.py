from __future__ import annotations

import ast
import json
import socket
from pathlib import Path

import pytest

from simulator.clock import ControllableClock
from simulator.engine import ScenarioEngine
from simulator.mail import InMemoryMailCapture
from simulator.protocol import (
    MAX_MAIL_BODY_BYTES,
    MAX_MAIL_MESSAGES,
    MAX_REQUEST_BODY_BYTES,
    MailFixture,
    ResourceLimitError,
)
from simulator.safety import assert_deterministic_source, assert_no_outbound_network_source
from simulator.web import LOOPBACK_ADDRESS, LocalWebSimulator, WebRequest, create_loopback_server

SIMULATOR_ROOT = Path(__file__).parents[2] / "simulator"


def _fixture() -> tuple[LocalWebSimulator, InMemoryMailCapture]:
    mail = InMemoryMailCapture()
    return LocalWebSimulator(ScenarioEngine(clock=ControllableClock()), mail), mail


def test_typed_web_boundary_advances_scenario_and_captures_mail_locally() -> None:
    fixture, mail = _fixture()
    response = fixture.handle(
        WebRequest("GET", "/v1/scenarios/happy/sessions/web-happy/next/start")
    )
    document = json.loads(response.body)
    assert response.status_code == 200
    assert document["state"] == "candidate"
    assert len(mail.messages) == 1
    assert mail.messages[0].recipient.endswith(".test")


@pytest.mark.parametrize(
    "path",
    [
        "/v1/scenarios/happy/sessions/../next/start",
        "/v1/scenarios/happy/sessions/%2e%2e/next/start",
        "/v1/scenarios/happy/sessions/good%5cbad/next/start",
        "//outside.test/v1/scenarios/happy/sessions/good/next/start",
    ],
)
def test_path_traversal_and_authority_mutations_fail_closed(path: str) -> None:
    fixture, _ = _fixture()
    response = fixture.handle(WebRequest("GET", path))
    assert response.status_code == 400
    assert json.loads(response.body)["error"] == "noncanonical_path"


def test_oversized_request_body_fails_before_scenario_execution() -> None:
    fixture, _ = _fixture()
    response = fixture.handle(
        WebRequest(
            "GET",
            "/v1/scenarios/happy/sessions/oversized/next/start",
            b"x" * (MAX_REQUEST_BODY_BYTES + 1),
        )
    )
    assert response.status_code == 413


def test_mail_boundary_rejects_non_reserved_and_oversized_messages() -> None:
    non_reserved = "fixture@" + "public" + ".com"
    with pytest.raises(ValueError, match="reserved domain"):
        MailFixture(non_reserved, "Mutation", "Mutation")
    with pytest.raises(ResourceLimitError, match="body exceeds hard cap"):
        MailFixture("fixture@notices.test", "Mutation", "x" * (MAX_MAIL_BODY_BYTES + 1))


def test_mail_capture_has_a_hard_message_cap() -> None:
    capture = InMemoryMailCapture()
    message = MailFixture("fixture@notices.test", "Fixture", "Fixture")
    for _ in range(MAX_MAIL_MESSAGES):
        capture.capture(message)
    with pytest.raises(ResourceLimitError, match="mail fixture hard cap"):
        capture.capture(message)


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
    fixture, _ = _fixture()
    server = create_loopback_server(fixture)
    try:
        assert server.server_address[0] == LOOPBACK_ADDRESS
    finally:
        server.server_close()


def test_simulator_sources_do_not_import_trusted_core_or_outbound_clients() -> None:
    for path in sorted(SIMULATOR_ROOT.glob("*.py")):
        assert_no_outbound_network_source(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0
        }
        assert not any(name == "mycogni" or name.startswith("mycogni.") for name in imported)


def test_accidental_socket_egress_mutation_fails_guard(tmp_path: Path) -> None:
    mutation = tmp_path / "socket_egress.py"
    mutation.write_text(
        'import socket\nsocket.create_connection(("outside" + ".test", 443))\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="outbound network import denied"):
        assert_no_outbound_network_source(mutation)


def test_dynamic_socket_import_mutation_fails_guard(tmp_path: Path) -> None:
    mutation = tmp_path / "dynamic_socket_egress.py"
    mutation.write_text('__import__("socket")\n', encoding="utf-8")
    with pytest.raises(AssertionError, match="dynamic import denied"):
        assert_no_outbound_network_source(mutation)


def test_nondeterministic_source_mutation_fails_guard(tmp_path: Path) -> None:
    mutation = tmp_path / "nondeterministic.py"
    mutation.write_text("import secrets\nsecrets.token_hex(8)\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="nondeterministic"):
        assert_deterministic_source(mutation)


def test_aliased_wall_clock_mutation_fails_guard(tmp_path: Path) -> None:
    mutation = tmp_path / "wall_clock.py"
    mutation.write_text(
        "from datetime import datetime as moment\nmoment.now()\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="wall-clock call denied"):
        assert_deterministic_source(mutation)


def test_deterministic_modules_pass_source_guard() -> None:
    for name in ("clock.py", "corpus.py", "engine.py"):
        assert_deterministic_source(SIMULATOR_ROOT / name)
