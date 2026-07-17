"""Adversarial evidence for the NET-001 default-deny pytest harness."""

from __future__ import annotations

import asyncio
import http.client
import os
import socket
import ssl
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest

from scripts.ci import network_guard, network_source_guard


def _assert_safe_denial(error: NetworkError, *inputs: str) -> None:
    rendered = f"{error!s} {error!r}"
    for value in inputs:
        assert value not in rendered
    assert isinstance(error.category, network_guard.DenialCategory)
    assert isinstance(error.reason, network_guard.DenialReason)
    assert error.opaque_test_id.startswith("nt_")
    assert len(error.opaque_test_id) == 19


NetworkError = network_guard.NetworkDenied


@pytest.mark.parametrize(
    "operation",
    [
        lambda: socket.getaddrinfo("outside.test", 443),
        lambda: socket.gethostbyname("outside.test"),
        lambda: socket.gethostbyname_ex("outside.test"),
        lambda: socket.gethostbyaddr("192.0.2.7"),
        lambda: socket.getnameinfo(("192.0.2.7", 443), 0),
    ],
)
def test_dns_apis_are_denied_without_reaching_os_primitive(
    monkeypatch: pytest.MonkeyPatch, operation: Any
) -> None:
    reached = False

    def spy(*args: object, **kwargs: object) -> object:
        nonlocal reached
        reached = True
        raise AssertionError("OS DNS primitive reached")

    monkeypatch.setattr(network_guard, "_ORIGINAL_GETADDRINFO", spy)
    monkeypatch.setattr(network_guard, "_ORIGINAL_GETHOSTBYNAME", spy)
    with pytest.raises(NetworkError) as raised:
        operation()
    assert not reached
    _assert_safe_denial(raised.value, "outside.test", "192.0.2.7")


class _FakeSocket:
    family = socket.AF_INET

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 43123)


@pytest.mark.parametrize(
    "operation",
    [
        lambda: network_guard.GuardedSocket.connect(_FakeSocket(), ("192.0.2.7", 443)),
        lambda: network_guard.GuardedSocket.connect_ex(_FakeSocket(), ("127.0.0.1", 80)),
        lambda: network_guard.GuardedSocket.bind(_FakeSocket(), ("0.0.0.0", 0)),
        lambda: network_guard.GuardedSocket.listen(_FakeSocket(), 1),
    ],
)
def test_socket_connect_bind_and_listen_deny_before_os_descriptor(operation: Any) -> None:
    with pytest.raises(NetworkError) as raised:
        operation()
    _assert_safe_denial(raised.value, "192.0.2.7", "0.0.0.0")


def test_create_connection_denies_before_socket_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached = False

    def spy(*args: object, **kwargs: object) -> object:
        nonlocal reached
        reached = True
        raise AssertionError("OS socket primitive reached")

    monkeypatch.setattr(network_guard, "GuardedSocket", spy)
    with pytest.raises(NetworkError) as raised:
        socket.create_connection(("127.0.0.1", 43123))
    assert not reached
    _assert_safe_denial(raised.value)


def test_asyncio_open_connection_denies_before_loop_primitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached = False

    async def spy(*args: object, **kwargs: object) -> object:
        nonlocal reached
        reached = True
        raise AssertionError("asyncio primitive reached")

    monkeypatch.setattr(network_guard, "_ORIGINAL_ASYNCIO_OPEN_CONNECTION", spy)

    async def attempt() -> None:
        await asyncio.open_connection("127.0.0.1", 43123)

    with pytest.raises(NetworkError) as raised:
        asyncio.run(attempt())
    assert not reached
    _assert_safe_denial(raised.value)


def test_httpx_and_urllib_deny_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def transport(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, request=request)

    with (
        httpx.Client(transport=httpx.MockTransport(transport)) as client,
        pytest.raises(NetworkError) as raised,
    ):
        client.get("http://outside.test/path?synthetic=canary")
    assert calls == 0
    _assert_safe_denial(raised.value, "outside.test", "synthetic=canary")

    reached = False

    def urlopen_spy(*args: object, **kwargs: object) -> object:
        nonlocal reached
        reached = True
        raise AssertionError("urllib primitive reached")

    monkeypatch.setattr(network_guard, "_ORIGINAL_URLOPEN", urlopen_spy)
    with pytest.raises(NetworkError) as urllib_denial:
        urllib.request.urlopen("http://outside.test/path")
    assert not reached
    _assert_safe_denial(urllib_denial.value, "outside.test")

    with pytest.raises(NetworkError) as http_client_denial:
        http.client.HTTPConnection("outside.test", 80).connect()
    _assert_safe_denial(http_client_denial.value, "outside.test")


def test_proxy_environment_and_explicit_httpx_proxy_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("hTtPs_PrOxY", "http://127.0.0.1:43123/synthetic-secret")
    with pytest.raises(NetworkError) as env_denial:
        socket.create_connection(("127.0.0.1", 43123))
    assert env_denial.value.category is network_guard.DenialCategory.POLICY
    _assert_safe_denial(env_denial.value, "synthetic-secret")

    monkeypatch.delenv("hTtPs_PrOxY")
    with pytest.raises(NetworkError) as explicit_denial:
        httpx.Client(proxy="http://127.0.0.1:43123/synthetic-secret")
    assert explicit_denial.value.category is network_guard.DenialCategory.PROXY
    _assert_safe_denial(explicit_denial.value, "synthetic-secret")


def test_tls_entrypoints_deny_sni_without_wrapping_primitive() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with pytest.raises(NetworkError) as raised:
        context.wrap_bio(
            ssl.MemoryBIO(),
            ssl.MemoryBIO(),
            server_hostname="outside.test",
        )
    assert raised.value.reason is network_guard.DenialReason.TLS_FORBIDDEN
    _assert_safe_denial(raised.value, "outside.test")


def test_context_does_not_propagate_to_new_thread() -> None:
    token = network_guard.activate_test("synthetic-parent", simulator_loopback=True)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                network_guard.authorize_socket_address,
                socket.AF_INET,
                ("127.0.0.1", 43123),
            )
            with pytest.raises(NetworkError) as raised:
                future.result()
        assert raised.value.reason is network_guard.DenialReason.CAPABILITY_ABSENT
        assert raised.value.opaque_test_id == "nt_unscoped"
    finally:
        network_guard.deactivate_test(token)


def test_previous_test_capability_is_not_present() -> None:
    with pytest.raises(NetworkError) as raised:
        network_guard.authorize_socket_address(socket.AF_INET, ("127.0.0.1", 43123))
    assert raised.value.reason is network_guard.DenialReason.CAPABILITY_ABSENT


def test_marker_forgery_outside_simulator_is_a_collection_error(tmp_path: Path) -> None:
    mutation = tmp_path / "test_marker_forgery.py"
    mutation.write_text(
        "import pytest\n\n@pytest.mark.simulator_loopback\ndef test_forged():\n    pass\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "scripts.ci.network_guard_plugin",
            str(mutation),
        ],
        cwd=Path(__file__).parents[2],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode != 0
    assert "simulator loopback marker is restricted" in completed.stderr


def test_guard_off_environment_is_a_configuration_error() -> None:
    environment = dict(os.environ)
    environment["MYCOGNI_DISABLE_NETWORK_GUARD"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "tests/domain/test_contracts.py",
        ],
        cwd=Path(__file__).parents[2],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode != 0
    assert "network guard cannot be disabled" in completed.stderr


def test_network_source_architecture_guard_passes() -> None:
    assert network_source_guard.check() == []


@pytest.mark.parametrize(
    "source",
    [
        "import _socket\n",
        "import builtins\n",
        "import ctypes\n",
        "import httpx\n",
        "import importlib\n",
        "import socket\n",
        "import ssl\n",
        "import subprocess\n",
        "from urllib import request\n",
    ],
)
def test_unreviewed_test_escape_import_mutations_fail_static_guard(
    tmp_path: Path, source: str
) -> None:
    mutation = tmp_path / "test_escape.py"
    mutation.write_text(source, encoding="utf-8")
    assert network_source_guard.test_import_violations(mutation)
