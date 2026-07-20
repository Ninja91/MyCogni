"""Adversarial evidence for the NET-001 default-deny pytest harness."""

from __future__ import annotations

import asyncio
import hashlib
import http.client
import json
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

from scripts.ci import (
    guarded_pytest,
    network_guard,
    network_guard_plugin,
    network_namespace,
    network_source_guard,
)

ROOT = Path(__file__).parents[2]
GUARDED_PYTEST = ROOT / "scripts" / "ci" / "guarded_pytest.py"


def _run_pytest(
    *arguments: str,
    cwd: Path = ROOT,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GUARDED_PYTEST), *arguments],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


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
    type = socket.SOCK_STREAM
    _mycogni_anonymous_pair = False
    _mycogni_lease = None
    _require_descriptor = network_guard.GuardedSocket._require_descriptor
    _require_tcp_ipv4 = network_guard.GuardedSocket._require_tcp_ipv4

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


def test_already_created_async_task_loses_revoked_authority() -> None:
    async def scenario() -> NetworkError:
        release = asyncio.Event()
        handle = network_guard.activate_test("synthetic-async", simulator_loopback=True)

        async def delayed_attempt() -> None:
            await release.wait()
            network_guard.authorize_socket_address(socket.AF_INET, ("127.0.0.1", 43123))

        task = asyncio.create_task(delayed_attempt())
        await asyncio.sleep(0)
        network_guard.deactivate_test(handle)
        release.set()
        with pytest.raises(NetworkError) as raised:
            await task
        return raised.value

    denial = asyncio.run(scenario())
    assert denial.reason is network_guard.DenialReason.AUTHORITY_REVOKED


def test_revoked_descriptor_cannot_send_or_receive() -> None:
    handle = network_guard.activate_test("synthetic-descriptor", simulator_loopback=True)
    candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        candidate._attach_current_lease()
        network_guard.deactivate_test(handle)
        with pytest.raises(NetworkError, match="authority_revoked"):
            candidate.send(b"synthetic")
        with pytest.raises(NetworkError, match="authority_revoked"):
            candidate.recv(1)
    finally:
        candidate.close()


def test_inherited_and_duplicated_descriptors_fail_before_os_use() -> None:
    with pytest.raises(NetworkError, match="descriptor_forbidden"):
        network_guard.GuardedSocket(fileno=999_999)
    if hasattr(socket, "fromfd"):
        with pytest.raises(NetworkError, match="descriptor_forbidden"):
            socket.fromfd(999_999, socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "dup"):
        with pytest.raises(NetworkError, match="descriptor_forbidden"):
            socket.dup(999_999)


def test_datagram_send_and_connect_are_denied_even_with_loopback_authority() -> None:
    handle = network_guard.activate_test("synthetic-datagram", simulator_loopback=True)
    candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(NetworkError, match="socket_type_forbidden"):
            candidate.connect(("127.0.0.1", 43123))
        with pytest.raises(NetworkError, match="socket_type_forbidden"):
            candidate.sendto(b"synthetic", ("127.0.0.1", 43123))
    finally:
        candidate.close()
        network_guard.deactivate_test(handle)


def test_anonymous_socketpair_is_local_only_and_cannot_be_duplicated() -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(b"x")
        assert right.recv(1) == b"x"
        with pytest.raises(NetworkError, match="descriptor_forbidden"):
            left.dup()
        with pytest.raises(NetworkError, match="descriptor_forbidden"):
            left.detach()
        handle = network_guard.activate_test("synthetic-unix", simulator_loopback=True)
        try:
            with pytest.raises(NetworkError, match="family_forbidden"):
                left.connect("/tmp/synthetic.sock")
        finally:
            network_guard.deactivate_test(handle)
    finally:
        left.close()
        right.close()


def test_previous_test_capability_is_not_present() -> None:
    with pytest.raises(NetworkError) as raised:
        network_guard.authorize_socket_address(socket.AF_INET, ("127.0.0.1", 43123))
    assert raised.value.reason is network_guard.DenialReason.CAPABILITY_ABSENT


def test_marker_forgery_outside_simulator_is_a_collection_error(tmp_path: Path) -> None:
    mutation = tmp_path / "test_marker_forgery.py"
    mutation.write_text(
        "import pytest\n\n" + "@pytest.mark.simulator_loopback\ndef test_forged():\n    pass\n",
        encoding="utf-8",
    )
    completed = _run_pytest("-q", str(mutation))
    assert completed.returncode != 0
    assert "simulator loopback marker is restricted" in completed.stderr


def test_guard_off_environment_is_a_configuration_error() -> None:
    environment = dict(os.environ)
    environment["MYCOGNI_DISABLE_NETWORK_GUARD"] = "1"
    completed = _run_pytest(
        "--collect-only",
        "-q",
        "tests/domain/test_contracts.py",
        environment=environment,
    )
    assert completed.returncode != 0
    assert "guarded_pytest=denied" in completed.stdout


@pytest.mark.parametrize(
    ("arguments", "environment"),
    [
        (("-p", "no:scripts.ci.network_guard_plugin"), None),
        (("-pno:network_guard_plugin",), None),
        (("-p=no:scripts.ci.network_guard_plugin",), None),
        (("--noconftest",), None),
        (("--noconftest=true",), None),
        (("--confcutdir=/tmp",), None),
        ((), {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}),
        ((), {"PYTEST_ADDOPTS": "-p no:network_guard_plugin"}),
        ((), {"PYTEST_ADDOPTS": "'-pno:scripts.ci.network_guard_plugin'"}),
        ((), {"PYTEST_ADDOPTS": "'-p=no:scripts.ci.network_guard_plugin'"}),
        ((), {"PYTEST_ADDOPTS": "'--noconftest'"}),
        (("no:scripts.ci.network_guard_plugin",), {"PYTEST_ADDOPTS": "'-p'"}),
        (("--noconftest",), {"PYTEST_ADDOPTS": "'-q'"}),
        ((), {"PYTEST_ADDOPTS": "'malformed"}),
    ],
)
def test_guard_exclusion_options_fail_in_launcher(
    arguments: tuple[str, ...], environment: dict[str, str] | None
) -> None:
    process_environment = dict(os.environ)
    if environment:
        process_environment.update(environment)
    completed = _run_pytest(
        *arguments,
        "--collect-only",
        "-q",
        "tests/domain/test_contracts.py",
        environment=process_environment,
    )
    assert completed.returncode == 4
    assert completed.stdout.strip() == "guarded_pytest=denied"


def test_exact_quoted_addopts_exclusion_denies_root_and_package_before_pytest() -> None:
    environment = dict(os.environ)
    environment["PYTEST_ADDOPTS"] = "'--noconftest' '-p' 'no:scripts.ci.network_guard_plugin'"
    package = ROOT / "packages" / "mycogni-connector-sdk"
    for cwd, target in (
        (ROOT, "tests/domain/test_contracts.py"),
        (package, "tests/test_boundaries.py"),
    ):
        completed = _run_pytest(
            "--collect-only",
            "-q",
            target,
            cwd=cwd,
            environment=environment,
        )
        assert completed.returncode == 4
        assert completed.stdout.strip() == "guarded_pytest=denied"
        assert completed.stderr == ""


@pytest.mark.parametrize(
    ("arguments", "addopts", "plugin_environment"),
    [
        (("-p", "pre_snapshot_forge"), None, None),
        (("-ppre_snapshot_forge",), None, None),
        (("-p=pre_snapshot_forge",), None, None),
        (("--plugins", "pre_snapshot_forge"), None, None),
        (("--plugins=pre_snapshot_forge",), None, None),
        ((), "'-p' 'pre_snapshot_forge'", None),
        ((), "'-ppre_snapshot_forge'", None),
        (("pre_snapshot_forge",), "'-p'", None),
        ((), None, "pre_snapshot_forge"),
    ],
    ids=[
        "short-split",
        "short-combined",
        "short-equals",
        "long-split-future-surface",
        "long-equals-future-surface",
        "addopts-split",
        "addopts-combined",
        "addopts-argv-composed",
        "pytest-plugins-environment",
    ],
)
def test_positive_plugin_injection_is_denied_before_plugin_import(
    tmp_path: Path,
    arguments: tuple[str, ...],
    addopts: str | None,
    plugin_environment: str | None,
) -> None:
    sentinel = tmp_path / "plugin-imported"
    plugin = tmp_path / "pre_snapshot_forge.py"
    plugin.write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('imported', encoding='utf-8')\n\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        replacement = lambda: None\n"
        "        replacement.__name__ = getattr(item, 'originalname', item.name)\n"
        "        replacement.__qualname__ = replacement.__name__\n"
        "        item._obj = replacement\n"
        "        item._nodeid = item.nodeid\n"
        "        setattr(item.module, replacement.__name__, replacement)\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(tmp_path), str(ROOT)))
    if addopts is not None:
        environment["PYTEST_ADDOPTS"] = addopts
    if plugin_environment is not None:
        environment["PYTEST_PLUGINS"] = plugin_environment
    completed = _run_pytest(
        *arguments,
        "--collect-only",
        "-q",
        "tests/domain/test_contracts.py",
        environment=environment,
    )
    assert completed.returncode == 4
    assert completed.stdout.strip() == "guarded_pytest=denied"
    assert completed.stderr == ""
    assert not sentinel.exists()


def test_addopts_override_denies_root_and_package_before_pytest() -> None:
    override = "addopts=--noconftest -p no:scripts.ci.network_guard_plugin"
    package = ROOT / "packages" / "mycogni-connector-sdk"
    for cwd, target in (
        (ROOT, "tests/domain/test_contracts.py"),
        (package, "tests/test_boundaries.py"),
    ):
        completed = _run_pytest(
            "-o",
            override,
            "--collect-only",
            "-q",
            target,
            cwd=cwd,
        )
        assert completed.returncode == 4
        assert completed.stdout.strip() == "guarded_pytest=denied"
        assert completed.stderr == ""


@pytest.mark.parametrize(
    ("arguments", "addopts"),
    [
        (("--override-ini", "addopts=--noconftest"), None),
        (("--override-ini=addopts=--noconftest",), None),
        (("-oaddopts=--noconftest",), None),
        (("-o=addopts=--noconftest",), None),
        (("-c", "{config}"), None),
        (("-c={config}",), None),
        (("-c{config}",), None),
        (("--config-file", "{config}"), None),
        (("--config-file={config}",), None),
        (("--inifile", "{config}"), None),
        (("--inifile={config}",), None),
        ((), "'-o' 'addopts=--noconftest'"),
        (("addopts=--noconftest",), "'-o'"),
        ((), "'-c' '{config}'"),
        (("-o",), None),
        (("--override-ini",), None),
        (("-c",), None),
        (("--config-file",), None),
        (("--inifile",), None),
        (("-p",), None),
        (("--plugins",), None),
    ],
    ids=[
        "override-long-split",
        "override-long-equals",
        "override-short-combined",
        "override-short-equals",
        "config-short-split",
        "config-short-equals",
        "config-short-combined",
        "config-long-split",
        "config-long-equals",
        "legacy-inifile-split",
        "legacy-inifile-equals",
        "addopts-override",
        "addopts-argv-override",
        "addopts-config",
        "missing-short-override-value",
        "missing-long-override-value",
        "missing-short-config-value",
        "missing-long-config-value",
        "missing-inifile-value",
        "missing-short-plugin-value",
        "missing-long-plugin-value",
    ],
)
def test_config_and_addopts_override_surfaces_are_denied_before_pytest(
    tmp_path: Path,
    arguments: tuple[str, ...],
    addopts: str | None,
) -> None:
    config = tmp_path / "pytest.ini"
    config.write_text(
        "[pytest]\naddopts = --noconftest -p no:scripts.ci.network_guard_plugin\n",
        encoding="utf-8",
    )
    rendered_arguments = tuple(value.format(config=config) for value in arguments)
    environment = dict(os.environ)
    if addopts is not None:
        environment["PYTEST_ADDOPTS"] = addopts.format(config=config)
    completed = _run_pytest(
        *rendered_arguments,
        "--collect-only",
        "-q",
        "tests/domain/test_contracts.py",
        environment=environment,
    )
    assert completed.returncode == 4
    assert completed.stdout.strip() == "guarded_pytest=denied"
    assert completed.stderr == ""


def test_launcher_has_exact_explicit_required_plugin_allowlist() -> None:
    assert guarded_pytest.REQUIRED_PLUGIN_MODULES == (
        "_hypothesis_pytestplugin",
        "anyio.pytest_plugin",
        "pytest_cov.plugin",
    )


def test_unreviewed_installed_pytest_entrypoint_is_not_autoloaded(tmp_path: Path) -> None:
    sentinel = tmp_path / "autoload-imported"
    plugin = tmp_path / "synthetic_autoload_plugin.py"
    plugin.write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('imported', encoding='utf-8')\n",
        encoding="utf-8",
    )
    distribution = tmp_path / "synthetic_autoload-1.0.dist-info"
    distribution.mkdir()
    (distribution / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: synthetic-autoload\nVersion: 1.0\n",
        encoding="utf-8",
    )
    (distribution / "entry_points.txt").write_text(
        "[pytest11]\nsynthetic_autoload = synthetic_autoload_plugin\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(tmp_path), str(ROOT)))
    completed = _run_pytest(
        "--collect-only",
        "-q",
        "tests/domain/test_contracts.py",
        environment=environment,
    )
    assert completed.returncode == 0
    assert not sentinel.exists()


def test_safely_quoted_addopts_remains_supported_for_root_and_package() -> None:
    environment = dict(os.environ)
    environment["PYTEST_ADDOPTS"] = "'-q'"
    root = _run_pytest(
        "--collect-only",
        "tests/domain/test_contracts.py",
        environment=environment,
    )
    package = _run_pytest(
        "--collect-only",
        "tests/test_boundaries.py",
        cwd=ROOT / "packages" / "mycogni-connector-sdk",
        environment=environment,
    )
    assert root.returncode == 0
    assert package.returncode == 0


def test_direct_root_and_package_pytest_fail_but_guarded_package_suite_collects() -> None:
    direct_root = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/domain/test_contracts.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert direct_root.returncode != 0
    assert "pytest must run through" in direct_root.stderr

    package = ROOT / "packages" / "mycogni-connector-sdk"
    direct_package = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/test_boundaries.py"],
        cwd=package,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert direct_package.returncode != 0
    assert "pytest must run through" in direct_package.stderr

    guarded_package = _run_pytest(
        "--collect-only",
        "-q",
        "tests/test_boundaries.py",
        cwd=package,
    )
    assert guarded_package.returncode == 0
    assert "3 tests collected" in guarded_package.stdout


def test_dynamic_marker_and_generated_node_lack_reviewed_provenance() -> None:
    probe = ROOT / "tests" / "simulator" / "test_dynamic_marker_probe.py"
    conftest = ROOT / "tests" / "simulator" / "conftest.py"
    probe.write_text(
        "import pytest\n\n"
        + "@pytest.mark.parametrize('case', [1, 2])\ndef test_dynamic(case):\n    pass\n",
        encoding="utf-8",
    )
    conftest.write_text(
        "import pytest\n\n"
        "@pytest.hookimpl(tryfirst=True)\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n        item.add_marker(pytest.mark.simulator_loopback)\n",
        encoding="utf-8",
    )
    try:
        completed = _run_pytest(
            "-q",
            str(probe),
        )
    finally:
        probe.unlink(missing_ok=True)
        conftest.unlink(missing_ok=True)
    assert completed.returncode != 0
    assert "provenance" in (completed.stdout + completed.stderr)


@pytest.mark.parametrize(
    "source",
    [
        (
            "import pytest\n\n"
            "@pytest.mark.parametrize('case', "
            "[pytest.param(1, marks=pytest.mark.simulator_loopback)])\n"
            "def test_parameter_marker(case):\n    pass\n"
        ),
        (
            "import pytest\n\n"
            "@pytest.mark.simulator_loopback\n"
            "class TestCollision:\n"
            "    def test_raw_http_success_has_deterministic_headers_without_date(self):\n"
            "        pass\n"
        ),
        (
            "import pytest\n\npytestmark = pytest.mark.simulator_loopback\n\n"
            "def test_module_marker():\n    pass\n"
        ),
    ],
    ids=["parameter-level", "class-level-duplicate-name", "module-level"],
)
def test_non_function_marker_scopes_never_gain_authority(tmp_path: Path, source: str) -> None:
    probe = ROOT / "tests" / "simulator" / "test_marker_scope_probe.py"
    probe.write_text(source, encoding="utf-8")
    try:
        completed = _run_pytest("-q", str(probe))
    finally:
        probe.unlink(missing_ok=True)
    assert completed.returncode != 0
    assert "provenance" in (completed.stdout + completed.stderr)


def test_canonical_node_preserves_full_collector_and_parameter_hierarchy() -> None:
    path = ROOT / "tests" / "simulator" / "test_web_mail_safety.py"

    class FakeItem:
        def __init__(self, nodeid: str) -> None:
            self.path = path
            self.nodeid = nodeid

    class_collision = FakeItem(
        "ignored-prefix::TestCollision::"
        "test_raw_http_success_has_deterministic_headers_without_date[duplicate]"
    )
    canonical = network_guard_plugin._canonical_node(class_collision)  # type: ignore[arg-type]
    assert canonical.endswith(
        "::TestCollision::test_raw_http_success_has_deterministic_headers_without_date[duplicate]"
    )
    assert canonical not in network_guard_plugin._REGISTRY.nodes


def test_custom_generated_item_cannot_spoof_authorized_top_level_node() -> None:
    path = ROOT / "tests" / "simulator" / "test_web_mail_safety.py"
    canonical = (
        "tests/simulator/test_web_mail_safety.py::"
        "test_raw_http_success_has_deterministic_headers_without_date"
    )

    class FakeGeneratedItem:
        def __init__(self) -> None:
            self.nodeid = canonical
            self.name = "test_raw_http_success_has_deterministic_headers_without_date"
            self.originalname = self.name
            self.parent = object()
            self.path = path

    fake = FakeGeneratedItem()
    assert network_guard_plugin._canonical_node(fake) == canonical  # type: ignore[arg-type]
    assert network_guard_plugin._reviewed_item(fake) is None  # type: ignore[arg-type]


def test_post_collection_node_and_callable_mutation_revokes_authority() -> None:
    conftest = ROOT / "tests" / "simulator" / "conftest.py"
    conftest.write_text(
        "import pytest\n\n"
        "@pytest.hookimpl(trylast=True)\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        item._nodeid = item.nodeid + '::mutated'\n"
        "        item._obj = lambda: None\n",
        encoding="utf-8",
    )
    try:
        completed = _run_pytest(
            "-q",
            "tests/simulator/test_web_mail_safety.py::"
            "test_raw_http_success_has_deterministic_headers_without_date",
        )
    finally:
        conftest.unlink(missing_ok=True)
    assert completed.returncode != 0
    assert "provenance" in (completed.stdout + completed.stderr)


def test_authority_registry_binds_exact_parameter_nodes_and_source_digests() -> None:
    registry = json.loads((ROOT / "ci" / "network-loopback-authority.json").read_text())
    assert registry["schema_version"] == 2
    nodes = registry["authorized_nodes"]
    assert len(nodes) == 38
    assert nodes == sorted(set(nodes))
    assert any("[missing-host]" in node for node in nodes)
    assert any("[overflow-port]" in node for node in nodes)
    assert len(registry["callable_provenance"]) == 9
    assert all(node.count("::") == 1 for node in nodes)
    for relative, expected in registry["source_sha256"].items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected


def test_every_runtime_patch_is_integrity_checked_and_leaks_fail_session(tmp_path: Path) -> None:
    bindings = network_guard.integrity_bindings()
    names = {
        (getattr(owner, "__name__", type(owner).__name__), name) for owner, name, _ in bindings
    }
    assert {
        ("socket", "getaddrinfo"),
        ("socket", "gethostbyname_ex"),
        ("SSLContext", "wrap_bio"),
        ("OpenerDirector", "open"),
        ("ProxyHandler", "__init__"),
        ("HTTPConnection", "connect"),
        ("Client", "_send_single_request"),
        ("AsyncClient", "_send_single_request"),
    } <= names
    for owner, name, expected in bindings:
        setattr(owner, name, object())
        try:
            with pytest.raises(RuntimeError, match="integrity failure"):
                network_guard.assert_installed()
        finally:
            setattr(owner, name, expected)
    network_guard.assert_installed()

    mutation = tmp_path / "test_integrity_leak.py"
    mutation.write_text(
        "import socket\n\ndef test_leak():\n    socket.getaddrinfo = lambda *a, **k: []\n",
        encoding="utf-8",
    )
    completed = _run_pytest("-q", str(mutation))
    assert completed.returncode != 0
    assert "network guard integrity failure" in (completed.stdout + completed.stderr)


@pytest.mark.parametrize(
    ("side_effect", "expected"),
    [
        (subprocess.TimeoutExpired("unshare", 10), network_namespace.NamespaceState.FAILURE),
        (OSError("synthetic"), network_namespace.NamespaceState.FAILURE),
    ],
)
def test_namespace_probe_classifies_timeout_and_oserror_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
    side_effect: BaseException,
    expected: network_namespace.NamespaceState,
) -> None:
    monkeypatch.setattr(network_namespace, "_prefix", lambda: ["unshare", "--"])

    def fail(*args: object, **kwargs: object) -> object:
        raise side_effect

    monkeypatch.setattr(network_namespace.subprocess, "run", fail)
    assert network_namespace.probe() is expected


@pytest.mark.parametrize(
    ("prefix", "returncode", "expected"),
    [
        (None, 0, network_namespace.NamespaceState.UNSUPPORTED),
        (["unshare", "--"], 1, network_namespace.NamespaceState.DENIED),
        (["unshare", "--"], 0, network_namespace.NamespaceState.SUPPORTED),
    ],
)
def test_namespace_probe_has_exact_nonexception_states(
    monkeypatch: pytest.MonkeyPatch,
    prefix: list[str] | None,
    returncode: int,
    expected: network_namespace.NamespaceState,
) -> None:
    monkeypatch.setattr(network_namespace, "_prefix", lambda: prefix)
    monkeypatch.setattr(
        network_namespace.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], returncode),
    )
    assert network_namespace.probe() is expected


@pytest.mark.parametrize(
    ("state", "returncode", "label"),
    [
        (network_namespace.NamespaceState.UNSUPPORTED, 2, "unsupported"),
        (network_namespace.NamespaceState.DENIED, 3, "denied"),
        (network_namespace.NamespaceState.FAILURE, 4, "failure"),
    ],
)
def test_namespace_run_refuses_each_unavailable_state_exactly(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: network_namespace.NamespaceState,
    returncode: int,
    label: str,
) -> None:
    monkeypatch.setattr(network_namespace, "_prefix", lambda: ["unshare", "--"])
    monkeypatch.setattr(network_namespace, "probe", lambda: state)
    assert network_namespace.run(["synthetic-command"]) == returncode
    assert capsys.readouterr().out.strip() == f"network_namespace={label}"


@pytest.mark.parametrize(
    "side_effect",
    [subprocess.TimeoutExpired("unshare", 300), OSError("synthetic")],
)
def test_namespace_run_classifies_execution_failure_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    side_effect: BaseException,
) -> None:
    monkeypatch.setattr(network_namespace, "_prefix", lambda: ["unshare", "--"])
    monkeypatch.setattr(
        network_namespace,
        "probe",
        lambda: network_namespace.NamespaceState.SUPPORTED,
    )

    def fail(*args: object, **kwargs: object) -> object:
        raise side_effect

    monkeypatch.setattr(network_namespace.subprocess, "run", fail)
    assert network_namespace.run(["synthetic-command"]) == 4
    assert capsys.readouterr().out.strip() == "network_namespace=failure"


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


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system('synthetic')\n",
        "import os\nos.popen('synthetic')\n",
        "import asyncio\nasyncio.create_subprocess_shell('synthetic')\n",
        "import importlib\nimportlib.import_module('socket')\n",
        "import subprocess\nsubprocess.run(['synthetic'])\n",
        "import builtins\nbuiltins.__import__('socket')\n",
    ],
)
def test_unreviewed_process_and_dynamic_call_mutations_fail_static_guard(
    tmp_path: Path, source: str
) -> None:
    mutation = tmp_path / "test_process_escape.py"
    mutation.write_text(source, encoding="utf-8")
    assert network_source_guard.test_call_violations(mutation)


@pytest.mark.parametrize(
    ("relative", "source", "expected"),
    [
        (
            "tests/architecture/test_runner_containment.py",
            "import subprocess\nsubprocess.run(['ok'])\nsubprocess.Popen(['denied'])\n",
            {"subprocess.Popen"},
        ),
        (
            "tests/runner_mailbox/test_persistent.py",
            "import os\nos.fork()\nos.system('denied')\n",
            {"os.system"},
        ),
        (
            "tests/architecture/test_runner_containment.py",
            "import subprocess as sp\nsp.run(['ok'])\nsp.Popen(['denied'])\n",
            {"subprocess.Popen"},
        ),
        (
            "tests/runner_mailbox/test_persistent.py",
            "from os import fork, system\nfork()\nsystem('denied')\n",
            {"os.system"},
        ),
    ],
)
def test_reviewed_test_process_calls_are_exact_not_whole_file_exemptions(
    tmp_path: Path, relative: str, source: str, expected: set[str]
) -> None:
    mutation = tmp_path / "test_reviewed_process.py"
    mutation.write_text(source, encoding="utf-8")
    assert network_source_guard.process_call_violations(mutation, relative) == expected


def test_runner_probe_socket_exemption_is_bound_to_reviewed_source_bytes(tmp_path: Path) -> None:
    source = (network_source_guard.ROOT / network_source_guard.CONTAINER_PROBE).read_bytes()
    mutation = tmp_path / "container_probe.py"
    mutation.write_bytes(source + b"\n# synthetic mutation\n")
    assert not network_source_guard.reviewed_runtime_import_provenance_valid(
        mutation, network_source_guard.CONTAINER_PROBE
    )
    assert network_source_guard.runtime_import_violations(
        mutation, network_source_guard.CONTAINER_PROBE
    ) == {"socket"}
