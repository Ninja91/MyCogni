"""Pytest lifecycle integration for the process-local network guard."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import network_guard

MARKER = "simulator_loopback"
_TOKENS: dict[str, Any] = {}


def _is_simulator_test(item: pytest.Item) -> bool:
    path = Path(str(item.path)).resolve()
    simulator_root = (Path(str(item.config.rootpath)) / "tests" / "simulator").resolve()
    try:
        path.relative_to(simulator_root)
    except ValueError:
        return False
    return True


def pytest_configure(config: pytest.Config) -> None:
    if os.environ.get("MYCOGNI_DISABLE_NETWORK_GUARD") is not None:
        raise pytest.UsageError("network guard cannot be disabled")
    network_guard.install()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    del config
    for item in items:
        markers = list(item.iter_markers(name=MARKER))
        if not markers:
            continue
        own_markers = [marker for marker in item.own_markers if marker.name == MARKER]
        if len(markers) != 1 or len(own_markers) != 1 or markers[0].args or markers[0].kwargs:
            raise pytest.UsageError("simulator loopback marker must be exact and argument-free")
        if not _is_simulator_test(item):
            raise pytest.UsageError("simulator loopback marker is restricted to simulator tests")


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> Any:
    network_guard.assert_installed()
    enabled = item.get_closest_marker(MARKER) is not None
    token = network_guard.activate_test(item.nodeid, simulator_loopback=enabled)
    _TOKENS[item.nodeid] = token
    yield


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item) -> Any:
    yield
    token = _TOKENS.pop(item.nodeid, None)
    if token is None:
        raise RuntimeError("network guard test context was not installed")
    network_guard.deactivate_test(token)
    network_guard.assert_installed()


def pytest_unconfigure(config: pytest.Config) -> None:
    del config
    _TOKENS.clear()
    network_guard.uninstall()
