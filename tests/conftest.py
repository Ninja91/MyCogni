"""Repository pytest configuration and guarded-launcher sentinel."""

from __future__ import annotations

import pytest

from scripts.ci import network_guard_plugin

pytest_plugins = ["scripts.ci.governance_evidence_plugin"]


def pytest_configure(config: pytest.Config) -> None:
    if network_guard_plugin not in config.pluginmanager.get_plugins():
        raise pytest.UsageError("pytest must run through scripts/ci/guarded_pytest.py")
