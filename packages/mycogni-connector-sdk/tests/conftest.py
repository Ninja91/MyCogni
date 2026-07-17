"""Package-suite sentinel for the repository guarded pytest launcher."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.ci import network_guard_plugin  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    if network_guard_plugin not in config.pluginmanager.get_plugins():
        raise pytest.UsageError("pytest must run through scripts/ci/guarded_pytest.py")
