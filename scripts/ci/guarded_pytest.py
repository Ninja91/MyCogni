"""The only supported pytest launcher for repository and package test suites."""

from __future__ import annotations

import importlib
import os
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

import pytest  # noqa: E402

from scripts.ci import network_guard_plugin  # noqa: E402

REQUIRED_PLUGIN_MODULES = (
    "_hypothesis_pytestplugin",
    "anyio.pytest_plugin",
    "pytest_cov.plugin",
)
FORBIDDEN_ENVIRONMENT = {
    "MYCOGNI_DISABLE_NETWORK_GUARD",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "PYTEST_PLUGINS",
}
FORBIDDEN_EXACT_OPTIONS = {
    "--config-file",
    "--confcutdir",
    "--disable-network-guard",
    "--inifile",
    "--noconftest",
    "--override-ini",
    "--plugins",
    "-c",
    "-o",
    "-p",
}
FORBIDDEN_LONG_PREFIXES = (
    "--config-file=",
    "--confcutdir=",
    "--inifile=",
    "--noconftest=",
    "--override-ini=",
    "--plugins=",
)


def _parsed_addopts(environment: dict[str, str]) -> list[str] | None:
    try:
        return shlex.split(environment.get("PYTEST_ADDOPTS", ""), posix=True)
    except ValueError:
        return None


def _is_exclusion(tokens: Sequence[str]) -> bool:
    for argument in tokens:
        lowered = argument.casefold()
        if lowered in FORBIDDEN_EXACT_OPTIONS or lowered.startswith(FORBIDDEN_LONG_PREFIXES):
            return True
        if lowered.startswith(("-c", "-o", "-p")) and not lowered.startswith("--"):
            return True
    return False


def _disabled(arguments: Sequence[str], environment: dict[str, str]) -> bool:
    if FORBIDDEN_ENVIRONMENT & environment.keys():
        return True
    addopts = _parsed_addopts(environment)
    if addopts is None:
        return True
    all_arguments = [*addopts, *arguments]
    return _is_exclusion(all_arguments)


def _required_plugins() -> list[object]:
    return [
        network_guard_plugin,
        *(importlib.import_module(name) for name in REQUIRED_PLUGIN_MODULES),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _disabled(arguments, dict(os.environ)):
        print("guarded_pytest=denied")
        return 4
    return pytest.main(
        [*arguments, "--disable-plugin-autoload"],
        plugins=_required_plugins(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
