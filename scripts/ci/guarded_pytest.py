"""The only supported pytest launcher for repository and package test suites."""

from __future__ import annotations

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

FORBIDDEN_OPTIONS = {
    "--noconftest",
    "--disable-network-guard",
}


def _parsed_addopts(environment: dict[str, str]) -> list[str] | None:
    try:
        return shlex.split(environment.get("PYTEST_ADDOPTS", ""), posix=True)
    except ValueError:
        return None


def _is_exclusion(tokens: Sequence[str]) -> bool:
    for index, argument in enumerate(tokens):
        lowered = argument.casefold()
        if lowered == "--noconftest" or lowered.startswith("--noconftest="):
            return True
        if lowered == "--confcutdir" or lowered.startswith("--confcutdir="):
            return True
        if lowered.startswith("-pno:") or lowered.startswith("-p=no:"):
            return True
        if (
            lowered == "-p"
            and index + 1 < len(tokens)
            and tokens[index + 1].casefold().startswith("no:")
        ):
            return True
    return False


def _disabled(arguments: Sequence[str], environment: dict[str, str]) -> bool:
    if (
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD" in environment
        or "MYCOGNI_DISABLE_NETWORK_GUARD" in environment
    ):
        return True
    addopts = _parsed_addopts(environment)
    if addopts is None:
        return True
    all_arguments = [*addopts, *arguments]
    return any(argument in FORBIDDEN_OPTIONS for argument in all_arguments) or _is_exclusion(
        all_arguments
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _disabled(arguments, dict(os.environ)):
        print("guarded_pytest=denied")
        return 4
    return pytest.main(arguments, plugins=[network_guard_plugin])


if __name__ == "__main__":
    raise SystemExit(main())
