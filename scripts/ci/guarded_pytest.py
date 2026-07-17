"""The only supported pytest launcher for repository and package test suites."""

from __future__ import annotations

import os
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


def _disabled(arguments: Sequence[str], environment: dict[str, str]) -> bool:
    if (
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD" in environment
        or "MYCOGNI_DISABLE_NETWORK_GUARD" in environment
    ):
        return True
    all_arguments = [*environment.get("PYTEST_ADDOPTS", "").split(), *arguments]
    for index, argument in enumerate(all_arguments):
        lowered = argument.lower()
        if argument in FORBIDDEN_OPTIONS or argument.startswith("--confcutdir"):
            return True
        if lowered.startswith("-pno:") and "network_guard" in lowered:
            return True
        if argument == "-p" and index + 1 < len(all_arguments):
            value = all_arguments[index + 1].lower()
            if value.startswith("no:") and "network_guard" in value:
                return True
    return False


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _disabled(arguments, dict(os.environ)):
        print("guarded_pytest=denied")
        return 4
    return pytest.main(arguments, plugins=[network_guard_plugin])


if __name__ == "__main__":
    raise SystemExit(main())
