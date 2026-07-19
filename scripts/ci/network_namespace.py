"""Probe or optionally run a command in an isolated Linux network namespace."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from enum import StrEnum


class NamespaceState(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    DENIED = "denied"
    FAILURE = "failure"


def _prefix() -> list[str] | None:
    if not sys.platform.startswith("linux"):
        return None
    unshare = shutil.which("unshare")
    if unshare is None:
        return None
    return [unshare, "--user", "--map-root-user", "--net", "--"]


def probe() -> NamespaceState:
    prefix = _prefix()
    if prefix is None:
        return NamespaceState.UNSUPPORTED
    try:
        completed = subprocess.run(
            [*prefix, sys.executable, "-c", "raise SystemExit(0)"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired):
        return NamespaceState.FAILURE
    if completed.returncode == 0:
        return NamespaceState.SUPPORTED
    return NamespaceState.DENIED


def run(command: Sequence[str]) -> int:
    prefix = _prefix()
    state = probe()
    if prefix is None or state is not NamespaceState.SUPPORTED:
        print(f"network_namespace={state.value}")
        return {
            NamespaceState.UNSUPPORTED: 2,
            NamespaceState.DENIED: 3,
            NamespaceState.FAILURE: 4,
        }[state]
    try:
        completed = subprocess.run([*prefix, *command], check=False, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        print("network_namespace=failure")
        return 4
    print("network_namespace=supported")
    return completed.returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    if arguments.run:
        return run(arguments.run)
    print(f"network_namespace={probe().value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
