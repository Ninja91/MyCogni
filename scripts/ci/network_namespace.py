"""Probe or optionally run a command in an isolated Linux network namespace."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence


def _prefix() -> list[str] | None:
    if not sys.platform.startswith("linux"):
        return None
    unshare = shutil.which("unshare")
    if unshare is None:
        return None
    return [unshare, "--user", "--map-root-user", "--net", "--"]


def supported() -> bool:
    prefix = _prefix()
    if prefix is None:
        return False
    completed = subprocess.run(
        [*prefix, sys.executable, "-c", "raise SystemExit(0)"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        env={"PATH": os.environ.get("PATH", "")},
    )
    return completed.returncode == 0


def run(command: Sequence[str]) -> int:
    prefix = _prefix()
    if prefix is None or not supported():
        print("network_namespace=unsupported")
        return 2
    print("network_namespace=enforced")
    return subprocess.run([*prefix, *command], check=False).returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    if arguments.run:
        return run(arguments.run)
    if supported():
        print("network_namespace=supported_optional")
    else:
        print("network_namespace=unsupported")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
