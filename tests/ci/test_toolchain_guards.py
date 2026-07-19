"""Failing fixtures for exact toolchain and frozen-lock enforcement."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]


def _run(*command: str, cwd: Path = REPOSITORY_ROOT) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("UV_BUILD_CONSTRAINT", None)
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_verify_toolchain_rejects_wrong_uv_version() -> None:
    completed = _run("make", "verify-toolchain", "UV_VERSION=0.0.0")
    assert completed.returncode != 0
    assert "Expected uv 0.0.0" in completed.stdout


def test_verify_toolchain_rejects_wrong_python_pin() -> None:
    completed = _run("make", "verify-toolchain", "PYTHON_VERSION=0.0.0")
    assert completed.returncode != 0
    assert "Expected .python-version 0.0.0" in completed.stdout


def test_frozen_lock_check_rejects_stale_project_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    pyproject = project / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "lock-canary"
version = "0.0.0"
requires-python = ">=3.12"
dependencies = []
""",
        encoding="utf-8",
    )
    created = _run("uv", "lock", "--offline", cwd=project)
    assert created.returncode == 0, created.stderr

    pyproject.write_text(pyproject.read_text(encoding="utf-8").replace("0.0.0", "0.0.1"))
    checked = _run("uv", "lock", "--check", "--offline", cwd=project)
    assert checked.returncode != 0
    assert "needs to be updated" in checked.stderr
