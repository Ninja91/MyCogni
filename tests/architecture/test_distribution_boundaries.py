"""Build and inspect release archives for package and license separation."""

from __future__ import annotations

import os
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
EXPECTED_LEGAL_FILES = {
    "LICENSE": (REPOSITORY_ROOT / "LICENSE").read_bytes(),
    "NOTICE": (REPOSITORY_ROOT / "NOTICE").read_bytes(),
}


def _build(package: str, output: Path) -> tuple[Path, Path]:
    environment = os.environ.copy()
    environment.setdefault("UV_BUILD_CONSTRAINT", "build-constraints.txt")
    completed = subprocess.run(
        ["uv", "build", "--package", package, "--out-dir", str(output)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return next(output.glob("*.whl")), next(output.glob("*.tar.gz"))


def _matching_member(names: list[str], filename: str) -> str:
    matches = [name for name in names if Path(name).name == filename]
    assert len(matches) == 1, f"expected one {filename}, found {matches}"
    return matches[0]


@pytest.mark.parametrize(
    ("package", "required_prefix", "forbidden_prefix"),
    [
        ("mycogni", "mycogni/", "connector_protocol/"),
        ("mycogni-connector-sdk", "connector_protocol/", "mycogni/"),
    ],
)
def test_distributions_keep_code_and_legal_material_separate(
    tmp_path: Path, package: str, required_prefix: str, forbidden_prefix: str
) -> None:
    wheel, source = _build(package, tmp_path / package)

    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
        assert any(name.startswith(required_prefix) for name in wheel_names)
        assert not any(name.startswith(forbidden_prefix) for name in wheel_names)
        assert not any("/tests/" in name or "__pycache__" in name for name in wheel_names)
        for filename, expected in EXPECTED_LEGAL_FILES.items():
            member = _matching_member(wheel_names, filename)
            assert archive.read(member) == expected

    with tarfile.open(source, "r:gz") as archive:
        source_names = archive.getnames()
        for filename, expected in EXPECTED_LEGAL_FILES.items():
            member = _matching_member(source_names, filename)
            extracted = archive.extractfile(member)
            assert extracted is not None
            assert extracted.read() == expected
