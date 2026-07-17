"""Mutation evidence for the offline GitHub Pages guard."""

from __future__ import annotations

import shutil
from pathlib import Path

from scripts.ci.site_guard import ROOT, validate_repository


def _site_fixture(tmp_path: Path) -> Path:
    for relative in (
        "site",
        "docs/v1/COMPLETION_MATRIX.md",
        "docs/07-deployment-architecture.md",
    ):
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
    return tmp_path


def test_repository_site_passes_offline_guard() -> None:
    assert validate_repository() == []


def test_stale_status_and_missing_asset_fail_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8")
        .replace(
            "M0 implementation is in progress",
            "The implementation is next",
        )
        .replace(
            '<script src="app.js" defer></script>',
            '<script src="missing.js" defer></script>',
        ),
        encoding="utf-8",
    )

    errors = validate_repository(root)

    assert any("stale project-status phrase" in error for error in errors)
    assert any("missing local src asset" in error for error in errors)


def test_incomplete_no_script_story_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace("System authority", "Authority details"),
        encoding="utf-8",
    )

    assert any(
        "no-script walkthrough is missing: system authority" in error
        for error in validate_repository(root)
    )


def test_matrix_status_drift_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    matrix = root / "docs/v1/COMPLETION_MATRIX.md"
    matrix.write_text(
        matrix.read_text(encoding="utf-8").replace(
            "| Network-deny proof | NET-001 | `IN_PROGRESS` |",
            "| Network-deny proof | NET-001 | `COMPLETE` |",
        ),
        encoding="utf-8",
    )

    assert any(
        "data-net-status" in error and "does not match matrix" in error
        for error in validate_repository(root)
    )


def test_placeholder_no_script_bodies_fail_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    html = index.read_text(encoding="utf-8")
    start = html.index("<noscript>")
    end = html.index("</noscript>") + len("</noscript>")
    index.write_text(
        html[:start]
        + "<noscript><section><h2>Product promise</h2><h2>Intended case experience</h2><h2>System authority</h2><h2>Failure behavior</h2><h2>Delivery path and current status</h2><p>Placeholder</p></section></noscript>"
        + html[end:],
        encoding="utf-8",
    )

    assert any("substantive concept" in error for error in validate_repository(root))
