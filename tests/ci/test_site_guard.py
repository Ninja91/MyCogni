"""Mutation evidence for the offline GitHub Pages guard."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

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


def test_superseded_net_remediation_claim_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace(
            "GOV-001, NET-001, auth, runner, and the exact SQLite durability remediation have code-level acceptance",
            "GOV-001 has code-level acceptance; NET-001 remains in remediation review",
            1,
        ),
        encoding="utf-8",
    )

    assert any("stale project-status phrase" in error for error in validate_repository(root))


def test_unqualified_architecture_verification_claim_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace(
            "architecture specified and adversarially reviewed",
            "architecture verified",
            1,
        ),
        encoding="utf-8",
    )

    assert any("stale project-status phrase" in error for error in validate_repository(root))


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


def test_visible_status_date_drift_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace(
            "STATUS · 2026-07-20",
            "STATUS · 2026-07-19",
        ),
        encoding="utf-8",
    )

    assert any(
        "visible status date" in error and "does not match matrix snapshot date" in error
        for error in validate_repository(root)
    )


@pytest.mark.parametrize(
    ("current", "replacement", "label"),
    [
        ('data-status-date="2026-07-20"', 'data-status-date="2026-07-19"', "data-status-date"),
        (
            "<strong>2026-07-20:</strong> architecture is specified",
            "<strong>2026-07-19:</strong> architecture is specified",
            "current narrative date",
        ),
    ],
)
def test_other_status_date_drift_fails_closed(
    tmp_path: Path,
    current: str,
    replacement: str,
    label: str,
) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace(current, replacement),
        encoding="utf-8",
    )

    assert any(
        label in error and "does not match matrix snapshot date" in error
        for error in validate_repository(root)
    )


def test_invalid_calendar_status_date_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    matrix = root / "docs/v1/COMPLETION_MATRIX.md"
    matrix.write_text(
        matrix.read_text(encoding="utf-8").replace("2026-07-20", "2026-99-99"),
        encoding="utf-8",
    )
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace("2026-07-20", "2026-99-99"),
        encoding="utf-8",
    )

    assert any("snapshot date is invalid" in error for error in validate_repository(root))


def test_spike_key_status_drift_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace(
            'data-spike-key-status="IN_PROGRESS"',
            'data-spike-key-status="COMPLETE"',
        ),
        encoding="utf-8",
    )

    assert any(
        "data-spike-key-status" in error and "does not match matrix" in error
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


def test_synthetic_badge_and_atomic_regions_fail_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    index = root / "site/index.html"
    index.write_text(
        index.read_text(encoding="utf-8")
        .replace("ILLUSTRATIVE SYNTHETIC DEMO", "")
        .replace(
            'id="architecture-detail" aria-live="polite" aria-atomic="true"',
            'id="architecture-detail" aria-live="polite" aria-atomic="false"',
        )
        .replace(
            'id="scenario-answer" aria-live="polite" aria-atomic="true"',
            'id="scenario-answer" aria-live="polite" aria-atomic="false"',
        ),
        encoding="utf-8",
    )

    errors = validate_repository(root)
    assert any("illustrative badge" in error for error in errors)
    assert any("architecture-detail" in error and "atomic" in error for error in errors)
    assert any("scenario-answer" in error and "atomic" in error for error in errors)


def test_mobile_navigation_removal_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    styles = root / "site/styles.css"
    styles.write_text(
        styles.read_text(encoding="utf-8")
        + "\n@media (max-width: 1000px) { .chapter-nav { display: none; } }\n",
        encoding="utf-8",
    )

    assert any("removes chapter navigation" in error for error in validate_repository(root))


def test_contradictory_csp_claim_fails_closed(tmp_path: Path) -> None:
    root = _site_fixture(tmp_path)
    readme = root / "site/README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "It is not a `frame-ancestors` or clickjacking control",
            "It is a `frame-ancestors` and clickjacking control",
        ),
        encoding="utf-8",
    )

    assert any("framing nonclaim" in error for error in validate_repository(root))
