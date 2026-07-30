"""Installed synthetic developer-preview contract."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mycogni.adapters.synthetic_preview import PosixSyntheticPreview
from mycogni.bootstrap.synthetic_preview import run_cli
from mycogni.entrypoints.cli import build_app

runner = CliRunner()
app = build_app(PosixSyntheticPreview())


def invoke(*arguments: str) -> tuple[int, str]:
    result = runner.invoke(app, list(arguments))
    assert result.exception is None or result.exit_code != 0
    return result.exit_code, result.stdout


def test_init_health_and_idempotency_are_bounded_and_deterministic(tmp_path: Path) -> None:
    state_dir = tmp_path / "preview"
    code, output = invoke("synthetic", "init", "--state-dir", str(state_dir), "--json")
    assert code == 0
    initialized = json.loads(output)
    assert initialized["command"] == "synthetic.init"
    assert initialized["overall"] == "initialized"
    assert initialized["profile"] == "developer_preview_synthetic_only"
    assert [check["id"] for check in initialized["checks"]] == [
        "state_layout",
        "fixtures",
        "authentication",
        "key_custody",
        "external_actions",
        "runtime_network_containment",
    ]

    manifest = state_dir / "installation.v1.json"
    before = (manifest.read_bytes(), manifest.stat().st_mtime_ns, sorted(state_dir.iterdir()))
    code, output = invoke("synthetic", "health", "--state-dir", str(state_dir), "--json")
    after = (manifest.read_bytes(), manifest.stat().st_mtime_ns, sorted(state_dir.iterdir()))
    assert code == 0
    assert json.loads(output)["overall"] == "synthetic_ready"
    assert before == after

    code, output = invoke("synthetic", "init", "--state-dir", str(state_dir), "--json")
    assert code == 0
    assert json.loads(output)["overall"] == "already_initialized"
    assert before == (
        manifest.read_bytes(),
        manifest.stat().st_mtime_ns,
        sorted(state_dir.iterdir()),
    )


@pytest.mark.parametrize(
    ("scenario", "fixture_result", "safe_stop"),
    [
        ("happy", "simulated_complete", "scenario_complete"),
        ("ambiguous", "simulated_ambiguous", "operator_review_required"),
        (
            "challenge_captcha",
            "simulated_challenge_captcha",
            "challenge_not_bypassed",
        ),
        ("timeout_unknown", "simulated_outcome_unknown", "retry_prohibited"),
        ("resurfacing", "simulated_resurfaced", "recurrence_observed"),
        ("not_found", "simulated_not_found", "no_match_observed"),
        ("schema_drift", "simulated_schema_drift", "connector_update_required"),
        ("partial", "simulated_partial", "operator_review_required"),
        ("denied", "simulated_denied", "broker_denial_recorded"),
        ("rate_limit", "simulated_candidate", "rate_limit_respected"),
    ],
)
def test_demo_reports_safe_synthetic_semantics(
    scenario: str, fixture_result: str, safe_stop: str
) -> None:
    code, output = invoke("synthetic", "demo", "--scenario", scenario, "--json")
    assert code == 0
    report = json.loads(output)
    assert report["scenario"] == scenario
    assert report["fixture_result"] == fixture_result
    assert report["safe_stop"] == safe_stop
    assert report["real_pii_accepted"] is False
    assert report["live_brokers"] == 0
    assert report["external_actions"] == "unavailable_by_composition"
    assert report["runtime_network_containment"] == "not_proven"
    assert report["real_removal_outcome"] == "not_applicable"
    assert "verified_removed" not in output


def test_relative_path_and_unknown_scenario_are_redacted() -> None:
    path_canary = "private-person-name-and-address"
    code, output = invoke("synthetic", "health", "--state-dir", path_canary, "--json")
    assert code == 2
    assert path_canary not in output
    assert json.loads(output)["overall"] == "usage_error"

    scenario_canary = "secret-user-value"
    code, output = invoke("synthetic", "demo", "--scenario", scenario_canary, "--json")
    assert code == 2
    assert scenario_canary not in output
    assert json.loads(output)["overall"] == "usage_error"


def test_installed_parser_errors_are_redacted_json(capsys: pytest.CaptureFixture[str]) -> None:
    canary = "private-secret-extra-argument"
    assert run_cli(["synthetic", "demo", "--json", canary]) == 2
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err
    assert json.loads(captured.out)["overall"] == "usage_error"


def test_absent_partial_and_unexpected_state_have_finite_outcomes(tmp_path: Path) -> None:
    absent = tmp_path / "absent"
    code, output = invoke("synthetic", "health", "--state-dir", str(absent), "--json")
    assert code == 20
    assert json.loads(output)["overall"] == "not_initialized"

    partial = tmp_path / "partial"
    partial.mkdir(mode=0o700)
    (partial / ".initialize.v1").write_text('{"format_version":1}\n')
    os.chmod(partial / ".initialize.v1", 0o600)
    code, output = invoke("synthetic", "health", "--state-dir", str(partial), "--json")
    assert code == 21
    assert json.loads(output)["overall"] == "initialization_incomplete"
    code, output = invoke("synthetic", "init", "--state-dir", str(partial), "--json")
    assert code == 0
    assert json.loads(output)["overall"] == "initialized"
    assert sorted(path.name for path in partial.iterdir()) == ["installation.v1.json"]

    unexpected = tmp_path / "unexpected"
    unexpected.mkdir(mode=0o700)
    (unexpected / "user-file").write_text("preserve")
    code, output = invoke("synthetic", "init", "--state-dir", str(unexpected), "--json")
    assert code == 23
    assert (unexpected / "user-file").read_text() == "preserve"
    assert json.loads(output)["overall"] == "state_incompatible"


def test_unsafe_directory_and_symlink_are_rejected_without_repair(tmp_path: Path) -> None:
    permissive = tmp_path / "permissive"
    permissive.mkdir(mode=0o755)
    code, output = invoke("synthetic", "init", "--state-dir", str(permissive), "--json")
    assert code == 22
    assert json.loads(output)["overall"] == "unsafe_storage"
    assert permissive.stat().st_mode & 0o777 == 0o755

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    code, output = invoke("synthetic", "init", "--state-dir", str(link), "--json")
    assert code == 22
    assert json.loads(output)["overall"] == "unsafe_storage"


def test_init_enforces_file_modes_under_restrictive_umask(tmp_path: Path) -> None:
    state_dir = tmp_path / "preview"
    state_dir.mkdir(mode=0o700)
    previous = os.umask(0o777)
    try:
        code, output = invoke("synthetic", "init", "--state-dir", str(state_dir), "--json")
    finally:
        os.umask(previous)
    assert code == 0
    assert json.loads(output)["overall"] == "initialized"
    assert (state_dir / "installation.v1.json").stat().st_mode & 0o777 == 0o600
    code, _output = invoke("synthetic", "health", "--state-dir", str(state_dir), "--json")
    assert code == 0


def test_human_output_keeps_nonclaims_prominent(tmp_path: Path) -> None:
    state_dir = tmp_path / "preview"
    code, output = invoke("synthetic", "init", "--state-dir", str(state_dir))
    assert code == 0
    assert "synthetic developer preview" in output
    assert "not a working privacy service" in output

    code, output = invoke("synthetic", "demo", "--scenario", "happy")
    assert code == 0
    assert "real PII accepted: no" in output
    assert "supported live brokers: 0" in output
    assert "runtime network containment: not proven" in output
    assert "real removal outcome: not_applicable" in output
