"""Delivery layer for the installed synthetic-only developer preview."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Annotated

import typer

from mycogni.application.synthetic_preview import (
    EXIT_CODES,
    DemoReport,
    PreviewReason,
    PreviewReport,
    SyntheticPreviewError,
    SyntheticPreviewPort,
)


def _json(value: object) -> None:
    typer.echo(json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


def _failure(reason: PreviewReason) -> None:
    _json(
        {
            "command": "synthetic",
            "overall": reason.value,
            "profile": "developer_preview_synthetic_only",
            "schema_version": 1,
        }
    )
    raise typer.Exit(EXIT_CODES[reason])


def _run[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except SyntheticPreviewError as error:
        _failure(error.reason)
    except KeyboardInterrupt:
        _failure(PreviewReason.INTERRUPTED)
    except Exception:
        _failure(PreviewReason.INTERNAL_ERROR)
    raise AssertionError("unreachable")


def _human_report(report: PreviewReport) -> None:
    label = report.command.removeprefix("synthetic.").upper()
    typer.echo(f"MyCogni synthetic developer preview: {label} {report.overall.upper()}")
    for check in report.checks:
        typer.echo(f"{check.id}: {check.reason} [{check.status}]")
    typer.echo("This is synthetic developer state, not a working privacy service.")


def _human_demo(report: DemoReport) -> None:
    typer.echo("MyCogni synthetic developer preview: SYNTHETIC DEMO")
    typer.echo(f"scenario: {report.scenario}")
    typer.echo(f"fixture result: {report.fixture_result}")
    typer.echo(f"safe stop: {report.safe_stop}")
    typer.echo("real PII accepted: no")
    typer.echo("supported live brokers: 0")
    typer.echo("external actions: unavailable by composition")
    typer.echo("runtime network containment: not proven")
    typer.echo("real removal outcome: not_applicable")
    typer.echo("This does not scan, contact, submit to, or verify removal from a real broker.")


def build_app(preview: SyntheticPreviewPort) -> typer.Typer:
    """Bind CLI commands to a port supplied by the composition root."""
    app = typer.Typer(
        help="MyCogni developer tools. This package is not a working privacy service.",
        no_args_is_help=True,
        pretty_exceptions_enable=False,
    )
    synthetic = typer.Typer(
        help="Synthetic developer preview; accepts no real PII and performs no external action.",
        no_args_is_help=True,
    )
    app.add_typer(synthetic, name="synthetic")

    @synthetic.command("init")
    def synthetic_init(
        state_dir: Annotated[
            str,
            typer.Option(
                "--state-dir",
                help="Absolute owner-private directory for non-production synthetic state.",
            ),
        ],
        json_output: Annotated[
            bool, typer.Option("--json", help="Emit one stable JSON document.")
        ] = False,
    ) -> None:
        """Initialize a separate synthetic-only state directory."""
        report = _run(lambda: preview.initialize(state_dir))
        _json(report.as_dict()) if json_output else _human_report(report)

    @synthetic.command("health")
    def synthetic_health(
        state_dir: Annotated[
            str,
            typer.Option(
                "--state-dir",
                help="Absolute owner-private directory for non-production synthetic state.",
            ),
        ],
        json_output: Annotated[
            bool, typer.Option("--json", help="Emit one stable JSON document.")
        ] = False,
    ) -> None:
        """Inspect synthetic readiness without changing preview state."""
        report = _run(lambda: preview.health(state_dir))
        _json(report.as_dict()) if json_output else _human_report(report)

    @synthetic.command("demo")
    def synthetic_demo(
        scenario: Annotated[
            str,
            typer.Option("--scenario", help="Reviewed finite fixture scenario name."),
        ] = "happy",
        json_output: Annotated[
            bool, typer.Option("--json", help="Emit one stable JSON document.")
        ] = False,
    ) -> None:
        """Run one deterministic fixture scenario without real-world effects."""
        report = _run(lambda: preview.demo(scenario))
        _json(report.as_dict()) if json_output else _human_demo(report)

    return app
