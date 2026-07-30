"""Composition boundary for the synthetic-only preview."""

import json

import click

from mycogni.adapters.synthetic_preview import PosixSyntheticPreview
from mycogni.application.synthetic_preview import SyntheticPreviewPort


def build_synthetic_preview() -> SyntheticPreviewPort:
    return PosixSyntheticPreview()


def _usage_error_payload() -> str:
    return json.dumps(
        {
            "command": "synthetic",
            "overall": "usage_error",
            "profile": "developer_preview_synthetic_only",
            "schema_version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _is_vendored_usage_error(error: Exception) -> bool:
    return any(
        base.__name__ == "UsageError" and base.__module__.startswith("typer._click")
        for base in type(error).__mro__
    )


def run_cli(args: list[str] | None = None) -> int:
    from mycogni.entrypoints.cli import build_app

    try:
        result = build_app(build_synthetic_preview())(args=args, standalone_mode=False)
        return int(result or 0)
    except click.UsageError:
        click.echo(_usage_error_payload())
        return 2
    except click.Abort:
        click.echo(
            '{"command":"synthetic","overall":"interrupted",'
            '"profile":"developer_preview_synthetic_only","schema_version":1}'
        )
        return 130
    except Exception as error:
        if not _is_vendored_usage_error(error):
            raise
        click.echo(_usage_error_payload())
        return 2


def main() -> int:
    return run_cli()
