"""Composition tests for the private-terminal UX-001 launcher boundary."""

from __future__ import annotations

import pytest

from mycogni.application.operator_terminal import (
    OperatorTerminalError,
    OperatorTerminalFailure,
    SecretField,
)
from mycogni.bootstrap import web_shell


class FailingTerminal:
    def __enter__(self) -> FailingTerminal:
        raise OperatorTerminalError(OperatorTerminalFailure.NON_INTERACTIVE)

    def __exit__(self, *_args: object) -> None:
        return None


class RecordingTerminal:
    def __init__(self) -> None:
        self.public: list[str] = []
        self.disclosed: tuple[SecretField, ...] | None = None

    def __enter__(self) -> RecordingTerminal:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def check_ready(self) -> None:
        return None

    def write_public(self, value: str) -> None:
        self.public.append(value)

    def disclose(self, fields: tuple[SecretField, ...]) -> None:
        self.disclosed = fields


def test_launcher_fails_closed_without_private_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(web_shell, "PosixOperatorTerminal", FailingTerminal)
    uvicorn_called = False

    def fail_if_started(*_args: object, **_kwargs: object) -> None:
        nonlocal uvicorn_called
        uvicorn_called = True

    monkeypatch.setattr(web_shell.uvicorn, "run", fail_if_started)

    with pytest.raises(SystemExit) as raised:
        web_shell.main()

    assert raised.value.code == 2
    assert uvicorn_called is False
    captured = capsys.readouterr()
    assert "server not started" in captured.err
    assert "bootstrap-code" not in captured.err


def test_launcher_discloses_only_through_terminal_before_starting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = web_shell.build_synthetic_web_shell()
    terminal = RecordingTerminal()
    monkeypatch.setattr(web_shell, "build_synthetic_web_shell", lambda: bundle)
    monkeypatch.setattr(web_shell, "PosixOperatorTerminal", lambda: terminal)
    started: list[dict[str, object]] = []
    monkeypatch.setattr(web_shell.uvicorn, "run", lambda *args, **kwargs: started.append(kwargs))

    web_shell.main()

    assert started == [
        {
            "host": "127.0.0.1",
            "port": 8000,
            "access_log": False,
            "log_config": None,
            "use_colors": False,
        }
    ]
    assert terminal.public and "127.0.0.1:8000/login" in terminal.public[0]
    assert terminal.disclosed == (SecretField("bootstrap-code", bundle.bootstrap_code),)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
