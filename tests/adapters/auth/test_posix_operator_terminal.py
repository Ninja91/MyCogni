"""Deterministic and real-PTY evidence for the native operator terminal."""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import termios
import textwrap
import threading
import time
from copy import deepcopy
from pathlib import Path

import pytest

from mycogni.adapters.auth.posix_operator_terminal import PosixOperatorTerminal
from mycogni.application.operator_terminal import (
    OperatorTerminalError,
    OperatorTerminalFailure,
    SecretDeliveryState,
    SecretField,
)


def _attached(fd: int = 41) -> PosixOperatorTerminal:
    terminal = PosixOperatorTerminal()
    terminal._fd = fd  # noqa: SLF001 - exact adapter boundary test
    return terminal


def test_secret_write_handles_short_writes_and_drains(monkeypatch: pytest.MonkeyPatch) -> None:
    pieces: list[bytes] = []
    drained: list[int] = []

    def short_write(fd: int, payload: bytes) -> int:
        assert fd == 41
        count = min(3, len(payload))
        pieces.append(payload[:count])
        return count

    monkeypatch.setattr(os, "write", short_write)
    monkeypatch.setattr(termios, "tcdrain", drained.append)
    _attached().disclose((SecretField("code", "opaque-value"),))
    assert b"".join(pieces) == b"code: opaque-value\n"
    assert drained == [41]


def test_secret_write_failure_before_first_byte_is_not_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_fd: int, _payload: bytes) -> int:
        raise OSError("redacted")

    monkeypatch.setattr(os, "write", fail)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached().disclose((SecretField("code", "opaque-value"),))
    assert raised.value.failure is OperatorTerminalFailure.IO_FAILED
    assert raised.value.delivery is SecretDeliveryState.NOT_STARTED
    assert "opaque-value" not in repr(raised.value)


def test_secret_write_failure_after_a_byte_is_may_have_disclosed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def partial_then_fail(_fd: int, _payload: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return 1
        raise OSError("redacted")

    monkeypatch.setattr(os, "write", partial_then_fail)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached().disclose((SecretField("code", "opaque-value"),))
    assert raised.value.delivery is SecretDeliveryState.MAY_HAVE_DISCLOSED


def test_drain_failure_is_may_have_disclosed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "write", lambda _fd, payload: len(payload))

    def fail_drain(_fd: int) -> None:
        raise OSError("redacted")

    monkeypatch.setattr(termios, "tcdrain", fail_drain)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached().disclose((SecretField("code", "opaque-value"),))
    assert raised.value.delivery is SecretDeliveryState.MAY_HAVE_DISCLOSED


@pytest.mark.parametrize(
    "field",
    [
        SecretField("bad\nlabel", "value"),
        SecretField("label", "bad\x1bvalue"),
        SecretField("x" * 97, "value"),
        SecretField("label", "x" * 513),
    ],
)
def test_disclosure_bounds_fail_before_io_and_redact(
    monkeypatch: pytest.MonkeyPatch, field: SecretField
) -> None:
    called = False

    def forbidden(_fd: int, _payload: bytes) -> int:
        nonlocal called
        called = True
        raise AssertionError("invalid disclosure must not write")

    monkeypatch.setattr(os, "write", forbidden)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached().disclose((field,))
    assert raised.value.delivery is SecretDeliveryState.NOT_STARTED
    assert field.value not in str(raised.value)
    assert called is False


def test_error_text_is_exact_and_redacted() -> None:
    error = OperatorTerminalError(
        OperatorTerminalFailure.OUTPUT_UNCERTAIN,
        SecretDeliveryState.MAY_HAVE_DISCLOSED,
    )
    assert str(error) == "operator_terminal:output_uncertain:may_have_disclosed"


def test_same_thread_reentry_is_busy_before_nested_io(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = _attached()

    def reenter(_fd: int, _payload: bytes) -> int:
        terminal.write_public("nested")
        raise AssertionError("nested write must not start")

    monkeypatch.setattr(os, "write", reenter)
    with pytest.raises(OperatorTerminalError) as raised:
        terminal.write_public("outer")
    assert raised.value.failure is OperatorTerminalFailure.BUSY


def test_second_thread_is_busy_before_io(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = _attached()
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    def blocked_write(_fd: int, payload: bytes) -> int:
        entered.set()
        release.wait(timeout=5)
        return len(payload)

    monkeypatch.setattr(os, "write", blocked_write)
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)

    def first() -> None:
        try:
            terminal.write_public("first")
        except BaseException as exc:  # pragma: no cover - assertion below reports it
            failures.append(exc)

    worker = threading.Thread(target=first)
    worker.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(OperatorTerminalError) as raised:
            terminal.write_public("second")
        assert raised.value.failure is OperatorTerminalFailure.BUSY
    finally:
        release.set()
        worker.join(timeout=5)
    assert not failures


def test_non_main_thread_read_is_busy_before_termios(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = _attached()
    called = False

    def forbidden(_fd: int) -> list[object]:
        nonlocal called
        called = True
        raise AssertionError("termios must not be touched")

    monkeypatch.setattr(termios, "tcgetattr", forbidden)
    failure: list[OperatorTerminalError] = []

    def invoke() -> None:
        try:
            terminal.read_secret("prompt", 16)
        except OperatorTerminalError as exc:
            failure.append(exc)

    worker = threading.Thread(target=invoke)
    worker.start()
    worker.join(timeout=5)
    assert len(failure) == 1
    assert failure[0].failure is OperatorTerminalFailure.BUSY
    assert called is False


def _fake_attrs() -> list[object]:
    return [1, 2, 3, termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG, 5, 6, []]


def test_secret_read_restores_exact_attributes(monkeypatch: pytest.MonkeyPatch) -> None:
    original = _fake_attrs()
    applied: list[tuple[int, list[object]]] = []
    monkeypatch.setattr(termios, "tcgetattr", lambda _fd: deepcopy(original))
    monkeypatch.setattr(
        termios,
        "tcsetattr",
        lambda _fd, when, attrs: applied.append((when, deepcopy(attrs))),
    )
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)
    monkeypatch.setattr(os, "write", lambda _fd, payload: len(payload))
    monkeypatch.setattr(os, "read", lambda _fd, _size: b"secret\n")
    assert _attached().read_secret("prompt", 16) == "secret"
    assert len(applied) == 2
    assert applied[0][0] == termios.TCSAFLUSH
    assert applied[0][1][3] == (original[3] & ~(termios.ECHO | termios.ECHONL))
    assert applied[1] == (termios.TCSAFLUSH, original)


def test_secret_read_hides_and_flushes_before_prompt_is_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _fake_attrs()
    events: list[str] = []
    monkeypatch.setattr(termios, "tcgetattr", lambda _fd: deepcopy(original))
    monkeypatch.setattr(
        termios,
        "tcsetattr",
        lambda _fd, _when, _attrs: events.append("hide" if not events else "restore"),
    )
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)

    def write(_fd: int, payload: bytes) -> int:
        events.append("prompt" if payload == b"prompt" else "newline")
        return len(payload)

    monkeypatch.setattr(os, "write", write)
    monkeypatch.setattr(os, "read", lambda _fd, _size: b"secret\n")
    assert _attached().read_secret("prompt", 16) == "secret"
    assert events == ["hide", "prompt", "restore", "newline"]


def test_restore_failure_latches_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    original = _fake_attrs()
    calls = 0

    def set_attrs(_fd: int, _when: int, _attrs: list[object]) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("redacted")

    monkeypatch.setattr(termios, "tcgetattr", lambda _fd: deepcopy(original))
    monkeypatch.setattr(termios, "tcsetattr", set_attrs)
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)
    monkeypatch.setattr(os, "write", lambda _fd, payload: len(payload))
    monkeypatch.setattr(os, "read", lambda _fd, _size: b"secret\n")
    terminal = _attached()
    with pytest.raises(OperatorTerminalError) as raised:
        terminal.read_secret("prompt", 16)
    assert raised.value.failure is OperatorTerminalFailure.RESTORE_FAILED
    with pytest.raises(OperatorTerminalError) as latched:
        terminal.write_public("must not write")
    assert latched.value.failure is OperatorTerminalFailure.RESTORE_FAILED


@pytest.mark.skipif(not hasattr(termios, "TIOCSCTTY"), reason="requires a POSIX controlling TTY")
def test_fresh_exec_real_pty_hides_input_and_restores_exact_attributes(tmp_path: Path) -> None:
    """A fresh interpreter uses one controlling PTY and restores its exact termios state."""
    master, slave = os.openpty()
    script = tmp_path / "pty_probe.py"
    script.write_text(
        textwrap.dedent(
            """
            import termios
            from mycogni.adapters.auth.posix_operator_terminal import PosixOperatorTerminal

            with PosixOperatorTerminal() as tty:
                before = termios.tcgetattr(tty._fd)
                value = tty.read_secret("READY\\n", 128)
                after = termios.tcgetattr(tty._fd)
                tty.write_public("RESULT:" + str(value == "hidden-value") + ":" + str(before == after) + "\\n")
            """
        ),
        encoding="utf-8",
    )

    def attach_controlling_tty() -> None:
        os.setsid()
        import fcntl

        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.tcsetpgrp(slave, os.getpgrp())

    process = subprocess.Popen(
        [sys.executable, str(script)],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        preexec_fn=attach_controlling_tty,
        text=False,
    )
    os.close(slave)
    transcript = bytearray()
    deadline = time.monotonic() + 5

    def read_until(expected: bytes) -> None:
        while expected not in transcript:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _writable, _exceptional = select.select([master], [], [], remaining)
            if not readable:
                break
            try:
                transcript.extend(os.read(master, 1024))
            except OSError:
                break

    try:
        read_until(b"READY\r\n")
        if b"operator_terminal:io_failed:not_started" in transcript:
            pytest.skip("host sandbox prohibits fresh-exec /dev/tty access")
        assert b"READY\r\n" in transcript, transcript.decode("utf-8", "replace")
        os.write(master, b"hidden-value\n")
        read_until(b"RESULT:True:True\r\n")
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        os.close(master)
    assert b"RESULT:True:True\r\n" in transcript
    assert b"hidden-value" not in transcript
