"""Deterministic and real-PTY evidence for the native operator terminal."""

from __future__ import annotations

import os
import select
import signal
import stat
import subprocess
import sys
import termios
import textwrap
import threading
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from mycogni.adapters.auth import posix_operator_terminal as terminal_module
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


@pytest.fixture(autouse=True)
def _synthetic_attached_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make synthetic fd 41 pass the real adapter's repeated identity checks."""
    real_fstat = os.fstat
    real_isatty = os.isatty
    real_tcgetpgrp = os.tcgetpgrp

    monkeypatch.setattr(
        os,
        "fstat",
        lambda fd: SimpleNamespace(st_mode=stat.S_IFCHR) if fd == 41 else real_fstat(fd),
    )
    monkeypatch.setattr(os, "isatty", lambda fd: True if fd == 41 else real_isatty(fd))
    monkeypatch.setattr(
        os, "tcgetpgrp", lambda fd: os.getpgrp() if fd == 41 else real_tcgetpgrp(fd)
    )


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


@pytest.mark.parametrize("partial_write", [False, True])
def test_handler_cleanup_failure_cannot_downgrade_secret_delivery(
    monkeypatch: pytest.MonkeyPatch, partial_write: bool
) -> None:
    calls = 0

    def write(_fd: int, payload: bytes) -> int:
        nonlocal calls
        calls += 1
        if partial_write and calls > 1:
            raise OSError("synthetic partial failure")
        return 1 if partial_write else len(payload)

    monkeypatch.setattr(os, "write", write)
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)
    monkeypatch.setattr(
        PosixOperatorTerminal,
        "_end_cancel_session",
        lambda _self, _previous: (_ for _ in ()).throw(
            OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        ),
    )
    with pytest.raises(OperatorTerminalError) as raised:
        _attached().disclose((SecretField("code", "opaque-value"),))
    assert raised.value.failure is OperatorTerminalFailure.OUTPUT_UNCERTAIN
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


def test_close_is_busy_and_preserves_fd_during_inflight_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = _attached()
    entered = threading.Event()
    release = threading.Event()

    def blocked_write(_fd: int, payload: bytes) -> int:
        entered.set()
        assert release.wait(timeout=5)
        return len(payload)

    monkeypatch.setattr(os, "write", blocked_write)
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)
    worker = threading.Thread(
        target=terminal.disclose, args=((SecretField("code", "opaque-value"),),)
    )
    worker.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(OperatorTerminalError) as raised:
            terminal.close()
        assert raised.value.failure is OperatorTerminalFailure.BUSY
        assert terminal._fd == 41  # noqa: SLF001 - ownership regression
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_child_after_fork_close_refuses_without_touching_inherited_ownership() -> None:
    terminal = _attached()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no branch - separate child process
        os.close(read_fd)
        try:
            terminal.close()
        except OperatorTerminalError as exc:
            os.write(write_fd, exc.failure.value.encode("ascii"))
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        readable, _writable, _exceptional = select.select([read_fd], [], [], 5)
        assert readable
        assert os.read(read_fd, 64) == b"forked"
        waited, status = os.waitpid(child, 0)
        assert waited == child
        assert os.waitstatus_to_exitcode(status) == 0
        assert terminal._fd == 41  # noqa: SLF001 - parent ownership is intact
    finally:
        os.close(read_fd)


@pytest.mark.parametrize("background_at", [1, 2])
def test_each_public_write_revalidates_foreground_before_bytes(
    monkeypatch: pytest.MonkeyPatch, background_at: int
) -> None:
    calls = 0
    wrote = False

    def pgrp(_fd: int) -> int:
        nonlocal calls
        calls += 1
        return os.getpgrp() + 1 if calls == background_at else os.getpgrp()

    def forbidden(_fd: int, _payload: bytes) -> int:
        nonlocal wrote
        wrote = True
        return 1

    monkeypatch.setattr(os, "tcgetpgrp", pgrp)
    monkeypatch.setattr(os, "write", forbidden)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached().write_public("safe")
    assert raised.value.failure is OperatorTerminalFailure.NOT_FOREGROUND
    assert wrote is False


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


def test_secret_read_best_effort_scrubs_mutable_input_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _fake_attrs()
    scrubbed: list[bytes] = []
    real_scrub = PosixOperatorTerminal._scrub_mutable
    monkeypatch.setattr(termios, "tcgetattr", lambda _fd: deepcopy(original))
    monkeypatch.setattr(termios, "tcsetattr", lambda _fd, _when, _attrs: None)
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)
    monkeypatch.setattr(os, "write", lambda _fd, payload: len(payload))
    monkeypatch.setattr(os, "read", lambda _fd, _size: b"secret\n")

    def scrub(data: bytearray) -> None:
        real_scrub(data)
        scrubbed.append(bytes(data))

    monkeypatch.setattr(PosixOperatorTerminal, "_scrub_mutable", staticmethod(scrub))
    assert _attached().read_secret("prompt", 16) == "secret"
    assert scrubbed == [b"\0" * len(b"secret\n")]


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


def test_partial_handler_install_restores_handlers_and_signal_mask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, object]] = []
    installed = 0

    monkeypatch.setattr(signal, "getsignal", lambda item: f"old-{item}")

    def set_handler(item: signal.Signals, handler: object) -> None:
        nonlocal installed
        events.append(("handler", handler))
        if handler == PosixOperatorTerminal._cancel_handler:
            installed += 1
            if installed == 2:
                raise ValueError("synthetic")

    mask_calls = 0

    def mask(_how: int, value: object) -> set[signal.Signals]:
        nonlocal mask_calls
        mask_calls += 1
        events.append(("mask", value))
        return {signal.SIGUSR1}

    monkeypatch.setattr(signal, "signal", set_handler)
    monkeypatch.setattr(signal, "pthread_sigmask", mask)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached()._begin_cancel_session()  # noqa: SLF001
    assert raised.value.failure is OperatorTerminalFailure.IO_FAILED
    assert mask_calls == 2
    assert any(event == ("handler", f"old-{signal.SIGINT}") for event in events)


def test_mask_restore_failure_restores_previous_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    restored: list[object] = []
    monkeypatch.setattr(signal, "getsignal", lambda item: f"old-{item}")
    monkeypatch.setattr(signal, "signal", lambda _item, handler: restored.append(handler))
    calls = 0

    def mask(_how: int, _value: object) -> set[signal.Signals]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic")
        return {signal.SIGUSR1}

    monkeypatch.setattr(signal, "pthread_sigmask", mask)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached()._begin_cancel_session()  # noqa: SLF001
    assert raised.value.failure is OperatorTerminalFailure.IO_FAILED
    assert {f"old-{item}" for item in _attached()._cancel_signals()} <= set(restored)  # noqa: SLF001


def test_termios_is_restored_before_handlers_and_pending_signals_are_unmasked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _fake_attrs()
    events: list[str] = []
    set_attrs_calls = 0
    monkeypatch.setattr(termios, "tcgetattr", lambda _fd: deepcopy(original))

    def set_attrs(_fd: int, _when: int, _attrs: list[object]) -> None:
        nonlocal set_attrs_calls
        set_attrs_calls += 1
        events.append("hide" if set_attrs_calls == 1 else "restore-termios")

    monkeypatch.setattr(termios, "tcsetattr", set_attrs)
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)
    monkeypatch.setattr(os, "write", lambda _fd, payload: len(payload))
    monkeypatch.setattr(os, "read", lambda _fd, _size: b"secret\n")
    monkeypatch.setattr(signal, "getsignal", lambda _item: signal.SIG_DFL)

    def set_handler(_item: signal.Signals, handler: object) -> None:
        if handler is signal.SIG_DFL:
            events.append("restore-handler")

    monkeypatch.setattr(signal, "signal", set_handler)

    def mask(how: int, _value: object) -> set[signal.Signals]:
        events.append("unmask" if how == signal.SIG_SETMASK else "block")
        return set()

    monkeypatch.setattr(signal, "pthread_sigmask", mask)
    assert _attached().read_secret("prompt", 16) == "secret"
    last_termios = events.index("restore-termios")
    first_handler_restore = events.index("restore-handler")
    final_unmask = len(events) - 1 - events[::-1].index("unmask")
    assert last_termios < first_handler_restore < final_unmask


def test_end_cancel_session_contains_private_cancel_during_handler_restore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def set_handler(_item: signal.Signals, _handler: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise terminal_module._Cancelled  # noqa: SLF001 - containment regression

    monkeypatch.setattr(signal, "signal", set_handler)
    monkeypatch.setattr(signal, "pthread_sigmask", lambda _how, _value: set())
    _attached()._end_cancel_session({signal.SIGINT: signal.SIG_DFL})  # noqa: SLF001
    assert calls == 2


def test_end_cancel_session_maps_private_cancel_during_unmask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(signal, "signal", lambda _item, _handler: None)
    calls = 0

    def mask(_how: int, _value: object) -> set[signal.Signals]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise terminal_module._Cancelled  # noqa: SLF001 - containment regression
        return set()

    monkeypatch.setattr(signal, "pthread_sigmask", mask)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached()._end_cancel_session({signal.SIGINT: signal.SIG_DFL})  # noqa: SLF001
    assert raised.value.failure is OperatorTerminalFailure.IO_FAILED


def test_permanent_handler_restore_failure_latches_and_does_not_unmask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def set_handler(_item: signal.Signals, _handler: object) -> None:
        events.append("restore-attempt")
        raise OSError("synthetic permanent failure")

    def mask(how: int, _value: object) -> set[signal.Signals]:
        events.append("unmask" if how == signal.SIG_SETMASK else "block")
        return set()

    monkeypatch.setattr(signal, "signal", set_handler)
    monkeypatch.setattr(signal, "pthread_sigmask", mask)
    terminal = _attached()
    with pytest.raises(OperatorTerminalError) as raised:
        terminal._end_cancel_session({signal.SIGINT: signal.SIG_DFL})  # noqa: SLF001
    assert raised.value.failure is OperatorTerminalFailure.RESTORE_FAILED
    assert events == ["block", "restore-attempt", "restore-attempt", "restore-attempt"]
    with pytest.raises(OperatorTerminalError) as latched:
        terminal.write_public("must not write")
    assert latched.value.failure is OperatorTerminalFailure.RESTORE_FAILED


@pytest.mark.parametrize(
    "value",
    ["bad\x7fpublic", "bad\x85public", "bad\x7fsecret", "bad\x85secret"],
)
def test_del_and_c1_controls_are_rejected_before_io(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setattr(
        os, "write", lambda *_args: (_ for _ in ()).throw(AssertionError("must not write"))
    )
    terminal = _attached()
    with pytest.raises(OperatorTerminalError):
        if value.endswith("public"):
            terminal.write_public(value)
        else:
            terminal.disclose((SecretField("code", value),))


@pytest.mark.parametrize("encoded", [b"bad\x7fvalue\n", "bad\x85value\n".encode()])
def test_del_and_c1_controls_in_secret_input_are_rejected_and_terminal_restored(
    monkeypatch: pytest.MonkeyPatch, encoded: bytes
) -> None:
    original = _fake_attrs()
    applied: list[list[object]] = []
    monkeypatch.setattr(termios, "tcgetattr", lambda _fd: deepcopy(original))
    monkeypatch.setattr(
        termios,
        "tcsetattr",
        lambda _fd, _when, attrs: applied.append(deepcopy(attrs)),
    )
    monkeypatch.setattr(termios, "tcdrain", lambda _fd: None)
    monkeypatch.setattr(os, "write", lambda _fd, payload: len(payload))
    monkeypatch.setattr(os, "read", lambda _fd, _size: encoded)
    with pytest.raises(OperatorTerminalError) as raised:
        _attached().read_secret("prompt", 32)
    assert raised.value.failure is OperatorTerminalFailure.IO_FAILED
    assert applied[-1] == original


@pytest.mark.skipif(not hasattr(termios, "TIOCSCTTY"), reason="requires a POSIX controlling TTY")
def test_fresh_exec_real_pty_hides_input_and_restores_exact_attributes(tmp_path: Path) -> None:
    """A fresh interpreter uses one controlling PTY and restores its exact termios state."""
    master, slave = os.openpty()
    slave_path = os.ttyname(slave)
    script = tmp_path / "pty_probe.py"
    script.write_text(
        textwrap.dedent(
            """
            import fcntl
            import os
            import sys
            import termios
            from mycogni.adapters.auth.posix_operator_terminal import PosixOperatorTerminal

            os.setsid()
            slave = os.open(sys.argv[1], os.O_RDWR)
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.tcsetpgrp(slave, os.getpgrp())
            for target in (0, 1, 2):
                os.dup2(slave, target)
            if slave > 2:
                os.close(slave)

            # External host precondition, intentionally independent of the
            # adapter: some macOS application sandboxes deny /dev/tty even
            # after a controlling PTY is established.
            try:
                check = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
                assert os.isatty(check)
                assert os.tcgetpgrp(check) == os.getpgrp()
                termios.tcgetattr(check)
                os.close(check)
            except (OSError, AssertionError):
                os.write(1, b"HOST_PRECONDITION_NO_DEV_TTY\\n")
                raise SystemExit(77)

            with PosixOperatorTerminal() as tty:
                before = termios.tcgetattr(tty._fd)
                value = tty.read_secret("READY\\n", 128)
                after = termios.tcgetattr(tty._fd)
                tty.write_public("RESULT:" + str(value == "hidden-value") + ":" + str(before == after) + "\\n")
            """
        ),
        encoding="utf-8",
    )

    process = subprocess.Popen(
        [sys.executable, str(script), slave_path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
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
        if b"HOST_PRECONDITION_NO_DEV_TTY\r\n" in transcript:
            assert process.wait(timeout=5) == 77
            pytest.skip("external host precondition denies controlling /dev/tty access")
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
