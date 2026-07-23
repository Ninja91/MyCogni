"""Native POSIX ``/dev/tty`` boundary for private operator ceremonies.

There is deliberately no stdio, environment, argv, logging, keyring, browser,
network, subprocess, or container fallback.
"""

from __future__ import annotations

import errno
import os
import signal
import stat
import sys
import termios
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from types import FrameType, TracebackType

from mycogni.application.operator_terminal import (
    OperatorTerminalError,
    OperatorTerminalFailure,
    SecretDeliveryState,
    SecretField,
)

MAX_PUBLIC_CHARS = 4096
MAX_FIELDS = 8
MAX_LABEL_CHARS = 96
MAX_VALUE_BYTES = 512
MAX_SECRET_BLOCK_BYTES = 8192

_PROCESS_LOCK = threading.Lock()
_OPERATION_LOCK = threading.Lock()
_OWNER_PID = os.getpid()


class _Cancelled(BaseException):
    """Private signal-to-unwind sentinel; never crosses the adapter boundary."""


def _poison_after_fork() -> None:
    global _OWNER_PID
    _OWNER_PID = -1


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_poison_after_fork)


class PosixOperatorTerminal:
    """Exclusive, foreground, one-descriptor ``/dev/tty`` session."""

    def __init__(self) -> None:
        self._fd: int | None = None
        self._owns_lock = False
        self._pid = os.getpid()
        self._restore_failed = False

    def __enter__(self) -> PosixOperatorTerminal:
        pid = os.getpid()
        if pid != _OWNER_PID or pid != self._pid:
            raise OperatorTerminalError(OperatorTerminalFailure.FORKED)
        if not _PROCESS_LOCK.acquire(blocking=False):
            raise OperatorTerminalError(OperatorTerminalFailure.BUSY)
        self._owns_lock = True
        base_flags = os.O_RDWR | os.O_NOCTTY | getattr(os, "O_CLOEXEC", 0)
        nofollow = getattr(os, "O_NOFOLLOW_ANY", getattr(os, "O_NOFOLLOW", 0))
        try:
            try:
                fd = os.open("/dev/tty", base_flags | nofollow)
            except PermissionError:
                # Darwin rejects no-follow flags for this special character device.
                # /dev is root-owned; bind the fallback to the same char-device inode.
                if sys.platform != "darwin":
                    raise
                if not stat.S_ISCHR(os.lstat("/dev/tty").st_mode):
                    raise
                fd = os.open("/dev/tty", base_flags)
            self._fd = fd
            if not stat.S_ISCHR(os.fstat(fd).st_mode) or not os.isatty(fd):
                raise OperatorTerminalError(OperatorTerminalFailure.NON_INTERACTIVE)
            if os.tcgetpgrp(fd) != os.getpgrp():
                raise OperatorTerminalError(OperatorTerminalFailure.NOT_FOREGROUND)
            termios.tcgetattr(fd)
        except OperatorTerminalError:
            self.close()
            raise
        except OSError as exc:
            self.close()
            failure = (
                OperatorTerminalFailure.NON_INTERACTIVE
                if exc.errno in {errno.ENXIO, errno.ENODEV, errno.ENOTTY}
                else OperatorTerminalFailure.IO_FAILED
            )
            raise OperatorTerminalError(failure) from None
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            with suppress(OSError):
                os.close(fd)
        if self._owns_lock:
            self._owns_lock = False
            _PROCESS_LOCK.release()

    def _checked_fd(self) -> int:
        if os.getpid() != _OWNER_PID or os.getpid() != self._pid:
            raise OperatorTerminalError(OperatorTerminalFailure.FORKED)
        if self._restore_failed:
            raise OperatorTerminalError(OperatorTerminalFailure.RESTORE_FAILED)
        if self._fd is None:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        return self._fd

    @contextmanager
    def _operation(self, *, main_thread: bool = False) -> Iterator[None]:
        self._checked_fd()
        if main_thread and threading.current_thread() is not threading.main_thread():
            raise OperatorTerminalError(OperatorTerminalFailure.BUSY)
        if not _OPERATION_LOCK.acquire(blocking=False):
            raise OperatorTerminalError(OperatorTerminalFailure.BUSY)
        try:
            yield
        finally:
            _OPERATION_LOCK.release()

    def isatty(self) -> bool:
        try:
            with self._operation():
                fd = self._checked_fd()
                return os.isatty(fd) and stat.S_ISCHR(os.fstat(fd).st_mode)
        except (OSError, OperatorTerminalError):
            return False

    @staticmethod
    def _public_bytes(value: str) -> bytes:
        if type(value) is not str or len(value) > MAX_PUBLIC_CHARS:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        if any(ord(char) < 0x20 and char != "\n" for char in value) or "\x1b" in value:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        try:
            return value.encode("utf-8", "strict")
        except UnicodeError:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED) from None

    def _write_unlocked(self, payload: bytes, *, secret: bool) -> None:
        fd = self._checked_fd()
        written = 0
        try:
            while written < len(payload):
                count = os.write(fd, payload[written:])
                if count <= 0:
                    raise OSError(errno.EIO, "terminal write failed")
                written += count
            termios.tcdrain(fd)
        except _Cancelled:
            state = (
                SecretDeliveryState.MAY_HAVE_DISCLOSED
                if secret and written > 0
                else SecretDeliveryState.NOT_STARTED
            )
            failure = (
                OperatorTerminalFailure.OUTPUT_UNCERTAIN
                if state is SecretDeliveryState.MAY_HAVE_DISCLOSED
                else OperatorTerminalFailure.CANCELLED
            )
            raise OperatorTerminalError(failure, state) from None
        except (KeyboardInterrupt, InterruptedError):
            state = (
                SecretDeliveryState.MAY_HAVE_DISCLOSED
                if secret and written > 0
                else SecretDeliveryState.NOT_STARTED
            )
            raise OperatorTerminalError(OperatorTerminalFailure.OUTPUT_UNCERTAIN, state) from None
        except OSError:
            state = (
                SecretDeliveryState.MAY_HAVE_DISCLOSED
                if secret and written > 0
                else SecretDeliveryState.NOT_STARTED
            )
            failure = (
                OperatorTerminalFailure.OUTPUT_UNCERTAIN
                if state is SecretDeliveryState.MAY_HAVE_DISCLOSED
                else OperatorTerminalFailure.IO_FAILED
            )
            raise OperatorTerminalError(failure, state) from None

    def write_public(self, value: str) -> None:
        with self._operation():
            self._write_unlocked(self._public_bytes(value), secret=False)

    @staticmethod
    def _cancel_handler(_signum: int, _frame: FrameType | None) -> None:
        raise _Cancelled

    def _install_cancel_handlers(self) -> dict[signal.Signals, signal.Handlers]:
        previous: dict[signal.Signals, signal.Handlers] = {}
        for item in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            previous[item] = signal.getsignal(item)  # type: ignore[assignment]
            signal.signal(item, self._cancel_handler)
        return previous

    @staticmethod
    def _restore_cancel_handlers(previous: dict[signal.Signals, signal.Handlers]) -> None:
        for item, handler in previous.items():
            signal.signal(item, handler)

    def read_secret(self, prompt: str, max_bytes: int) -> str:
        with self._operation(main_thread=True):
            return self._read_secret_unlocked(prompt, max_bytes)

    def _read_secret_unlocked(self, prompt: str, max_bytes: int) -> str:
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_VALUE_BYTES:
            raise OperatorTerminalError(OperatorTerminalFailure.INPUT_TOO_LONG)
        prompt_bytes = self._public_bytes(prompt)
        fd = self._checked_fd()
        original = termios.tcgetattr(fd)
        hidden = termios.tcgetattr(fd)
        hidden[3] &= ~(termios.ECHO | termios.ECHONL)
        failure: OperatorTerminalError | None = None
        data = bytearray()
        previous = self._install_cancel_handlers()
        try:
            self._write_unlocked(prompt_bytes, secret=False)
            termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
            while True:
                chunk = os.read(fd, max_bytes + 2)
                if chunk == b"":
                    raise OperatorTerminalError(OperatorTerminalFailure.EOF)
                data.extend(chunk)
                if b"\n" in chunk:
                    break
                if len(data) > max_bytes + 1:
                    while b"\n" not in chunk:
                        chunk = os.read(fd, max_bytes + 2)
                        if chunk == b"":
                            break
                    raise OperatorTerminalError(OperatorTerminalFailure.INPUT_TOO_LONG)
            line, _separator, _remainder = bytes(data).partition(b"\n")
            if line.endswith(b"\r"):
                line = line[:-1]
            if len(line) > max_bytes:
                raise OperatorTerminalError(OperatorTerminalFailure.INPUT_TOO_LONG)
            value = line.decode("utf-8", "strict")
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
                raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        except OperatorTerminalError as exc:
            failure = exc
            value = ""
        except (_Cancelled, KeyboardInterrupt, InterruptedError):
            failure = OperatorTerminalError(OperatorTerminalFailure.CANCELLED)
            value = ""
        except (OSError, UnicodeError):
            failure = OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
            value = ""
        finally:
            while True:
                try:
                    termios.tcsetattr(fd, termios.TCSAFLUSH, original)
                    break
                except _Cancelled:
                    failure = OperatorTerminalError(OperatorTerminalFailure.CANCELLED)
                except OSError:
                    self._restore_failed = True
                    failure = OperatorTerminalError(OperatorTerminalFailure.RESTORE_FAILED)
                    break
            try:
                self._write_unlocked(b"\n", secret=False)
            except (OperatorTerminalError, _Cancelled) as exc:
                if isinstance(exc, OperatorTerminalError):
                    failure = failure or exc
                else:
                    failure = failure or OperatorTerminalError(OperatorTerminalFailure.CANCELLED)
            self._restore_cancel_handlers(previous)
        if failure is not None:
            raise failure
        return value

    def confirm(self, prompt: str) -> bool:
        with self._operation(main_thread=True):
            return self._read_secret_unlocked(prompt, 3) == "YES"

    def disclose(self, fields: tuple[SecretField, ...]) -> None:
        with self._operation():
            self._disclose_unlocked(fields)

    def _disclose_unlocked(self, fields: tuple[SecretField, ...]) -> None:
        if type(fields) is not tuple or not 1 <= len(fields) <= MAX_FIELDS:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        lines: list[bytes] = []
        for field in fields:
            if type(field) is not SecretField:
                raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
            label = field.label
            if not 1 <= len(label) <= MAX_LABEL_CHARS or any(
                ord(char) < 0x21 or ord(char) > 0x7E or char == ":" for char in label
            ):
                raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
            try:
                value = field.value.encode("utf-8", "strict")
            except UnicodeError:
                raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED) from None
            if (
                not value
                or len(value) > MAX_VALUE_BYTES
                or any(byte < 0x20 or byte == 0x7F for byte in value)
            ):
                raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
            lines.append(label.encode("ascii") + b": " + value + b"\n")
        payload = b"".join(lines)
        if len(payload) > MAX_SECRET_BLOCK_BYTES:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        previous = (
            self._install_cancel_handlers()
            if threading.current_thread() is threading.main_thread()
            else {}
        )
        try:
            self._write_unlocked(payload, secret=True)
        finally:
            self._restore_cancel_handlers(previous)
