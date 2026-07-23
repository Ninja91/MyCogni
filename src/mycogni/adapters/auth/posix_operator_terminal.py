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
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from types import FrameType, TracebackType
from typing import cast

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

_MaskCallable = Callable[
    [int, tuple[signal.Signals, ...] | set[signal.Signals]], set[signal.Signals]
]


class _Cancelled(BaseException):
    """Private signal-to-unwind sentinel; never crosses the adapter boundary."""


class _HandlerInstallFailed(BaseException):
    """Private carrier for the exact subset of handlers already replaced."""

    def __init__(self, previous: dict[signal.Signals, signal.Handlers]) -> None:
        self.previous = previous


class _CancelSession:
    """Exact saved signal state returned while cancellation signals stay blocked."""

    def __init__(
        self,
        previous: dict[signal.Signals, signal.Handlers],
        old_mask: set[signal.Signals],
        mask: _MaskCallable,
    ) -> None:
        self.previous = previous
        self.old_mask = old_mask
        self.mask = mask


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
                # /dev is root-owned; require the path and opened fd to be char devices.
                if sys.platform != "darwin":
                    raise
                path_stat = os.lstat("/dev/tty")
                if path_stat.st_uid != 0 or not stat.S_ISCHR(path_stat.st_mode):
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
        if os.getpid() != _OWNER_PID or os.getpid() != self._pid:
            raise OperatorTerminalError(OperatorTerminalFailure.FORKED)
        if not _OPERATION_LOCK.acquire(blocking=False):
            raise OperatorTerminalError(OperatorTerminalFailure.BUSY)
        try:
            fd, self._fd = self._fd, None
            if fd is not None:
                with suppress(OSError):
                    os.close(fd)
            if self._owns_lock:
                self._owns_lock = False
                _PROCESS_LOCK.release()
        finally:
            _OPERATION_LOCK.release()

    def _checked_fd(self) -> int:
        if os.getpid() != _OWNER_PID or os.getpid() != self._pid:
            raise OperatorTerminalError(OperatorTerminalFailure.FORKED)
        if self._restore_failed:
            raise OperatorTerminalError(OperatorTerminalFailure.RESTORE_FAILED)
        if self._fd is None:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        fd = self._fd
        try:
            if not stat.S_ISCHR(os.fstat(fd).st_mode) or not os.isatty(fd):
                raise OperatorTerminalError(OperatorTerminalFailure.NON_INTERACTIVE)
            if os.tcgetpgrp(fd) != os.getpgrp():
                raise OperatorTerminalError(OperatorTerminalFailure.NOT_FOREGROUND)
        except OperatorTerminalError:
            raise
        except OSError as exc:
            failure = (
                OperatorTerminalFailure.NON_INTERACTIVE
                if exc.errno in {errno.ENXIO, errno.ENODEV, errno.ENOTTY}
                else OperatorTerminalFailure.IO_FAILED
            )
            raise OperatorTerminalError(failure) from None
        return fd

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

    def check_ready(self) -> None:
        """Raise the exact finite reason this terminal cannot start a ceremony."""
        with self._operation():
            self._checked_fd()

    @staticmethod
    def _public_bytes(value: str) -> bytes:
        if type(value) is not str or len(value) > MAX_PUBLIC_CHARS:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        if any(
            (ord(char) < 0x20 and char != "\n") or ord(char) == 0x7F or 0x80 <= ord(char) <= 0x9F
            for char in value
        ):
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        try:
            return value.encode("utf-8", "strict")
        except UnicodeError:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED) from None

    def _write_unlocked(self, payload: bytes, *, secret: bool) -> None:
        # Revalidate immediately before publication, after all potentially slow
        # validation and signal setup.  A backgrounded or replaced descriptor
        # never receives public or secret bytes.
        written = 0
        secret_write_attempted = False
        try:
            while written < len(payload):
                fd = self._checked_fd()
                if secret:
                    # This transition precedes the syscall.  An exception can
                    # occur after the kernel accepted bytes but before Python
                    # receives a count, so attempt itself is disclosure risk.
                    secret_write_attempted = True
                count = os.write(fd, payload[written:])
                if count <= 0:
                    raise OSError(errno.EIO, "terminal write failed")
                written += count
            termios.tcdrain(self._checked_fd())
        except OperatorTerminalError as exc:
            if secret and secret_write_attempted:
                raise OperatorTerminalError(
                    OperatorTerminalFailure.OUTPUT_UNCERTAIN,
                    SecretDeliveryState.MAY_HAVE_DISCLOSED,
                ) from None
            raise exc
        except _Cancelled:
            state = (
                SecretDeliveryState.MAY_HAVE_DISCLOSED
                if secret and secret_write_attempted
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
                if secret and secret_write_attempted
                else SecretDeliveryState.NOT_STARTED
            )
            failure = (
                OperatorTerminalFailure.OUTPUT_UNCERTAIN
                if state is SecretDeliveryState.MAY_HAVE_DISCLOSED
                else OperatorTerminalFailure.CANCELLED
            )
            raise OperatorTerminalError(failure, state) from None
        except OSError:
            state = (
                SecretDeliveryState.MAY_HAVE_DISCLOSED
                if secret and secret_write_attempted
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

    @staticmethod
    def _cancel_signals() -> tuple[signal.Signals, ...]:
        return (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)

    def _install_cancel_handlers(self) -> dict[signal.Signals, signal.Handlers]:
        previous: dict[signal.Signals, signal.Handlers] = {}
        try:
            for item in self._cancel_signals():
                previous[item] = signal.getsignal(item)  # type: ignore[assignment]
                signal.signal(item, self._cancel_handler)
        except BaseException:
            raise _HandlerInstallFailed(previous) from None
        return previous

    def _begin_cancel_session(self) -> _CancelSession:
        signals = self._cancel_signals()
        mask = cast(
            "_MaskCallable | None",
            getattr(signal, "pthread_sigmask", None),
        )
        if mask is None:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        try:
            old_mask = mask(signal.SIG_BLOCK, signals)
        except BaseException:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED) from None
        try:
            previous = self._install_cancel_handlers()
        except _HandlerInstallFailed as exc:
            restored = self._restore_cancel_handlers(exc.previous)
            if not restored:
                self._restore_failed = True
            if restored:
                with suppress(BaseException):
                    mask(signal.SIG_SETMASK, old_mask)
            failure = (
                OperatorTerminalFailure.IO_FAILED
                if restored
                else OperatorTerminalFailure.RESTORE_FAILED
            )
            raise OperatorTerminalError(failure) from None
        except BaseException:
            with suppress(BaseException):
                mask(signal.SIG_SETMASK, old_mask)
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED) from None
        return _CancelSession(previous, old_mask, mask)

    @staticmethod
    def _activate_cancel_session(session: _CancelSession) -> None:
        """Enter cancellable execution; caller already owns a protecting try."""
        try:
            session.mask(signal.SIG_SETMASK, session.old_mask)
        except _Cancelled:
            raise
        except BaseException:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED) from None

    def _end_cancel_session(self, session: _CancelSession) -> None:
        signals = self._cancel_signals()
        succeeded = True
        try:
            session.mask(signal.SIG_BLOCK, signals)
        except BaseException:
            succeeded = False
        try:
            restored = self._restore_cancel_handlers(session.previous)
        except _Cancelled:
            # A failed SIG_BLOCK transition can leave the private handlers
            # momentarily live.  Contain their sentinel and latch the session.
            restored = False
        if not restored:
            self._restore_failed = True
            succeeded = False
        try:
            if restored:
                session.mask(signal.SIG_SETMASK, session.old_mask)
        except BaseException:
            succeeded = False
        if not succeeded:
            failure = (
                OperatorTerminalFailure.IO_FAILED
                if restored
                else OperatorTerminalFailure.RESTORE_FAILED
            )
            raise OperatorTerminalError(failure)

    @staticmethod
    def _merge_cleanup_failure(
        current: OperatorTerminalError | None, cleanup: OperatorTerminalError
    ) -> OperatorTerminalError:
        """Restoration failure outranks earlier non-disclosure read failures."""
        if cleanup.failure is OperatorTerminalFailure.RESTORE_FAILED:
            return cleanup
        return current or cleanup

    @staticmethod
    def _restore_cancel_handlers(previous: dict[signal.Signals, signal.Handlers]) -> bool:
        succeeded = True
        for item, handler in previous.items():
            for _attempt in range(3):
                try:
                    signal.signal(item, handler)
                    break
                except _Cancelled:
                    continue
                except (OSError, ValueError):
                    continue
            else:
                succeeded = False
        return succeeded

    def read_secret(self, prompt: str, max_bytes: int) -> str:
        with self._operation(main_thread=True):
            return self._read_secret_unlocked(prompt, max_bytes)

    def _read_secret_unlocked(self, prompt: str, max_bytes: int) -> str:
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_VALUE_BYTES:
            raise OperatorTerminalError(OperatorTerminalFailure.INPUT_TOO_LONG)
        prompt_bytes = self._public_bytes(prompt)
        fd = self._checked_fd()
        try:
            original = termios.tcgetattr(fd)
            hidden = termios.tcgetattr(fd)
        except OSError:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED) from None
        hidden[3] &= ~(termios.ECHO | termios.ECHONL)
        failure: OperatorTerminalError | None = None
        data = bytearray()
        cancel_session = self._begin_cancel_session()
        try:
            self._activate_cancel_session(cancel_session)
            # Foreground ownership may change after the first validation.
            self._checked_fd()
            termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
            # Emit the prompt only after the flush-and-hide transition.  If the
            # operator responds as soon as the prompt is visible, their input
            # cannot race ahead of TCSAFLUSH and be discarded or echoed.
            self._write_unlocked(prompt_bytes, secret=False)
            self._checked_fd()
            while True:
                chunk = os.read(fd, max_bytes + 2)
                if chunk == b"":
                    raise OperatorTerminalError(OperatorTerminalFailure.EOF)
                data.extend(chunk)
                if b"\n" in chunk:
                    break
                if len(data) > max_bytes + 1:
                    while b"\n" not in chunk:
                        self._checked_fd()
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
            if any(
                ord(char) < 0x20 or ord(char) == 0x7F or 0x80 <= ord(char) <= 0x9F for char in value
            ):
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
            try:
                self._end_cancel_session(cancel_session)
            except OperatorTerminalError as exc:
                failure = self._merge_cleanup_failure(failure, exc)
            self._scrub_mutable(data)
        if failure is not None:
            raise failure
        return value

    @staticmethod
    def _scrub_mutable(data: bytearray) -> None:
        """Best-effort overwrite; no allocator or immutable-string erasure claim."""
        for index in range(len(data)):
            data[index] = 0

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
                if any(
                    ord(char) < 0x20 or ord(char) == 0x7F or 0x80 <= ord(char) <= 0x9F
                    for char in field.value
                ):
                    raise UnicodeError
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
        if threading.current_thread() is threading.main_thread():
            cancel_session = self._begin_cancel_session()
            write_failure: OperatorTerminalError | None = None
            cleanup_failure: OperatorTerminalError | None = None
            try:
                self._activate_cancel_session(cancel_session)
                self._write_unlocked(payload, secret=True)
            except OperatorTerminalError as exc:
                write_failure = exc
            except (_Cancelled, KeyboardInterrupt, InterruptedError):
                write_failure = OperatorTerminalError(OperatorTerminalFailure.CANCELLED)
            finally:
                try:
                    self._end_cancel_session(cancel_session)
                except OperatorTerminalError as exc:
                    cleanup_failure = exc
            if write_failure is not None:
                if write_failure.delivery is SecretDeliveryState.NOT_STARTED:
                    if (
                        cleanup_failure is not None
                        and cleanup_failure.failure is OperatorTerminalFailure.RESTORE_FAILED
                    ):
                        raise cleanup_failure
                    raise write_failure
                raise OperatorTerminalError(
                    OperatorTerminalFailure.OUTPUT_UNCERTAIN,
                    SecretDeliveryState.MAY_HAVE_DISCLOSED,
                ) from None
            if cleanup_failure is not None:
                # The payload and drain completed, but a cancellation transition
                # failure prevents an atomic COMPLETE assertion to the caller.
                raise OperatorTerminalError(
                    OperatorTerminalFailure.OUTPUT_UNCERTAIN,
                    SecretDeliveryState.MAY_HAVE_DISCLOSED,
                ) from None
        else:
            self._write_unlocked(payload, secret=True)
