"""Explicit operator-channel helpers for the synthetic SPIKE-AUTH ceremony.

This module is intentionally not installed as a command. In particular, it has
no command-line secret argument and no web/query-string transport.
"""

from __future__ import annotations

from typing import Protocol

from mycogni.application.auth import AuthService
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    AuthDenial,
    AuthOutcome,
    BootstrapExchange,
    OpaqueCredential,
)


class OperatorTty(Protocol):
    """Narrow interactive channel; ordinary stdout/stderr are not authority channels."""

    def isatty(self) -> bool: ...

    def write(self, value: str) -> int: ...

    def read_secret(self) -> str:
        """Read without echo or history retention."""
        ...

    def flush(self) -> None: ...


def begin_bootstrap_on_tty(
    service: AuthService,
    *,
    actor_id: OpaqueId,
    represented_profile_id: OpaqueId,
    operator_tty: OperatorTty,
) -> AuthOutcome[OpaqueId]:
    """Issue and disclose bootstrap material only on an interactive channel."""
    if not operator_tty.isatty():
        operator_tty.write("bootstrap-denied: non_interactive\n")
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    credential = service.begin_bootstrap(
        actor_id=actor_id, represented_profile_id=represented_profile_id
    )
    operator_tty.write("bootstrap-code (one-use, short-lived): ")
    operator_tty.write(credential.operator_code())
    operator_tty.write("\n")
    operator_tty.flush()
    return AuthOutcome.allowed(credential.handle)


def recover_headless_on_tty(
    service: AuthService,
    *,
    actor_id: OpaqueId,
    represented_profile_id: OpaqueId,
    operator_tty: OperatorTty,
) -> AuthOutcome[BootstrapExchange]:
    """Recover without browser state, rotating all prior actor authority."""
    if not operator_tty.isatty():
        operator_tty.write("recovery-denied: non_interactive\n")
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    operator_tty.write("recovery-code: ")
    operator_tty.flush()
    raw = operator_tty.read_secret()
    try:
        credential = OpaqueCredential.parse_operator_code(raw)
    except ValueError:
        operator_tty.write("recovery-denied: malformed_credential\n")
        return AuthOutcome.denied(AuthDenial.MALFORMED_CREDENTIAL)
    outcome = service.recover(
        recovery=credential,
        actor_id=actor_id,
        represented_profile_id=represented_profile_id,
    )
    if outcome.denial is not None:
        operator_tty.write(f"recovery-denied: {outcome.denial.value}\n")
        return outcome
    assert outcome.value is not None
    operator_tty.write("new-session-code: ")
    operator_tty.write(outcome.value.session.operator_code())
    operator_tty.write("\nnew-recovery-code: ")
    operator_tty.write(outcome.value.recovery.operator_code())
    operator_tty.write("\n")
    operator_tty.flush()
    return outcome


def redact_operator_transcript(transcript: str, credentials: tuple[OpaqueCredential, ...]) -> str:
    """Produce a review artifact without retaining disclosed authority material."""
    redacted = transcript
    for credential in credentials:
        redacted = redacted.replace(credential.operator_code(), "[REDACTED:auth_secret]")
    return redacted
