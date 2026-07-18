"""Explicit operator-channel helpers for the synthetic SPIKE-AUTH ceremony.

This module is intentionally not installed as a command. It accepts no command-
line secret argument and implements no web or query-string transport.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

from mycogni.application.auth import AuthService
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    AuthDenial,
    AuthOutcome,
    BootstrapExchange,
    OpaqueCredential,
    RootCapability,
    RootPurpose,
)

SCROLLBACK_WARNING = (
    "WARNING: SECRET DISPLAY. Use a private terminal; disable recording, scrollback saving, "
    "copy synchronization and session logging before continuing."
)

REPROVISION_WARNING = (
    "DESTRUCTIVE REPROVISION: continuing revokes every old session and recovery code, consumes "
    "the current offline reprovision route, and requires you to save the replacement route. "
    "Interruption or process loss after consume but before handoff can leave no authority route."
)

HANDOFF_INTERRUPTED = (
    "authority-handoff-interrupted: replacement authority remains only in this process; do not "
    "resubmit the consumed code; redisplay the in-process result now. Process loss before a "
    "complete handoff can leave no authority route.\n"
)

DENIAL_GUIDANCE: dict[AuthDenial, str] = {
    AuthDenial.INVALID_PROOF: (
        "code is unknown or retired; verify the complete no-echo input, then use an authorized route; "
        "remaining attempts are unavailable"
    ),
    AuthDenial.ATTEMPTS_EXHAUSTED: "this code is burned; use another authorized recovery path",
    AuthDenial.REPLAYED: "this one-use code is already burned; do not retry it",
    AuthDenial.EXPIRED: "renew while authenticated or use the one-use reprovision capability",
    AuthDenial.NOT_YET_VALID: "wait for the activation instant before retrying",
    AuthDenial.CLOCK_ROLLBACK: "correct the trusted clock; retries remain blocked",
    AuthDenial.STALE_EPOCH: "authority changed; use the newest recovery or reprovision capability",
    AuthDenial.NON_INTERACTIVE: "attach a private interactive operator terminal",
    AuthDenial.MALFORMED_CREDENTIAL: "re-enter the complete code through no-echo input",
    AuthDenial.OPERATOR_DECLINED: "no credential was issued or consumed",
    AuthDenial.OUTPUT_INTERRUPTED: (
        "secret output did not complete; follow the displayed redisplay or restart instructions; "
        "never resubmit a consumed code"
    ),
}


class OperatorTty(Protocol):
    """Narrow no-echo/all-or-nothing secret channel supplied by composition.

    ``write_secret_block`` must either display the complete block or raise
    ``OSError`` without retaining a partial block. This spike proves the port
    contract with a synthetic channel; it does not claim a real terminal driver.
    """

    def isatty(self) -> bool: ...

    def write_public(self, value: str) -> None: ...

    def confirm_secret_display(self, warning: str) -> bool: ...

    def read_secret_no_echo(self) -> str: ...

    def write_secret_block(self, values: tuple[tuple[str, str], ...]) -> None: ...


@dataclass(frozen=True, slots=True)
class OperatorRecoveryResult:
    exchange: BootstrapExchange
    displayed: bool


@dataclass(frozen=True, slots=True)
class OperatorBootstrapResult:
    exchange: BootstrapExchange
    displayed: bool


def _deny(operator_tty: OperatorTty, prefix: str, denial: AuthDenial) -> None:
    guidance = DENIAL_GUIDANCE.get(denial, "follow the reviewed recovery procedure")
    operator_tty.write_public(f"{prefix}-denied: {denial.value}; {guidance}\n")


def begin_bootstrap_on_tty(
    service: AuthService,
    *,
    root: RootCapability,
    operator_tty: OperatorTty,
) -> AuthOutcome[OpaqueId]:
    """Issue/disclose bootstrap only after root authorization and confirmation."""
    if root.purpose is RootPurpose.REPROVISION:
        _deny(operator_tty, "bootstrap", AuthDenial.WRONG_PURPOSE)
        return AuthOutcome.denied(AuthDenial.WRONG_PURPOSE)
    if not operator_tty.isatty():
        _deny(operator_tty, "bootstrap", AuthDenial.NON_INTERACTIVE)
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm_secret_display(SCROLLBACK_WARNING):
        _deny(operator_tty, "bootstrap", AuthDenial.OPERATOR_DECLINED)
        return AuthOutcome.denied(AuthDenial.OPERATOR_DECLINED)
    outcome = service.begin_bootstrap(root)
    if outcome.denial is not None:
        _deny(operator_tty, "bootstrap", outcome.denial)
        return AuthOutcome.denied(outcome.denial)
    assert outcome.value is not None
    credential = outcome.value
    try:
        operator_tty.write_secret_block(
            (("bootstrap-code (one-use, short-lived)", credential.operator_code()),)
        )
    except OSError:
        service.cancel_bootstrap(credential.handle)
        with suppress(OSError):
            _deny(operator_tty, "bootstrap", AuthDenial.OUTPUT_INTERRUPTED)
            operator_tty.write_public(
                "bootstrap-restart: no bootstrap was disclosed or consumed; begin again with "
                "the same unconsumed initial root.\n"
            )
        return AuthOutcome.denied(AuthDenial.OUTPUT_INTERRUPTED)
    operator_tty.write_public(
        f"bootstrap-guidance: expires in {service.policy.bootstrap_ttl_seconds} seconds; "
        f"burns after {service.policy.max_attempts} failed proofs\n"
    )
    return AuthOutcome.allowed(credential.handle)


def exchange_bootstrap_code(
    service: AuthService, submitted_code: str
) -> AuthOutcome[BootstrapExchange]:
    """Model a manual body submission without URL, argv, echo, or logging."""
    try:
        credential = OpaqueCredential.parse_operator_code(submitted_code)
    except ValueError:
        return AuthOutcome.denied(AuthDenial.MALFORMED_CREDENTIAL)
    return service.exchange_operator_bootstrap(credential, reprovision=False)


def begin_reprovision_on_tty(
    service: AuthService,
    *,
    operator_tty: OperatorTty,
) -> AuthOutcome[OpaqueId]:
    """Issue a reprovision bootstrap from an opaque code and canonical store binding only."""
    if not operator_tty.isatty():
        _deny(operator_tty, "reprovision", AuthDenial.NON_INTERACTIVE)
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm_secret_display(SCROLLBACK_WARNING):
        _deny(operator_tty, "reprovision", AuthDenial.OPERATOR_DECLINED)
        return AuthOutcome.denied(AuthDenial.OPERATOR_DECLINED)
    operator_tty.write_public("reprovision-code (input hidden): ")
    raw = operator_tty.read_secret_no_echo()
    try:
        reprovision = OpaqueCredential.parse_operator_code(raw)
    except ValueError:
        _deny(operator_tty, "reprovision", AuthDenial.MALFORMED_CREDENTIAL)
        return AuthOutcome.denied(AuthDenial.MALFORMED_CREDENTIAL)
    outcome = service.begin_reprovision(reprovision)
    if outcome.denial is not None:
        _deny(operator_tty, "reprovision", outcome.denial)
        return AuthOutcome.denied(outcome.denial)
    assert outcome.value is not None
    credential = outcome.value
    try:
        operator_tty.write_secret_block(
            (("reprovision-bootstrap-code (one-use, short-lived)", credential.operator_code()),)
        )
    except OSError:
        service.cancel_bootstrap(credential.handle)
        with suppress(OSError):
            _deny(operator_tty, "reprovision", AuthDenial.OUTPUT_INTERRUPTED)
            operator_tty.write_public(
                "reprovision-restart: the offline route was not consumed; begin again with the "
                "same current reprovision code.\n"
            )
        return AuthOutcome.denied(AuthDenial.OUTPUT_INTERRUPTED)
    operator_tty.write_public(
        f"reprovision-guidance: bootstrap expires in {service.policy.bootstrap_ttl_seconds} "
        "seconds; the offline route is not consumed until the separately confirmed exchange\n"
    )
    return AuthOutcome.allowed(credential.handle)


def _display_bootstrap_handoff(exchange: BootstrapExchange, operator_tty: OperatorTty) -> bool:
    values = [
        ("new-session-code", exchange.session.operator_code()),
        ("new-recovery-code", exchange.recovery.operator_code()),
    ]
    if exchange.replacement_reprovision is not None:
        values.append(
            (
                "replacement-reprovision-code",
                exchange.replacement_reprovision.credential.operator_code(),
            )
        )
    try:
        operator_tty.write_secret_block(tuple(values))
    except OSError:
        with suppress(OSError):
            operator_tty.write_public(HANDOFF_INTERRUPTED)
        return False
    operator_tty.write_public(
        "bootstrap-exchange-succeeded: session and recovery handed off; save offline authority now\n"
    )
    return True


def exchange_bootstrap_on_tty(
    service: AuthService,
    *,
    submitted_code: str,
    operator_tty: OperatorTty,
) -> AuthOutcome[OperatorBootstrapResult]:
    """Consume bootstrap only after confirmation, then hand off all issued authority."""
    return _exchange_bootstrap_on_tty(
        service,
        submitted_code=submitted_code,
        operator_tty=operator_tty,
        reprovision=False,
    )


def exchange_reprovision_on_tty(
    service: AuthService,
    *,
    submitted_code: str,
    operator_tty: OperatorTty,
) -> AuthOutcome[OperatorBootstrapResult]:
    """Consume only a reprovision bootstrap after explicit destructive confirmation."""
    return _exchange_bootstrap_on_tty(
        service,
        submitted_code=submitted_code,
        operator_tty=operator_tty,
        reprovision=True,
    )


def _exchange_bootstrap_on_tty(
    service: AuthService,
    *,
    submitted_code: str,
    operator_tty: OperatorTty,
    reprovision: bool,
) -> AuthOutcome[OperatorBootstrapResult]:
    if not operator_tty.isatty():
        prefix = "reprovision-exchange" if reprovision else "bootstrap-exchange"
        _deny(operator_tty, prefix, AuthDenial.NON_INTERACTIVE)
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    warning = REPROVISION_WARNING if reprovision else SCROLLBACK_WARNING
    if reprovision:
        operator_tty.write_public(REPROVISION_WARNING + "\n")
    if not operator_tty.confirm_secret_display(warning):
        prefix = "reprovision-exchange" if reprovision else "bootstrap-exchange"
        _deny(operator_tty, prefix, AuthDenial.OPERATOR_DECLINED)
        return AuthOutcome.denied(AuthDenial.OPERATOR_DECLINED)
    try:
        credential = OpaqueCredential.parse_operator_code(submitted_code)
    except ValueError:
        outcome: AuthOutcome[BootstrapExchange] = AuthOutcome.denied(
            AuthDenial.MALFORMED_CREDENTIAL
        )
    else:
        outcome = service.exchange_operator_bootstrap(credential, reprovision=reprovision)
    if outcome.denial is not None:
        prefix = "reprovision-exchange" if reprovision else "bootstrap-exchange"
        _deny(operator_tty, prefix, outcome.denial)
        return AuthOutcome.denied(outcome.denial)
    assert outcome.value is not None
    displayed = _display_bootstrap_handoff(outcome.value, operator_tty)
    return AuthOutcome.allowed(OperatorBootstrapResult(exchange=outcome.value, displayed=displayed))


def redisplay_interrupted_bootstrap(
    result: OperatorBootstrapResult, operator_tty: OperatorTty
) -> OperatorBootstrapResult:
    """Retry a bootstrap authority handoff without replaying the consumed bootstrap."""
    if result.displayed or not operator_tty.isatty():
        return result
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm_secret_display(SCROLLBACK_WARNING):
        return result
    return OperatorBootstrapResult(
        exchange=result.exchange,
        displayed=_display_bootstrap_handoff(result.exchange, operator_tty),
    )


def _display_recovery(exchange: BootstrapExchange, operator_tty: OperatorTty) -> bool:
    try:
        operator_tty.write_secret_block(
            (
                ("new-session-code", exchange.session.operator_code()),
                ("new-recovery-code", exchange.recovery.operator_code()),
            )
        )
    except OSError:
        with suppress(OSError):
            operator_tty.write_public(HANDOFF_INTERRUPTED)
        return False
    operator_tty.write_public("recovery-succeeded: old sessions and old recovery codes revoked\n")
    return True


def recover_headless_on_tty(
    service: AuthService,
    *,
    operator_tty: OperatorTty,
) -> AuthOutcome[OperatorRecoveryResult]:
    """Recover by opaque handle lookup without browser, actor ID, profile ID or argv."""
    if not operator_tty.isatty():
        _deny(operator_tty, "recovery", AuthDenial.NON_INTERACTIVE)
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm_secret_display(SCROLLBACK_WARNING):
        _deny(operator_tty, "recovery", AuthDenial.OPERATOR_DECLINED)
        return AuthOutcome.denied(AuthDenial.OPERATOR_DECLINED)
    operator_tty.write_public("recovery-code (input hidden): ")
    raw = operator_tty.read_secret_no_echo()
    try:
        credential = OpaqueCredential.parse_operator_code(raw)
    except ValueError:
        _deny(operator_tty, "recovery", AuthDenial.MALFORMED_CREDENTIAL)
        return AuthOutcome.denied(AuthDenial.MALFORMED_CREDENTIAL)
    outcome = service.recover(recovery=credential)
    if outcome.denial is not None:
        _deny(operator_tty, "recovery", outcome.denial)
        return AuthOutcome.denied(outcome.denial)
    assert outcome.value is not None
    displayed = _display_recovery(outcome.value, operator_tty)
    return AuthOutcome.allowed(OperatorRecoveryResult(exchange=outcome.value, displayed=displayed))


def redisplay_interrupted_recovery(
    result: OperatorRecoveryResult, operator_tty: OperatorTty
) -> OperatorRecoveryResult:
    """Retry an all-or-nothing display without reusing consumed recovery authority."""
    if result.displayed or not operator_tty.isatty():
        return result
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm_secret_display(SCROLLBACK_WARNING):
        return result
    return OperatorRecoveryResult(
        exchange=result.exchange,
        displayed=_display_recovery(result.exchange, operator_tty),
    )


def redact_operator_transcript(transcript: str, credentials: tuple[OpaqueCredential, ...]) -> str:
    """Produce a review artifact without retaining disclosed authority material."""
    redacted = transcript
    for credential in credentials:
        redacted = redacted.replace(credential.operator_code(), "[REDACTED:auth_secret]")
    return redacted
