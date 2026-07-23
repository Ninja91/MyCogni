"""Explicit operator-channel helpers for the synthetic SPIKE-AUTH ceremony.

This module is intentionally not installed as a command. It accepts no command-
line secret argument and implements no web or query-string transport.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass

from mycogni.application.auth import AuthService, ReprovisionOperatorAuthority
from mycogni.application.operator_terminal import (
    OperatorTerminal as OperatorTty,
)
from mycogni.application.operator_terminal import (
    OperatorTerminalError,
    OperatorTerminalFailure,
    SecretDeliveryState,
    SecretField,
)
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
    "authority-handoff-interrupted: some secret output may already be visible and replacement "
    "authority remains only in this process; do not resubmit the consumed code; redisplay the "
    "in-process result now. Process loss before a complete handoff can leave no authority route.\n"
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
    AuthDenial.TERMINAL_NOT_FOREGROUND: "return the private terminal to the foreground",
    AuthDenial.TERMINAL_BUSY: "wait for the active operator terminal operation",
    AuthDenial.TERMINAL_FORKED: "open a fresh operator terminal session in this process",
    AuthDenial.TERMINAL_IO_FAILED: "inspect the private terminal before retrying",
    AuthDenial.TERMINAL_RESTORE_FAILED: "restore or close the terminal before retrying",
    AuthDenial.MALFORMED_CREDENTIAL: "re-enter the complete code through no-echo input",
    AuthDenial.OPERATOR_DECLINED: "no credential was issued or consumed",
    AuthDenial.OUTPUT_INTERRUPTED: (
        "secret output did not complete; follow the displayed redisplay or restart instructions; "
        "never resubmit a consumed code"
    ),
    AuthDenial.CAPACITY_EXHAUSTED: (
        "no authority was consumed; wait for the finite ceremony TTL or allow trusted "
        "composition garbage collection, then retry the dedicated reprovision ceremony"
    ),
}

TERMINAL_INPUT_GUIDANCE: dict[OperatorTerminalFailure, tuple[AuthDenial, str]] = {
    OperatorTerminalFailure.CANCELLED: (
        AuthDenial.OPERATOR_DECLINED,
        "secret input was cancelled before authority was consumed",
    ),
    OperatorTerminalFailure.EOF: (
        AuthDenial.MALFORMED_CREDENTIAL,
        "private terminal input ended before a complete code was received",
    ),
    OperatorTerminalFailure.INPUT_TOO_LONG: (
        AuthDenial.MALFORMED_CREDENTIAL,
        "private terminal input exceeded the finite credential bound",
    ),
    OperatorTerminalFailure.NON_INTERACTIVE: (
        AuthDenial.NON_INTERACTIVE,
        "attach a private interactive operator terminal",
    ),
    OperatorTerminalFailure.NOT_FOREGROUND: (
        AuthDenial.TERMINAL_NOT_FOREGROUND,
        "return the private operator terminal to the foreground before retrying",
    ),
    OperatorTerminalFailure.IO_FAILED: (
        AuthDenial.TERMINAL_IO_FAILED,
        "private terminal input failed before authority was consumed; inspect the terminal",
    ),
    OperatorTerminalFailure.RESTORE_FAILED: (
        AuthDenial.TERMINAL_RESTORE_FAILED,
        "terminal restoration failed; close this terminal session and restore it before retrying",
    ),
    OperatorTerminalFailure.BUSY: (
        AuthDenial.TERMINAL_BUSY,
        "another operator terminal operation is active; wait for it to finish",
    ),
    OperatorTerminalFailure.FORKED: (
        AuthDenial.TERMINAL_FORKED,
        "open a fresh operator terminal session in this process",
    ),
    OperatorTerminalFailure.OUTPUT_UNCERTAIN: (
        AuthDenial.OUTPUT_INTERRUPTED,
        "terminal output may have started; follow the interrupted-handoff procedure",
    ),
}


@dataclass(frozen=True, slots=True)
class OperatorRecoveryResult:
    exchange: BootstrapExchange
    delivery: SecretDeliveryState

    @property
    def displayed(self) -> bool:
        """Compatibility projection; callers should retain the typed state."""
        return self.delivery is SecretDeliveryState.COMPLETE


@dataclass(frozen=True, slots=True)
class OperatorBootstrapResult:
    exchange: BootstrapExchange
    delivery: SecretDeliveryState

    @property
    def displayed(self) -> bool:
        """Compatibility projection; callers should retain the typed state."""
        return self.delivery is SecretDeliveryState.COMPLETE


def _secret_delivery(
    operator_tty: OperatorTty, values: tuple[tuple[str, str], ...]
) -> SecretDeliveryState:
    """Translate the terminal exception contract into durable ceremony state."""
    try:
        operator_tty.disclose(tuple(SecretField(label, value) for label, value in values))
    except OperatorTerminalError as exc:
        return exc.delivery
    except OSError:
        # A generic byte-stream exception cannot prove that zero bytes escaped.
        return SecretDeliveryState.MAY_HAVE_DISCLOSED
    return SecretDeliveryState.COMPLETE


def _deny(
    operator_tty: OperatorTty,
    prefix: str,
    denial: AuthDenial,
    *,
    guidance: str | None = None,
) -> None:
    if guidance is None:
        guidance = DENIAL_GUIDANCE.get(denial, "follow the reviewed recovery procedure")
    operator_tty.write_public(f"{prefix}-denied: {denial.value}; {guidance}\n")


def _deny_terminal_input(
    operator_tty: OperatorTty, prefix: str, error: OperatorTerminalError
) -> AuthDenial:
    denial, guidance = TERMINAL_INPUT_GUIDANCE[error.failure]
    with suppress(OSError, OperatorTerminalError):
        _deny(operator_tty, prefix, denial, guidance=guidance)
    return denial


def _write_public_after_complete(operator_tty: OperatorTty, value: str) -> None:
    """Best-effort status: never hide already completed secret publication."""
    with suppress(OSError, OperatorTerminalError):
        operator_tty.write_public(value)


def begin_bootstrap_on_tty(
    service: AuthService,
    *,
    root: RootCapability,
    operator_tty: OperatorTty,
) -> AuthOutcome[OpaqueId]:
    """Issue/disclose bootstrap only after root authorization and confirmation."""
    if root.purpose is RootPurpose.REPROVISION:
        _deny(
            operator_tty,
            "bootstrap",
            AuthDenial.WRONG_PURPOSE,
            guidance="use the dedicated reprovision ceremony; no authority was consumed",
        )
        return AuthOutcome.denied(AuthDenial.WRONG_PURPOSE)
    if not operator_tty.isatty():
        _deny(operator_tty, "bootstrap", AuthDenial.NON_INTERACTIVE)
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm(SCROLLBACK_WARNING):
        _deny(operator_tty, "bootstrap", AuthDenial.OPERATOR_DECLINED)
        return AuthOutcome.denied(AuthDenial.OPERATOR_DECLINED)
    outcome = service.begin_bootstrap(root)
    if outcome.denial is not None:
        _deny(operator_tty, "bootstrap", outcome.denial)
        return AuthOutcome.denied(outcome.denial)
    assert outcome.value is not None
    credential = outcome.value
    delivery = _secret_delivery(
        operator_tty,
        (("bootstrap-code (one-use, short-lived)", credential.operator_code()),),
    )
    if delivery is not SecretDeliveryState.COMPLETE:
        service.cancel_bootstrap(credential.handle)
        with suppress(OSError, OperatorTerminalError):
            _deny(operator_tty, "bootstrap", AuthDenial.OUTPUT_INTERRUPTED)
            operator_tty.write_public(
                "bootstrap-restart: the issued bootstrap is burned and output may have disclosed; "
                "begin again with the same unconsumed initial root.\n"
            )
        return AuthOutcome.denied(AuthDenial.OUTPUT_INTERRUPTED)
    _write_public_after_complete(
        operator_tty,
        f"bootstrap-guidance: expires in {service.policy.bootstrap_ttl_seconds} seconds; "
        f"burns after {service.policy.max_attempts} failed proofs\n",
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
    return service.exchange_bootstrap(credential)


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
    if not operator_tty.confirm(SCROLLBACK_WARNING):
        _deny(operator_tty, "reprovision", AuthDenial.OPERATOR_DECLINED)
        return AuthOutcome.denied(AuthDenial.OPERATOR_DECLINED)
    try:
        raw = operator_tty.read_secret("reprovision-code (input hidden): ", 128)
    except OperatorTerminalError as exc:
        return AuthOutcome.denied(_deny_terminal_input(operator_tty, "reprovision", exc))
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
    delivery = _secret_delivery(
        operator_tty,
        (("reprovision-bootstrap-code (one-use, short-lived)", credential.operator_code()),),
    )
    if delivery is not SecretDeliveryState.COMPLETE:
        service.cancel_bootstrap(credential.handle)
        with suppress(OSError, OperatorTerminalError):
            _deny(operator_tty, "reprovision", AuthDenial.OUTPUT_INTERRUPTED)
            operator_tty.write_public(
                "reprovision-restart: the issued bootstrap is burned and output may have "
                "disclosed; the offline route was not consumed, so begin again with it.\n"
            )
        return AuthOutcome.denied(AuthDenial.OUTPUT_INTERRUPTED)
    _write_public_after_complete(
        operator_tty,
        f"reprovision-guidance: bootstrap expires in {service.policy.bootstrap_ttl_seconds} "
        "seconds; the offline route is not consumed until the separately confirmed exchange\n",
    )
    return AuthOutcome.allowed(credential.handle)


def _display_bootstrap_handoff(
    exchange: BootstrapExchange, operator_tty: OperatorTty
) -> SecretDeliveryState:
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
    delivery = _secret_delivery(operator_tty, tuple(values))
    if delivery is not SecretDeliveryState.COMPLETE:
        with suppress(OSError, OperatorTerminalError):
            operator_tty.write_public(HANDOFF_INTERRUPTED)
        return delivery
    _write_public_after_complete(
        operator_tty,
        "bootstrap-exchange-succeeded: session and recovery handed off; save offline authority now\n",
    )
    return SecretDeliveryState.COMPLETE


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
    operator_authority: ReprovisionOperatorAuthority,
) -> AuthOutcome[OperatorBootstrapResult]:
    """Consume only a reprovision bootstrap after explicit destructive confirmation."""
    return _exchange_bootstrap_on_tty(
        service,
        submitted_code=submitted_code,
        operator_tty=operator_tty,
        reprovision=True,
        operator_authority=operator_authority,
    )


def _exchange_bootstrap_on_tty(
    service: AuthService,
    *,
    submitted_code: str,
    operator_tty: OperatorTty,
    reprovision: bool,
    operator_authority: ReprovisionOperatorAuthority | None = None,
) -> AuthOutcome[OperatorBootstrapResult]:
    if not operator_tty.isatty():
        prefix = "reprovision-exchange" if reprovision else "bootstrap-exchange"
        _deny(operator_tty, prefix, AuthDenial.NON_INTERACTIVE)
        return AuthOutcome.denied(AuthDenial.NON_INTERACTIVE)
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    warning = REPROVISION_WARNING if reprovision else SCROLLBACK_WARNING
    if reprovision:
        operator_tty.write_public(REPROVISION_WARNING + "\n")
    if not operator_tty.confirm(warning):
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
        if reprovision:
            authorized = service.authorize_reprovision_ceremony(credential, operator_authority)
            if authorized.denial is not None:
                outcome = AuthOutcome.denied(authorized.denial)
            else:
                assert authorized.value is not None
                outcome = service.exchange_confirmed_reprovision(credential, authorized.value)
        else:
            outcome = service.exchange_bootstrap(credential)
    if outcome.denial is not None:
        prefix = "reprovision-exchange" if reprovision else "bootstrap-exchange"
        guidance = None
        if outcome.denial is AuthDenial.CAPACITY_EXHAUSTED:
            guidance = (
                "no authority was consumed; wait for the "
                f"{service.policy.reprovision_ceremony_ttl_seconds}-second ceremony TTL or "
                "allow trusted composition garbage collection, then retry the dedicated "
                "reprovision ceremony"
            )
        elif outcome.denial is AuthDenial.WRONG_PURPOSE:
            if reprovision:
                guidance = (
                    "submitted code is not a reprovision bootstrap; no ceremony, root, session, "
                    "or recovery authority was consumed; begin the dedicated reprovision flow "
                    "with the current offline reprovision route"
                )
            else:
                guidance = "use the dedicated reprovision ceremony; no authority was consumed"
        _deny(operator_tty, prefix, outcome.denial, guidance=guidance)
        return AuthOutcome.denied(outcome.denial)
    assert outcome.value is not None
    delivery = _display_bootstrap_handoff(outcome.value, operator_tty)
    return AuthOutcome.allowed(OperatorBootstrapResult(exchange=outcome.value, delivery=delivery))


def redisplay_interrupted_bootstrap(
    result: OperatorBootstrapResult, operator_tty: OperatorTty
) -> OperatorBootstrapResult:
    """Retry a bootstrap authority handoff without replaying the consumed bootstrap."""
    if result.delivery is SecretDeliveryState.COMPLETE or not operator_tty.isatty():
        return result
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm(SCROLLBACK_WARNING):
        return result
    return OperatorBootstrapResult(
        exchange=result.exchange,
        delivery=_display_bootstrap_handoff(result.exchange, operator_tty),
    )


def _display_recovery(
    exchange: BootstrapExchange, operator_tty: OperatorTty
) -> SecretDeliveryState:
    delivery = _secret_delivery(
        operator_tty,
        (
            ("new-session-code", exchange.session.operator_code()),
            ("new-recovery-code", exchange.recovery.operator_code()),
        ),
    )
    if delivery is not SecretDeliveryState.COMPLETE:
        with suppress(OSError, OperatorTerminalError):
            operator_tty.write_public(HANDOFF_INTERRUPTED)
        return delivery
    _write_public_after_complete(
        operator_tty, "recovery-succeeded: old sessions and old recovery codes revoked\n"
    )
    return SecretDeliveryState.COMPLETE


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
    if not operator_tty.confirm(SCROLLBACK_WARNING):
        _deny(operator_tty, "recovery", AuthDenial.OPERATOR_DECLINED)
        return AuthOutcome.denied(AuthDenial.OPERATOR_DECLINED)
    try:
        raw = operator_tty.read_secret("recovery-code (input hidden): ", 128)
    except OperatorTerminalError as exc:
        return AuthOutcome.denied(_deny_terminal_input(operator_tty, "recovery", exc))
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
    delivery = _display_recovery(outcome.value, operator_tty)
    return AuthOutcome.allowed(OperatorRecoveryResult(exchange=outcome.value, delivery=delivery))


def redisplay_interrupted_recovery(
    result: OperatorRecoveryResult, operator_tty: OperatorTty
) -> OperatorRecoveryResult:
    """Retry an all-or-nothing display without reusing consumed recovery authority."""
    if result.delivery is SecretDeliveryState.COMPLETE or not operator_tty.isatty():
        return result
    operator_tty.write_public(SCROLLBACK_WARNING + "\n")
    if not operator_tty.confirm(SCROLLBACK_WARNING):
        return result
    return OperatorRecoveryResult(
        exchange=result.exchange,
        delivery=_display_recovery(result.exchange, operator_tty),
    )


def redact_operator_transcript(transcript: str, credentials: tuple[OpaqueCredential, ...]) -> str:
    """Produce a review artifact without retaining disclosed authority material."""
    redacted = transcript
    for credential in credentials:
        redacted = redacted.replace(credential.operator_code(), "[REDACTED:auth_secret]")
    return redacted
