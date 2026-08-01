"""Composition root for the UX-001 synthetic authenticated shell."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime

import uvicorn
from fastapi import FastAPI

from mycogni.adapters.auth import OsTokenSource, VolatileAuthDecisionStore
from mycogni.adapters.auth.posix_operator_terminal import PosixOperatorTerminal
from mycogni.adapters.web_shell import DEFAULT_ALLOWED_HOSTS, create_synthetic_web_app
from mycogni.application.auth import AuthService
from mycogni.application.operator_terminal import OperatorTerminalError, SecretField
from mycogni.application.ports import Clock
from mycogni.application.web_shell import SyntheticWebShell
from mycogni.bootstrap.auth_setup import TrustedLocalAuthSetup
from mycogni.domain import OpaqueId


class SystemClock:
    """UTC wall clock for the non-durable synthetic developer process."""

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True, repr=False)
class SyntheticWebShellBundle:
    """Composed app and one-time code; the code is intentionally not repr-able."""

    app: FastAPI
    shell: SyntheticWebShell
    bootstrap_code: str

    def __repr__(self) -> str:
        return "SyntheticWebShellBundle(app=[opaque], shell=[opaque], bootstrap_code=[REDACTED])"


def build_synthetic_web_shell(
    *,
    allowed_hosts: tuple[str, ...] = tuple(sorted(DEFAULT_ALLOWED_HOSTS)),
    secure_cookies: bool = False,
) -> SyntheticWebShellBundle:
    """Compose auth, volatile state, and the browser adapter for UX-001 only."""
    clock: Clock = SystemClock()
    tokens = OsTokenSource()
    store = VolatileAuthDecisionStore()
    setup = TrustedLocalAuthSetup(clock=clock, token_source=tokens, store=store)
    auth = AuthService(
        clock=clock,
        token_source=tokens,
        store=store,
        reprovision_operator_authority=setup.reprovision_operator_authority,
    )
    setup.bind_auth_service(auth)
    roots = setup.provision(
        installation_id=OpaqueId.new(),
        actor_id=OpaqueId.new(),
        represented_profile_id=OpaqueId.new(),
    )
    issued = auth.begin_bootstrap(roots.initial_bootstrap)
    if issued.denial is not None or issued.value is None:
        raise RuntimeError("synthetic web bootstrap composition failed")
    shell = SyntheticWebShell(auth=auth, clock=clock)
    app = create_synthetic_web_app(
        shell,
        allowed_hosts=allowed_hosts,
        secure_cookies=secure_cookies,
    )
    return SyntheticWebShellBundle(
        app=app,
        shell=shell,
        bootstrap_code=issued.value.operator_code(),
    )


def main() -> None:
    """Start the loopback-only server after a private terminal disclosure."""
    bundle = build_synthetic_web_shell()
    try:
        with PosixOperatorTerminal() as terminal:
            terminal.check_ready()
            terminal.write_public(
                "MyCogni synthetic shell: no real PII, broker traffic, mail, or removal action.\n"
                "Open http://127.0.0.1:8000/login and enter the one-time code below.\n"
                "Loopback HTTP uses non-secure cookies only for this developer profile.\n"
            )
            terminal.disclose((SecretField("bootstrap-code", bundle.bootstrap_code),))
    except (OperatorTerminalError, OSError):
        # Never substitute stderr, stdout, logs, argv, or environment for the
        # private foreground terminal.  The server must not start without it.
        print(
            "MyCogni synthetic shell requires a private foreground terminal; server not started.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    uvicorn.run(
        bundle.app,
        host="127.0.0.1",
        port=8000,
        access_log=False,
        log_config=None,
        use_colors=False,
    )
