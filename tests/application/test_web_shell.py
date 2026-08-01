"""Pure application evidence for the bounded UX-001 browser state contract."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from mycogni.adapters.auth import VolatileAuthDecisionStore
from mycogni.application.auth import AuthService
from mycogni.application.web_shell import LoginFailure, SyntheticWebShell
from mycogni.bootstrap.auth_setup import TrustedLocalAuthSetup
from mycogni.domain import OpaqueId

NOW = datetime(2030, 1, 1, tzinfo=UTC)


class FixedClock:
    def __init__(self) -> None:
        self.current = NOW

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


class SyntheticTokens:
    def __init__(self) -> None:
        self.counter = 0

    def generate(self, length: int) -> bytes:
        self.counter += 1
        value = hashlib.sha256(self.counter.to_bytes(16, "big")).digest()
        assert length == len(value)
        return value


def _shell() -> tuple[SyntheticWebShell, FixedClock, str]:
    clock = FixedClock()
    tokens = SyntheticTokens()
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
    assert issued.denial is None and issued.value is not None
    return SyntheticWebShell(auth=auth, clock=clock), clock, issued.value.operator_code()


def test_login_challenge_is_one_use_and_session_logout_is_bound() -> None:
    shell, _clock, bootstrap_code = _shell()
    start = shell.begin_login()

    result = shell.authenticate_login(
        challenge_cookie=start.challenge_cookie,
        csrf_token=start.csrf_token,
        operator_code=bootstrap_code,
    )
    assert result.failure is None
    assert result.session_cookie is not None
    assert result.csrf_token is not None
    view = shell.view(result.session_cookie)
    assert view is not None

    assert (
        shell.logout(
            session_cookie=result.session_cookie,
            csrf_token=view.csrf_token,
        )
        is True
    )
    assert shell.view(result.session_cookie) is None
    assert (
        shell.logout(
            session_cookie=result.session_cookie,
            csrf_token=view.csrf_token,
        )
        is False
    )


def test_recent_form_tokens_are_bounded_and_secret_values_are_not_reprable() -> None:
    shell, _clock, bootstrap_code = _shell()
    start = shell.begin_login()
    result = shell.authenticate_login(
        challenge_cookie=start.challenge_cookie,
        csrf_token=start.csrf_token,
        operator_code=bootstrap_code,
    )
    assert result.session_cookie is not None and result.csrf_token is not None
    first_tab = shell.view(result.session_cookie)
    second_tab = shell.view(result.session_cookie)
    assert first_tab is not None and second_tab is not None
    assert shell.logout(session_cookie=result.session_cookie, csrf_token=first_tab.csrf_token)
    assert repr(start) == "LoginStart([REDACTED])"
    assert repr(result) == "LoginResult([REDACTED])"
    assert repr(first_tab) == "AuthenticatedShellView([REDACTED])"
    for value in (
        start.challenge_cookie,
        start.csrf_token,
        result.session_cookie,
        result.csrf_token,
        first_tab.csrf_token,
        second_tab.csrf_token,
    ):
        assert value not in repr(start)
        assert value not in repr(result)
        assert value not in repr(first_tab)


def test_wrong_csrf_burns_login_form_without_attempting_code() -> None:
    shell, _clock, bootstrap_code = _shell()
    start = shell.begin_login()
    result = shell.authenticate_login(
        challenge_cookie=start.challenge_cookie,
        csrf_token="wrong-csrf",
        operator_code=bootstrap_code,
    )
    assert result.failure is LoginFailure.CSRF_REJECTED
    replay = shell.authenticate_login(
        challenge_cookie=start.challenge_cookie,
        csrf_token=start.csrf_token,
        operator_code=bootstrap_code,
    )
    assert replay.failure is LoginFailure.CHALLENGE_MISSING


def test_expired_session_is_removed_without_revealing_auth_state() -> None:
    shell, clock, bootstrap_code = _shell()
    start = shell.begin_login()
    result = shell.authenticate_login(
        challenge_cookie=start.challenge_cookie,
        csrf_token=start.csrf_token,
        operator_code=bootstrap_code,
    )
    assert result.session_cookie is not None
    clock.advance(1_801)
    assert shell.view(result.session_cookie) is None
    assert shell.active_session_count() == 0
