"""Framework-free state contract for the UX-001 synthetic web shell.

This is deliberately smaller than the production control plane.  It proves the
browser-facing authority choreography without accepting personal data,
contacting a broker, or composing a connector.  FastAPI and HTML rendering
remain adapters; this module only owns bounded session/challenge state and
delegates credential decisions to the existing authentication service.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from threading import RLock

from mycogni.application.auth import AuthService
from mycogni.application.ports import Clock
from mycogni.domain import OpaqueId
from mycogni.domain.auth import AuthDenial, OpaqueCredential, require_utc

LOGIN_CHALLENGE_TTL_SECONDS = 300
MAX_LOGIN_CHALLENGES = 32
MAX_SESSIONS = 16
MAX_CSRF_TOKENS = 4
TOKEN_BYTES = 32


class LoginFailure(StrEnum):
    """Non-secret reasons used by the delivery adapter."""

    CHALLENGE_MISSING = "challenge_missing"
    CSRF_REJECTED = "csrf_rejected"
    CREDENTIAL_REJECTED = "credential_rejected"


@dataclass(frozen=True, slots=True)
class LoginChallenge:
    """One browser login form; only a digest of its CSRF value is retained."""

    challenge_id: OpaqueId
    csrf_digest: bytes
    expires_at_utc: datetime


@dataclass(frozen=True, slots=True, repr=False)
class LoginStart:
    """Values needed to render a login form and its cookie."""

    challenge_cookie: str
    csrf_token: str

    def __repr__(self) -> str:
        return "LoginStart([REDACTED])"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class LoginResult:
    """Successful session material or a finite, non-secret failure."""

    session_cookie: str | None = None
    csrf_token: str | None = None
    failure: LoginFailure | None = None
    denial: AuthDenial | None = None

    def __repr__(self) -> str:
        return "LoginResult([REDACTED])"

    __str__ = __repr__

    def __post_init__(self) -> None:
        successful = self.session_cookie is not None and self.csrf_token is not None
        failed = self.failure is not None
        if successful == failed:
            raise ValueError("login result must be either successful or failed")
        if successful and self.denial is not None:
            raise ValueError("successful login cannot carry a denial")
        if failed and (self.session_cookie is not None or self.csrf_token is not None):
            raise ValueError("failed login cannot carry session material")


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedShellView:
    """Redacted dashboard projection plus a fresh form token."""

    csrf_token: str
    actor_label: str = "synthetic operator"
    profile_label: str = "synthetic profile"

    def __repr__(self) -> str:
        return "AuthenticatedShellView([REDACTED])"

    __str__ = __repr__


@dataclass(slots=True, repr=False)
class _Session:
    credential: OpaqueCredential
    csrf_digests: tuple[bytes, ...]
    expires_at_utc: datetime

    def __repr__(self) -> str:
        return "_Session([REDACTED])"


class SyntheticWebShell:
    """Bounded local session/challenge state for the synthetic UX-001 surface."""

    def __init__(self, *, auth: AuthService, clock: Clock) -> None:
        if type(auth) is not AuthService:
            raise TypeError("synthetic web shell requires the exact auth service")
        self._auth = auth
        self._clock = clock
        self._lock = RLock()
        self._challenges: dict[OpaqueId, LoginChallenge] = {}
        self._sessions: dict[OpaqueId, _Session] = {}

    def begin_login(self) -> LoginStart:
        """Create a bounded, one-use login form challenge."""
        now = self._now()
        self._revoke_sessions(self._purge_expired(now))
        challenge_id = OpaqueId.new()
        csrf_token = _new_token()
        challenge = LoginChallenge(
            challenge_id=challenge_id,
            csrf_digest=_digest(csrf_token),
            expires_at_utc=now + timedelta(seconds=LOGIN_CHALLENGE_TTL_SECONDS),
        )
        with self._lock:
            while len(self._challenges) >= MAX_LOGIN_CHALLENGES:
                self._challenges.pop(next(iter(self._challenges)))
            self._challenges[challenge_id] = challenge
        return LoginStart(challenge_cookie=str(challenge_id), csrf_token=csrf_token)

    def authenticate_login(
        self, *, challenge_cookie: str | None, csrf_token: str, operator_code: str
    ) -> LoginResult:
        """Consume one form challenge before attempting the opaque code exchange."""
        challenge_id = _parse_id(challenge_cookie)
        if challenge_id is None:
            return LoginResult(failure=LoginFailure.CHALLENGE_MISSING)
        now = self._now()
        with self._lock:
            challenge = self._challenges.pop(challenge_id, None)
        if challenge is None or now >= challenge.expires_at_utc:
            return LoginResult(failure=LoginFailure.CHALLENGE_MISSING)
        if not _matches(challenge.csrf_digest, _digest(csrf_token)):
            return LoginResult(failure=LoginFailure.CSRF_REJECTED)

        try:
            credential = OpaqueCredential.parse_operator_code(operator_code)
        except (TypeError, ValueError):
            return LoginResult(failure=LoginFailure.CREDENTIAL_REJECTED)
        exchanged = self._auth.exchange_bootstrap(credential)
        if exchanged.denial is not None or exchanged.value is None:
            return LoginResult(
                failure=LoginFailure.CREDENTIAL_REJECTED,
                denial=exchanged.denial,
            )
        return self._install_session(exchanged.value.session, now)

    def view(self, session_cookie: str | None) -> AuthenticatedShellView | None:
        """Validate a session with the auth service and issue a fresh form token."""
        session_id = _parse_id(session_cookie)
        if session_id is None:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            return None
        now = self._now()
        auth_denied = self._auth.authenticate_session(session.credential).denial is not None
        if now >= session.expires_at_utc or auth_denied:
            with self._lock:
                removed = self._sessions.pop(session_id, None)
            if removed is not None:
                self._revoke_sessions((removed.credential,))
            return None
        csrf_token = _new_token()
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None:
                return None
            current.csrf_digests = (*current.csrf_digests, _digest(csrf_token))[-MAX_CSRF_TOKENS:]
        return AuthenticatedShellView(csrf_token=csrf_token)

    def logout(self, *, session_cookie: str | None, csrf_token: str) -> bool:
        """Invalidate the local session and the underlying auth session."""
        session_id = _parse_id(session_cookie)
        if session_id is None:
            return False
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not _matches_any(session.csrf_digests, _digest(csrf_token)):
                return False
            self._sessions.pop(session_id, None)
        self._auth.revoke_session(session.credential)
        return True

    def active_session_count(self) -> int:
        """Expose only bounded non-secret operational state for tests/health."""
        self._revoke_sessions(self._purge_expired(self._now()))
        with self._lock:
            return len(self._sessions)

    def _install_session(self, credential: OpaqueCredential, now: datetime) -> LoginResult:
        csrf_token = _new_token()
        session_id = credential.handle
        evicted: list[OpaqueCredential] = []
        with self._lock:
            while len(self._sessions) >= MAX_SESSIONS:
                removed = self._sessions.pop(next(iter(self._sessions)))
                evicted.append(removed.credential)
            self._sessions[session_id] = _Session(
                credential=credential,
                csrf_digests=(_digest(csrf_token),),
                expires_at_utc=now + timedelta(seconds=self._auth.policy.session_ttl_seconds),
            )
        self._revoke_sessions(tuple(evicted))
        return LoginResult(session_cookie=str(session_id), csrf_token=csrf_token)

    def _purge_expired(self, now: datetime) -> tuple[OpaqueCredential, ...]:
        with self._lock:
            expired_challenges = [
                key
                for key, challenge in self._challenges.items()
                if now >= challenge.expires_at_utc
            ]
            for key in expired_challenges:
                self._challenges.pop(key, None)
            expired_sessions = [
                key for key, session in self._sessions.items() if now >= session.expires_at_utc
            ]
            expired_credentials = tuple(
                self._sessions[key].credential for key in expired_sessions if key in self._sessions
            )
            for key in expired_sessions:
                self._sessions.pop(key, None)
        return expired_credentials

    def _revoke_sessions(self, credentials: tuple[OpaqueCredential, ...]) -> None:
        for credential in credentials:
            self._auth.revoke_session(credential)

    def _now(self) -> datetime:
        now = self._clock.now()
        require_utc(now, "web shell clock value")
        return now


def _new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _matches(expected: bytes, actual: bytes) -> bool:
    return hmac.compare_digest(expected, actual)


def _matches_any(expected_values: tuple[bytes, ...], actual: bytes) -> bool:
    matched = False
    for expected in expected_values:
        matched = _matches(expected, actual) or matched
    return matched


def _parse_id(value: str | None) -> OpaqueId | None:
    if value is None or type(value) is not str:
        return None
    try:
        return OpaqueId.parse(value)
    except (TypeError, ValueError):
        return None
