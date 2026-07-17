"""Process-local authentication state used only to resolve the SPIKE-AUTH design."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import replace
from datetime import datetime
from enum import StrEnum
from threading import RLock

from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    ActorRecord,
    AuthDenial,
    AuthorityGrant,
    AuthOutcome,
    AuthPurpose,
    AuthScope,
    BootstrapRecord,
    OpaqueCredential,
    RecoveryRecord,
    SecretDigest,
    SessionRecord,
    StepUpRecord,
    require_utc,
)


class CrashPoint(StrEnum):
    """Synthetic post-consume failure boundaries exercised by spike tests."""

    BOOTSTRAP = "bootstrap"
    STEP_UP = "step_up"
    RECOVERY = "recovery"


class SyntheticCrash(RuntimeError):
    """Non-secret fault injected after authority material becomes one-use."""


class OsTokenSource:
    """Opaque material source backed by the operating-system CSPRNG."""

    def generate(self, length: int) -> bytes:
        if type(length) is not int or length < 32:
            raise ValueError("opaque token length must be at least 32 bytes")
        return secrets.token_bytes(length)


class VolatileAuthDecisionStore:
    """Lock-serialized, digest-only state with deliberate restart loss.

    A post-consume injected crash preserves the consumed bit but intentionally
    does not issue replacement authority. This models the fail-closed side of a
    crash boundary; it is not evidence of durable transaction semantics.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._actors: dict[OpaqueId, ActorRecord] = {}
        self._bootstraps: dict[OpaqueId, BootstrapRecord] = {}
        self._sessions: dict[OpaqueId, SessionRecord] = {}
        self._recoveries: dict[OpaqueId, RecoveryRecord] = {}
        self._step_ups: dict[OpaqueId, StepUpRecord] = {}
        self._crash_once: CrashPoint | None = None

    def arm_crash_once(self, point: CrashPoint) -> None:
        """Inject one reviewed synthetic failure; never a production control."""
        with self._lock:
            self._crash_once = point

    def _crash_if_armed(self, point: CrashPoint) -> None:
        if self._crash_once is point:
            self._crash_once = None
            raise SyntheticCrash("synthetic post-consume crash")

    @staticmethod
    def _matches(left: SecretDigest, right: SecretDigest) -> bool:
        return hmac.compare_digest(left.value, right.value)

    def _observe(self, actor_id: OpaqueId, now: datetime) -> AuthDenial | None:
        require_utc(now, "decision time")
        actor = self._actors.get(actor_id)
        if actor is None:
            return AuthDenial.WRONG_ACTOR
        if now < actor.last_observed_utc:
            return AuthDenial.CLOCK_ROLLBACK
        actor.last_observed_utc = now
        return None

    @staticmethod
    def _time_denial(
        now: datetime, not_before_utc: datetime, expires_at_utc: datetime
    ) -> AuthDenial | None:
        if now < not_before_utc:
            return AuthDenial.NOT_YET_VALID
        if now >= expires_at_utc:
            return AuthDenial.EXPIRED
        return None

    @staticmethod
    def _wrong_proof(
        record: BootstrapRecord | RecoveryRecord | StepUpRecord,
    ) -> AuthDenial:
        record.attempts_remaining -= 1
        if record.attempts_remaining == 0:
            record.consumed = True
            return AuthDenial.ATTEMPTS_EXHAUSTED
        return AuthDenial.INVALID_PROOF

    def create_bootstrap(self, record: BootstrapRecord, now: datetime) -> None:
        with self._lock:
            require_utc(now, "bootstrap creation time")
            actor = self._actors.get(record.actor_id)
            if actor is None:
                self._actors[record.actor_id] = ActorRecord(
                    actor_id=record.actor_id,
                    represented_profile_id=record.represented_profile_id,
                    epoch=1,
                    last_observed_utc=now,
                )
            elif actor.represented_profile_id != record.represented_profile_id:
                raise ValueError("actor bootstrap cannot change represented profile")
            elif now < actor.last_observed_utc:
                raise ValueError("bootstrap creation rejected a clock rollback")
            else:
                actor.last_observed_utc = now
            for existing in self._bootstraps.values():
                if existing.actor_id == record.actor_id and not existing.consumed:
                    existing.consumed = True
            self._bootstraps[record.handle] = record

    def exchange_bootstrap(
        self,
        handle: OpaqueId,
        presented_digest: SecretDigest,
        now: datetime,
        session: SessionRecord,
        recovery: RecoveryRecord,
    ) -> AuthOutcome[SessionRecord]:
        with self._lock:
            record = self._bootstraps.get(handle)
            if record is None:
                return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
            clock_denial = self._observe(record.actor_id, now)
            if clock_denial is not None:
                return AuthOutcome.denied(clock_denial)
            if record.consumed:
                denial = (
                    AuthDenial.ATTEMPTS_EXHAUSTED
                    if record.attempts_remaining == 0
                    else AuthDenial.REPLAYED
                )
                return AuthOutcome.denied(denial)
            time_denial = self._time_denial(now, record.not_before_utc, record.expires_at_utc)
            if time_denial is not None:
                if time_denial is AuthDenial.EXPIRED:
                    record.consumed = True
                return AuthOutcome.denied(time_denial)
            if not self._matches(record.digest, presented_digest):
                return AuthOutcome.denied(self._wrong_proof(record))
            record.consumed = True
            self._crash_if_armed(CrashPoint.BOOTSTRAP)
            actor = self._actors[record.actor_id]
            issued_session = replace(
                session,
                actor_id=actor.actor_id,
                represented_profile_id=actor.represented_profile_id,
                epoch=actor.epoch,
            )
            issued_recovery = replace(
                recovery,
                actor_id=actor.actor_id,
                represented_profile_id=actor.represented_profile_id,
                epoch=actor.epoch,
            )
            self._sessions[issued_session.handle] = issued_session
            self._recoveries[issued_recovery.handle] = issued_recovery
            return AuthOutcome.allowed(issued_session)

    def _authenticate_session_locked(
        self, credential: OpaqueCredential, digest: SecretDigest, now: datetime
    ) -> AuthOutcome[SessionRecord]:
        record = self._sessions.get(credential.handle)
        if record is None:
            return AuthOutcome.denied(AuthDenial.SESSION_NOT_FOUND)
        if not self._matches(record.digest, digest):
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        clock_denial = self._observe(record.actor_id, now)
        if clock_denial is not None:
            return AuthOutcome.denied(clock_denial)
        actor = self._actors[record.actor_id]
        if record.epoch != actor.epoch:
            return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
        if record.revoked:
            return AuthOutcome.denied(AuthDenial.REVOKED)
        time_denial = self._time_denial(now, record.not_before_utc, record.expires_at_utc)
        if time_denial is not None:
            return AuthOutcome.denied(time_denial)
        return AuthOutcome.allowed(record)

    def authenticate_session(
        self, credential: OpaqueCredential, presented_digest: SecretDigest, now: datetime
    ) -> AuthOutcome[SessionRecord]:
        with self._lock:
            return self._authenticate_session_locked(credential, presented_digest, now)

    def create_step_up(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        now: datetime,
        challenge: StepUpRecord,
    ) -> AuthOutcome[StepUpRecord]:
        with self._lock:
            authenticated = self._authenticate_session_locked(session, session_digest, now)
            if authenticated.denial is not None:
                return AuthOutcome.denied(authenticated.denial)
            assert authenticated.value is not None
            current = authenticated.value
            if challenge.actor_id != current.actor_id:
                return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
            if challenge.represented_profile_id != current.represented_profile_id:
                return AuthOutcome.denied(AuthDenial.WRONG_PROFILE)
            issued = replace(challenge, session_id=current.handle, epoch=current.epoch)
            self._step_ups[issued.handle] = issued
            return AuthOutcome.allowed(issued)

    def consume_step_up(
        self,
        challenge: OpaqueCredential,
        challenge_digest: SecretDigest,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        purpose: AuthPurpose,
        scopes: frozenset[AuthScope],
        now: datetime,
    ) -> AuthOutcome[StepUpRecord]:
        with self._lock:
            record = self._step_ups.get(challenge.handle)
            if record is None:
                return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
            authenticated = self._authenticate_session_locked(session, session_digest, now)
            if authenticated.denial is not None:
                return AuthOutcome.denied(authenticated.denial)
            assert authenticated.value is not None
            if session.handle != record.session_id:
                return AuthOutcome.denied(AuthDenial.WRONG_SESSION)
            actor = self._actors[record.actor_id]
            if record.epoch != actor.epoch:
                return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
            if record.consumed:
                denial = (
                    AuthDenial.ATTEMPTS_EXHAUSTED
                    if record.attempts_remaining == 0
                    else AuthDenial.REPLAYED
                )
                return AuthOutcome.denied(denial)
            time_denial = self._time_denial(now, record.not_before_utc, record.expires_at_utc)
            if time_denial is not None:
                if time_denial is AuthDenial.EXPIRED:
                    record.consumed = True
                return AuthOutcome.denied(time_denial)
            if not self._matches(record.digest, challenge_digest):
                return AuthOutcome.denied(self._wrong_proof(record))
            if actor_id != record.actor_id:
                return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
            if represented_profile_id != record.represented_profile_id:
                return AuthOutcome.denied(AuthDenial.WRONG_PROFILE)
            if purpose is not record.purpose:
                return AuthOutcome.denied(AuthDenial.WRONG_PURPOSE)
            if scopes != record.scopes:
                return AuthOutcome.denied(AuthDenial.SCOPE_WIDENING)
            record.consumed = True
            self._crash_if_armed(CrashPoint.STEP_UP)
            return AuthOutcome.allowed(record)

    def rotate_session(
        self,
        current: OpaqueCredential,
        current_digest: SecretDigest,
        now: datetime,
        replacement: SessionRecord,
    ) -> AuthOutcome[SessionRecord]:
        with self._lock:
            authenticated = self._authenticate_session_locked(current, current_digest, now)
            if authenticated.denial is not None:
                return AuthOutcome.denied(authenticated.denial)
            assert authenticated.value is not None
            prior = authenticated.value
            prior.revoked = True
            for challenge in self._step_ups.values():
                if challenge.session_id == prior.handle:
                    challenge.consumed = True
            issued = replace(
                replacement,
                actor_id=prior.actor_id,
                represented_profile_id=prior.represented_profile_id,
                epoch=prior.epoch,
            )
            self._sessions[issued.handle] = issued
            return AuthOutcome.allowed(issued)

    def revoke_session(
        self, current: OpaqueCredential, current_digest: SecretDigest, now: datetime
    ) -> AuthOutcome[OpaqueId]:
        with self._lock:
            authenticated = self._authenticate_session_locked(current, current_digest, now)
            if authenticated.denial is not None:
                return AuthOutcome.denied(authenticated.denial)
            assert authenticated.value is not None
            authenticated.value.revoked = True
            for challenge in self._step_ups.values():
                if challenge.session_id == authenticated.value.handle:
                    challenge.consumed = True
            return AuthOutcome.allowed(authenticated.value.handle)

    def revoke_all(self, actor_id: OpaqueId, now: datetime) -> AuthOutcome[int]:
        with self._lock:
            clock_denial = self._observe(actor_id, now)
            if clock_denial is not None:
                return AuthOutcome.denied(clock_denial)
            actor = self._actors[actor_id]
            actor.epoch += 1
            for session in self._sessions.values():
                if session.actor_id == actor_id:
                    session.revoked = True
            for challenge in self._step_ups.values():
                if challenge.actor_id == actor_id:
                    challenge.consumed = True
            return AuthOutcome.allowed(actor.epoch)

    def recover(
        self,
        recovery: OpaqueCredential,
        recovery_digest: SecretDigest,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        now: datetime,
        session: SessionRecord,
        replacement_recovery: RecoveryRecord,
    ) -> AuthOutcome[int]:
        with self._lock:
            record = self._recoveries.get(recovery.handle)
            if record is None:
                return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
            clock_denial = self._observe(record.actor_id, now)
            if clock_denial is not None:
                return AuthOutcome.denied(clock_denial)
            if record.consumed:
                denial = (
                    AuthDenial.ATTEMPTS_EXHAUSTED
                    if record.attempts_remaining == 0
                    else AuthDenial.REPLAYED
                )
                return AuthOutcome.denied(denial)
            time_denial = self._time_denial(now, record.not_before_utc, record.expires_at_utc)
            if time_denial is not None:
                if time_denial is AuthDenial.EXPIRED:
                    record.consumed = True
                return AuthOutcome.denied(time_denial)
            if not self._matches(record.digest, recovery_digest):
                return AuthOutcome.denied(self._wrong_proof(record))
            if actor_id != record.actor_id:
                return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
            if represented_profile_id != record.represented_profile_id:
                return AuthOutcome.denied(AuthDenial.WRONG_PROFILE)
            record.consumed = True
            actor = self._actors[record.actor_id]
            actor.epoch += 1
            for prior_session in self._sessions.values():
                if prior_session.actor_id == actor.actor_id:
                    prior_session.revoked = True
            for challenge in self._step_ups.values():
                if challenge.actor_id == actor.actor_id:
                    challenge.consumed = True
            self._crash_if_armed(CrashPoint.RECOVERY)
            issued_session = replace(session, epoch=actor.epoch)
            issued_recovery = replace(replacement_recovery, epoch=actor.epoch)
            self._sessions[issued_session.handle] = issued_session
            self._recoveries[issued_recovery.handle] = issued_recovery
            return AuthOutcome.allowed(actor.epoch)

    def validate_grant(
        self,
        grant: AuthorityGrant,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[AuthorityGrant]:
        with self._lock:
            authenticated = self._authenticate_session_locked(session, session_digest, now)
            if authenticated.denial is not None:
                return AuthOutcome.denied(authenticated.denial)
            assert authenticated.value is not None
            current = authenticated.value
            actor = self._actors[current.actor_id]
            if grant.actor_id != current.actor_id:
                return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
            if grant.represented_profile_id != current.represented_profile_id:
                return AuthOutcome.denied(AuthDenial.WRONG_PROFILE)
            if grant.session_id != current.handle:
                return AuthOutcome.denied(AuthDenial.WRONG_SESSION)
            if grant.epoch != actor.epoch:
                return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
            time_denial = self._time_denial(now, grant.not_before_utc, grant.expires_at_utc)
            if time_denial is not None:
                return AuthOutcome.denied(time_denial)
            return AuthOutcome.allowed(grant)

    def retained_secret_material(self) -> tuple[SecretDigest, ...]:
        """Test-only inspection proving volatile state stores digest objects only."""
        with self._lock:
            return tuple(
                record.digest
                for collection in (
                    self._bootstraps,
                    self._sessions,
                    self._recoveries,
                    self._step_ups,
                )
                for record in collection.values()
            )
