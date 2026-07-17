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
    BootstrapDecision,
    BootstrapRecord,
    GrantProvenanceRecord,
    OpaqueCredential,
    RecoveryIssue,
    RecoveryRecord,
    RootCapability,
    RootCapabilityBinding,
    RootCapabilityIssue,
    RootCapabilityRecord,
    RootPurpose,
    SecretDigest,
    SessionIssue,
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
        self._installation_actors: dict[OpaqueId, OpaqueId] = {}
        self._roots: dict[OpaqueId, RootCapabilityRecord] = {}
        self._bootstraps: dict[OpaqueId, BootstrapRecord] = {}
        self._sessions: dict[OpaqueId, SessionRecord] = {}
        self._recoveries: dict[OpaqueId, RecoveryRecord] = {}
        self._step_ups: dict[OpaqueId, StepUpRecord] = {}
        self._grant_provenance: dict[OpaqueId, GrantProvenanceRecord] = {}
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
        record: BootstrapRecord | RecoveryRecord | StepUpRecord, now: datetime
    ) -> AuthDenial:
        record.attempts_remaining -= 1
        if record.attempts_remaining == 0:
            record.consumed = True
            record.retired_at_utc = now
            return AuthDenial.ATTEMPTS_EXHAUSTED
        return AuthDenial.INVALID_PROOF

    def initialize_installation(
        self,
        *,
        installation_id: OpaqueId,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        records: tuple[RootCapabilityRecord, ...],
        now: datetime,
    ) -> None:
        """Called only by trusted local composition before application startup."""
        with self._lock:
            require_utc(now, "trusted installation setup time")
            if installation_id in self._installation_actors or actor_id in self._actors:
                raise ValueError("installation or actor is already initialized")
            if type(records) is not tuple or len(records) != 3:
                raise ValueError("trusted setup requires exactly three root records")
            if any(type(record) is not RootCapabilityRecord for record in records):
                raise TypeError("trusted setup records must be root capability records")
            if len({id(record) for record in records}) != 3:
                raise ValueError("trusted setup requires three unique root records")
            if len({record.handle for record in records}) != 3:
                raise ValueError("trusted setup requires three unique root handles")
            if tuple(sorted(record.purpose.value for record in records)) != tuple(
                sorted(purpose.value for purpose in RootPurpose)
            ):
                raise ValueError("trusted setup requires exactly one root capability per purpose")
            if any(
                record.installation_id != installation_id
                or record.actor_id != actor_id
                or record.represented_profile_id != represented_profile_id
                for record in records
            ):
                raise ValueError("root capability bindings do not match trusted setup")
            self._installation_actors[installation_id] = actor_id
            self._actors[actor_id] = ActorRecord(
                actor_id=actor_id,
                represented_profile_id=represented_profile_id,
                epoch=1,
                last_observed_utc=now,
            )
            self._roots.update({record.handle: replace(record) for record in records})

    def _validate_root_locked(
        self,
        capability: RootCapability,
        digest: SecretDigest,
        expected_purposes: frozenset[RootPurpose],
    ) -> AuthOutcome[RootCapabilityRecord]:
        record = self._roots.get(capability.credential.handle)
        if record is None or not self._matches(record.digest, digest):
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        if capability.installation_id != record.installation_id:
            return AuthOutcome.denied(AuthDenial.WRONG_INSTALLATION)
        if capability.actor_id != record.actor_id:
            return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
        if capability.represented_profile_id != record.represented_profile_id:
            return AuthOutcome.denied(AuthDenial.WRONG_PROFILE)
        if capability.purpose is not record.purpose or record.purpose not in expected_purposes:
            return AuthOutcome.denied(AuthDenial.WRONG_PURPOSE)
        if record.consumed:
            return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
        return AuthOutcome.allowed(record)

    def _invalidate_bootstraps(self, actor_id: OpaqueId, now: datetime) -> None:
        for existing in self._bootstraps.values():
            if existing.actor_id == actor_id and not existing.consumed:
                existing.consumed = True
                existing.retired_at_utc = now

    def create_root_bootstrap(
        self,
        root: RootCapability,
        root_digest: SecretDigest,
        record: BootstrapRecord,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]:
        with self._lock:
            validated = self._validate_root_locked(
                root,
                root_digest,
                frozenset({RootPurpose.INITIAL_BOOTSTRAP, RootPurpose.REPROVISION}),
            )
            if validated.denial is not None:
                return AuthOutcome.denied(validated.denial)
            actor = self._actors[root.actor_id]
            clock_denial = self._observe(actor.actor_id, now)
            if clock_denial is not None:
                return AuthOutcome.denied(clock_denial)
            if root.purpose is RootPurpose.INITIAL_BOOTSTRAP and actor.initialized:
                return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
            if root.purpose is RootPurpose.REPROVISION and not actor.initialized:
                return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
            if (
                record.actor_id != actor.actor_id
                or record.represented_profile_id != actor.represented_profile_id
                or record.root_capability_id != root.credential.handle
                or record.root_purpose is not root.purpose
            ):
                return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
            self._invalidate_bootstraps(actor.actor_id, now)
            stored = replace(record)
            self._bootstraps[stored.handle] = stored
            return AuthOutcome.allowed(replace(stored))

    def create_authenticated_bootstrap(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        record: BootstrapRecord,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]:
        with self._lock:
            authorized = self._authorize_grant_locked(
                session,
                session_digest,
                grant,
                AuthPurpose.SETUP_AUTHORITY_CHANGE,
                now,
                consume=True,
            )
            if authorized.denial is not None:
                return AuthOutcome.denied(authorized.denial)
            if (
                record.actor_id != grant.actor_id
                or record.represented_profile_id != grant.represented_profile_id
                or record.root_capability_id is not None
            ):
                return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
            self._invalidate_bootstraps(record.actor_id, now)
            stored = replace(record)
            self._bootstraps[stored.handle] = stored
            return AuthOutcome.allowed(replace(stored))

    def cancel_bootstrap(self, handle: OpaqueId, now: datetime) -> None:
        with self._lock:
            record = self._bootstraps.get(handle)
            if record is not None and not record.consumed:
                record.consumed = True
                record.retired_at_utc = now

    def _retire_actor_authority(self, actor_id: OpaqueId, now: datetime) -> None:
        for session in self._sessions.values():
            if session.actor_id == actor_id:
                session.revoked = True
                session.retired_at_utc = now
        for challenge in self._step_ups.values():
            if challenge.actor_id == actor_id:
                challenge.consumed = True
                challenge.retired_at_utc = now
        for recovery in self._recoveries.values():
            if recovery.actor_id == actor_id:
                recovery.consumed = True
                recovery.retired_at_utc = now

    def _consume_actor_recoveries(self, actor_id: OpaqueId, now: datetime) -> None:
        for recovery in self._recoveries.values():
            if recovery.actor_id == actor_id:
                recovery.consumed = True
                recovery.retired_at_utc = now

    def _consume_root(self, record: RootCapabilityRecord, now: datetime) -> None:
        record.consumed = True
        record.retired_at_utc = now

    def exchange_bootstrap(
        self,
        handle: OpaqueId,
        presented_digest: SecretDigest,
        now: datetime,
        session: SessionRecord,
        recovery: RecoveryRecord,
        replacement_reprovision: RootCapabilityIssue,
    ) -> AuthOutcome[BootstrapDecision]:
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
                    record.retired_at_utc = now
                return AuthOutcome.denied(time_denial)
            if not self._matches(record.digest, presented_digest):
                return AuthOutcome.denied(self._wrong_proof(record, now))
            actor = self._actors[record.actor_id]
            replacement_root_record: RootCapabilityRecord | None = None
            if record.root_capability_id is not None:
                root = self._roots.get(record.root_capability_id)
                if root is None or root.consumed or root.purpose is not record.root_purpose:
                    return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
                if root.purpose is RootPurpose.INITIAL_BOOTSTRAP and actor.initialized:
                    return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
                if root.purpose is RootPurpose.REPROVISION and not actor.initialized:
                    return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
                if (
                    root.purpose is RootPurpose.REPROVISION
                    and replacement_reprovision.handle in self._roots
                ):
                    return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
                self._consume_root(root, now)
                if root.purpose is RootPurpose.REPROVISION:
                    actor.epoch += 1
                    self._retire_actor_authority(actor.actor_id, now)
                    replacement_root_record = RootCapabilityRecord(
                        handle=replacement_reprovision.handle,
                        installation_id=root.installation_id,
                        actor_id=root.actor_id,
                        represented_profile_id=root.represented_profile_id,
                        purpose=RootPurpose.REPROVISION,
                        digest=replacement_reprovision.digest,
                    )
                actor.initialized = True
            record.consumed = True
            record.retired_at_utc = now
            self._crash_if_armed(CrashPoint.BOOTSTRAP)
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
            replacement_binding = None
            if replacement_root_record is not None:
                self._roots[replacement_root_record.handle] = replacement_root_record
                replacement_binding = RootCapabilityBinding(
                    handle=replacement_root_record.handle,
                    installation_id=replacement_root_record.installation_id,
                    actor_id=replacement_root_record.actor_id,
                    represented_profile_id=replacement_root_record.represented_profile_id,
                    purpose=replacement_root_record.purpose,
                )
            return AuthOutcome.allowed(
                BootstrapDecision(
                    actor_id=issued_session.actor_id,
                    represented_profile_id=issued_session.represented_profile_id,
                    epoch=issued_session.epoch,
                    replacement_reprovision=replacement_binding,
                )
            )

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
            outcome = self._authenticate_session_locked(credential, presented_digest, now)
            if outcome.denial is not None:
                return AuthOutcome.denied(outcome.denial)
            assert outcome.value is not None
            return AuthOutcome.allowed(replace(outcome.value))

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
            return AuthOutcome.allowed(replace(issued))

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
                    record.retired_at_utc = now
                return AuthOutcome.denied(time_denial)
            if not self._matches(record.digest, challenge_digest):
                return AuthOutcome.denied(self._wrong_proof(record, now))
            if actor_id != record.actor_id:
                return AuthOutcome.denied(AuthDenial.WRONG_ACTOR)
            if represented_profile_id != record.represented_profile_id:
                return AuthOutcome.denied(AuthDenial.WRONG_PROFILE)
            if purpose is not record.purpose:
                return AuthOutcome.denied(AuthDenial.WRONG_PURPOSE)
            if scopes != record.scopes:
                return AuthOutcome.denied(AuthDenial.SCOPE_WIDENING)
            record.consumed = True
            record.retired_at_utc = now
            self._crash_if_armed(CrashPoint.STEP_UP)
            grant = AuthorityGrant(
                actor_id=record.actor_id,
                represented_profile_id=record.represented_profile_id,
                session_id=record.session_id,
                authority_evidence_id=record.handle,
                purpose=record.purpose,
                scopes=record.scopes,
                not_before_utc=record.not_before_utc,
                expires_at_utc=record.expires_at_utc,
                epoch=record.epoch,
            )
            self._grant_provenance[record.handle] = GrantProvenanceRecord(grant=grant)
            return AuthOutcome.allowed(replace(record))

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
            prior.retired_at_utc = now
            for challenge in self._step_ups.values():
                if challenge.session_id == prior.handle:
                    challenge.consumed = True
                    challenge.retired_at_utc = now
            issued = replace(
                replacement,
                actor_id=prior.actor_id,
                represented_profile_id=prior.represented_profile_id,
                epoch=prior.epoch,
            )
            self._sessions[issued.handle] = issued
            return AuthOutcome.allowed(replace(issued))

    def revoke_session(
        self, current: OpaqueCredential, current_digest: SecretDigest, now: datetime
    ) -> AuthOutcome[OpaqueId]:
        with self._lock:
            authenticated = self._authenticate_session_locked(current, current_digest, now)
            if authenticated.denial is not None:
                return AuthOutcome.denied(authenticated.denial)
            assert authenticated.value is not None
            authenticated.value.revoked = True
            authenticated.value.retired_at_utc = now
            for challenge in self._step_ups.values():
                if challenge.session_id == authenticated.value.handle:
                    challenge.consumed = True
                    challenge.retired_at_utc = now
            return AuthOutcome.allowed(authenticated.value.handle)

    def _authorize_grant_locked(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        purpose: AuthPurpose,
        now: datetime,
        *,
        consume: bool,
    ) -> AuthOutcome[AuthorityGrant]:
        if type(grant) is not AuthorityGrant:
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        provenance = self._grant_provenance.get(grant.authority_evidence_id)
        if provenance is None or provenance.grant != grant:
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
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
        if grant.purpose is not purpose:
            return AuthOutcome.denied(AuthDenial.WRONG_PURPOSE)
        time_denial = self._time_denial(now, grant.not_before_utc, grant.expires_at_utc)
        if time_denial is not None:
            return AuthOutcome.denied(time_denial)
        if provenance.used_at_utc is not None:
            return AuthOutcome.denied(AuthDenial.REPLAYED)
        if consume:
            self._grant_provenance[grant.authority_evidence_id] = replace(
                provenance, used_at_utc=now
            )
        return AuthOutcome.allowed(grant)

    def renew_recovery(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        replacement: RecoveryRecord,
        now: datetime,
    ) -> AuthOutcome[RecoveryRecord]:
        with self._lock:
            authorized = self._authorize_grant_locked(
                session,
                session_digest,
                grant,
                AuthPurpose.KEY_RECOVERY_CHANGE,
                now,
                consume=True,
            )
            if authorized.denial is not None:
                return AuthOutcome.denied(authorized.denial)
            actor = self._actors[grant.actor_id]
            self._consume_actor_recoveries(actor.actor_id, now)
            issued = replace(
                replacement,
                actor_id=actor.actor_id,
                represented_profile_id=actor.represented_profile_id,
                epoch=actor.epoch,
            )
            self._recoveries[issued.handle] = issued
            return AuthOutcome.allowed(replace(issued))

    def revoke_all_authenticated(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        replacement: RecoveryRecord,
        now: datetime,
    ) -> AuthOutcome[RecoveryRecord]:
        with self._lock:
            authorized = self._authorize_grant_locked(
                session,
                session_digest,
                grant,
                AuthPurpose.ALL_SESSION_REVOKE,
                now,
                consume=True,
            )
            if authorized.denial is not None:
                return AuthOutcome.denied(authorized.denial)
            actor = self._actors[grant.actor_id]
            actor.epoch += 1
            self._retire_actor_authority(actor.actor_id, now)
            issued = replace(
                replacement,
                actor_id=actor.actor_id,
                represented_profile_id=actor.represented_profile_id,
                epoch=actor.epoch,
            )
            self._recoveries[issued.handle] = issued
            return AuthOutcome.allowed(replace(issued))

    def emergency_revoke(
        self,
        root: RootCapability,
        root_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[int]:
        with self._lock:
            validated = self._validate_root_locked(
                root, root_digest, frozenset({RootPurpose.EMERGENCY_REVOKE})
            )
            if validated.denial is not None:
                return AuthOutcome.denied(validated.denial)
            assert validated.value is not None
            clock_denial = self._observe(root.actor_id, now)
            if clock_denial is not None:
                return AuthOutcome.denied(clock_denial)
            root_record = validated.value
            self._consume_root(root_record, now)
            actor = self._actors[root.actor_id]
            actor.epoch += 1
            self._retire_actor_authority(actor.actor_id, now)
            return AuthOutcome.allowed(actor.epoch)

    def recover(
        self,
        recovery: OpaqueCredential,
        recovery_digest: SecretDigest,
        now: datetime,
        session: SessionIssue,
        replacement_recovery: RecoveryIssue,
    ) -> AuthOutcome[SessionRecord]:
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
                    record.retired_at_utc = now
                return AuthOutcome.denied(time_denial)
            if not self._matches(record.digest, recovery_digest):
                return AuthOutcome.denied(self._wrong_proof(record, now))
            actor = self._actors[record.actor_id]
            if record.epoch != actor.epoch:
                record.consumed = True
                record.retired_at_utc = now
                return AuthOutcome.denied(AuthDenial.STALE_EPOCH)
            self._consume_actor_recoveries(actor.actor_id, now)
            actor.epoch += 1
            self._retire_actor_authority(actor.actor_id, now)
            self._crash_if_armed(CrashPoint.RECOVERY)
            issued_session = SessionRecord(
                handle=session.handle,
                actor_id=actor.actor_id,
                represented_profile_id=actor.represented_profile_id,
                digest=session.digest,
                epoch=actor.epoch,
                not_before_utc=session.not_before_utc,
                expires_at_utc=session.expires_at_utc,
            )
            issued_recovery = RecoveryRecord(
                handle=replacement_recovery.handle,
                actor_id=actor.actor_id,
                represented_profile_id=actor.represented_profile_id,
                digest=replacement_recovery.digest,
                epoch=actor.epoch,
                not_before_utc=replacement_recovery.not_before_utc,
                expires_at_utc=replacement_recovery.expires_at_utc,
                attempts_remaining=replacement_recovery.attempts,
            )
            self._sessions[issued_session.handle] = issued_session
            self._recoveries[issued_recovery.handle] = issued_recovery
            return AuthOutcome.allowed(replace(issued_session))

    def validate_grant(
        self,
        grant: AuthorityGrant,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[AuthorityGrant]:
        with self._lock:
            return self._authorize_grant_locked(
                session,
                session_digest,
                grant,
                grant.purpose,
                now,
                consume=True,
            )

    def garbage_collect(self, now: datetime, retention_seconds: int) -> int:
        """Delete retired/expired volatile records after a small bounded audit window."""
        require_utc(now, "garbage collection time")
        if type(retention_seconds) is not int or not 0 <= retention_seconds <= 86_400:
            raise ValueError("retention_seconds must be from 0 through 86400")
        cutoff = now.timestamp() - retention_seconds

        def retired(record: object) -> bool:
            retired_at = getattr(record, "retired_at_utc", None)
            expires_at = getattr(record, "expires_at_utc", None)
            return bool(
                (retired_at is not None and retired_at.timestamp() <= cutoff)
                or (expires_at is not None and expires_at.timestamp() <= cutoff)
            )

        with self._lock:
            removed = 0
            for collection in (
                self._roots,
                self._bootstraps,
                self._sessions,
                self._recoveries,
                self._step_ups,
            ):
                doomed = [handle for handle, record in collection.items() if retired(record)]
                for handle in doomed:
                    del collection[handle]
                removed += len(doomed)
            expired_grants = [
                evidence_id
                for evidence_id, provenance in self._grant_provenance.items()
                if provenance.grant.expires_at_utc.timestamp() <= cutoff
            ]
            for evidence_id in expired_grants:
                del self._grant_provenance[evidence_id]
            removed += len(expired_grants)
            return removed

    def record_counts(self) -> dict[str, int]:
        """Test-only bounded-retention observation without authority material."""
        with self._lock:
            return {
                "roots": len(self._roots),
                "bootstraps": len(self._bootstraps),
                "sessions": len(self._sessions),
                "recoveries": len(self._recoveries),
                "step_ups": len(self._step_ups),
                "grant_provenance": len(self._grant_provenance),
            }
