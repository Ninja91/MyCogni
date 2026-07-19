"""Application-owned ports and orchestration for the volatile auth spike."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock
from typing import Protocol, runtime_checkable

from mycogni.application.ports import Clock
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    PURPOSE_SCOPE,
    AuthDenial,
    AuthorityGrant,
    AuthOutcome,
    AuthPolicy,
    AuthPurpose,
    AuthScope,
    BootstrapDecision,
    BootstrapExchange,
    BootstrapIssue,
    BootstrapRecord,
    OpaqueCredential,
    RecoveryIssue,
    RecoveryRecord,
    RootCapability,
    RootCapabilityIssue,
    RootPurpose,
    SecretDigest,
    SessionIssue,
    SessionRecord,
    StepUpRecord,
    require_utc,
)

TOKEN_BYTES = 32


@dataclass(frozen=True, slots=True, repr=False)
class ReprovisionCeremonyAuthorization:
    """Opaque one-use proof that the owned operator boundary confirmed destruction.

    Callers can construct values of this type, but only this service can register
    their random proof.  The authorization is bound to one bootstrap and is
    consumed before the destructive store decision is attempted.
    """

    credential: OpaqueCredential
    bootstrap_handle: OpaqueId

    def __post_init__(self) -> None:
        if type(self.credential) is not OpaqueCredential:
            raise TypeError("ceremony authorization requires an opaque credential")
        if type(self.bootstrap_handle) is not OpaqueId:
            raise TypeError("ceremony authorization requires an opaque bootstrap handle")

    def __repr__(self) -> str:
        return "ReprovisionCeremonyAuthorization([REDACTED])"


@dataclass(frozen=True, slots=True, repr=False)
class ReprovisionOperatorAuthority:
    """Composition-held identity for the sole owned destructive operator boundary."""

    credential: OpaqueCredential

    def __post_init__(self) -> None:
        if type(self.credential) is not OpaqueCredential:
            raise TypeError("operator authority requires an opaque credential")

    def __repr__(self) -> str:
        return "ReprovisionOperatorAuthority([REDACTED])"


@dataclass(slots=True)
class _ReprovisionCeremonyRecord:
    digest: SecretDigest
    bootstrap_handle: OpaqueId
    expires_at_utc: datetime
    terminal_at_utc: datetime | None = None
    terminal_denial: AuthDenial | None = None


@runtime_checkable
class TokenSource(Protocol):
    """High-entropy opaque material source owned by application composition."""

    def generate(self, length: int) -> bytes:
        """Return exactly ``length`` fresh bytes."""
        ...


@runtime_checkable
class AuthDecisionStore(Protocol):
    """Atomic decision operations required from an auth-state adapter."""

    def create_root_bootstrap(
        self,
        root: RootCapability,
        root_digest: SecretDigest,
        record: BootstrapRecord,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]: ...

    def create_authenticated_bootstrap(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        record: BootstrapRecord,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]: ...

    def create_reprovision_bootstrap(
        self,
        reprovision: OpaqueCredential,
        reprovision_digest: SecretDigest,
        issue: BootstrapIssue,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]: ...

    def cancel_bootstrap(self, handle: OpaqueId, now: datetime) -> None: ...

    def exchange_bootstrap(
        self,
        handle: OpaqueId,
        presented_digest: SecretDigest,
        now: datetime,
        session: SessionRecord,
        recovery: RecoveryRecord,
        replacement_reprovision: RootCapabilityIssue,
        allowed_root_purposes: frozenset[RootPurpose | None],
    ) -> AuthOutcome[BootstrapDecision]: ...

    def authenticate_session(
        self, credential: OpaqueCredential, presented_digest: SecretDigest, now: datetime
    ) -> AuthOutcome[SessionRecord]: ...

    def create_step_up(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        now: datetime,
        challenge: StepUpRecord,
    ) -> AuthOutcome[StepUpRecord]: ...

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
    ) -> AuthOutcome[StepUpRecord]: ...

    def rotate_session(
        self,
        current: OpaqueCredential,
        current_digest: SecretDigest,
        now: datetime,
        replacement: SessionRecord,
    ) -> AuthOutcome[SessionRecord]: ...

    def revoke_session(
        self, current: OpaqueCredential, current_digest: SecretDigest, now: datetime
    ) -> AuthOutcome[OpaqueId]: ...

    def renew_recovery(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        replacement: RecoveryRecord,
        now: datetime,
    ) -> AuthOutcome[RecoveryRecord]: ...

    def revoke_all_authenticated(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        replacement: RecoveryRecord,
        now: datetime,
    ) -> AuthOutcome[RecoveryRecord]: ...

    def emergency_revoke(
        self,
        root: RootCapability,
        root_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[int]: ...

    def recover(
        self,
        recovery: OpaqueCredential,
        recovery_digest: SecretDigest,
        now: datetime,
        session: SessionIssue,
        replacement_recovery: RecoveryIssue,
    ) -> AuthOutcome[SessionRecord]: ...

    def validate_grant(
        self,
        grant: object,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[AuthorityGrant]: ...

    def garbage_collect(self, now: datetime, retention_seconds: int) -> int: ...


class AuthService:
    """Synthetic auth ceremonies with injected time, material, and state ports."""

    def __init__(
        self,
        *,
        clock: Clock,
        token_source: TokenSource,
        store: AuthDecisionStore,
        reprovision_operator_authority: ReprovisionOperatorAuthority,
        policy: AuthPolicy | None = None,
    ) -> None:
        self._clock = clock
        self._token_source = token_source
        self._store = store
        self._policy = policy if policy is not None else AuthPolicy()
        if type(reprovision_operator_authority) is not ReprovisionOperatorAuthority:
            raise TypeError("auth service requires composition-held reprovision operator authority")
        self._reprovision_operator_handle = reprovision_operator_authority.credential.handle
        self._reprovision_operator_digest = self._digest(reprovision_operator_authority.credential)
        self._reprovision_ceremony_lock = RLock()
        self._reprovision_ceremonies: dict[OpaqueId, _ReprovisionCeremonyRecord] = {}

    def _now(self) -> datetime:
        now = self._clock.now()
        require_utc(now, "clock value")
        return now

    def _credential(self) -> tuple[OpaqueCredential, SecretDigest]:
        material = self._token_source.generate(TOKEN_BYTES)
        if type(material) is not bytes or len(material) != TOKEN_BYTES:
            raise RuntimeError("token source violated the opaque-material contract")
        credential = OpaqueCredential.from_secret(OpaqueId.new(), material)
        return credential, SecretDigest(hashlib.sha256(material).digest())

    def _window(self, now: datetime, ttl_seconds: int) -> tuple[datetime, datetime]:
        not_before = now + timedelta(seconds=self._policy.activation_delay_seconds)
        return not_before, not_before + timedelta(seconds=ttl_seconds)

    def begin_bootstrap(self, root: RootCapability) -> AuthOutcome[OpaqueCredential]:
        """Create a bootstrap only with exact trusted composition authority."""
        now = self._now()
        credential, digest = self._credential()
        not_before, expires = self._window(now, self._policy.bootstrap_ttl_seconds)
        record = BootstrapRecord(
            handle=credential.handle,
            actor_id=root.actor_id,
            represented_profile_id=root.represented_profile_id,
            digest=digest,
            not_before_utc=not_before,
            expires_at_utc=expires,
            attempts_remaining=self._policy.max_attempts,
            root_capability_id=root.credential.handle,
            root_purpose=root.purpose,
        )
        result = self._store.create_root_bootstrap(
            root,
            self._digest(root.credential),
            record,
            now,
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        return AuthOutcome.allowed(credential)

    def begin_authenticated_bootstrap(
        self, *, session: OpaqueCredential, grant: AuthorityGrant
    ) -> AuthOutcome[OpaqueCredential]:
        """Rebootstrap an initialized actor only through current step-up authority."""
        now = self._now()
        credential, digest = self._credential()
        not_before, expires = self._window(now, self._policy.bootstrap_ttl_seconds)
        record = BootstrapRecord(
            handle=credential.handle,
            actor_id=grant.actor_id,
            represented_profile_id=grant.represented_profile_id,
            digest=digest,
            not_before_utc=not_before,
            expires_at_utc=expires,
            attempts_remaining=self._policy.max_attempts,
        )
        result = self._store.create_authenticated_bootstrap(
            session, self._digest(session), grant, record, now
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        return AuthOutcome.allowed(credential)

    def begin_reprovision(self, reprovision: OpaqueCredential) -> AuthOutcome[OpaqueCredential]:
        """Resolve a purpose-fixed reprovision code without caller authority bindings."""
        if type(reprovision) is not OpaqueCredential:
            return AuthOutcome.denied(AuthDenial.MALFORMED_CREDENTIAL)
        now = self._now()
        credential, digest = self._credential()
        not_before, expires = self._window(now, self._policy.bootstrap_ttl_seconds)
        result = self._store.create_reprovision_bootstrap(
            reprovision,
            self._digest(reprovision),
            BootstrapIssue(
                handle=credential.handle,
                digest=digest,
                not_before_utc=not_before,
                expires_at_utc=expires,
                attempts=self._policy.max_attempts,
            ),
            now,
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        return AuthOutcome.allowed(credential)

    def cancel_bootstrap(self, handle: OpaqueId) -> None:
        """Burn an undisclosed/partially disclosed code while preserving root retry."""
        self._store.cancel_bootstrap(handle, self._now())

    def exchange_bootstrap(self, bootstrap: OpaqueCredential) -> AuthOutcome[BootstrapExchange]:
        """Exchange only non-destructive initial/authenticated bootstraps."""
        return self._exchange_bootstrap(
            bootstrap,
            frozenset({None, RootPurpose.INITIAL_BOOTSTRAP}),
        )

    def authorize_reprovision_ceremony(
        self,
        bootstrap: OpaqueCredential,
        operator_authority: object,
    ) -> AuthOutcome[ReprovisionCeremonyAuthorization]:
        """Mint a finite permit only for the composition-owned operator boundary."""
        if type(bootstrap) is not OpaqueCredential:
            return AuthOutcome.denied(AuthDenial.MALFORMED_CREDENTIAL)
        if type(operator_authority) is not ReprovisionOperatorAuthority:
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        if (
            operator_authority.credential.handle != self._reprovision_operator_handle
            or not self._matches_digest(
                self._reprovision_operator_digest, operator_authority.credential
            )
        ):
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        now = self._now()
        credential, digest = self._credential()
        authorization = ReprovisionCeremonyAuthorization(
            credential=credential,
            bootstrap_handle=bootstrap.handle,
        )
        with self._reprovision_ceremony_lock:
            self._garbage_collect_reprovision_ceremonies_locked(now)
            active = sum(
                record.terminal_at_utc is None for record in self._reprovision_ceremonies.values()
            )
            if active >= self._policy.reprovision_ceremony_capacity:
                return AuthOutcome.denied(AuthDenial.CAPACITY_EXHAUSTED)
            self._reprovision_ceremonies[credential.handle] = _ReprovisionCeremonyRecord(
                digest=digest,
                bootstrap_handle=bootstrap.handle,
                expires_at_utc=now
                + timedelta(seconds=self._policy.reprovision_ceremony_ttl_seconds),
            )
        return AuthOutcome.allowed(authorization)

    def exchange_confirmed_reprovision(
        self,
        bootstrap: OpaqueCredential,
        authorization: object,
    ) -> AuthOutcome[BootstrapExchange]:
        """Consume reprovision only with a registered, bound, one-use ceremony proof."""
        if type(bootstrap) is not OpaqueCredential:
            return AuthOutcome.denied(AuthDenial.MALFORMED_CREDENTIAL)
        if type(authorization) is not ReprovisionCeremonyAuthorization:
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        now = self._now()
        with self._reprovision_ceremony_lock:
            self._garbage_collect_reprovision_ceremonies_locked(now)
            registered = self._reprovision_ceremonies.get(authorization.credential.handle)
            if registered is None:
                return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
            if registered.terminal_at_utc is not None:
                return AuthOutcome.denied(registered.terminal_denial or AuthDenial.REPLAYED)
            if (
                registered.bootstrap_handle != bootstrap.handle
                or authorization.bootstrap_handle != bootstrap.handle
                or not self._matches_digest(registered.digest, authorization.credential)
            ):
                return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
            if now >= registered.expires_at_utc:
                registered.terminal_at_utc = now
                registered.terminal_denial = AuthDenial.EXPIRED
                self._trim_reprovision_tombstones_locked()
                return AuthOutcome.denied(AuthDenial.EXPIRED)
            # Burn before entering the destructive store decision so exception,
            # denial, replay, and concurrent calls cannot reuse confirmation.
            registered.terminal_at_utc = now
            registered.terminal_denial = AuthDenial.REPLAYED
            self._trim_reprovision_tombstones_locked()
        return self._exchange_bootstrap(bootstrap, frozenset({RootPurpose.REPROVISION}))

    def _garbage_collect_reprovision_ceremonies_locked(self, now: datetime) -> int:
        replay = timedelta(seconds=self._policy.reprovision_ceremony_replay_seconds)
        for record in self._reprovision_ceremonies.values():
            if record.terminal_at_utc is None and now >= record.expires_at_utc:
                record.terminal_at_utc = record.expires_at_utc
                record.terminal_denial = AuthDenial.EXPIRED
        doomed = [
            handle
            for handle, record in self._reprovision_ceremonies.items()
            if (record.terminal_at_utc is not None and now >= record.terminal_at_utc + replay)
        ]
        for handle in doomed:
            del self._reprovision_ceremonies[handle]
        self._trim_reprovision_tombstones_locked()
        return len(doomed)

    def _trim_reprovision_tombstones_locked(self) -> None:
        terminal = sorted(
            (
                (record.terminal_at_utc, handle)
                for handle, record in self._reprovision_ceremonies.items()
                if record.terminal_at_utc is not None
            ),
            key=lambda item: (item[0], str(item[1])),
        )
        overflow = len(terminal) - self._policy.reprovision_ceremony_tombstone_capacity
        for _terminal_at, handle in terminal[: max(0, overflow)]:
            del self._reprovision_ceremonies[handle]

    def reprovision_ceremony_counts(self) -> dict[str, int]:
        """Expose finite non-secret retention counts for operations and tests."""
        with self._reprovision_ceremony_lock:
            active = sum(
                record.terminal_at_utc is None for record in self._reprovision_ceremonies.values()
            )
            return {
                "active": active,
                "tombstones": len(self._reprovision_ceremonies) - active,
                "total": len(self._reprovision_ceremonies),
            }

    @staticmethod
    def _matches_digest(expected: SecretDigest, credential: OpaqueCredential) -> bool:
        presented = hashlib.sha256(credential.secret.reveal()).digest()
        return hmac.compare_digest(expected.value, presented)

    def _exchange_bootstrap(
        self,
        bootstrap: OpaqueCredential,
        allowed_root_purposes: frozenset[RootPurpose | None],
    ) -> AuthOutcome[BootstrapExchange]:
        now = self._now()
        session, session_digest = self._credential()
        recovery, recovery_digest = self._credential()
        replacement_root, replacement_root_digest = self._credential()
        session_not_before, session_expires = self._window(now, self._policy.session_ttl_seconds)
        recovery_not_before, recovery_expires = self._window(now, self._policy.recovery_ttl_seconds)
        placeholder = OpaqueId.new()
        result = self._store.exchange_bootstrap(
            bootstrap.handle,
            SecretDigest(hashlib.sha256(bootstrap.secret.reveal()).digest()),
            now,
            SessionRecord(
                handle=session.handle,
                actor_id=placeholder,
                represented_profile_id=placeholder,
                digest=session_digest,
                epoch=1,
                not_before_utc=session_not_before,
                expires_at_utc=session_expires,
            ),
            RecoveryRecord(
                handle=recovery.handle,
                actor_id=placeholder,
                represented_profile_id=placeholder,
                digest=recovery_digest,
                epoch=1,
                not_before_utc=recovery_not_before,
                expires_at_utc=recovery_expires,
                attempts_remaining=self._policy.max_attempts,
            ),
            RootCapabilityIssue(
                handle=replacement_root.handle,
                digest=replacement_root_digest,
            ),
            allowed_root_purposes,
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        assert result.value is not None
        record = result.value
        replacement_reprovision = None
        if record.replacement_reprovision is not None:
            binding = record.replacement_reprovision
            replacement_reprovision = RootCapability(
                credential=replacement_root,
                installation_id=binding.installation_id,
                actor_id=binding.actor_id,
                represented_profile_id=binding.represented_profile_id,
                purpose=binding.purpose,
            )
        return AuthOutcome.allowed(
            BootstrapExchange(
                session=session,
                recovery=recovery,
                actor_id=record.actor_id,
                represented_profile_id=record.represented_profile_id,
                epoch=record.epoch,
                replacement_reprovision=replacement_reprovision,
            )
        )

    def authenticate_session(self, session: OpaqueCredential) -> AuthOutcome[OpaqueId]:
        result = self._store.authenticate_session(session, self._digest(session), self._now())
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        assert result.value is not None
        return AuthOutcome.allowed(result.value.handle)

    def issue_step_up(
        self,
        *,
        session: OpaqueCredential,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        purpose: AuthPurpose,
        scopes: frozenset[AuthScope],
    ) -> AuthOutcome[OpaqueCredential]:
        if type(purpose) is not AuthPurpose:
            return AuthOutcome.denied(AuthDenial.WRONG_PURPOSE)
        if type(scopes) is not frozenset or any(type(scope) is not AuthScope for scope in scopes):
            return AuthOutcome.denied(AuthDenial.SCOPE_WIDENING)
        if scopes != frozenset({PURPOSE_SCOPE[purpose]}):
            return AuthOutcome.denied(AuthDenial.SCOPE_WIDENING)
        now = self._now()
        credential, digest = self._credential()
        not_before, expires = self._window(now, self._policy.step_up_ttl_seconds)
        proposed = StepUpRecord(
            handle=credential.handle,
            actor_id=actor_id,
            represented_profile_id=represented_profile_id,
            session_id=session.handle,
            digest=digest,
            epoch=1,
            purpose=purpose,
            scopes=scopes,
            not_before_utc=not_before,
            expires_at_utc=expires,
            attempts_remaining=self._policy.max_attempts,
        )
        result = self._store.create_step_up(session, self._digest(session), now, proposed)
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        return AuthOutcome.allowed(credential)

    def consume_step_up(
        self,
        *,
        challenge: OpaqueCredential,
        session: OpaqueCredential,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        purpose: AuthPurpose,
        scopes: frozenset[AuthScope],
    ) -> AuthOutcome[AuthorityGrant]:
        now = self._now()
        result = self._store.consume_step_up(
            challenge,
            self._digest(challenge),
            session,
            self._digest(session),
            actor_id,
            represented_profile_id,
            purpose,
            scopes,
            now,
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        assert result.value is not None
        record = result.value
        return AuthOutcome.allowed(
            AuthorityGrant(
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
        )

    def rotate_session(self, session: OpaqueCredential) -> AuthOutcome[OpaqueCredential]:
        now = self._now()
        replacement, replacement_digest = self._credential()
        not_before, expires = self._window(now, self._policy.session_ttl_seconds)
        placeholder = OpaqueId.new()
        result = self._store.rotate_session(
            session,
            self._digest(session),
            now,
            SessionRecord(
                handle=replacement.handle,
                actor_id=placeholder,
                represented_profile_id=placeholder,
                digest=replacement_digest,
                epoch=1,
                not_before_utc=not_before,
                expires_at_utc=expires,
            ),
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        return AuthOutcome.allowed(replacement)

    def revoke_session(self, session: OpaqueCredential) -> AuthOutcome[OpaqueId]:
        return self._store.revoke_session(session, self._digest(session), self._now())

    def renew_recovery(
        self, *, session: OpaqueCredential, grant: AuthorityGrant
    ) -> AuthOutcome[OpaqueCredential]:
        """Rotate offline recovery through a current key-recovery step-up."""
        now = self._now()
        replacement, replacement_digest = self._credential()
        not_before, expires = self._window(now, self._policy.recovery_ttl_seconds)
        proposed = RecoveryRecord(
            handle=replacement.handle,
            actor_id=grant.actor_id,
            represented_profile_id=grant.represented_profile_id,
            digest=replacement_digest,
            epoch=grant.epoch,
            not_before_utc=not_before,
            expires_at_utc=expires,
            attempts_remaining=self._policy.max_attempts,
        )
        result = self._store.renew_recovery(session, self._digest(session), grant, proposed, now)
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        return AuthOutcome.allowed(replacement)

    def revoke_all_authenticated(
        self, *, session: OpaqueCredential, grant: AuthorityGrant
    ) -> AuthOutcome[OpaqueCredential]:
        """Revoke every session/recovery and return one replacement recovery code."""
        now = self._now()
        replacement, replacement_digest = self._credential()
        not_before, expires = self._window(now, self._policy.recovery_ttl_seconds)
        proposed = RecoveryRecord(
            handle=replacement.handle,
            actor_id=grant.actor_id,
            represented_profile_id=grant.represented_profile_id,
            digest=replacement_digest,
            epoch=grant.epoch,
            not_before_utc=not_before,
            expires_at_utc=expires,
            attempts_remaining=self._policy.max_attempts,
        )
        result = self._store.revoke_all_authenticated(
            session, self._digest(session), grant, proposed, now
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        return AuthOutcome.allowed(replacement)

    def emergency_revoke(self, root: RootCapability) -> AuthOutcome[int]:
        """Consume exact offline emergency authority and invalidate all actor authority."""
        return self._store.emergency_revoke(root, self._digest(root.credential), self._now())

    def recover(
        self,
        *,
        recovery: OpaqueCredential,
    ) -> AuthOutcome[BootstrapExchange]:
        now = self._now()
        session, session_digest = self._credential()
        replacement, replacement_digest = self._credential()
        session_not_before, session_expires = self._window(now, self._policy.session_ttl_seconds)
        recovery_not_before, recovery_expires = self._window(now, self._policy.recovery_ttl_seconds)
        result = self._store.recover(
            recovery,
            self._digest(recovery),
            now,
            SessionIssue(
                handle=session.handle,
                digest=session_digest,
                not_before_utc=session_not_before,
                expires_at_utc=session_expires,
            ),
            RecoveryIssue(
                handle=replacement.handle,
                digest=replacement_digest,
                not_before_utc=recovery_not_before,
                expires_at_utc=recovery_expires,
                attempts=self._policy.max_attempts,
            ),
        )
        if result.denial is not None:
            return AuthOutcome.denied(result.denial)
        assert result.value is not None
        return AuthOutcome.allowed(
            BootstrapExchange(
                session=session,
                recovery=replacement,
                actor_id=result.value.actor_id,
                represented_profile_id=result.value.represented_profile_id,
                epoch=result.value.epoch,
            )
        )

    def validate_grant(
        self, grant: object, session: OpaqueCredential
    ) -> AuthOutcome[AuthorityGrant]:
        if type(grant) is not AuthorityGrant:
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        return self._store.validate_grant(grant, session, self._digest(session), self._now())

    def garbage_collect(self, retention_seconds: int) -> int:
        now = self._now()
        removed = self._store.garbage_collect(now, retention_seconds)
        with self._reprovision_ceremony_lock:
            removed += self._garbage_collect_reprovision_ceremonies_locked(now)
        return removed

    @property
    def policy(self) -> AuthPolicy:
        """Expose immutable finite operator guidance, never credential state."""
        return self._policy

    @staticmethod
    def _digest(credential: OpaqueCredential) -> SecretDigest:
        return SecretDigest(hashlib.sha256(credential.secret.reveal()).digest())
