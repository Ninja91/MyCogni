"""Application-owned ports and orchestration for the volatile auth spike."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol, cast, runtime_checkable

from mycogni.application.ports import Clock
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    PURPOSE_SCOPE,
    ActorRecord,
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
    CompositionBindingRecord,
    GrantProvenanceRecord,
    OpaqueCredential,
    RecoveryIssue,
    RecoveryRecord,
    ReprovisionCeremonyIssue,
    ReprovisionCeremonyRecord,
    RootCapability,
    RootCapabilityIssue,
    RootCapabilityRecord,
    RootPurpose,
    SecretDigest,
    SessionIssue,
    SessionRecord,
    StepUpRecord,
    require_utc,
)

TOKEN_BYTES = 32


@dataclass(frozen=True, slots=True)
class AuthStateSnapshotV1:
    """Explicit fixed-field durable representation of the auth decision state."""

    actors: tuple[ActorRecord, ...]
    installation_actors: tuple[tuple[OpaqueId, OpaqueId], ...]
    roots: tuple[RootCapabilityRecord, ...]
    bootstraps: tuple[BootstrapRecord, ...]
    sessions: tuple[SessionRecord, ...]
    recoveries: tuple[RecoveryRecord, ...]
    step_ups: tuple[StepUpRecord, ...]
    grant_provenance: tuple[GrantProvenanceRecord, ...]
    composition_bindings: tuple[CompositionBindingRecord, ...]
    reprovision_ceremonies: tuple[ReprovisionCeremonyRecord, ...]

    def __post_init__(self) -> None:
        expected_types: tuple[tuple[object, type[object]], ...] = (
            (self.actors, ActorRecord),
            (self.roots, RootCapabilityRecord),
            (self.bootstraps, BootstrapRecord),
            (self.sessions, SessionRecord),
            (self.recoveries, RecoveryRecord),
            (self.step_ups, StepUpRecord),
            (self.grant_provenance, GrantProvenanceRecord),
            (self.composition_bindings, CompositionBindingRecord),
            (self.reprovision_ceremonies, ReprovisionCeremonyRecord),
        )
        for collection, item_type in expected_types:
            if type(collection) is not tuple or any(
                type(item) is not item_type for item in collection
            ):
                raise TypeError("auth snapshot collection has the wrong exact record type")
        if type(self.installation_actors) is not tuple or any(
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not OpaqueId
            or type(pair[1]) is not OpaqueId
            for pair in self.installation_actors
        ):
            raise TypeError("auth snapshot installation actors are malformed")

        def unique(records: tuple[object, ...], attribute: str) -> dict[OpaqueId, Any]:
            indexed: dict[OpaqueId, Any] = {}
            for record in records:
                handle = getattr(record, attribute)
                if type(handle) is not OpaqueId or handle in indexed:
                    raise ValueError("auth snapshot contains a duplicate record key")
                indexed[handle] = record
            return indexed

        actors = unique(self.actors, "actor_id")
        roots = unique(self.roots, "handle")
        bootstraps = unique(self.bootstraps, "handle")
        sessions = unique(self.sessions, "handle")
        unique(self.recoveries, "handle")
        step_ups = unique(self.step_ups, "handle")
        unique(self.reprovision_ceremonies, "handle")
        installation_map = dict(self.installation_actors)
        if len(installation_map) != len(self.installation_actors):
            raise ValueError("auth snapshot contains duplicate installation bindings")
        compositions = {record.installation_id: record for record in self.composition_bindings}
        if len(compositions) != len(self.composition_bindings):
            raise ValueError("auth snapshot contains duplicate composition bindings")
        if (
            len(set(installation_map.values())) != len(installation_map)
            or set(installation_map.values()) != set(actors)
            or set(installation_map) != set(compositions)
        ):
            raise ValueError("auth snapshot installation, actor, and composition coverage differs")
        for installation_id, actor_id in installation_map.items():
            if actor_id not in actors or installation_id not in compositions:
                raise ValueError("auth snapshot installation binding is incomplete")
        for root in roots.values():
            assert isinstance(root, RootCapabilityRecord)
            actor = actors.get(root.actor_id)
            if (
                installation_map.get(root.installation_id) != root.actor_id
                or actor is None
                or actor.represented_profile_id != root.represented_profile_id
            ):
                raise ValueError("auth snapshot root binding is inconsistent")
        active_root_purposes: set[tuple[OpaqueId, RootPurpose]] = set()
        for root in roots.values():
            if root.consumed:
                continue
            identity = (root.installation_id, root.purpose)
            if identity in active_root_purposes:
                raise ValueError("auth snapshot has duplicate active root purpose")
            active_root_purposes.add(identity)
        authority_handles = set(roots)
        for composition in self.composition_bindings:
            if (
                composition.operator_handle in authority_handles
                or composition.service_handle in authority_handles
            ):
                raise ValueError("auth snapshot authority handles are not globally unique")
            authority_handles.update((composition.operator_handle, composition.service_handle))
        for record in (*self.bootstraps, *self.sessions, *self.recoveries, *self.step_ups):
            record = cast(BootstrapRecord | SessionRecord | RecoveryRecord | StepUpRecord, record)
            actor = actors.get(record.actor_id)
            if actor is None or actor.represented_profile_id != record.represented_profile_id:
                raise ValueError("auth snapshot record binding is inconsistent")
            if isinstance(record, (SessionRecord, RecoveryRecord, StepUpRecord)) and (
                record.epoch > actor.epoch
            ):
                raise ValueError("auth snapshot record epoch is from the future")
        for bootstrap in self.bootstraps:
            if bootstrap.root_capability_id is None:
                continue
            root = roots.get(bootstrap.root_capability_id)
            if (
                root is None
                or bootstrap.root_purpose is not root.purpose
                or bootstrap.actor_id != root.actor_id
                or bootstrap.represented_profile_id != root.represented_profile_id
            ):
                raise ValueError("auth snapshot bootstrap root binding is inconsistent")
        for step_up in self.step_ups:
            session = sessions.get(step_up.session_id)
            if session is None:
                if not step_up.consumed:
                    raise ValueError("active auth snapshot step-up has no session")
                continue
            if (
                step_up.actor_id != session.actor_id
                or step_up.represented_profile_id != session.represented_profile_id
                or step_up.epoch != session.epoch
            ):
                raise ValueError("auth snapshot step-up session binding is inconsistent")
        provenance_ids: set[OpaqueId] = set()
        for provenance in self.grant_provenance:
            grant = provenance.grant
            evidence_id = grant.authority_evidence_id
            if evidence_id in provenance_ids:
                raise ValueError("auth snapshot contains duplicate grant provenance")
            provenance_ids.add(evidence_id)
            actor = actors.get(grant.actor_id)
            if (
                actor is None
                or actor.represented_profile_id != grant.represented_profile_id
                or grant.epoch > actor.epoch
            ):
                raise ValueError("auth snapshot grant binding is inconsistent")
            session = sessions.get(grant.session_id)
            if session is not None and (
                session.actor_id != grant.actor_id
                or session.represented_profile_id != grant.represented_profile_id
                or session.epoch != grant.epoch
            ):
                raise ValueError("auth snapshot grant session binding is inconsistent")
            provenance_step = cast(StepUpRecord | None, step_ups.get(evidence_id))
            if provenance_step is not None and (
                provenance_step.actor_id != grant.actor_id
                or provenance_step.represented_profile_id != grant.represented_profile_id
                or provenance_step.session_id != grant.session_id
                or provenance_step.epoch != grant.epoch
                or provenance_step.purpose is not grant.purpose
                or provenance_step.scopes != grant.scopes
            ):
                raise ValueError("auth snapshot grant provenance is inconsistent")
        for ceremony in self.reprovision_ceremonies:
            matching_composition = compositions.get(ceremony.installation_id)
            if (
                matching_composition is None
                or matching_composition.service_handle != ceremony.service_handle
            ):
                raise ValueError("auth snapshot ceremony binding is inconsistent")
            ceremony_bootstrap = cast(
                BootstrapRecord | None, bootstraps.get(ceremony.bootstrap_handle)
            )
            if ceremony_bootstrap is None:
                if ceremony.terminal_at_utc is None:
                    raise ValueError("active auth snapshot ceremony has no bootstrap")
                continue
            root = (
                roots.get(ceremony_bootstrap.root_capability_id)
                if ceremony_bootstrap.root_capability_id is not None
                else None
            )
            if (
                ceremony_bootstrap.root_purpose is not RootPurpose.REPROVISION
                or root is None
                or root.purpose is not RootPurpose.REPROVISION
                or root.installation_id != ceremony.installation_id
                or root.actor_id != ceremony_bootstrap.actor_id
                or root.represented_profile_id != ceremony_bootstrap.represented_profile_id
            ):
                raise ValueError("auth snapshot ceremony authority chain is inconsistent")


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
    ) -> AuthOutcome[BootstrapDecision]: ...

    def create_reprovision_ceremony(
        self,
        service_identity: OpaqueCredential,
        service_digest: SecretDigest,
        operator_identity: OpaqueCredential,
        operator_digest: SecretDigest,
        bootstrap_handle: OpaqueId,
        issue: ReprovisionCeremonyIssue,
        now: datetime,
        *,
        active_capacity: int,
        tombstone_capacity: int,
        replay_seconds: int,
    ) -> AuthOutcome[OpaqueId]: ...

    def exchange_reprovision_bootstrap(
        self,
        handle: OpaqueId,
        presented_digest: SecretDigest,
        service_identity: OpaqueCredential,
        service_digest: SecretDigest,
        ceremony: OpaqueCredential,
        ceremony_digest: SecretDigest,
        now: datetime,
        session: SessionRecord,
        recovery: RecoveryRecord,
        replacement_reprovision: RootCapabilityIssue,
        *,
        tombstone_capacity: int,
        replay_seconds: int,
    ) -> AuthOutcome[BootstrapDecision]: ...

    def reprovision_ceremony_counts(self, service_handle: OpaqueId) -> dict[str, int]: ...

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
        self._reprovision_operator_authority = reprovision_operator_authority
        self._service_identity, _digest = self._credential()

    def _composition_identity_for_setup(
        self,
        store: AuthDecisionStore,
        operator_authority: ReprovisionOperatorAuthority,
    ) -> OpaqueCredential:
        """Expose identity only to trusted setup bound to this exact composition."""
        if (
            store is not self._store
            or operator_authority is not self._reprovision_operator_authority
        ):
            raise ValueError("service composition binding does not match")
        return self._service_identity

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
        return self._exchange_bootstrap(bootstrap)

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
        now = self._now()
        credential, digest = self._credential()
        authorization = ReprovisionCeremonyAuthorization(
            credential=credential,
            bootstrap_handle=bootstrap.handle,
        )
        registered = self._store.create_reprovision_ceremony(
            self._service_identity,
            self._digest(self._service_identity),
            operator_authority.credential,
            self._digest(operator_authority.credential),
            bootstrap.handle,
            ReprovisionCeremonyIssue(
                handle=credential.handle,
                digest=digest,
                expires_at_utc=now
                + timedelta(seconds=self._policy.reprovision_ceremony_ttl_seconds),
            ),
            now,
            active_capacity=self._policy.reprovision_ceremony_capacity,
            tombstone_capacity=self._policy.reprovision_ceremony_tombstone_capacity,
            replay_seconds=self._policy.reprovision_ceremony_replay_seconds,
        )
        if registered.denial is not None:
            return AuthOutcome.denied(registered.denial)
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
        if authorization.bootstrap_handle != bootstrap.handle:
            return AuthOutcome.denied(AuthDenial.INVALID_PROOF)
        return self._exchange_bootstrap(bootstrap, authorization=authorization)

    def reprovision_ceremony_counts(self) -> dict[str, int]:
        """Expose finite non-secret retention counts for operations and tests."""
        return self._store.reprovision_ceremony_counts(self._service_identity.handle)

    def _exchange_bootstrap(
        self,
        bootstrap: OpaqueCredential,
        authorization: ReprovisionCeremonyAuthorization | None = None,
    ) -> AuthOutcome[BootstrapExchange]:
        now = self._now()
        session, session_digest = self._credential()
        recovery, recovery_digest = self._credential()
        replacement_root, replacement_root_digest = self._credential()
        session_not_before, session_expires = self._window(now, self._policy.session_ttl_seconds)
        recovery_not_before, recovery_expires = self._window(now, self._policy.recovery_ttl_seconds)
        placeholder = OpaqueId.new()
        session_record = SessionRecord(
            handle=session.handle,
            actor_id=placeholder,
            represented_profile_id=placeholder,
            digest=session_digest,
            epoch=1,
            not_before_utc=session_not_before,
            expires_at_utc=session_expires,
        )
        recovery_record = RecoveryRecord(
            handle=recovery.handle,
            actor_id=placeholder,
            represented_profile_id=placeholder,
            digest=recovery_digest,
            epoch=1,
            not_before_utc=recovery_not_before,
            expires_at_utc=recovery_expires,
            attempts_remaining=self._policy.max_attempts,
        )
        replacement_issue = RootCapabilityIssue(
            handle=replacement_root.handle,
            digest=replacement_root_digest,
        )
        if authorization is None:
            result = self._store.exchange_bootstrap(
                bootstrap.handle,
                self._digest(bootstrap),
                now,
                session_record,
                recovery_record,
                replacement_issue,
            )
        else:
            result = self._store.exchange_reprovision_bootstrap(
                bootstrap.handle,
                self._digest(bootstrap),
                self._service_identity,
                self._digest(self._service_identity),
                authorization.credential,
                self._digest(authorization.credential),
                now,
                session_record,
                recovery_record,
                replacement_issue,
                tombstone_capacity=self._policy.reprovision_ceremony_tombstone_capacity,
                replay_seconds=self._policy.reprovision_ceremony_replay_seconds,
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
        return self._store.garbage_collect(self._now(), retention_seconds)

    @property
    def policy(self) -> AuthPolicy:
        """Expose immutable finite operator guidance, never credential state."""
        return self._policy

    @staticmethod
    def _digest(credential: OpaqueCredential) -> SecretDigest:
        return SecretDigest(hashlib.sha256(credential.secret.reveal()).digest())
