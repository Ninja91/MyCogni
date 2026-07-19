"""Trusted local composition ceremony for one installation's root capabilities."""

from __future__ import annotations

import hashlib

from mycogni.adapters.auth import VolatileAuthDecisionStore
from mycogni.application.auth import (
    TOKEN_BYTES,
    AuthService,
    ReprovisionOperatorAuthority,
    TokenSource,
)
from mycogni.application.ports import Clock
from mycogni.domain import OpaqueId, Sensitive
from mycogni.domain.auth import (
    AUTH_SECRET_CATEGORY,
    OpaqueCredential,
    RootAuthorityBundle,
    RootCapability,
    RootCapabilityIssue,
    RootCapabilityRecord,
    RootPurpose,
    SecretDigest,
    require_utc,
)


class TrustedLocalAuthSetup:
    """Composition-only issuer; ordinary application services cannot mint root power."""

    def __init__(
        self,
        *,
        clock: Clock,
        token_source: TokenSource,
        store: VolatileAuthDecisionStore,
    ) -> None:
        self._clock = clock
        self._token_source = token_source
        self._store = store
        material = token_source.generate(TOKEN_BYTES)
        if type(material) is not bytes or len(material) != TOKEN_BYTES:
            raise RuntimeError(
                "operator-boundary token source violated the opaque-material contract"
            )
        self._reprovision_operator_authority = ReprovisionOperatorAuthority(
            OpaqueCredential(
                handle=OpaqueId.new(),
                secret=Sensitive(material, category=AUTH_SECRET_CATEGORY),
            )
        )
        self._service_identity: OpaqueCredential | None = None

    def bind_auth_service(self, service: AuthService) -> None:
        """Bind exactly one service instance to this store and operator authority."""
        if self._service_identity is not None:
            raise ValueError("trusted setup is already bound to an auth service")
        self._service_identity = service._composition_identity_for_setup(
            self._store, self._reprovision_operator_authority
        )

    @property
    def reprovision_operator_authority(self) -> ReprovisionOperatorAuthority:
        """Return authority only to trusted composition wiring the owned TTY boundary."""
        return self._reprovision_operator_authority

    def _capability(
        self,
        *,
        installation_id: OpaqueId,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        purpose: RootPurpose,
    ) -> tuple[RootCapability, RootCapabilityRecord]:
        material = self._token_source.generate(TOKEN_BYTES)
        if type(material) is not bytes or len(material) != TOKEN_BYTES:
            raise RuntimeError("root token source violated the opaque-material contract")
        credential = OpaqueCredential(
            handle=OpaqueId.new(),
            secret=Sensitive(material, category=AUTH_SECRET_CATEGORY),
        )
        capability = RootCapability(
            credential=credential,
            installation_id=installation_id,
            actor_id=actor_id,
            represented_profile_id=represented_profile_id,
            purpose=purpose,
        )
        return capability, RootCapabilityRecord(
            handle=credential.handle,
            installation_id=installation_id,
            actor_id=actor_id,
            represented_profile_id=represented_profile_id,
            purpose=purpose,
            digest=SecretDigest(hashlib.sha256(material).digest()),
        )

    def provision(
        self,
        *,
        installation_id: OpaqueId,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
    ) -> RootAuthorityBundle:
        """Provision exactly once before any actor bootstrap."""
        now = self._clock.now()
        require_utc(now, "trusted setup time")
        if self._service_identity is None:
            raise ValueError("trusted setup must bind the exact auth service before provisioning")
        issued = [
            self._capability(
                installation_id=installation_id,
                actor_id=actor_id,
                represented_profile_id=represented_profile_id,
                purpose=purpose,
            )
            for purpose in RootPurpose
        ]
        self._store.initialize_installation(
            installation_id=installation_id,
            actor_id=actor_id,
            represented_profile_id=represented_profile_id,
            records=tuple(record for _capability, record in issued),
            operator_authority=RootCapabilityIssue(
                handle=self._reprovision_operator_authority.credential.handle,
                digest=SecretDigest(
                    hashlib.sha256(
                        self._reprovision_operator_authority.credential.secret.reveal()
                    ).digest()
                ),
            ),
            service_identity=RootCapabilityIssue(
                handle=self._service_identity.handle,
                digest=SecretDigest(
                    hashlib.sha256(self._service_identity.secret.reveal()).digest()
                ),
            ),
            now=now,
        )
        by_purpose = {capability.purpose: capability for capability, _record in issued}
        return RootAuthorityBundle(
            initial_bootstrap=by_purpose[RootPurpose.INITIAL_BOOTSTRAP],
            emergency_revoke=by_purpose[RootPurpose.EMERGENCY_REVOKE],
            reprovision=by_purpose[RootPurpose.REPROVISION],
        )
