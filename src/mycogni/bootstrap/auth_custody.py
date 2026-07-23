"""Custody-aware trusted composition for AUTH-001B."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from mycogni.application.auth import (
    TOKEN_BYTES,
    AuthService,
    AuthServiceMode,
    ReprovisionOperatorAuthority,
    TokenSource,
)
from mycogni.application.auth_custody import (
    AuthCustodyBinding,
    AuthCustodyBundle,
    AuthCustodyError,
    AuthCustodyFailureCode,
    AuthCustodyPort,
    AuthCustodyProvisioner,
    AuthCustodyStatus,
)
from mycogni.application.ports import Clock
from mycogni.bootstrap.auth_setup import AuthInstallationStore
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    OpaqueCredential,
    RootAuthorityBundle,
    RootCapability,
    RootCapabilityIssue,
    RootCapabilityRecord,
    RootPurpose,
    SecretDigest,
    require_utc,
)


def _digest(credential: OpaqueCredential) -> SecretDigest:
    return SecretDigest(hashlib.sha256(credential.secret.reveal()).digest())


def _credential(source: TokenSource) -> OpaqueCredential:
    material = source.generate(TOKEN_BYTES)
    if type(material) is not bytes or len(material) != TOKEN_BYTES:
        raise RuntimeError("auth custody token source violated the opaque-material contract")
    return OpaqueCredential.from_secret(OpaqueId.new(), material)


@dataclass(frozen=True, slots=True, repr=False)
class CustodiedAuthComposition:
    """Authorities released only after custody and durable state agree."""

    service: AuthService
    roots: RootAuthorityBundle
    operator_authority: ReprovisionOperatorAuthority

    def __repr__(self) -> str:
        return "CustodiedAuthComposition([REDACTED])"


def mint_auth_custody_bundle(
    *, binding: AuthCustodyBinding, token_source: TokenSource
) -> AuthCustodyBundle:
    """Mint a bundle only for an explicit empty-install administration ceremony."""
    if type(binding) is not AuthCustodyBinding:
        raise TypeError("auth custody mint requires an exact binding")
    operator = ReprovisionOperatorAuthority(_credential(token_source))
    service = _credential(token_source)

    def root(purpose: RootPurpose) -> RootCapability:
        return RootCapability(
            credential=_credential(token_source),
            installation_id=binding.installation_id,
            actor_id=binding.actor_id,
            represented_profile_id=binding.represented_profile_id,
            purpose=purpose,
        )

    roots = tuple(root(purpose) for purpose in RootPurpose)
    return AuthCustodyBundle(
        binding=binding,
        generation=1,
        operator_authority=operator,
        service_identity=service,
        initial_bootstrap=roots[0],
        emergency_revoke=roots[1],
        reprovision=roots[2],
    )


def _compose(
    *,
    bundle: AuthCustodyBundle,
    clock: Clock,
    token_source: TokenSource,
    store: AuthInstallationStore,
) -> CustodiedAuthComposition:
    if not store.verify_loaded_composition(bundle):
        raise AuthCustodyError(AuthCustodyFailureCode.BINDING_MISMATCH)
    service = AuthService(
        clock=clock,
        token_source=token_source,
        store=store,
        reprovision_operator_authority=bundle.operator_authority,
        service_identity=bundle.service_identity,
        mode=AuthServiceMode.CUSTODIED_STATIC_ROOTS,
    )
    return CustodiedAuthComposition(
        service=service,
        roots=RootAuthorityBundle(*bundle.roots),
        operator_authority=bundle.operator_authority,
    )


def open_custodied_auth(
    *,
    expected: AuthCustodyBinding,
    custody: AuthCustodyPort,
    clock: Clock,
    token_source: TokenSource,
    store: AuthInstallationStore,
) -> CustodiedAuthComposition:
    """Open an existing installation and deny every presence/binding mismatch."""
    state_exists = store.auth_state_exists()
    status = custody.status(expected)
    if status is not AuthCustodyStatus.READY or not state_exists:
        raise AuthCustodyError(AuthCustodyFailureCode.RECOVERY_REQUIRED)
    bundle = custody.load(expected)
    return _compose(bundle=bundle, clock=clock, token_source=token_source, store=store)


def provision_custodied_auth(
    *,
    binding: AuthCustodyBinding,
    provisioner: AuthCustodyProvisioner,
    clock: Clock,
    token_source: TokenSource,
    store: AuthInstallationStore,
) -> CustodiedAuthComposition:
    """Create custody first, then initialize an exactly empty durable store once."""
    if store.auth_state_exists():
        raise AuthCustodyError(AuthCustodyFailureCode.ALREADY_PROVISIONED)
    bundle = mint_auth_custody_bundle(binding=binding, token_source=token_source)
    provisioner.provision_empty(bundle)
    now = clock.now()
    require_utc(now, "auth custody provisioning time")
    records = tuple(
        RootCapabilityRecord(
            handle=root.credential.handle,
            installation_id=binding.installation_id,
            actor_id=binding.actor_id,
            represented_profile_id=binding.represented_profile_id,
            purpose=root.purpose,
            digest=_digest(root.credential),
        )
        for root in bundle.roots
    )
    store.initialize_installation(
        installation_id=binding.installation_id,
        actor_id=binding.actor_id,
        represented_profile_id=binding.represented_profile_id,
        records=records,
        operator_authority=RootCapabilityIssue(
            handle=bundle.operator_authority.credential.handle,
            digest=_digest(bundle.operator_authority.credential),
        ),
        service_identity=RootCapabilityIssue(
            handle=bundle.service_identity.handle,
            digest=_digest(bundle.service_identity),
        ),
        now=now,
    )
    return _compose(bundle=bundle, clock=clock, token_source=token_source, store=store)


__all__ = (
    "CustodiedAuthComposition",
    "mint_auth_custody_bundle",
    "open_custodied_auth",
    "provision_custodied_auth",
)
