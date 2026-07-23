"""Application-owned contract for restart-safe authentication secret custody."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from mycogni.application.auth import ReprovisionOperatorAuthority
from mycogni.domain import OpaqueId
from mycogni.domain.auth import OpaqueCredential, RootCapability, RootPurpose


class AuthCustodyStatus(StrEnum):
    READY = "ready"
    UNPROVISIONED = "unprovisioned"
    RECOVERY_REQUIRED = "recovery_required"


class AuthCustodyFailureCode(StrEnum):
    UNAVAILABLE = "unavailable"
    UNSAFE_STORAGE = "unsafe_storage"
    MALFORMED_RECORD = "malformed_record"
    BINDING_MISMATCH = "binding_mismatch"
    FORKED_PROCESS = "forked_process"
    RECOVERY_REQUIRED = "recovery_required"
    ALREADY_PROVISIONED = "already_provisioned"
    CAS_MISMATCH = "cas_mismatch"


class AuthCustodyError(RuntimeError):
    """Finite, deliberately redacted custody failure."""

    def __init__(self, code: AuthCustodyFailureCode) -> None:
        if type(code) is not AuthCustodyFailureCode:
            raise TypeError("auth custody failure code must be exact")
        self.code = code
        super().__init__(code.value)

    def __str__(self) -> str:
        return f"auth_custody:{self.code.value}"

    def __repr__(self) -> str:
        return f"AuthCustodyError({self.code.value!r})"


@dataclass(frozen=True, slots=True)
class AuthCustodyBinding:
    installation_id: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    format_version: Literal[1] = 1

    def __post_init__(self) -> None:
        if any(
            type(value) is not OpaqueId
            for value in (self.installation_id, self.actor_id, self.represented_profile_id)
        ):
            raise TypeError("auth custody binding requires opaque IDs")
        if type(self.format_version) is not int or self.format_version != 1:
            raise ValueError("auth custody binding requires format version 1")


@dataclass(frozen=True, slots=True, repr=False)
class AuthCustodyBundle:
    binding: AuthCustodyBinding
    generation: int
    operator_authority: ReprovisionOperatorAuthority
    service_identity: OpaqueCredential
    initial_bootstrap: RootCapability
    emergency_revoke: RootCapability
    reprovision: RootCapability

    def __post_init__(self) -> None:
        if type(self.binding) is not AuthCustodyBinding:
            raise TypeError("auth custody bundle requires an exact binding")
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("auth custody generation must be positive")
        if type(self.operator_authority) is not ReprovisionOperatorAuthority:
            raise TypeError("auth custody bundle requires operator authority")
        if type(self.service_identity) is not OpaqueCredential:
            raise TypeError("auth custody bundle requires service identity")
        roots = (self.initial_bootstrap, self.emergency_revoke, self.reprovision)
        if any(type(root) is not RootCapability for root in roots):
            raise TypeError("auth custody bundle requires root capabilities")
        if tuple(root.purpose for root in roots) != tuple(RootPurpose):
            raise ValueError("auth custody bundle requires canonical root purposes")
        expected = (
            self.binding.installation_id,
            self.binding.actor_id,
            self.binding.represented_profile_id,
        )
        if any(
            (root.installation_id, root.actor_id, root.represented_profile_id) != expected
            for root in roots
        ):
            raise ValueError("auth custody root binding differs")
        credentials = (
            self.operator_authority.credential,
            self.service_identity,
            *(root.credential for root in roots),
        )
        if len({credential.handle for credential in credentials}) != len(credentials):
            raise ValueError("auth custody handles must be globally unique")
        if any(len(credential.secret.reveal()) != 32 for credential in credentials):
            raise ValueError("auth custody secrets must be exactly 32 bytes")

    def __repr__(self) -> str:
        return "AuthCustodyBundle([REDACTED])"

    __str__ = __repr__

    @property
    def roots(self) -> tuple[RootCapability, RootCapability, RootCapability]:
        return (self.initial_bootstrap, self.emergency_revoke, self.reprovision)


@runtime_checkable
class AuthCustodyPort(Protocol):
    def status(self, expected: AuthCustodyBinding) -> AuthCustodyStatus: ...

    def load(self, expected: AuthCustodyBinding) -> AuthCustodyBundle: ...


@runtime_checkable
class AuthCustodyProvisioner(Protocol):
    """Separate create-new administration boundary, absent from runtime custody."""

    def provision_empty(self, bundle: AuthCustodyBundle) -> None: ...
