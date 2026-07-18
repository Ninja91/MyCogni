"""Framework-free authentication spike values and volatile state records.

These types model a synthetic decision spike. They do not implement browser
security, durable persistence, cloud identity, or production authentication.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType

from mycogni.domain.contracts import OpaqueId, Sensitive

AUTH_SECRET_CATEGORY = "auth_secret"
MIN_SECRET_BYTES = 32
SHA256_BYTES = 32
MAX_OPERATOR_CODE_CHARS = 128
DAY_SECONDS = 86_400
RECOVERY_MIN_SECONDS = 30 * DAY_SECONDS
RECOVERY_MAX_SECONDS = 730 * DAY_SECONDS
DEFAULT_RECOVERY_SECONDS = 365 * DAY_SECONDS


def require_utc(value: datetime, field_name: str) -> None:
    """Reject naive and non-UTC policy timestamps."""
    if type(value) is not datetime:
        raise TypeError(f"{field_name} must be a datetime")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be an aware UTC instant")


class AuthPurpose(StrEnum):
    """Finite privileged ceremonies requiring a one-use step-up."""

    SETUP_AUTHORITY_CHANGE = "setup_authority_change"
    EXTERNAL_ACTION_RESUME = "external_action_resume"
    EXCEPTION_SUBMISSION = "exception_submission"
    KEY_RECOVERY_CHANGE = "key_recovery_change"
    PROFILE_DELETION = "profile_deletion"
    DESTRUCTIVE_RESTORE = "destructive_restore"
    ALL_SESSION_REVOKE = "all_session_revoke"


class AuthScope(StrEnum):
    """Finite authority scopes bound into a step-up grant."""

    CHANGE_SETUP_AUTHORITY = "change_setup_authority"
    RESUME_EXTERNAL_ACTIONS = "resume_external_actions"
    SUBMIT_EXCEPTION = "submit_exception"
    CHANGE_KEY_RECOVERY = "change_key_recovery"
    DELETE_PROFILE = "delete_profile"
    RESTORE_DESTRUCTIVELY = "restore_destructively"
    REVOKE_ALL_SESSIONS = "revoke_all_sessions"


PURPOSE_SCOPE: Mapping[AuthPurpose, AuthScope] = MappingProxyType(
    {
        AuthPurpose.SETUP_AUTHORITY_CHANGE: AuthScope.CHANGE_SETUP_AUTHORITY,
        AuthPurpose.EXTERNAL_ACTION_RESUME: AuthScope.RESUME_EXTERNAL_ACTIONS,
        AuthPurpose.EXCEPTION_SUBMISSION: AuthScope.SUBMIT_EXCEPTION,
        AuthPurpose.KEY_RECOVERY_CHANGE: AuthScope.CHANGE_KEY_RECOVERY,
        AuthPurpose.PROFILE_DELETION: AuthScope.DELETE_PROFILE,
        AuthPurpose.DESTRUCTIVE_RESTORE: AuthScope.RESTORE_DESTRUCTIVELY,
        AuthPurpose.ALL_SESSION_REVOKE: AuthScope.REVOKE_ALL_SESSIONS,
    }
)


class AuthDenial(StrEnum):
    """Finite, non-secret denial vocabulary for the spike decision surface."""

    NON_INTERACTIVE = "non_interactive"
    INVALID_PROOF = "invalid_proof"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    REPLAYED = "replayed"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    CLOCK_ROLLBACK = "clock_rollback"
    SESSION_NOT_FOUND = "session_not_found"
    REVOKED = "revoked"
    WRONG_ACTOR = "wrong_actor"
    WRONG_PROFILE = "wrong_profile"
    WRONG_INSTALLATION = "wrong_installation"
    WRONG_SESSION = "wrong_session"
    WRONG_PURPOSE = "wrong_purpose"
    SCOPE_WIDENING = "scope_widening"
    STALE_EPOCH = "stale_epoch"
    MALFORMED_CREDENTIAL = "malformed_credential"
    OPERATOR_DECLINED = "operator_declined"
    OUTPUT_INTERRUPTED = "output_interrupted"


class RootPurpose(StrEnum):
    """Exact one-use powers issued only by trusted local composition."""

    INITIAL_BOOTSTRAP = "initial_bootstrap"
    EMERGENCY_REVOKE = "emergency_revoke"
    REPROVISION = "reprovision"


@dataclass(frozen=True, slots=True, repr=False)
class SecretDigest:
    """Fixed-size digest retained instead of opaque credential material."""

    value: bytes

    def __post_init__(self) -> None:
        if type(self.value) is not bytes:
            raise TypeError("secret digest must be bytes")
        if len(self.value) != SHA256_BYTES:
            raise ValueError("secret digest must be a SHA-256 digest")

    def __repr__(self) -> str:
        return "SecretDigest([REDACTED])"


@dataclass(frozen=True, slots=True, repr=False)
class OpaqueCredential:
    """Handle plus high-entropy secret, redacted from ordinary rendering."""

    handle: OpaqueId
    secret: Sensitive[bytes]

    def __post_init__(self) -> None:
        if type(self.handle) is not OpaqueId:
            raise TypeError("credential handle must be an OpaqueId")
        if type(self.secret) is not Sensitive:
            raise TypeError("credential secret must be Sensitive")
        if self.secret.category != AUTH_SECRET_CATEGORY:
            raise ValueError("credential secret has the wrong category")
        revealed = self.secret.reveal()
        if type(revealed) is not bytes or len(revealed) < MIN_SECRET_BYTES:
            raise ValueError("credential secret must contain at least 256 bits")

    @classmethod
    def from_secret(cls, handle: OpaqueId, secret: bytes) -> OpaqueCredential:
        """Wrap newly generated material at its issuance boundary."""
        return cls(handle=handle, secret=Sensitive(secret, category=AUTH_SECRET_CATEGORY))

    def operator_code(self) -> str:
        """Render only for an explicitly reviewed interactive operator channel."""
        encoded = base64.urlsafe_b64encode(self.secret.reveal()).rstrip(b"=").decode("ascii")
        return f"{self.handle}.{encoded}"

    @classmethod
    def parse_operator_code(cls, value: str) -> OpaqueCredential:
        """Parse without incorporating attacker-controlled material into errors."""
        try:
            if type(value) is not str or not 1 <= len(value) <= MAX_OPERATOR_CODE_CHARS:
                raise ValueError
            handle_text, encoded = value.strip().split(".", 1)
            padding = "=" * (-len(encoded) % 4)
            secret = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
            return cls.from_secret(OpaqueId.parse(handle_text), secret)
        except (TypeError, ValueError):
            raise ValueError("malformed opaque credential") from None

    def __repr__(self) -> str:
        return f"OpaqueCredential(handle={self.handle}, secret=[REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED:auth_secret]"


@dataclass(frozen=True, slots=True)
class AuthPolicy:
    """Bounded time and guessing policy selected by composition."""

    bootstrap_ttl_seconds: int = 300
    session_ttl_seconds: int = 1_800
    step_up_ttl_seconds: int = 120
    recovery_ttl_seconds: int = DEFAULT_RECOVERY_SECONDS
    activation_delay_seconds: int = 0
    max_attempts: int = 5

    def __post_init__(self) -> None:
        for field_name in ("bootstrap_ttl_seconds", "session_ttl_seconds", "step_up_ttl_seconds"):
            value = getattr(self, field_name)
            if type(value) is not int or not 1 <= value <= 604_800:
                raise ValueError(f"{field_name} must be an integer from 1 through 604800")
        if (
            type(self.recovery_ttl_seconds) is not int
            or not RECOVERY_MIN_SECONDS <= self.recovery_ttl_seconds <= RECOVERY_MAX_SECONDS
        ):
            raise ValueError("recovery_ttl_seconds must be an integer from 30 through 730 days")
        if (
            type(self.activation_delay_seconds) is not int
            or not 0 <= self.activation_delay_seconds <= 60
        ):
            raise ValueError("activation_delay_seconds must be an integer from 0 through 60")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be an integer from 1 through 10")


@dataclass(frozen=True, slots=True)
class AuthOutcome[T]:
    """Exactly one successful value or finite denial."""

    value: T | None = None
    denial: AuthDenial | None = None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.denial is None):
            raise ValueError("auth outcome must contain exactly one value or denial")
        if self.denial is not None and type(self.denial) is not AuthDenial:
            raise TypeError("auth outcome denial must be an AuthDenial")

    @classmethod
    def allowed(cls, value: T) -> AuthOutcome[T]:
        return cls(value=value)

    @classmethod
    def denied(cls, denial: AuthDenial) -> AuthOutcome[T]:
        return cls(denial=denial)


@dataclass(frozen=True, slots=True)
class BootstrapExchange:
    """Synthetic bootstrap result disclosed only to the calling composition."""

    session: OpaqueCredential
    recovery: OpaqueCredential
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    epoch: int
    replacement_reprovision: RootCapability | None = None

    def __post_init__(self) -> None:
        if (
            type(self.session) is not OpaqueCredential
            or type(self.recovery) is not OpaqueCredential
        ):
            raise TypeError("bootstrap exchange requires opaque session and recovery credentials")
        if type(self.actor_id) is not OpaqueId or type(self.represented_profile_id) is not OpaqueId:
            raise TypeError("bootstrap exchange requires opaque actor and profile IDs")
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("bootstrap exchange epoch must be positive")
        if self.replacement_reprovision is not None:
            if type(self.replacement_reprovision) is not RootCapability:
                raise TypeError("replacement reprovision must be a root capability")
            if self.replacement_reprovision.purpose is not RootPurpose.REPROVISION:
                raise ValueError("replacement reprovision capability has the wrong purpose")
            if (
                self.replacement_reprovision.actor_id != self.actor_id
                or self.replacement_reprovision.represented_profile_id
                != self.represented_profile_id
            ):
                raise ValueError("replacement reprovision capability has the wrong binding")


@dataclass(frozen=True, slots=True, repr=False)
class RootCapability:
    """Installation/actor/profile/purpose-bound composition authority."""

    credential: OpaqueCredential
    installation_id: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    purpose: RootPurpose

    def __post_init__(self) -> None:
        if type(self.credential) is not OpaqueCredential:
            raise TypeError("root capability requires an opaque credential")
        if any(
            type(value) is not OpaqueId
            for value in (self.installation_id, self.actor_id, self.represented_profile_id)
        ):
            raise TypeError("root capability bindings must use opaque IDs")
        if type(self.purpose) is not RootPurpose:
            raise TypeError("root capability purpose must be a RootPurpose")

    def __repr__(self) -> str:
        return (
            "RootCapability(credential=[REDACTED], "
            f"installation_id={self.installation_id}, actor_id={self.actor_id}, "
            f"represented_profile_id={self.represented_profile_id}, purpose={self.purpose!r})"
        )


@dataclass(frozen=True, slots=True)
class RootAuthorityBundle:
    """Three separate one-use powers provisioned at trusted local setup."""

    initial_bootstrap: RootCapability
    emergency_revoke: RootCapability
    reprovision: RootCapability

    def __post_init__(self) -> None:
        capabilities = (self.initial_bootstrap, self.emergency_revoke, self.reprovision)
        if any(type(capability) is not RootCapability for capability in capabilities):
            raise TypeError("root authority bundle requires root capabilities")
        if tuple(capability.purpose for capability in capabilities) != tuple(RootPurpose):
            raise ValueError("root authority bundle purposes are not canonical")
        bindings = {
            (
                capability.installation_id,
                capability.actor_id,
                capability.represented_profile_id,
            )
            for capability in capabilities
        }
        if len(bindings) != 1:
            raise ValueError("root authority bundle capabilities must share exact bindings")
        if len({capability.credential.handle for capability in capabilities}) != 3:
            raise ValueError("root authority bundle requires three unique handles")


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    """Actor/profile/evidence/scope/time/epoch-bound authority decision."""

    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    session_id: OpaqueId
    authority_evidence_id: OpaqueId
    purpose: AuthPurpose
    scopes: frozenset[AuthScope]
    not_before_utc: datetime
    expires_at_utc: datetime
    epoch: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not OpaqueId
            for value in (
                self.actor_id,
                self.represented_profile_id,
                self.session_id,
                self.authority_evidence_id,
            )
        ):
            raise TypeError("grant bindings must use opaque IDs")
        if type(self.purpose) is not AuthPurpose:
            raise TypeError("grant purpose must be an AuthPurpose")
        if type(self.scopes) is not frozenset:
            raise TypeError("grant scopes must be a frozenset")
        require_utc(self.not_before_utc, "grant not_before_utc")
        require_utc(self.expires_at_utc, "grant expires_at_utc")
        if self.expires_at_utc <= self.not_before_utc:
            raise ValueError("grant expiry must follow not-before")
        if self.scopes != frozenset({PURPOSE_SCOPE[self.purpose]}):
            raise ValueError("grant scope must exactly match its purpose")
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("grant epoch must be positive")


@dataclass(frozen=True, slots=True)
class GrantProvenanceRecord:
    """Immutable proof that one exact grant came from successful step-up consumption."""

    grant: AuthorityGrant
    used_at_utc: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.grant) is not AuthorityGrant:
            raise TypeError("grant provenance requires an AuthorityGrant")
        if self.used_at_utc is not None:
            require_utc(self.used_at_utc, "grant provenance used_at_utc")
            if self.used_at_utc < self.grant.not_before_utc:
                raise ValueError("grant use cannot precede its not-before instant")


@dataclass(frozen=True, slots=True)
class RootCapabilityIssue:
    """Unbound replacement root material; the store supplies canonical bindings."""

    handle: OpaqueId
    digest: SecretDigest

    def __post_init__(self) -> None:
        if type(self.handle) is not OpaqueId or type(self.digest) is not SecretDigest:
            raise TypeError("root capability issue requires an opaque handle and digest")


@dataclass(frozen=True, slots=True)
class BootstrapIssue:
    """Unbound bootstrap material; the store supplies every authority binding."""

    handle: OpaqueId
    digest: SecretDigest
    not_before_utc: datetime
    expires_at_utc: datetime
    attempts: int

    def __post_init__(self) -> None:
        if type(self.handle) is not OpaqueId or type(self.digest) is not SecretDigest:
            raise TypeError("bootstrap issue requires an opaque handle and digest")
        require_utc(self.not_before_utc, "bootstrap issue not_before_utc")
        require_utc(self.expires_at_utc, "bootstrap issue expires_at_utc")
        if self.expires_at_utc <= self.not_before_utc:
            raise ValueError("bootstrap issue expiry must follow not-before")
        _validate_attempts(self.attempts)


@dataclass(frozen=True, slots=True)
class RootCapabilityBinding:
    """Non-secret canonical binding returned after replacement root registration."""

    handle: OpaqueId
    installation_id: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    purpose: RootPurpose

    def __post_init__(self) -> None:
        if any(
            type(value) is not OpaqueId
            for value in (
                self.handle,
                self.installation_id,
                self.actor_id,
                self.represented_profile_id,
            )
        ):
            raise TypeError("root capability binding requires opaque IDs")
        if self.purpose is not RootPurpose.REPROVISION:
            raise ValueError("replacement root binding must be for reprovision")


@dataclass(frozen=True, slots=True)
class BootstrapDecision:
    """Non-secret result of an atomic bootstrap consume/issue decision."""

    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    epoch: int
    replacement_reprovision: RootCapabilityBinding | None = None

    def __post_init__(self) -> None:
        if type(self.actor_id) is not OpaqueId or type(self.represented_profile_id) is not OpaqueId:
            raise TypeError("bootstrap decision requires opaque actor and profile IDs")
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("bootstrap decision epoch must be positive")
        if self.replacement_reprovision is not None and (
            self.replacement_reprovision.actor_id != self.actor_id
            or self.replacement_reprovision.represented_profile_id != self.represented_profile_id
        ):
            raise ValueError("replacement root decision binding is inconsistent")


@dataclass(slots=True)
class ActorRecord:
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    epoch: int
    last_observed_utc: datetime
    initialized: bool = False

    def __post_init__(self) -> None:
        if type(self.actor_id) is not OpaqueId or type(self.represented_profile_id) is not OpaqueId:
            raise TypeError("actor state requires opaque actor and profile IDs")
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("actor epoch must be positive")
        require_utc(self.last_observed_utc, "actor last_observed_utc")
        if type(self.initialized) is not bool:
            raise TypeError("actor initialized state must be boolean")


@dataclass(slots=True)
class RootCapabilityRecord:
    handle: OpaqueId
    installation_id: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    purpose: RootPurpose
    digest: SecretDigest
    consumed: bool = False
    retired_at_utc: datetime | None = None

    def __post_init__(self) -> None:
        if any(
            type(value) is not OpaqueId
            for value in (
                self.handle,
                self.installation_id,
                self.actor_id,
                self.represented_profile_id,
            )
        ):
            raise TypeError("root records require opaque bindings")
        if type(self.purpose) is not RootPurpose:
            raise TypeError("root record purpose must be a RootPurpose")
        if type(self.digest) is not SecretDigest:
            raise TypeError("root record digest must be a SecretDigest")
        _validate_mutable_state(self.consumed, self.retired_at_utc, "root")


def _validate_mutable_state(flag: bool, retired_at_utc: datetime | None, record_name: str) -> None:
    if type(flag) is not bool:
        raise TypeError(f"{record_name} state flag must be boolean")
    if retired_at_utc is not None:
        require_utc(retired_at_utc, f"{record_name} retired_at_utc")


def _validate_record(
    *,
    handle: OpaqueId,
    actor_id: OpaqueId,
    represented_profile_id: OpaqueId,
    digest: SecretDigest,
    not_before_utc: datetime,
    expires_at_utc: datetime,
) -> None:
    if any(type(value) is not OpaqueId for value in (handle, actor_id, represented_profile_id)):
        raise TypeError("auth records require opaque handle, actor, and profile IDs")
    if type(digest) is not SecretDigest:
        raise TypeError("auth record digest must be a SecretDigest")
    require_utc(not_before_utc, "auth record not_before_utc")
    require_utc(expires_at_utc, "auth record expires_at_utc")
    if expires_at_utc <= not_before_utc:
        raise ValueError("auth record expiry must follow not-before")


def _validate_attempts(value: int) -> None:
    if type(value) is not int or value < 1:
        raise ValueError("auth record attempts must be positive")


@dataclass(slots=True)
class BootstrapRecord:
    handle: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    digest: SecretDigest
    not_before_utc: datetime
    expires_at_utc: datetime
    attempts_remaining: int
    root_capability_id: OpaqueId | None = None
    root_purpose: RootPurpose | None = None
    consumed: bool = False
    retired_at_utc: datetime | None = None

    def __post_init__(self) -> None:
        _validate_record(
            handle=self.handle,
            actor_id=self.actor_id,
            represented_profile_id=self.represented_profile_id,
            digest=self.digest,
            not_before_utc=self.not_before_utc,
            expires_at_utc=self.expires_at_utc,
        )
        _validate_attempts(self.attempts_remaining)
        if (self.root_capability_id is None) != (self.root_purpose is None):
            raise ValueError("bootstrap root ID and purpose must appear together")
        if self.root_capability_id is not None and type(self.root_capability_id) is not OpaqueId:
            raise TypeError("bootstrap root capability ID must be opaque")
        if self.root_purpose is not None and type(self.root_purpose) is not RootPurpose:
            raise TypeError("bootstrap root purpose must be a RootPurpose")
        _validate_mutable_state(self.consumed, self.retired_at_utc, "bootstrap")


@dataclass(slots=True)
class SessionRecord:
    handle: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    digest: SecretDigest
    epoch: int
    not_before_utc: datetime
    expires_at_utc: datetime
    revoked: bool = False
    retired_at_utc: datetime | None = None

    def __post_init__(self) -> None:
        _validate_record(
            handle=self.handle,
            actor_id=self.actor_id,
            represented_profile_id=self.represented_profile_id,
            digest=self.digest,
            not_before_utc=self.not_before_utc,
            expires_at_utc=self.expires_at_utc,
        )
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("session epoch must be positive")
        _validate_mutable_state(self.revoked, self.retired_at_utc, "session")


@dataclass(frozen=True, slots=True)
class SessionIssue:
    """Unbound session material; the store supplies canonical authority bindings."""

    handle: OpaqueId
    digest: SecretDigest
    not_before_utc: datetime
    expires_at_utc: datetime

    def __post_init__(self) -> None:
        if type(self.handle) is not OpaqueId or type(self.digest) is not SecretDigest:
            raise TypeError("session issue requires an opaque handle and digest")
        require_utc(self.not_before_utc, "session issue not_before_utc")
        require_utc(self.expires_at_utc, "session issue expires_at_utc")
        if self.expires_at_utc <= self.not_before_utc:
            raise ValueError("session issue expiry must follow not-before")


@dataclass(slots=True)
class RecoveryRecord:
    handle: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    digest: SecretDigest
    epoch: int
    not_before_utc: datetime
    expires_at_utc: datetime
    attempts_remaining: int
    consumed: bool = False
    retired_at_utc: datetime | None = None

    def __post_init__(self) -> None:
        _validate_record(
            handle=self.handle,
            actor_id=self.actor_id,
            represented_profile_id=self.represented_profile_id,
            digest=self.digest,
            not_before_utc=self.not_before_utc,
            expires_at_utc=self.expires_at_utc,
        )
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("recovery epoch must be positive")
        _validate_attempts(self.attempts_remaining)
        _validate_mutable_state(self.consumed, self.retired_at_utc, "recovery")


@dataclass(frozen=True, slots=True)
class RecoveryIssue:
    """Unbound recovery material; the store supplies canonical actor/profile/epoch."""

    handle: OpaqueId
    digest: SecretDigest
    not_before_utc: datetime
    expires_at_utc: datetime
    attempts: int

    def __post_init__(self) -> None:
        if type(self.handle) is not OpaqueId or type(self.digest) is not SecretDigest:
            raise TypeError("recovery issue requires an opaque handle and digest")
        require_utc(self.not_before_utc, "recovery issue not_before_utc")
        require_utc(self.expires_at_utc, "recovery issue expires_at_utc")
        if self.expires_at_utc <= self.not_before_utc:
            raise ValueError("recovery issue expiry must follow not-before")
        _validate_attempts(self.attempts)


@dataclass(slots=True)
class StepUpRecord:
    handle: OpaqueId
    actor_id: OpaqueId
    represented_profile_id: OpaqueId
    session_id: OpaqueId
    digest: SecretDigest
    epoch: int
    purpose: AuthPurpose
    scopes: frozenset[AuthScope]
    not_before_utc: datetime
    expires_at_utc: datetime
    attempts_remaining: int
    consumed: bool = False
    retired_at_utc: datetime | None = None

    def __post_init__(self) -> None:
        _validate_record(
            handle=self.handle,
            actor_id=self.actor_id,
            represented_profile_id=self.represented_profile_id,
            digest=self.digest,
            not_before_utc=self.not_before_utc,
            expires_at_utc=self.expires_at_utc,
        )
        if type(self.session_id) is not OpaqueId:
            raise TypeError("step-up session ID must be opaque")
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("step-up epoch must be positive")
        if type(self.purpose) is not AuthPurpose:
            raise TypeError("step-up purpose must be an AuthPurpose")
        if type(self.scopes) is not frozenset:
            raise TypeError("step-up scopes must be a frozenset")
        if self.scopes != frozenset({PURPOSE_SCOPE[self.purpose]}):
            raise ValueError("step-up scope must exactly match purpose")
        _validate_attempts(self.attempts_remaining)
        _validate_mutable_state(self.consumed, self.retired_at_utc, "step-up")
