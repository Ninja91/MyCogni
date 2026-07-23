"""Adversarial evidence for the volatile SPIKE-AUTH decision model."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import io
import secrets
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import fields, is_dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mycogni.adapters.auth import (
    CrashPoint,
    OsTokenSource,
    SyntheticCrash,
    VolatileAuthDecisionStore,
)
from mycogni.application.auth import (
    AuthService,
    ReprovisionCeremonyAuthorization,
    ReprovisionOperatorAuthority,
)
from mycogni.application.diagnostics import (
    DiagnosticComponent,
    DiagnosticEvent,
    DiagnosticLevel,
    EventId,
    FieldName,
)
from mycogni.application.operator_terminal import (
    OperatorTerminalError,
    OperatorTerminalFailure,
    SecretDeliveryState,
    SecretField,
)
from mycogni.bootstrap.auth_setup import TrustedLocalAuthSetup
from mycogni.domain import OpaqueId, Sensitive
from mycogni.domain.auth import (
    PURPOSE_SCOPE,
    AuthDenial,
    AuthorityGrant,
    AuthOutcome,
    AuthPolicy,
    AuthPurpose,
    AuthScope,
    BootstrapExchange,
    BootstrapRecord,
    OpaqueCredential,
    RecoveryIssue,
    RecoveryRecord,
    RootAuthorityBundle,
    RootCapabilityIssue,
    RootCapabilityRecord,
    RootPurpose,
    SecretDigest,
    SessionIssue,
    SessionRecord,
)
from mycogni.entrypoints.auth_spike import (
    begin_bootstrap_on_tty,
    begin_reprovision_on_tty,
    exchange_bootstrap_code,
    exchange_bootstrap_on_tty,
    exchange_reprovision_on_tty,
    recover_headless_on_tty,
    redact_operator_transcript,
    redisplay_interrupted_bootstrap,
    redisplay_interrupted_recovery,
)

NOW = datetime(2030, 1, 1, tzinfo=UTC)
REPO_ROOT = Path(__file__).parents[2]


class MutableClock:
    def __init__(self) -> None:
        self.current = NOW

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


class DeterministicTokenSource:
    """Fresh synthetic material without retaining an issued secret fixture."""

    def __init__(self) -> None:
        self.counter = 0

    def generate(self, length: int) -> bytes:
        self.counter += 1
        material = hashlib.sha256(self.counter.to_bytes(16, "big")).digest()
        assert length == len(material)
        return material


class PseudoTty:
    """Reviewed test double for the narrow no-echo/all-or-nothing TTY port."""

    def __init__(
        self,
        input_value: str = "",
        *,
        interactive: bool = True,
        confirmed: bool = True,
        fail_secret_once: bool = False,
    ) -> None:
        self.input_value = input_value
        self.interactive = interactive
        self.confirmed = confirmed
        self.fail_secret_once = fail_secret_once
        self.transcript = io.StringIO()
        self.secret_values: list[tuple[tuple[str, str], ...]] = []

    def isatty(self) -> bool:
        return self.interactive

    def write_public(self, value: str) -> None:
        self.transcript.write(value)

    def confirm(self, warning: str) -> bool:
        assert warning.startswith(("WARNING: SECRET DISPLAY", "DESTRUCTIVE REPROVISION"))
        self.transcript.write(
            f"secret-display-confirmation: {'accepted' if self.confirmed else 'declined'}\n"
        )
        return self.confirmed

    def read_secret(self, prompt: str, max_bytes: int) -> str:
        assert prompt.endswith("(input hidden): ")
        assert max_bytes == 128
        self.transcript.write(prompt + "[NO-ECHO INPUT]\n")
        return self.input_value

    def disclose(self, fields: tuple[SecretField, ...]) -> None:
        if self.fail_secret_once:
            self.fail_secret_once = False
            raise OSError("synthetic all-or-nothing display failure")
        values = tuple((field.label, field.value) for field in fields)
        self.secret_values.append(values)
        for label, value in values:
            self.transcript.write(f"{label}: {value}\n")

    def getvalue(self) -> str:
        return self.transcript.getvalue()


class FailPublicAfterDisclosureTty(PseudoTty):
    """Fail only status text after a complete atomic secret disclosure."""

    def __init__(self, input_value: str = "") -> None:
        super().__init__(input_value)
        self._disclosed = False

    def disclose(self, fields: tuple[SecretField, ...]) -> None:
        super().disclose(fields)
        self._disclosed = True

    def write_public(self, value: str) -> None:
        if self._disclosed:
            raise OperatorTerminalError(OperatorTerminalFailure.IO_FAILED)
        super().write_public(value)


def _service(
    *, policy: AuthPolicy | None = None
) -> tuple[
    AuthService,
    MutableClock,
    DeterministicTokenSource,
    VolatileAuthDecisionStore,
    TrustedLocalAuthSetup,
]:
    clock = MutableClock()
    source = DeterministicTokenSource()
    store = VolatileAuthDecisionStore()
    setup = TrustedLocalAuthSetup(clock=clock, token_source=source, store=store)
    service = AuthService(
        clock=clock,
        token_source=source,
        store=store,
        reprovision_operator_authority=setup.reprovision_operator_authority,
        policy=policy,
    )
    setup.bind_auth_service(service)
    return (
        service,
        clock,
        source,
        store,
        setup,
    )


def _allowed[T](outcome: AuthOutcome[T]) -> T:
    assert outcome.denial is None
    assert outcome.value is not None
    return outcome.value


def _provision(
    setup: TrustedLocalAuthSetup,
    *,
    actor: OpaqueId | None = None,
    profile: OpaqueId | None = None,
) -> tuple[OpaqueId, OpaqueId, RootAuthorityBundle]:
    actor_id = actor or OpaqueId.new()
    profile_id = profile or OpaqueId.new()
    roots = setup.provision(
        installation_id=OpaqueId.new(),
        actor_id=actor_id,
        represented_profile_id=profile_id,
    )
    return actor_id, profile_id, roots


def _exchange(
    service: AuthService,
    setup: TrustedLocalAuthSetup,
) -> tuple[OpaqueId, OpaqueId, RootAuthorityBundle, BootstrapExchange]:
    actor, profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    return actor, profile, roots, _allowed(service.exchange_bootstrap(bootstrap))


def _wrong(credential: OpaqueCredential, source: DeterministicTokenSource) -> OpaqueCredential:
    return OpaqueCredential.from_secret(credential.handle, source.generate(32))


def _grant(
    service: AuthService,
    actor: OpaqueId,
    profile: OpaqueId,
    session: OpaqueCredential,
    purpose: AuthPurpose,
) -> AuthorityGrant:
    scopes = frozenset({PURPOSE_SCOPE[purpose]})
    challenge = _allowed(
        service.issue_step_up(
            session=session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
    )
    return _allowed(
        service.consume_step_up(
            challenge=challenge,
            session=session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
    )


def _secret_code(tty: PseudoTty, label: str) -> str:
    matches = [
        value for block in tty.secret_values for item_label, value in block if item_label == label
    ]
    assert len(matches) == 1
    return matches[0]


def test_root_bootstrap_is_bound_one_use_and_unauthenticated_rebootstrap_is_forbidden() -> None:
    service, _clock, source, _store, setup = _service()
    actor, profile, roots = _provision(setup)
    root = roots.initial_bootstrap
    wrong_installation = replace(root, installation_id=OpaqueId.new())
    assert service.begin_bootstrap(wrong_installation).denial is AuthDenial.WRONG_INSTALLATION
    assert (
        service.begin_bootstrap(replace(root, actor_id=OpaqueId.new())).denial
        is AuthDenial.WRONG_ACTOR
    )
    assert (
        service.begin_bootstrap(replace(root, represented_profile_id=OpaqueId.new())).denial
        is AuthDenial.WRONG_PROFILE
    )
    assert service.begin_bootstrap(roots.emergency_revoke).denial is AuthDenial.WRONG_PURPOSE
    forged = replace(root, credential=_wrong(root.credential, source))
    assert service.begin_bootstrap(forged).denial is AuthDenial.INVALID_PROOF

    bootstrap = _allowed(service.begin_bootstrap(root))
    exchange = _allowed(service.exchange_bootstrap(bootstrap))
    assert (exchange.actor_id, exchange.represented_profile_id) == (actor, profile)
    assert service.begin_bootstrap(root).denial is AuthDenial.STALE_EPOCH


def test_installation_requires_exactly_three_unique_roots_before_any_store_mutation() -> None:
    installation = OpaqueId.new()
    actor = OpaqueId.new()
    profile = OpaqueId.new()

    def record(purpose: RootPurpose, *, handle: OpaqueId | None = None) -> RootCapabilityRecord:
        return RootCapabilityRecord(
            handle=handle or OpaqueId.new(),
            installation_id=installation,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            digest=SecretDigest(hashlib.sha256(purpose.value.encode()).digest()),
        )

    valid = tuple(record(purpose) for purpose in RootPurpose)
    operator_authority = RootCapabilityIssue(
        OpaqueId.new(), SecretDigest(hashlib.sha256(b"operator").digest())
    )
    service_identity = RootCapabilityIssue(
        OpaqueId.new(), SecretDigest(hashlib.sha256(b"service").digest())
    )
    duplicate_handle = replace(valid[1], handle=valid[0].handle)
    duplicate_purpose = replace(valid[1], purpose=RootPurpose.INITIAL_BOOTSTRAP)
    invalid_sets = (
        valid[:2],
        (valid[0], valid[0], valid[2]),
        (valid[0], duplicate_handle, valid[2]),
        (valid[0], duplicate_purpose, valid[2]),
    )
    for invalid in invalid_sets:
        store = VolatileAuthDecisionStore()
        with pytest.raises(ValueError):
            store.initialize_installation(
                installation_id=installation,
                actor_id=actor,
                represented_profile_id=profile,
                records=invalid,
                operator_authority=operator_authority,
                service_identity=service_identity,
                now=NOW,
            )
        assert store.record_counts()["roots"] == 0
        store.initialize_installation(
            installation_id=installation,
            actor_id=actor,
            represented_profile_id=profile,
            records=valid,
            operator_authority=operator_authority,
            service_identity=service_identity,
            now=NOW,
        )
        assert store.record_counts()["roots"] == 3


def test_installation_authority_namespaces_are_globally_disjoint_and_atomic() -> None:
    first_installation = OpaqueId.new()
    first_actor = OpaqueId.new()
    first_profile = OpaqueId.new()
    second_installation = OpaqueId.new()
    second_actor = OpaqueId.new()
    second_profile = OpaqueId.new()

    def records(
        installation: OpaqueId,
        actor: OpaqueId,
        profile: OpaqueId,
        handles: tuple[OpaqueId, OpaqueId, OpaqueId] | None = None,
    ) -> tuple[RootCapabilityRecord, ...]:
        selected = handles or (OpaqueId.new(), OpaqueId.new(), OpaqueId.new())
        return tuple(
            RootCapabilityRecord(
                handle=handle,
                installation_id=installation,
                actor_id=actor,
                represented_profile_id=profile,
                purpose=purpose,
                digest=SecretDigest(hashlib.sha256(f"{installation}:{purpose}".encode()).digest()),
            )
            for handle, purpose in zip(selected, RootPurpose, strict=True)
        )

    first_roots = records(first_installation, first_actor, first_profile)
    first_operator = RootCapabilityIssue(
        OpaqueId.new(), SecretDigest(hashlib.sha256(b"first-operator").digest())
    )
    first_service = RootCapabilityIssue(
        OpaqueId.new(), SecretDigest(hashlib.sha256(b"first-service").digest())
    )
    fresh_roots = records(second_installation, second_actor, second_profile)

    def issue(handle: OpaqueId, label: bytes) -> RootCapabilityIssue:
        return RootCapabilityIssue(handle, SecretDigest(hashlib.sha256(label).digest()))

    shared_incoming_handle = OpaqueId.new()
    collision_cases = (
        (
            records(
                second_installation,
                second_actor,
                second_profile,
                (first_roots[0].handle, fresh_roots[1].handle, fresh_roots[2].handle),
            ),
            issue(OpaqueId.new(), b"operator"),
            issue(OpaqueId.new(), b"service"),
        ),
        (fresh_roots, issue(first_service.handle, b"operator-swap"), issue(OpaqueId.new(), b"s")),
        (fresh_roots, issue(OpaqueId.new(), b"o"), issue(first_operator.handle, b"service-swap")),
        (
            records(
                second_installation,
                second_actor,
                second_profile,
                (first_operator.handle, fresh_roots[1].handle, fresh_roots[2].handle),
            ),
            issue(OpaqueId.new(), b"operator"),
            issue(OpaqueId.new(), b"service"),
        ),
        (fresh_roots, issue(first_roots[1].handle, b"operator-root"), issue(OpaqueId.new(), b"s")),
        (fresh_roots, issue(OpaqueId.new(), b"o"), issue(first_roots[2].handle, b"service-root")),
        (
            fresh_roots,
            issue(first_service.handle, b"operator-combined"),
            issue(first_operator.handle, b"service-combined"),
        ),
        (
            fresh_roots,
            issue(first_operator.handle, b"operator-repeat"),
            issue(OpaqueId.new(), b"service-fresh"),
        ),
        (
            fresh_roots,
            issue(OpaqueId.new(), b"operator-fresh"),
            issue(first_service.handle, b"service-repeat"),
        ),
        (
            fresh_roots,
            issue(shared_incoming_handle, b"same-incoming-operator"),
            issue(shared_incoming_handle, b"same-incoming-service"),
        ),
    )

    for second_roots, second_operator, second_service in collision_cases:
        store = VolatileAuthDecisionStore()
        store.initialize_installation(
            installation_id=first_installation,
            actor_id=first_actor,
            represented_profile_id=first_profile,
            records=first_roots,
            operator_authority=first_operator,
            service_identity=first_service,
            now=NOW,
        )
        before = store.record_counts()
        with pytest.raises(ValueError, match="authority"):
            store.initialize_installation(
                installation_id=second_installation,
                actor_id=second_actor,
                represented_profile_id=second_profile,
                records=second_roots,
                operator_authority=second_operator,
                service_identity=second_service,
                now=NOW,
            )
        assert store.record_counts() == before


def test_bootstrap_is_short_lived_attempt_bounded_and_concurrently_one_use() -> None:
    service, clock, source, _store, setup = _service(
        policy=AuthPolicy(bootstrap_ttl_seconds=10, activation_delay_seconds=2, max_attempts=2)
    )
    _actor, _profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    assert service.exchange_bootstrap(bootstrap).denial is AuthDenial.NOT_YET_VALID
    clock.advance(2)
    assert service.exchange_bootstrap(_wrong(bootstrap, source)).denial is AuthDenial.INVALID_PROOF

    barrier = threading.Barrier(3)
    outcomes: list[AuthOutcome[BootstrapExchange]] = []

    def consume() -> None:
        barrier.wait()
        outcomes.append(service.exchange_bootstrap(bootstrap))

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert sum(item.value is not None for item in outcomes) == 1
    assert [item.denial for item in outcomes if item.denial] == [AuthDenial.REPLAYED]


def test_reprovision_requires_bound_one_use_operator_ceremony_authority() -> None:
    service, _clock, source, _store, setup = _service()
    _actor, _profile, roots, initial = _exchange(service, setup)
    bootstrap = _allowed(service.begin_reprovision(roots.reprovision.credential))

    # No generic or caller-asserted path may reach the destructive decision.
    assert service.exchange_bootstrap(bootstrap).denial is AuthDenial.WRONG_PURPOSE
    assert (
        service.exchange_confirmed_reprovision(bootstrap, None).denial is AuthDenial.INVALID_PROOF
    )
    assert not hasattr(service, "exchange_operator_bootstrap")
    forged = ReprovisionCeremonyAuthorization(
        credential=OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32)),
        bootstrap_handle=bootstrap.handle,
    )
    assert (
        service.exchange_confirmed_reprovision(bootstrap, forged).denial is AuthDenial.INVALID_PROOF
    )
    assert (
        service.authorize_reprovision_ceremony(bootstrap, None).denial is AuthDenial.INVALID_PROOF
    )
    forged_operator = ReprovisionOperatorAuthority(
        OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32))
    )
    assert (
        service.authorize_reprovision_ceremony(bootstrap, forged_operator).denial
        is AuthDenial.INVALID_PROOF
    )
    assert service.authenticate_session(initial.session).value == initial.session.handle
    assert service.reprovision_ceremony_counts()["total"] == 0

    # Declining the owned operator ceremony issues no capability and preserves
    # both the bootstrap and all current authority.
    declined_tty = PseudoTty(confirmed=False)
    assert (
        exchange_reprovision_on_tty(
            service,
            submitted_code=bootstrap.operator_code(),
            operator_tty=declined_tty,
            operator_authority=setup.reprovision_operator_authority,
        ).denial
        is AuthDenial.OPERATOR_DECLINED
    )
    assert service.authenticate_session(initial.session).value == initial.session.handle
    assert service.reprovision_ceremony_counts()["total"] == 0

    authorization = _allowed(
        service.authorize_reprovision_ceremony(bootstrap, setup.reprovision_operator_authority)
    )
    barrier = threading.Barrier(3)
    outcomes: list[AuthOutcome[BootstrapExchange]] = []

    def consume() -> None:
        barrier.wait()
        outcomes.append(service.exchange_confirmed_reprovision(bootstrap, authorization))

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert sum(item.value is not None for item in outcomes) == 1
    assert [item.denial for item in outcomes if item.denial] == [AuthDenial.REPLAYED]
    assert (
        service.exchange_confirmed_reprovision(bootstrap, authorization).denial
        is AuthDenial.REPLAYED
    )
    assert service.authenticate_session(initial.session).denial is AuthDenial.STALE_EPOCH


def test_store_generic_exchange_has_no_reprovision_purpose_override() -> None:
    service, clock, source, store, setup = _service()
    actor, profile, roots, _initial = _exchange(service, setup)
    bootstrap = _allowed(service.begin_reprovision(roots.reprovision.credential))
    parameters = inspect.signature(store.exchange_bootstrap).parameters
    assert "allowed_root_purposes" not in parameters

    session = OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32))
    recovery = OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32))
    replacement = OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32))
    assert (
        store.exchange_bootstrap(
            bootstrap.handle,
            SecretDigest(hashlib.sha256(bootstrap.secret.reveal()).digest()),
            clock.now(),
            SessionRecord(
                handle=session.handle,
                actor_id=actor,
                represented_profile_id=profile,
                digest=SecretDigest(hashlib.sha256(session.secret.reveal()).digest()),
                epoch=1,
                not_before_utc=clock.now(),
                expires_at_utc=clock.now() + timedelta(minutes=5),
            ),
            RecoveryRecord(
                handle=recovery.handle,
                actor_id=actor,
                represented_profile_id=profile,
                digest=SecretDigest(hashlib.sha256(recovery.secret.reveal()).digest()),
                epoch=1,
                not_before_utc=clock.now(),
                expires_at_utc=clock.now() + timedelta(days=30),
                attempts_remaining=5,
            ),
            RootCapabilityIssue(
                replacement.handle,
                SecretDigest(hashlib.sha256(replacement.secret.reveal()).digest()),
            ),
        ).denial
        is AuthDenial.WRONG_PURPOSE
    )


def test_foreign_service_operator_and_store_cannot_rebind_reprovision() -> None:
    service, clock, source, store, setup = _service()
    _actor, _profile, roots, _initial = _exchange(service, setup)
    bootstrap = _allowed(service.begin_reprovision(roots.reprovision.credential))

    foreign_setup = TrustedLocalAuthSetup(clock=clock, token_source=source, store=store)
    foreign = AuthService(
        clock=clock,
        token_source=source,
        store=store,
        reprovision_operator_authority=foreign_setup.reprovision_operator_authority,
    )
    foreign_setup.bind_auth_service(foreign)
    assert (
        foreign.authorize_reprovision_ceremony(
            bootstrap, foreign_setup.reprovision_operator_authority
        ).denial
        is AuthDenial.INVALID_PROOF
    )

    rebound = AuthService(
        clock=clock,
        token_source=source,
        store=store,
        reprovision_operator_authority=setup.reprovision_operator_authority,
    )
    assert (
        rebound.authorize_reprovision_ceremony(
            bootstrap, setup.reprovision_operator_authority
        ).denial
        is AuthDenial.INVALID_PROOF
    )

    other_service, _other_clock, _other_source, _other_store, other_setup = _service()
    assert (
        other_service.authorize_reprovision_ceremony(
            bootstrap, other_setup.reprovision_operator_authority
        ).denial
        is AuthDenial.INVALID_PROOF
    )

    _foreign_actor, _foreign_profile, foreign_roots, _foreign_initial = _exchange(
        foreign, foreign_setup
    )
    foreign_bootstrap = _allowed(foreign.begin_reprovision(foreign_roots.reprovision.credential))
    local_authorization = _allowed(
        service.authorize_reprovision_ceremony(bootstrap, setup.reprovision_operator_authority)
    )
    cross_installation = ReprovisionCeremonyAuthorization(
        credential=local_authorization.credential,
        bootstrap_handle=foreign_bootstrap.handle,
    )
    assert (
        foreign.exchange_confirmed_reprovision(foreign_bootstrap, cross_installation).denial
        is AuthDenial.INVALID_PROOF
    )


def test_crash_after_store_proof_consumption_is_fail_closed() -> None:
    service, _clock, _source, store, setup = _service()
    _actor, _profile, roots, initial = _exchange(service, setup)
    bootstrap = _allowed(service.begin_reprovision(roots.reprovision.credential))
    authorization = _allowed(
        service.authorize_reprovision_ceremony(bootstrap, setup.reprovision_operator_authority)
    )
    store.arm_crash_once(CrashPoint.REPROVISION_PROOF)
    with pytest.raises(SyntheticCrash):
        service.exchange_confirmed_reprovision(bootstrap, authorization)
    assert (
        service.exchange_confirmed_reprovision(bootstrap, authorization).denial
        is AuthDenial.REPLAYED
    )
    assert service.authenticate_session(initial.session).value == initial.session.handle

    retry_authorization = _allowed(
        service.authorize_reprovision_ceremony(bootstrap, setup.reprovision_operator_authority)
    )
    _allowed(service.exchange_confirmed_reprovision(bootstrap, retry_authorization))


def test_reprovision_ceremony_capacity_expiry_counts_and_bounded_tombstones() -> None:
    policy = AuthPolicy(
        reprovision_ceremony_ttl_seconds=1,
        reprovision_ceremony_capacity=2,
        reprovision_ceremony_tombstone_capacity=2,
        reprovision_ceremony_replay_seconds=10,
    )
    service, clock, _source, _store, setup = _service(policy=policy)
    _actor, _profile, roots, _initial = _exchange(service, setup)
    bootstrap = _allowed(service.begin_reprovision(roots.reprovision.credential))
    operator = setup.reprovision_operator_authority

    first = _allowed(service.authorize_reprovision_ceremony(bootstrap, operator))
    _allowed(service.authorize_reprovision_ceremony(bootstrap, operator))
    assert (
        service.authorize_reprovision_ceremony(bootstrap, operator).denial
        is AuthDenial.CAPACITY_EXHAUSTED
    )
    assert service.reprovision_ceremony_counts() == {
        "active": 2,
        "tombstones": 0,
        "total": 2,
    }

    clock.advance(1)
    service.garbage_collect(0)
    assert service.reprovision_ceremony_counts() == {
        "active": 0,
        "tombstones": 2,
        "total": 2,
    }
    assert service.exchange_confirmed_reprovision(bootstrap, first).denial is AuthDenial.EXPIRED

    replacement = _allowed(service.authorize_reprovision_ceremony(bootstrap, operator))
    _allowed(service.exchange_confirmed_reprovision(bootstrap, replacement))
    counts = service.reprovision_ceremony_counts()
    assert counts == {"active": 0, "tombstones": 2, "total": 2}
    assert counts["total"] <= (
        policy.reprovision_ceremony_capacity + policy.reprovision_ceremony_tombstone_capacity
    )


def test_operator_wrong_purpose_and_capacity_guidance_is_exact_and_non_destructive() -> None:
    service, _clock, _source, _store, setup = _service()
    _actor, _profile, roots, initial = _exchange(service, setup)
    bootstrap = _allowed(service.begin_reprovision(roots.reprovision.credential))

    wrong_purpose_tty = PseudoTty()
    assert (
        exchange_bootstrap_on_tty(
            service,
            submitted_code=bootstrap.operator_code(),
            operator_tty=wrong_purpose_tty,
        ).denial
        is AuthDenial.WRONG_PURPOSE
    )
    assert (
        "use the dedicated reprovision ceremony; no authority was consumed"
        in wrong_purpose_tty.getvalue()
    )

    operator = setup.reprovision_operator_authority
    for _ in range(service.policy.reprovision_ceremony_capacity):
        _allowed(service.authorize_reprovision_ceremony(bootstrap, operator))
    capacity_tty = PseudoTty()
    assert (
        exchange_reprovision_on_tty(
            service,
            submitted_code=bootstrap.operator_code(),
            operator_tty=capacity_tty,
            operator_authority=operator,
        ).denial
        is AuthDenial.CAPACITY_EXHAUSTED
    )
    transcript = capacity_tty.getvalue()
    assert "no authority was consumed" in transcript
    assert "wait for the 60-second ceremony TTL" in transcript
    assert "allow trusted composition garbage collection" in transcript
    assert "retry the dedicated reprovision ceremony" in transcript
    assert bootstrap.operator_code() not in (wrong_purpose_tty.getvalue() + transcript)
    assert service.authenticate_session(initial.session).value == initial.session.handle


def test_dedicated_reprovision_wrong_purpose_consumes_no_authority_or_proof() -> None:
    service, _clock, _source, _store, setup = _service()
    actor, profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    tty = PseudoTty()
    assert (
        exchange_reprovision_on_tty(
            service,
            submitted_code=bootstrap.operator_code(),
            operator_tty=tty,
            operator_authority=setup.reprovision_operator_authority,
        ).denial
        is AuthDenial.WRONG_PURPOSE
    )
    transcript = tty.getvalue()
    assert "no ceremony, root, session, or recovery authority was consumed" in transcript
    assert "begin the dedicated reprovision flow" in transcript
    assert "current offline reprovision route" in transcript
    assert bootstrap.operator_code() not in transcript
    assert service.reprovision_ceremony_counts() == {
        "active": 0,
        "tombstones": 0,
        "total": 0,
    }
    exchange = _allowed(service.exchange_bootstrap(bootstrap))
    assert (exchange.actor_id, exchange.represented_profile_id) == (actor, profile)


def test_reprovision_ceremony_replay_survives_only_its_finite_horizon() -> None:
    policy = AuthPolicy(reprovision_ceremony_replay_seconds=2)
    service, clock, _source, _store, setup = _service(policy=policy)
    _actor, _profile, roots, _initial = _exchange(service, setup)
    bootstrap = _allowed(service.begin_reprovision(roots.reprovision.credential))
    authorization = _allowed(
        service.authorize_reprovision_ceremony(bootstrap, setup.reprovision_operator_authority)
    )
    _allowed(service.exchange_confirmed_reprovision(bootstrap, authorization))
    assert (
        service.exchange_confirmed_reprovision(bootstrap, authorization).denial
        is AuthDenial.REPLAYED
    )
    clock.advance(1)
    service.garbage_collect(0)
    assert (
        service.exchange_confirmed_reprovision(bootstrap, authorization).denial
        is AuthDenial.REPLAYED
    )
    clock.advance(1)
    service.garbage_collect(0)
    assert (
        service.exchange_confirmed_reprovision(bootstrap, authorization).denial
        is AuthDenial.INVALID_PROOF
    )
    assert service.reprovision_ceremony_counts()["total"] == 0


def test_post_consume_crashes_burn_bootstrap_step_up_and_recovery() -> None:
    service, _clock, _source, store, setup = _service()
    actor, profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    store.arm_crash_once(CrashPoint.BOOTSTRAP)
    with pytest.raises(SyntheticCrash):
        service.exchange_bootstrap(bootstrap)
    assert service.exchange_bootstrap(bootstrap).denial is AuthDenial.REPLAYED

    service2, _clock2, _source2, store2, setup2 = _service()
    actor, profile, _roots, exchange = _exchange(service2, setup2)
    purpose = AuthPurpose.PROFILE_DELETION
    scopes = frozenset({PURPOSE_SCOPE[purpose]})
    challenge = _allowed(
        service2.issue_step_up(
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
    )
    arguments = {
        "challenge": challenge,
        "session": exchange.session,
        "actor_id": actor,
        "represented_profile_id": profile,
        "purpose": purpose,
        "scopes": scopes,
    }
    store2.arm_crash_once(CrashPoint.STEP_UP)
    with pytest.raises(SyntheticCrash):
        service2.consume_step_up(**arguments)
    assert service2.consume_step_up(**arguments).denial is AuthDenial.REPLAYED

    store2.arm_crash_once(CrashPoint.RECOVERY)
    with pytest.raises(SyntheticCrash):
        service2.recover(recovery=exchange.recovery)
    assert service2.recover(recovery=exchange.recovery).denial is AuthDenial.REPLAYED
    assert service2.authenticate_session(exchange.session).denial is AuthDenial.STALE_EPOCH


def test_step_up_exact_binding_typed_denials_replay_and_rotation() -> None:
    service, _clock, _source, _store, setup = _service()
    actor, profile, _roots, exchange = _exchange(service, setup)
    malformed_purpose = service.issue_step_up(
        session=exchange.session,
        actor_id=actor,
        represented_profile_id=profile,
        purpose="profile_deletion",  # type: ignore[arg-type]
        scopes=frozenset({AuthScope.DELETE_PROFILE}),
    )
    assert malformed_purpose.denial is AuthDenial.WRONG_PURPOSE
    malformed_scope = service.issue_step_up(
        session=exchange.session,
        actor_id=actor,
        represented_profile_id=profile,
        purpose=AuthPurpose.PROFILE_DELETION,
        scopes=[AuthScope.DELETE_PROFILE],  # type: ignore[arg-type]
    )
    assert malformed_scope.denial is AuthDenial.SCOPE_WIDENING

    purpose = AuthPurpose.PROFILE_DELETION
    scopes = frozenset({PURPOSE_SCOPE[purpose]})
    challenge = _allowed(
        service.issue_step_up(
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
    )
    wrong = service.consume_step_up(
        challenge=challenge,
        session=exchange.session,
        actor_id=actor,
        represented_profile_id=profile,
        purpose=AuthPurpose.DESTRUCTIVE_RESTORE,
        scopes=scopes,
    )
    assert wrong.denial is AuthDenial.WRONG_PURPOSE
    grant = _allowed(
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
    )
    assert service.validate_grant(grant, exchange.session).value == grant
    assert service.validate_grant(grant, exchange.session).denial is AuthDenial.REPLAYED
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        ).denial
        is AuthDenial.REPLAYED
    )
    rotated = _allowed(service.rotate_session(exchange.session))
    assert service.authenticate_session(exchange.session).denial is AuthDenial.REVOKED
    assert service.validate_grant(grant, rotated).denial is AuthDenial.WRONG_SESSION


def test_privileged_grants_require_exact_store_provenance_and_are_concurrently_one_use() -> None:
    service, _clock, _source, _store, setup = _service()
    actor, profile, _roots, exchange = _exchange(service, setup)
    purpose = AuthPurpose.KEY_RECOVERY_CHANGE
    scopes = frozenset({PURPOSE_SCOPE[purpose]})
    challenge = _allowed(
        service.issue_step_up(
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
    )
    fabricated = AuthorityGrant(
        actor_id=actor,
        represented_profile_id=profile,
        session_id=exchange.session.handle,
        authority_evidence_id=challenge.handle,
        purpose=purpose,
        scopes=scopes,
        not_before_utc=NOW,
        expires_at_utc=NOW + timedelta(seconds=service.policy.step_up_ttl_seconds),
        epoch=exchange.epoch,
    )
    assert (
        service.renew_recovery(session=exchange.session, grant=fabricated).denial
        is AuthDenial.INVALID_PROOF
    )
    grant = _allowed(
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
    )
    for altered in (
        replace(grant, actor_id=OpaqueId.new()),
        replace(grant, authority_evidence_id=OpaqueId.new()),
        replace(grant, session_id=OpaqueId.new()),
        replace(grant, expires_at_utc=grant.expires_at_utc + timedelta(seconds=1)),
        replace(grant, not_before_utc=grant.not_before_utc + timedelta(seconds=1)),
        replace(grant, represented_profile_id=OpaqueId.new()),
        replace(
            grant,
            purpose=AuthPurpose.DESTRUCTIVE_RESTORE,
            scopes=frozenset({AuthScope.RESTORE_DESTRUCTIVELY}),
        ),
        replace(grant, epoch=grant.epoch + 1),
    ):
        assert (
            service.renew_recovery(session=exchange.session, grant=altered).denial
            is AuthDenial.INVALID_PROOF
        )

    barrier = threading.Barrier(3)
    outcomes: list[AuthOutcome[OpaqueCredential]] = []

    def use_grant() -> None:
        barrier.wait()
        outcomes.append(service.renew_recovery(session=exchange.session, grant=grant))

    threads = [threading.Thread(target=use_grant) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert sum(outcome.value is not None for outcome in outcomes) == 1
    assert [outcome.denial for outcome in outcomes if outcome.denial] == [AuthDenial.REPLAYED]


def test_unconsumed_expired_exhausted_revoked_and_crash_consumed_steps_never_authorize() -> None:
    def synthetic_grant(
        actor: OpaqueId,
        profile: OpaqueId,
        session: OpaqueCredential,
        challenge: OpaqueCredential,
        expires_at: datetime,
    ) -> AuthorityGrant:
        return AuthorityGrant(
            actor_id=actor,
            represented_profile_id=profile,
            session_id=session.handle,
            authority_evidence_id=challenge.handle,
            purpose=AuthPurpose.KEY_RECOVERY_CHANGE,
            scopes=frozenset({AuthScope.CHANGE_KEY_RECOVERY}),
            not_before_utc=NOW,
            expires_at_utc=expires_at,
            epoch=1,
        )

    service, _clock, source, store, setup = _service(policy=AuthPolicy(max_attempts=1))
    actor, profile, _roots, exchange = _exchange(service, setup)
    challenge = _allowed(
        service.issue_step_up(
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.KEY_RECOVERY_CHANGE,
            scopes=frozenset({AuthScope.CHANGE_KEY_RECOVERY}),
        )
    )
    candidate = synthetic_grant(
        actor, profile, exchange.session, challenge, NOW + timedelta(seconds=120)
    )
    wrong_challenge = _wrong(challenge, source)
    assert (
        service.consume_step_up(
            challenge=wrong_challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.KEY_RECOVERY_CHANGE,
            scopes=frozenset({AuthScope.CHANGE_KEY_RECOVERY}),
        ).denial
        is AuthDenial.ATTEMPTS_EXHAUSTED
    )
    assert (
        service.renew_recovery(session=exchange.session, grant=candidate).denial
        is AuthDenial.INVALID_PROOF
    )

    crash_challenge = _allowed(
        service.issue_step_up(
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.KEY_RECOVERY_CHANGE,
            scopes=frozenset({AuthScope.CHANGE_KEY_RECOVERY}),
        )
    )
    crash_candidate = synthetic_grant(
        actor, profile, exchange.session, crash_challenge, NOW + timedelta(seconds=120)
    )
    store.arm_crash_once(CrashPoint.STEP_UP)
    with pytest.raises(SyntheticCrash):
        service.consume_step_up(
            challenge=crash_challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.KEY_RECOVERY_CHANGE,
            scopes=frozenset({AuthScope.CHANGE_KEY_RECOVERY}),
        )
    assert (
        service.renew_recovery(session=exchange.session, grant=crash_candidate).denial
        is AuthDenial.INVALID_PROOF
    )

    valid = _grant(service, actor, profile, exchange.session, AuthPurpose.KEY_RECOVERY_CHANGE)
    _allowed(service.revoke_session(exchange.session))
    assert (
        service.renew_recovery(session=exchange.session, grant=valid).denial is AuthDenial.REVOKED
    )

    expiring, clock, _source, _store, expiring_setup = _service(
        policy=AuthPolicy(session_ttl_seconds=20, step_up_ttl_seconds=1)
    )
    actor, profile, _roots, exchange = _exchange(expiring, expiring_setup)
    challenge = _allowed(
        expiring.issue_step_up(
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.KEY_RECOVERY_CHANGE,
            scopes=frozenset({AuthScope.CHANGE_KEY_RECOVERY}),
        )
    )
    clock.advance(1)
    assert (
        expiring.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.KEY_RECOVERY_CHANGE,
            scopes=frozenset({AuthScope.CHANGE_KEY_RECOVERY}),
        ).denial
        is AuthDenial.EXPIRED
    )
    expired_candidate = synthetic_grant(
        actor, profile, exchange.session, challenge, NOW + timedelta(seconds=1)
    )
    assert (
        expiring.renew_recovery(session=exchange.session, grant=expired_candidate).denial
        is AuthDenial.INVALID_PROOF
    )


def test_exact_two_bootstrap_sibling_recovery_is_atomically_revoked() -> None:
    service, _clock, _source, _store, setup = _service()
    actor, profile, _roots, first = _exchange(service, setup)
    grant = _grant(service, actor, profile, first.session, AuthPurpose.SETUP_AUTHORITY_CHANGE)
    second_bootstrap = _allowed(
        service.begin_authenticated_bootstrap(session=first.session, grant=grant)
    )
    second = _allowed(service.exchange_bootstrap(second_bootstrap))
    recovered = _allowed(service.recover(recovery=first.recovery))
    assert recovered.epoch == first.epoch + 1
    assert service.authenticate_session(first.session).denial is AuthDenial.STALE_EPOCH
    assert service.authenticate_session(second.session).denial is AuthDenial.STALE_EPOCH
    assert service.recover(recovery=second.recovery).denial is AuthDenial.REPLAYED
    assert service.recover(recovery=first.recovery).denial is AuthDenial.REPLAYED


def test_recovery_survives_months_can_be_renewed_and_expiry_has_no_data_recovery_claim() -> None:
    service, clock, _source, _store, setup = _service()
    actor, profile, roots, exchange = _exchange(service, setup)
    clock.advance(180 * 86_400)
    recovered = _allowed(service.recover(recovery=exchange.recovery))
    assert recovered.epoch == 2

    renewal_grant = _grant(
        service, actor, profile, recovered.session, AuthPurpose.KEY_RECOVERY_CHANGE
    )
    renewed = _allowed(service.renew_recovery(session=recovered.session, grant=renewal_grant))
    assert service.recover(recovery=recovered.recovery).denial is AuthDenial.REPLAYED
    clock.advance(service.policy.recovery_ttl_seconds)
    assert service.recover(recovery=renewed).denial is AuthDenial.EXPIRED

    reprovision_root_code = roots.reprovision.credential.operator_code()
    del roots, exchange, recovered, renewed
    reprovision_tty = PseudoTty(reprovision_root_code)
    _allowed(begin_reprovision_on_tty(service, operator_tty=reprovision_tty))
    reprovision_code = _secret_code(
        reprovision_tty, "reprovision-bootstrap-code (one-use, short-lived)"
    )
    declined = PseudoTty(confirmed=False)
    assert (
        exchange_reprovision_on_tty(
            service,
            submitted_code=reprovision_code,
            operator_tty=declined,
            operator_authority=setup.reprovision_operator_authority,
        ).denial
        is AuthDenial.OPERATOR_DECLINED
    )
    assert "old session" in declined.getvalue()
    assert "current offline reprovision route" in declined.getvalue()
    assert "replacement route" in declined.getvalue()
    assert "process loss" in declined.getvalue()
    assert exchange_bootstrap_code(service, reprovision_code).denial is AuthDenial.WRONG_PURPOSE
    interrupted_handoff = PseudoTty(fail_secret_once=True)
    first_reprovision = _allowed(
        exchange_reprovision_on_tty(
            service,
            submitted_code=reprovision_code,
            operator_tty=interrupted_handoff,
            operator_authority=setup.reprovision_operator_authority,
        )
    )
    assert first_reprovision.displayed is False
    assert first_reprovision.delivery is SecretDeliveryState.MAY_HAVE_DISCLOSED
    assert "do not resubmit the consumed code" in interrupted_handoff.getvalue()
    assert first_reprovision.exchange.session.operator_code() not in interrupted_handoff.getvalue()
    assert first_reprovision.exchange.recovery.operator_code() not in interrupted_handoff.getvalue()
    assert first_reprovision.exchange.replacement_reprovision is not None
    assert (
        first_reprovision.exchange.replacement_reprovision.credential.operator_code()
        not in interrupted_handoff.getvalue()
    )
    handoff = PseudoTty()
    first_reprovision = redisplay_interrupted_bootstrap(first_reprovision, handoff)
    assert first_reprovision.displayed is True
    assert first_reprovision.exchange.epoch == 3
    assert first_reprovision.exchange.actor_id == actor
    assert first_reprovision.exchange.replacement_reprovision is not None
    replacement_root_code = _secret_code(handoff, "replacement-reprovision-code")
    replacement_recovery_code = _secret_code(handoff, "new-recovery-code")
    assert first_reprovision.exchange.replacement_reprovision is not None
    assert replacement_root_code == (
        first_reprovision.exchange.replacement_reprovision.credential.operator_code()
    )
    del first_reprovision, handoff, reprovision_tty, interrupted_handoff

    clock.advance(service.policy.recovery_ttl_seconds)
    assert (
        service.recover(
            recovery=OpaqueCredential.parse_operator_code(replacement_recovery_code)
        ).denial
        is AuthDenial.EXPIRED
    )
    next_tty = PseudoTty(replacement_root_code)
    _allowed(begin_reprovision_on_tty(service, operator_tty=next_tty))
    next_handoff = PseudoTty()
    second_reprovision = _allowed(
        exchange_reprovision_on_tty(
            service,
            submitted_code=_secret_code(
                next_tty, "reprovision-bootstrap-code (one-use, short-lived)"
            ),
            operator_tty=next_handoff,
            operator_authority=setup.reprovision_operator_authority,
        )
    ).exchange
    assert second_reprovision.epoch == 4
    assert second_reprovision.replacement_reprovision is not None
    assert _secret_code(next_handoff, "replacement-reprovision-code") == (
        second_reprovision.replacement_reprovision.credential.operator_code()
    )
    assert (
        second_reprovision.replacement_reprovision.credential.handle
        != OpaqueCredential.parse_operator_code(replacement_root_code).handle
    )


@pytest.mark.parametrize("invalid_grant", [None, object(), "not-a-grant"])
def test_validate_grant_rejects_untyped_inputs_without_dereference(invalid_grant: object) -> None:
    service, clock, _source, store, setup = _service()
    _actor, _profile, _roots, exchange = _exchange(service, setup)
    assert (
        service.validate_grant(invalid_grant, exchange.session).denial is AuthDenial.INVALID_PROOF
    )
    digest = SecretDigest(hashlib.sha256(exchange.session.secret.reveal()).digest())
    assert (
        store.validate_grant(invalid_grant, exchange.session, digest, clock.now()).denial
        is AuthDenial.INVALID_PROOF
    )


def test_authenticated_and_emergency_revoke_have_exact_separate_authority() -> None:
    service, _clock, _source, _store, setup = _service()
    actor, profile, roots, exchange = _exchange(service, setup)
    wrong_grant = _grant(service, actor, profile, exchange.session, AuthPurpose.PROFILE_DELETION)
    assert (
        service.revoke_all_authenticated(session=exchange.session, grant=wrong_grant).denial
        is AuthDenial.WRONG_PURPOSE
    )
    grant = _grant(service, actor, profile, exchange.session, AuthPurpose.ALL_SESSION_REVOKE)
    recovery = _allowed(service.revoke_all_authenticated(session=exchange.session, grant=grant))
    assert service.authenticate_session(exchange.session).denial is AuthDenial.STALE_EPOCH
    replacement = _allowed(service.recover(recovery=recovery))
    assert replacement.epoch == 3

    assert service.emergency_revoke(roots.reprovision).denial is AuthDenial.WRONG_PURPOSE
    assert _allowed(service.emergency_revoke(roots.emergency_revoke)) == 4
    assert service.authenticate_session(replacement.session).denial is AuthDenial.STALE_EPOCH
    assert service.recover(recovery=replacement.recovery).denial is AuthDenial.REPLAYED
    assert service.emergency_revoke(roots.emergency_revoke).denial is AuthDenial.STALE_EPOCH


def test_recovery_port_canonically_binds_issued_records_from_consumed_record() -> None:
    service, clock, source, store, setup = _service()
    actor, profile, _roots, exchange = _exchange(service, setup)
    now = clock.now()
    session_secret = source.generate(32)
    recovery_secret = source.generate(32)
    result = store.recover(
        exchange.recovery,
        SecretDigest(hashlib.sha256(exchange.recovery.secret.reveal()).digest()),
        now,
        SessionIssue(
            handle=OpaqueId.new(),
            digest=SecretDigest(hashlib.sha256(session_secret).digest()),
            not_before_utc=now,
            expires_at_utc=now + timedelta(minutes=30),
        ),
        RecoveryIssue(
            handle=OpaqueId.new(),
            digest=SecretDigest(hashlib.sha256(recovery_secret).digest()),
            not_before_utc=now,
            expires_at_utc=now + timedelta(days=365),
            attempts=5,
        ),
    )
    issued = _allowed(result)
    assert (issued.actor_id, issued.represented_profile_id, issued.epoch) == (actor, profile, 2)
    assert not hasattr(SessionIssue, "actor_id") and not hasattr(RecoveryIssue, "actor_id")


def test_store_copies_mutable_records_and_retains_only_structural_digests() -> None:
    service, clock, source, store, setup = _service()
    actor, profile, roots = _provision(setup)
    bootstrap = OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32))
    proposed = BootstrapRecord(
        handle=bootstrap.handle,
        actor_id=actor,
        represented_profile_id=profile,
        digest=SecretDigest(hashlib.sha256(bootstrap.secret.reveal()).digest()),
        not_before_utc=clock.now(),
        expires_at_utc=clock.now() + timedelta(minutes=5),
        attempts_remaining=5,
        root_capability_id=roots.initial_bootstrap.credential.handle,
        root_purpose=RootPurpose.INITIAL_BOOTSTRAP,
    )
    stored = store.create_root_bootstrap(
        roots.initial_bootstrap,
        SecretDigest(hashlib.sha256(roots.initial_bootstrap.credential.secret.reveal()).digest()),
        proposed,
        clock.now(),
    )
    assert stored.denial is None
    proposed.consumed = True
    exchange = _allowed(service.exchange_bootstrap(bootstrap))
    _grant(service, actor, profile, exchange.session, AuthPurpose.PROFILE_DELETION)
    reprovision = _allowed(service.begin_bootstrap(roots.reprovision))
    authorization = _allowed(
        service.authorize_reprovision_ceremony(reprovision, setup.reprovision_operator_authority)
    )
    reprovisioned = _allowed(service.exchange_confirmed_reprovision(reprovision, authorization))
    assert reprovisioned.replacement_reprovision is not None
    digest = SecretDigest(hashlib.sha256(reprovisioned.session.secret.reveal()).digest())
    returned = _allowed(store.authenticate_session(reprovisioned.session, digest, clock.now()))
    returned.revoked = True
    assert service.authenticate_session(reprovisioned.session).value == reprovisioned.session.handle

    forbidden: list[object] = []
    bytes_found: list[bytes] = []

    def walk(value: object) -> None:
        if isinstance(value, (OpaqueCredential, Sensitive)):
            forbidden.append(value)
            return
        if type(value) is bytes:
            bytes_found.append(value)
            return
        if is_dataclass(value):
            for field in fields(value):
                walk(getattr(value, field.name))
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(key)
                walk(item)
        elif isinstance(value, (tuple, list, set, frozenset)):
            for item in value:
                walk(item)

    for name, value in vars(store).items():
        if name != "_lock":
            walk(value)
    assert forbidden == []
    assert bytes_found and all(len(value) == 32 for value in bytes_found)
    credentials = (
        bootstrap,
        exchange.session,
        exchange.recovery,
        reprovision,
        reprovisioned.session,
        reprovisioned.recovery,
        reprovisioned.replacement_reprovision.credential,
    )
    for credential in credentials:
        assert credential.secret.reveal() not in bytes_found


def test_store_uses_constant_time_compare_and_os_random_adapter() -> None:
    service, _clock, source, _store, setup = _service()
    _actor, _profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    calls: list[tuple[bytes, bytes]] = []
    original = hmac.compare_digest

    def observed(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return original(left, right)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(hmac, "compare_digest", observed)
        assert (
            service.exchange_bootstrap(_wrong(bootstrap, source)).denial is AuthDenial.INVALID_PROOF
        )
    assert calls and all(len(left) == len(right) == 32 for left, right in calls)

    expected = hashlib.sha256((99).to_bytes(16, "big")).digest()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(secrets, "token_bytes", lambda length: expected)
        assert OsTokenSource().generate(32) == expected
    with pytest.raises(ValueError, match="at least 32 bytes"):
        OsTokenSource().generate(16)


def test_bounded_gc_removes_expired_and_burned_records() -> None:
    service, clock, _source, store, setup = _service(policy=AuthPolicy(bootstrap_ttl_seconds=1))
    _actor, _profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    service.cancel_bootstrap(bootstrap.handle)
    before = store.record_counts()
    with pytest.raises(ValueError, match="0 through 86400"):
        service.garbage_collect(86_401)
    clock.advance(2)
    removed = service.garbage_collect(0)
    after = store.record_counts()
    assert removed >= 1
    assert after["bootstraps"] < before["bootstraps"]
    assert after["roots"] == 3


def test_grant_provenance_and_replay_survive_until_the_live_replay_horizon() -> None:
    service, clock, _source, store, setup = _service(
        policy=AuthPolicy(session_ttl_seconds=20, step_up_ttl_seconds=5)
    )
    actor, profile, _roots, exchange = _exchange(service, setup)
    grant = _grant(service, actor, profile, exchange.session, AuthPurpose.KEY_RECOVERY_CHANGE)
    _allowed(service.renew_recovery(session=exchange.session, grant=grant))
    assert store.record_counts()["grant_provenance"] == 1
    service.garbage_collect(0)
    assert store.record_counts()["grant_provenance"] == 1
    assert (
        service.renew_recovery(session=exchange.session, grant=grant).denial is AuthDenial.REPLAYED
    )
    clock.advance(5)
    service.garbage_collect(0)
    assert store.record_counts()["grant_provenance"] == 0
    assert (
        service.renew_recovery(session=exchange.session, grant=grant).denial
        is AuthDenial.INVALID_PROOF
    )


def test_unknown_and_gc_retired_codes_share_safe_attempt_agnostic_guidance() -> None:
    service, clock, source, _store, setup = _service()
    _actor, _profile, _roots, exchange = _exchange(service, setup)
    unknown = OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32))
    unknown_tty = PseudoTty(unknown.operator_code())
    assert (
        recover_headless_on_tty(service, operator_tty=unknown_tty).denial
        is AuthDenial.INVALID_PROOF
    )

    clock.advance(service.policy.recovery_ttl_seconds)
    expired_tty = PseudoTty(exchange.recovery.operator_code())
    assert recover_headless_on_tty(service, operator_tty=expired_tty).denial is AuthDenial.EXPIRED
    service.garbage_collect(0)
    retired_tty = PseudoTty(exchange.recovery.operator_code())
    assert (
        recover_headless_on_tty(service, operator_tty=retired_tty).denial
        is AuthDenial.INVALID_PROOF
    )
    assert unknown_tty.getvalue() == retired_tty.getvalue()
    assert "code is unknown or retired" in retired_tty.getvalue()
    assert "remaining attempts are unavailable" in retired_tty.getvalue()
    assert "retry only while attempts remain" not in (
        unknown_tty.getvalue() + expired_tty.getvalue() + retired_tty.getvalue()
    )


def test_public_status_failure_after_complete_delivery_preserves_all_authority_results() -> None:
    service, _clock, _source, _store, setup = _service()
    _actor, _profile, roots = _provision(setup)

    initial_tty = FailPublicAfterDisclosureTty()
    initial_handle = _allowed(
        begin_bootstrap_on_tty(service, root=roots.initial_bootstrap, operator_tty=initial_tty)
    )
    bootstrap_code = _secret_code(initial_tty, "bootstrap-code (one-use, short-lived)")
    assert initial_handle == OpaqueCredential.parse_operator_code(bootstrap_code).handle

    exchange_tty = FailPublicAfterDisclosureTty()
    exchange = _allowed(
        exchange_bootstrap_on_tty(service, submitted_code=bootstrap_code, operator_tty=exchange_tty)
    )
    assert exchange.delivery is SecretDeliveryState.COMPLETE
    recovery_code = _secret_code(exchange_tty, "new-recovery-code")

    recovery_tty = FailPublicAfterDisclosureTty(recovery_code)
    recovery = _allowed(recover_headless_on_tty(service, operator_tty=recovery_tty))
    assert recovery.delivery is SecretDeliveryState.COMPLETE
    assert recovery.exchange.session.operator_code() == _secret_code(
        recovery_tty, "new-session-code"
    )

    reprovision_tty = FailPublicAfterDisclosureTty(roots.reprovision.credential.operator_code())
    reprovision_handle = _allowed(begin_reprovision_on_tty(service, operator_tty=reprovision_tty))
    reprovision_code = _secret_code(
        reprovision_tty, "reprovision-bootstrap-code (one-use, short-lived)"
    )
    assert reprovision_handle == OpaqueCredential.parse_operator_code(reprovision_code).handle
    reprovision_exchange_tty = FailPublicAfterDisclosureTty()
    reprovision_exchange = _allowed(
        exchange_reprovision_on_tty(
            service,
            submitted_code=reprovision_code,
            operator_tty=reprovision_exchange_tty,
            operator_authority=setup.reprovision_operator_authority,
        )
    )
    assert reprovision_exchange.delivery is SecretDeliveryState.COMPLETE
    assert _secret_code(reprovision_exchange_tty, "replacement-reprovision-code")


@pytest.mark.parametrize(
    ("failure", "expected_denial", "guidance"),
    [
        (
            OperatorTerminalFailure.CANCELLED,
            AuthDenial.OPERATOR_DECLINED,
            "secret input was cancelled",
        ),
        (
            OperatorTerminalFailure.EOF,
            AuthDenial.MALFORMED_CREDENTIAL,
            "input ended before a complete code",
        ),
        (
            OperatorTerminalFailure.INPUT_TOO_LONG,
            AuthDenial.MALFORMED_CREDENTIAL,
            "exceeded the finite credential bound",
        ),
        (
            OperatorTerminalFailure.IO_FAILED,
            AuthDenial.TERMINAL_IO_FAILED,
            "terminal input failed",
        ),
        (
            OperatorTerminalFailure.RESTORE_FAILED,
            AuthDenial.TERMINAL_RESTORE_FAILED,
            "terminal restoration failed",
        ),
        (
            OperatorTerminalFailure.NON_INTERACTIVE,
            AuthDenial.NON_INTERACTIVE,
            "attach a private interactive operator terminal",
        ),
    ],
)
def test_secret_input_failures_have_truthful_finite_denials_and_guidance(
    failure: OperatorTerminalFailure,
    expected_denial: AuthDenial,
    guidance: str,
) -> None:
    class FailingInputTty(PseudoTty):
        def read_secret(self, prompt: str, max_bytes: int) -> str:
            assert prompt.endswith("(input hidden): ")
            assert max_bytes == 128
            raise OperatorTerminalError(failure)

    service, _clock, _source, _store, setup = _service()
    _actor, _profile, roots = _provision(setup)
    tty = FailingInputTty()
    outcome = begin_reprovision_on_tty(service, operator_tty=tty)
    assert outcome.denial is expected_denial
    assert guidance in tty.getvalue()
    assert roots.reprovision.credential.operator_code() not in tty.getvalue()


def test_operator_interruption_confirmation_and_redisplay_are_safe() -> None:
    service, _clock, _source, _store, setup = _service()
    _actor, _profile, roots = _provision(setup)
    declined = PseudoTty(confirmed=False)
    assert (
        begin_bootstrap_on_tty(service, root=roots.initial_bootstrap, operator_tty=declined).denial
        is AuthDenial.OPERATOR_DECLINED
    )
    interrupted = PseudoTty(fail_secret_once=True)
    assert (
        begin_bootstrap_on_tty(
            service, root=roots.initial_bootstrap, operator_tty=interrupted
        ).denial
        is AuthDenial.OUTPUT_INTERRUPTED
    )
    assert "bootstrap-restart" in interrupted.getvalue()
    assert "never resubmit a consumed code" in interrupted.getvalue()
    healthy = PseudoTty()
    _allowed(begin_bootstrap_on_tty(service, root=roots.initial_bootstrap, operator_tty=healthy))
    bootstrap_code = _secret_code(healthy, "bootstrap-code (one-use, short-lived)")
    interrupted_handoff = PseudoTty(fail_secret_once=True)
    bootstrap_result = _allowed(
        exchange_bootstrap_on_tty(
            service,
            submitted_code=bootstrap_code,
            operator_tty=interrupted_handoff,
        )
    )
    assert bootstrap_result.displayed is False
    assert bootstrap_result.delivery is SecretDeliveryState.MAY_HAVE_DISCLOSED
    assert "do not resubmit the consumed code" in interrupted_handoff.getvalue()
    assert "redisplay the in-process result" in interrupted_handoff.getvalue()
    handoff_tty = PseudoTty()
    bootstrap_result = redisplay_interrupted_bootstrap(bootstrap_result, handoff_tty)
    assert bootstrap_result.displayed is True

    recovery_tty = PseudoTty(_secret_code(handoff_tty, "new-recovery-code"), fail_secret_once=True)
    recovery_result = _allowed(recover_headless_on_tty(service, operator_tty=recovery_tty))
    assert recovery_result.displayed is False
    assert recovery_result.delivery is SecretDeliveryState.MAY_HAVE_DISCLOSED
    assert "do not resubmit the consumed code" in recovery_tty.getvalue()
    assert recovery_result.exchange.session.operator_code() not in recovery_tty.getvalue()
    assert recovery_result.exchange.recovery.operator_code() not in recovery_tty.getvalue()
    redisplay_tty = PseudoTty()
    redisplayed = redisplay_interrupted_recovery(recovery_result, redisplay_tty)
    assert redisplayed.displayed is True
    assert "old sessions and old recovery codes revoked" in redisplay_tty.getvalue()


def test_executable_operator_review_harness_matches_retained_transcript() -> None:
    service, clock, _source, _store, setup = _service()
    actor, profile, roots = _provision(setup)
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        tty = PseudoTty()
        _allowed(begin_bootstrap_on_tty(service, root=roots.initial_bootstrap, operator_tty=tty))
        bootstrap_code = _secret_code(tty, "bootstrap-code (one-use, short-lived)")
        handoff_tty = PseudoTty()
        handoff = _allowed(
            exchange_bootstrap_on_tty(
                service,
                submitted_code=bootstrap_code,
                operator_tty=handoff_tty,
            )
        )
        assert handoff.displayed
        tty.write_public(handoff_tty.getvalue())
        session = OpaqueCredential.parse_operator_code(
            _secret_code(handoff_tty, "new-session-code")
        )
        recovery_code = _secret_code(handoff_tty, "new-recovery-code")
        handed_off_recovery = OpaqueCredential.parse_operator_code(recovery_code)

        purpose = AuthPurpose.PROFILE_DELETION
        scopes = frozenset({PURPOSE_SCOPE[purpose]})
        challenge = _allowed(
            service.issue_step_up(
                session=session,
                actor_id=actor,
                represented_profile_id=profile,
                purpose=purpose,
                scopes=scopes,
            )
        )
        wrong = service.consume_step_up(
            challenge=challenge,
            session=session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.DESTRUCTIVE_RESTORE,
            scopes=scopes,
        )
        tty.write_public(f"step-up-wrong-purpose: {wrong.denial.value}\n")
        grant = _allowed(
            service.consume_step_up(
                challenge=challenge,
                session=session,
                actor_id=actor,
                represented_profile_id=profile,
                purpose=purpose,
                scopes=scopes,
            )
        )
        tty.write_public(f"step-up-correct: {grant.purpose.value}\n")
        replay = service.consume_step_up(
            challenge=challenge,
            session=session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
        tty.write_public(f"step-up-replay: {replay.denial.value}\n")

        recovery_tty = PseudoTty(recovery_code)
        recovered = _allowed(recover_headless_on_tty(service, operator_tty=recovery_tty))
        tty.write_public(recovery_tty.getvalue())
        tty.write_public(f"old-session: {service.authenticate_session(session).denial.value}\n")
        non_tty = PseudoTty(interactive=False)
        recover_headless_on_tty(service, operator_tty=non_tty)
        tty.write_public(non_tty.getvalue())

        clock.advance(service.policy.recovery_ttl_seconds)
        first_begin_tty = PseudoTty(roots.reprovision.credential.operator_code())
        _allowed(begin_reprovision_on_tty(service, operator_tty=first_begin_tty))
        tty.write_public(first_begin_tty.getvalue())
        first_bootstrap_code = _secret_code(
            first_begin_tty, "reprovision-bootstrap-code (one-use, short-lived)"
        )
        generic_tty = PseudoTty()
        generic = exchange_bootstrap_on_tty(
            service,
            submitted_code=first_bootstrap_code,
            operator_tty=generic_tty,
        )
        assert generic.denial is AuthDenial.WRONG_PURPOSE
        tty.write_public(generic_tty.getvalue())
        declined_tty = PseudoTty(confirmed=False)
        declined = exchange_reprovision_on_tty(
            service,
            submitted_code=first_bootstrap_code,
            operator_tty=declined_tty,
            operator_authority=setup.reprovision_operator_authority,
        )
        assert declined.denial is AuthDenial.OPERATOR_DECLINED
        tty.write_public(declined_tty.getvalue())
        first_handoff_tty = PseudoTty()
        first_reprovision = _allowed(
            exchange_reprovision_on_tty(
                service,
                submitted_code=first_bootstrap_code,
                operator_tty=first_handoff_tty,
                operator_authority=setup.reprovision_operator_authority,
            )
        )
        assert first_reprovision.displayed
        tty.write_public(first_handoff_tty.getvalue())
        first_reprovision_root_code = _secret_code(
            first_handoff_tty, "replacement-reprovision-code"
        )

        clock.advance(service.policy.recovery_ttl_seconds)
        second_begin_tty = PseudoTty(first_reprovision_root_code)
        _allowed(begin_reprovision_on_tty(service, operator_tty=second_begin_tty))
        tty.write_public(second_begin_tty.getvalue())
        second_bootstrap_code = _secret_code(
            second_begin_tty, "reprovision-bootstrap-code (one-use, short-lived)"
        )
        second_handoff_tty = PseudoTty()
        second_reprovision = _allowed(
            exchange_reprovision_on_tty(
                service,
                submitted_code=second_bootstrap_code,
                operator_tty=second_handoff_tty,
                operator_authority=setup.reprovision_operator_authority,
            )
        )
        assert second_reprovision.displayed
        tty.write_public(second_handoff_tty.getvalue())

    assert stdout.getvalue() == "" and stderr.getvalue() == ""
    assert second_reprovision.exchange.replacement_reprovision is not None
    credentials = (
        OpaqueCredential.parse_operator_code(bootstrap_code),
        session,
        handed_off_recovery,
        challenge,
        recovered.exchange.session,
        recovered.exchange.recovery,
        roots.reprovision.credential,
        OpaqueCredential.parse_operator_code(first_bootstrap_code),
        first_reprovision.exchange.session,
        first_reprovision.exchange.recovery,
        OpaqueCredential.parse_operator_code(first_reprovision_root_code),
        OpaqueCredential.parse_operator_code(second_bootstrap_code),
        second_reprovision.exchange.session,
        second_reprovision.exchange.recovery,
        second_reprovision.exchange.replacement_reprovision.credential,
    )
    transcript = redact_operator_transcript(tty.getvalue(), credentials)
    assert all(credential.operator_code() not in transcript for credential in credentials)
    retained = (REPO_ROOT / "docs/v1/spikes/SPIKE-AUTH-TRANSCRIPT.txt").read_text(encoding="utf-8")
    assert transcript == retained, transcript


def test_credentials_never_enter_repr_stdio_traceback_url_or_entrypoint_arguments() -> None:
    service, _clock, _source, _store, setup = _service()
    _actor, _profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    code = bootstrap.operator_code()
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            raise RuntimeError("synthetic failure")
        except RuntimeError:
            rendered_traceback = traceback.format_exc()
    assert code not in repr(bootstrap) + str(bootstrap) + stdout.getvalue() + stderr.getvalue()
    assert code not in rendered_traceback
    source = (REPO_ROOT / "src/mycogni/entrypoints/auth_spike.py").read_text(encoding="utf-8")
    assert "sys.argv" not in source and "argparse" not in source
    assert "http://" not in source and "https://" not in source


def test_typed_diagnostic_cannot_represent_auth_material() -> None:
    service, _clock, _source, _store, setup = _service()
    _actor, _profile, roots = _provision(setup)
    bootstrap = _allowed(service.begin_bootstrap(roots.initial_bootstrap))
    with pytest.raises(TypeError, match="action must be a ActionCode"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.AUTH,
            event_id=EventId.AUTH_DECISION,
            fields={
                FieldName.ACTION: bootstrap,  # type: ignore[dict-item]
                FieldName.RESULT_CODE: bootstrap,  # type: ignore[dict-item]
            },
        )
