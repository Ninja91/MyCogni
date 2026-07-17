"""Adversarial evidence for the volatile SPIKE-AUTH decision model."""

from __future__ import annotations

import hashlib
import hmac
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
from mycogni.application.auth import AuthService
from mycogni.application.diagnostics import (
    DiagnosticComponent,
    DiagnosticEvent,
    DiagnosticLevel,
    EventId,
    FieldName,
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
    RootAuthorityBundle,
    RootPurpose,
    SecretDigest,
    SessionIssue,
)
from mycogni.entrypoints.auth_spike import (
    begin_bootstrap_on_tty,
    exchange_bootstrap_code,
    recover_headless_on_tty,
    redact_operator_transcript,
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

    def confirm_secret_display(self, warning: str) -> bool:
        assert warning.startswith("WARNING: SECRET DISPLAY")
        self.transcript.write(
            f"secret-display-confirmation: {'accepted' if self.confirmed else 'declined'}\n"
        )
        return self.confirmed

    def read_secret_no_echo(self) -> str:
        self.transcript.write("[NO-ECHO INPUT]\n")
        return self.input_value

    def write_secret_block(self, values: tuple[tuple[str, str], ...]) -> None:
        if self.fail_secret_once:
            self.fail_secret_once = False
            raise OSError("synthetic all-or-nothing display failure")
        self.secret_values.append(values)
        for label, value in values:
            self.transcript.write(f"{label}: {value}\n")

    def getvalue(self) -> str:
        return self.transcript.getvalue()


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
    service = AuthService(clock=clock, token_source=source, store=store, policy=policy)
    return (
        service,
        clock,
        source,
        store,
        TrustedLocalAuthSetup(clock=clock, token_source=source, store=store),
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

    reprovision = _allowed(service.begin_bootstrap(roots.reprovision))
    replacement = _allowed(service.exchange_bootstrap(reprovision))
    assert replacement.epoch == 3
    assert replacement.actor_id == actor


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
    digest = SecretDigest(hashlib.sha256(exchange.session.secret.reveal()).digest())
    returned = _allowed(store.authenticate_session(exchange.session, digest, clock.now()))
    returned.revoked = True
    assert service.authenticate_session(exchange.session).value == exchange.session.handle

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
    for credential in (bootstrap, exchange.session, exchange.recovery):
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
    healthy = PseudoTty()
    _allowed(begin_bootstrap_on_tty(service, root=roots.initial_bootstrap, operator_tty=healthy))
    bootstrap_code = healthy.secret_values[0][0][1]
    exchange = _allowed(exchange_bootstrap_code(service, bootstrap_code))

    recovery_tty = PseudoTty(exchange.recovery.operator_code(), fail_secret_once=True)
    recovery_result = _allowed(recover_headless_on_tty(service, operator_tty=recovery_tty))
    assert recovery_result.displayed is False
    redisplay_tty = PseudoTty()
    redisplayed = redisplay_interrupted_recovery(recovery_result, redisplay_tty)
    assert redisplayed.displayed is True
    assert "old sessions and old recovery codes revoked" in redisplay_tty.getvalue()


def test_executable_operator_review_harness_matches_retained_transcript() -> None:
    service, _clock, _source, _store, setup = _service()
    actor, profile, roots = _provision(setup)
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        tty = PseudoTty()
        _allowed(begin_bootstrap_on_tty(service, root=roots.initial_bootstrap, operator_tty=tty))
        bootstrap_code = tty.secret_values[0][0][1]
        exchange = _allowed(exchange_bootstrap_code(service, bootstrap_code))

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
        tty.write_public(f"step-up-wrong-purpose: {wrong.denial.value}\n")
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
        tty.write_public(f"step-up-correct: {grant.purpose.value}\n")
        replay = service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=scopes,
        )
        tty.write_public(f"step-up-replay: {replay.denial.value}\n")

        recovery_tty = PseudoTty(exchange.recovery.operator_code())
        recovered = _allowed(recover_headless_on_tty(service, operator_tty=recovery_tty))
        tty.write_public(recovery_tty.getvalue())
        tty.write_public(
            f"old-session: {service.authenticate_session(exchange.session).denial.value}\n"
        )
        non_tty = PseudoTty(interactive=False)
        recover_headless_on_tty(service, operator_tty=non_tty)
        tty.write_public(non_tty.getvalue())

    assert stdout.getvalue() == "" and stderr.getvalue() == ""
    credentials = (
        OpaqueCredential.parse_operator_code(bootstrap_code),
        exchange.session,
        exchange.recovery,
        challenge,
        recovered.exchange.session,
        recovered.exchange.recovery,
    )
    transcript = redact_operator_transcript(tty.getvalue(), credentials)
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
