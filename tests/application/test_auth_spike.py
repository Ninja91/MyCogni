"""Synthetic adversarial evidence for the volatile SPIKE-AUTH decision model."""

from __future__ import annotations

import hashlib
import hmac
import io
import secrets
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
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
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    PURPOSE_SCOPE,
    AuthDenial,
    AuthorityGrant,
    AuthOutcome,
    AuthPolicy,
    AuthPurpose,
    AuthScope,
    BootstrapExchange,
    OpaqueCredential,
    SecretDigest,
)
from mycogni.entrypoints.auth_spike import (
    begin_bootstrap_on_tty,
    recover_headless_on_tty,
    redact_operator_transcript,
)

NOW = datetime(2030, 1, 1, tzinfo=UTC)


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


class PseudoTty(io.StringIO):
    def __init__(self, input_value: str = "", *, interactive: bool = True) -> None:
        super().__init__()
        self._input_value = input_value
        self._interactive = interactive

    def isatty(self) -> bool:
        return self._interactive

    def read_secret(self) -> str:
        return self._input_value


def _service(
    *, policy: AuthPolicy | None = None
) -> tuple[AuthService, MutableClock, DeterministicTokenSource, VolatileAuthDecisionStore]:
    clock = MutableClock()
    source = DeterministicTokenSource()
    store = VolatileAuthDecisionStore()
    return (
        AuthService(clock=clock, token_source=source, store=store, policy=policy),
        clock,
        source,
        store,
    )


def _allowed[T](outcome: AuthOutcome[T]) -> T:
    assert outcome.denial is None
    assert outcome.value is not None
    return outcome.value


def _exchange(
    service: AuthService, *, actor: OpaqueId | None = None, profile: OpaqueId | None = None
) -> tuple[OpaqueId, OpaqueId, OpaqueCredential, BootstrapExchange]:
    actor_id = actor or OpaqueId.new()
    profile_id = profile or OpaqueId.new()
    bootstrap = service.begin_bootstrap(actor_id=actor_id, represented_profile_id=profile_id)
    return actor_id, profile_id, bootstrap, _allowed(service.exchange_bootstrap(bootstrap))


def _wrong(credential: OpaqueCredential, source: DeterministicTokenSource) -> OpaqueCredential:
    return OpaqueCredential.from_secret(credential.handle, source.generate(32))


def _step(
    service: AuthService,
    actor: OpaqueId,
    profile: OpaqueId,
    session: OpaqueCredential,
    purpose: AuthPurpose = AuthPurpose.PROFILE_DELETION,
) -> OpaqueCredential:
    return _allowed(
        service.issue_step_up(
            session=session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=purpose,
            scopes=frozenset({PURPOSE_SCOPE[purpose]}),
        )
    )


def test_bootstrap_is_one_use_short_lived_and_attempt_bounded() -> None:
    service, clock, source, _store = _service(
        policy=AuthPolicy(
            bootstrap_ttl_seconds=10,
            activation_delay_seconds=2,
            max_attempts=2,
        )
    )
    actor = OpaqueId.new()
    profile = OpaqueId.new()
    bootstrap = service.begin_bootstrap(actor_id=actor, represented_profile_id=profile)
    assert service.exchange_bootstrap(bootstrap).denial is AuthDenial.NOT_YET_VALID
    clock.advance(2)
    exchange = _allowed(service.exchange_bootstrap(bootstrap))
    assert exchange.actor_id == actor
    assert service.exchange_bootstrap(bootstrap).denial is AuthDenial.REPLAYED

    expiring = service.begin_bootstrap(
        actor_id=OpaqueId.new(), represented_profile_id=OpaqueId.new()
    )
    clock.advance(12)
    assert service.exchange_bootstrap(expiring).denial is AuthDenial.EXPIRED

    guessed = service.begin_bootstrap(
        actor_id=OpaqueId.new(), represented_profile_id=OpaqueId.new()
    )
    clock.advance(2)
    assert service.exchange_bootstrap(_wrong(guessed, source)).denial is AuthDenial.INVALID_PROOF
    assert (
        service.exchange_bootstrap(_wrong(guessed, source)).denial is AuthDenial.ATTEMPTS_EXHAUSTED
    )
    assert service.exchange_bootstrap(guessed).denial is AuthDenial.ATTEMPTS_EXHAUSTED


def test_store_retains_only_digests_and_uses_constant_time_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _clock, source, store = _service()
    actor = OpaqueId.new()
    profile = OpaqueId.new()
    bootstrap = service.begin_bootstrap(actor_id=actor, represented_profile_id=profile)
    calls: list[tuple[bytes, bytes]] = []
    original = hmac.compare_digest

    def observed(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(hmac, "compare_digest", observed)
    assert service.exchange_bootstrap(_wrong(bootstrap, source)).denial is AuthDenial.INVALID_PROOF
    assert calls and all(len(left) == len(right) == 32 for left, right in calls)
    assert all(type(item) is SecretDigest for item in store.retained_secret_material())
    assert all(item.value != bootstrap.secret.reveal() for item in store.retained_secret_material())


def test_spike_token_adapter_delegates_to_operating_system_random_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = hashlib.sha256((99).to_bytes(16, "big")).digest()
    calls: list[int] = []

    def synthetic_os_source(length: int) -> bytes:
        calls.append(length)
        return expected

    monkeypatch.setattr(secrets, "token_bytes", synthetic_os_source)
    assert OsTokenSource().generate(32) == expected
    assert calls == [32]
    with pytest.raises(ValueError, match="at least 32 bytes"):
        OsTokenSource().generate(16)


def test_session_fixation_and_opaque_server_side_session_fail() -> None:
    service, _clock, source, _store = _service()
    fixed = OpaqueCredential.from_secret(OpaqueId.new(), source.generate(32))
    assert service.authenticate_session(fixed).denial is AuthDenial.SESSION_NOT_FOUND
    _actor, _profile, _bootstrap, exchange = _exchange(service)
    assert service.authenticate_session(fixed).denial is AuthDenial.SESSION_NOT_FOUND
    assert _allowed(service.authenticate_session(exchange.session)) == exchange.session.handle
    assert str(exchange.session) == "[REDACTED:auth_secret]"


def test_concurrent_bootstrap_consume_allows_exactly_one_session() -> None:
    service, _clock, _source, _store = _service()
    bootstrap = service.begin_bootstrap(
        actor_id=OpaqueId.new(), represented_profile_id=OpaqueId.new()
    )
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
    assert [item.denial for item in outcomes if item.denial is not None] == [AuthDenial.REPLAYED]


def test_post_consume_bootstrap_crash_burns_authority_without_partial_session() -> None:
    service, _clock, _source, store = _service()
    bootstrap = service.begin_bootstrap(
        actor_id=OpaqueId.new(), represented_profile_id=OpaqueId.new()
    )
    store.arm_crash_once(CrashPoint.BOOTSTRAP)
    with pytest.raises(SyntheticCrash, match="synthetic post-consume crash"):
        service.exchange_bootstrap(bootstrap)
    assert service.exchange_bootstrap(bootstrap).denial is AuthDenial.REPLAYED


def test_step_up_binds_actor_profile_session_purpose_scope_and_one_use() -> None:
    service, _clock, _source, _store = _service()
    actor, profile, _bootstrap, exchange = _exchange(service)
    challenge = _step(service, actor, profile, exchange.session)
    scope = frozenset({AuthScope.DELETE_PROFILE})
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=OpaqueId.new(),
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=scope,
        ).denial
        is AuthDenial.WRONG_ACTOR
    )
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=OpaqueId.new(),
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=scope,
        ).denial
        is AuthDenial.WRONG_PROFILE
    )
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.DESTRUCTIVE_RESTORE,
            scopes=scope,
        ).denial
        is AuthDenial.WRONG_PURPOSE
    )
    widened = frozenset({AuthScope.DELETE_PROFILE, AuthScope.RESTORE_DESTRUCTIVELY})
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=widened,
        ).denial
        is AuthDenial.SCOPE_WIDENING
    )
    grant = _allowed(
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=scope,
        )
    )
    assert grant.authority_evidence_id == challenge.handle
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=scope,
        ).denial
        is AuthDenial.REPLAYED
    )


def test_step_up_rejects_wrong_session_issue_widening_and_guess_exhaustion() -> None:
    service, _clock, source, _store = _service(policy=AuthPolicy(max_attempts=2))
    actor, profile, _bootstrap, exchange = _exchange(service)
    other_actor, other_profile, _other_bootstrap, other = _exchange(service)
    assert (
        service.issue_step_up(
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=frozenset({AuthScope.DELETE_PROFILE, AuthScope.RESTORE_DESTRUCTIVELY}),
        ).denial
        is AuthDenial.SCOPE_WIDENING
    )
    challenge = _step(service, actor, profile, exchange.session)
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=other.session,
            actor_id=other_actor,
            represented_profile_id=other_profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=frozenset({AuthScope.DELETE_PROFILE}),
        ).denial
        is AuthDenial.WRONG_SESSION
    )
    wrong = _wrong(challenge, source)
    arguments = {
        "challenge": wrong,
        "session": exchange.session,
        "actor_id": actor,
        "represented_profile_id": profile,
        "purpose": AuthPurpose.PROFILE_DELETION,
        "scopes": frozenset({AuthScope.DELETE_PROFILE}),
    }
    assert service.consume_step_up(**arguments).denial is AuthDenial.INVALID_PROOF
    assert service.consume_step_up(**arguments).denial is AuthDenial.ATTEMPTS_EXHAUSTED


def test_step_up_post_consume_crash_is_not_replayable() -> None:
    service, _clock, _source, store = _service()
    actor, profile, _bootstrap, exchange = _exchange(service)
    challenge = _step(service, actor, profile, exchange.session)
    store.arm_crash_once(CrashPoint.STEP_UP)
    arguments = {
        "challenge": challenge,
        "session": exchange.session,
        "actor_id": actor,
        "represented_profile_id": profile,
        "purpose": AuthPurpose.PROFILE_DELETION,
        "scopes": frozenset({AuthScope.DELETE_PROFILE}),
    }
    with pytest.raises(SyntheticCrash):
        service.consume_step_up(**arguments)
    assert service.consume_step_up(**arguments).denial is AuthDenial.REPLAYED


def test_concurrent_step_up_consume_allows_exactly_one_grant() -> None:
    service, _clock, _source, _store = _service()
    actor, profile, _bootstrap, exchange = _exchange(service)
    challenge = _step(service, actor, profile, exchange.session)
    barrier = threading.Barrier(3)
    outcomes: list[AuthOutcome[AuthorityGrant]] = []

    def consume() -> None:
        barrier.wait()
        outcomes.append(
            service.consume_step_up(
                challenge=challenge,
                session=exchange.session,
                actor_id=actor,
                represented_profile_id=profile,
                purpose=AuthPurpose.PROFILE_DELETION,
                scopes=frozenset({AuthScope.DELETE_PROFILE}),
            )
        )

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert sum(item.value is not None for item in outcomes) == 1
    assert [item.denial for item in outcomes if item.denial is not None] == [AuthDenial.REPLAYED]


def test_step_up_expiry_fails_closed_without_a_grant() -> None:
    service, clock, _source, _store = _service(policy=AuthPolicy(step_up_ttl_seconds=2))
    actor, profile, _bootstrap, exchange = _exchange(service)
    challenge = _step(service, actor, profile, exchange.session)
    clock.advance(2)
    assert (
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=frozenset({AuthScope.DELETE_PROFILE}),
        ).denial
        is AuthDenial.EXPIRED
    )


def test_rotation_revocation_and_grant_validation_invalidate_old_authority() -> None:
    service, _clock, _source, _store = _service()
    actor, profile, _bootstrap, exchange = _exchange(service)
    challenge = _step(service, actor, profile, exchange.session)
    grant = _allowed(
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=frozenset({AuthScope.DELETE_PROFILE}),
        )
    )
    assert _allowed(service.validate_grant(grant, exchange.session)) == grant
    rotated = _allowed(service.rotate_session(exchange.session))
    assert service.authenticate_session(exchange.session).denial is AuthDenial.REVOKED
    assert _allowed(service.authenticate_session(rotated)) == rotated.handle
    assert service.validate_grant(grant, rotated).denial is AuthDenial.WRONG_SESSION
    assert _allowed(service.revoke_session(rotated)) == rotated.handle
    assert service.authenticate_session(rotated).denial is AuthDenial.REVOKED


def test_recovery_rotates_epoch_recovery_secret_and_all_sessions() -> None:
    service, _clock, _source, _store = _service()
    actor, profile, _bootstrap, exchange = _exchange(service)
    second_bootstrap = service.begin_bootstrap(actor_id=actor, represented_profile_id=profile)
    second = _allowed(service.exchange_bootstrap(second_bootstrap))
    challenge = _step(service, actor, profile, exchange.session)
    recovered = _allowed(
        service.recover(
            recovery=exchange.recovery,
            actor_id=actor,
            represented_profile_id=profile,
        )
    )
    assert recovered.epoch == exchange.epoch + 1
    assert service.authenticate_session(exchange.session).denial is AuthDenial.STALE_EPOCH
    assert service.authenticate_session(second.session).denial is AuthDenial.STALE_EPOCH
    assert service.consume_step_up(
        challenge=challenge,
        session=recovered.session,
        actor_id=actor,
        represented_profile_id=profile,
        purpose=AuthPurpose.PROFILE_DELETION,
        scopes=frozenset({AuthScope.DELETE_PROFILE}),
    ).denial in {AuthDenial.WRONG_SESSION, AuthDenial.STALE_EPOCH}
    assert (
        service.recover(
            recovery=exchange.recovery,
            actor_id=actor,
            represented_profile_id=profile,
        ).denial
        is AuthDenial.REPLAYED
    )
    assert _allowed(service.authenticate_session(recovered.session)) == recovered.session.handle
    assert _allowed(service.revoke_all(actor)) == recovered.epoch + 1
    assert service.authenticate_session(recovered.session).denial is AuthDenial.STALE_EPOCH


def test_recovery_wrong_binding_and_post_consume_crash_fail_closed() -> None:
    service, _clock, _source, store = _service()
    actor, profile, _bootstrap, exchange = _exchange(service)
    assert (
        service.recover(
            recovery=exchange.recovery,
            actor_id=OpaqueId.new(),
            represented_profile_id=profile,
        ).denial
        is AuthDenial.WRONG_ACTOR
    )
    assert (
        service.recover(
            recovery=exchange.recovery,
            actor_id=actor,
            represented_profile_id=OpaqueId.new(),
        ).denial
        is AuthDenial.WRONG_PROFILE
    )
    store.arm_crash_once(CrashPoint.RECOVERY)
    with pytest.raises(SyntheticCrash):
        service.recover(
            recovery=exchange.recovery,
            actor_id=actor,
            represented_profile_id=profile,
        )
    assert (
        service.recover(
            recovery=exchange.recovery,
            actor_id=actor,
            represented_profile_id=profile,
        ).denial
        is AuthDenial.REPLAYED
    )
    assert service.authenticate_session(exchange.session).denial is AuthDenial.STALE_EPOCH


def test_clock_rollback_forward_jump_and_grant_expiry_fail_closed() -> None:
    service, clock, _source, _store = _service(
        policy=AuthPolicy(session_ttl_seconds=20, step_up_ttl_seconds=5)
    )
    actor, profile, _bootstrap, exchange = _exchange(service)
    clock.advance(2)
    assert _allowed(service.authenticate_session(exchange.session)) == exchange.session.handle
    clock.advance(-1)
    assert service.authenticate_session(exchange.session).denial is AuthDenial.CLOCK_ROLLBACK
    clock.advance(1)
    challenge = _step(service, actor, profile, exchange.session)
    grant = _allowed(
        service.consume_step_up(
            challenge=challenge,
            session=exchange.session,
            actor_id=actor,
            represented_profile_id=profile,
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=frozenset({AuthScope.DELETE_PROFILE}),
        )
    )
    clock.advance(5)
    assert service.validate_grant(grant, exchange.session).denial is AuthDenial.EXPIRED
    clock.advance(15)
    assert service.authenticate_session(exchange.session).denial is AuthDenial.EXPIRED


def test_credentials_never_enter_repr_stdio_traceback_url_or_entrypoint_arguments() -> None:
    service, _clock, _source, _store = _service()
    bootstrap = service.begin_bootstrap(
        actor_id=OpaqueId.new(), represented_profile_id=OpaqueId.new()
    )
    code = bootstrap.operator_code()
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            raise RuntimeError("synthetic failure")
        except RuntimeError:
            rendered_traceback = traceback.format_exc()
    assert code not in repr(bootstrap)
    assert code not in str(bootstrap)
    assert code not in stdout.getvalue()
    assert code not in stderr.getvalue()
    assert code not in rendered_traceback
    malformed = "not-an-id." + code.rsplit(".", 1)[1]
    try:
        OpaqueCredential.parse_operator_code(malformed)
    except ValueError:
        parse_traceback = traceback.format_exc()
    assert malformed not in parse_traceback
    assert all(character not in code for character in ("?", "#", "/"))
    source = (Path(__file__).parents[2] / "src/mycogni/entrypoints/auth_spike.py").read_text(
        encoding="utf-8"
    )
    assert "sys.argv" not in source
    assert "argparse" not in source
    assert "http://" not in source and "https://" not in source


def test_typed_diagnostic_cannot_represent_auth_material() -> None:
    service, _clock, _source, _store = _service()
    bootstrap = service.begin_bootstrap(
        actor_id=OpaqueId.new(), represented_profile_id=OpaqueId.new()
    )
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


def test_tty_ceremony_headless_recovery_and_redacted_transcript() -> None:
    service, _clock, _source, _store = _service()
    actor = OpaqueId.new()
    profile = OpaqueId.new()
    refused = PseudoTty(interactive=False)
    assert (
        begin_bootstrap_on_tty(
            service,
            actor_id=actor,
            represented_profile_id=profile,
            operator_tty=refused,
        ).denial
        is AuthDenial.NON_INTERACTIVE
    )
    assert refused.getvalue() == "bootstrap-denied: non_interactive\n"

    recovery_refused = PseudoTty(interactive=False)
    assert (
        recover_headless_on_tty(
            service,
            actor_id=actor,
            represented_profile_id=profile,
            operator_tty=recovery_refused,
        ).denial
        is AuthDenial.NON_INTERACTIVE
    )
    assert recovery_refused.getvalue() == "recovery-denied: non_interactive\n"

    bootstrap = service.begin_bootstrap(actor_id=actor, represented_profile_id=profile)
    exchange = _allowed(service.exchange_bootstrap(bootstrap))
    tty = PseudoTty(exchange.recovery.operator_code() + "\n")
    recovered = _allowed(
        recover_headless_on_tty(
            service,
            actor_id=actor,
            represented_profile_id=profile,
            operator_tty=tty,
        )
    )
    transcript = redact_operator_transcript(
        tty.getvalue(),
        (exchange.recovery, recovered.session, recovered.recovery),
    )
    assert "[REDACTED:auth_secret]" in transcript
    for credential in (exchange.recovery, recovered.session, recovered.recovery):
        assert credential.operator_code() not in transcript
    assert service.authenticate_session(exchange.session).denial is AuthDenial.STALE_EPOCH


def test_grant_constructor_rejects_scope_widening_even_outside_service() -> None:
    with pytest.raises(ValueError, match="scope must exactly match"):
        AuthorityGrant(
            actor_id=OpaqueId.new(),
            represented_profile_id=OpaqueId.new(),
            session_id=OpaqueId.new(),
            authority_evidence_id=OpaqueId.new(),
            purpose=AuthPurpose.PROFILE_DELETION,
            scopes=frozenset({AuthScope.DELETE_PROFILE, AuthScope.RESTORE_DESTRUCTIVELY}),
            not_before_utc=NOW,
            expires_at_utc=NOW + timedelta(seconds=1),
            epoch=1,
        )
