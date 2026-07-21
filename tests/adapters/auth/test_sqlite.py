"""Durability and boundary evidence for the AUTH-001A decision adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from mycogni.adapters.auth import (
    AuthCommitOutcomeUnknown,
    AuthStateCorrupt,
    DurableAuthCrashPoint,
    SqliteAuthDecisionStore,
)
from mycogni.adapters.persistence import FixedFilesystemProbe, SQLiteRuntime, SQLiteSettings
from mycogni.application.auth import AuthService
from mycogni.bootstrap.auth_setup import TrustedLocalAuthSetup
from mycogni.domain import OpaqueId
from mycogni.domain.auth import AuthDenial, AuthOutcome, OpaqueCredential

REPOSITORY_ROOT = Path(__file__).parents[3]
NOW = datetime(2030, 1, 1, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


class SyntheticTokenSource:
    def __init__(self) -> None:
        self.counter = 0

    def generate(self, length: int) -> bytes:
        self.counter += 1
        value = hashlib.sha256(self.counter.to_bytes(16, "big")).digest()
        assert len(value) == length
        return value


def _migrate(database_path: Path) -> None:
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    command.upgrade(config, "head")


def _open(database_path: Path) -> SQLiteRuntime:
    return SQLiteRuntime.open(
        SQLiteSettings(url=f"sqlite:///{database_path}"),
        probe=FixedFilesystemProbe("ext4"),
    )


def _initialized(
    runtime: SQLiteRuntime,
) -> tuple[AuthService, TrustedLocalAuthSetup, object]:
    clock = FixedClock()
    tokens = SyntheticTokenSource()
    store = SqliteAuthDecisionStore(runtime)
    setup = TrustedLocalAuthSetup(clock=clock, token_source=tokens, store=store)
    service = AuthService(
        clock=clock,
        token_source=tokens,
        store=store,
        reprovision_operator_authority=setup.reprovision_operator_authority,
    )
    setup.bind_auth_service(service)
    roots = setup.provision(
        installation_id=OpaqueId.new(),
        actor_id=OpaqueId.new(),
        represented_profile_id=OpaqueId.new(),
    )
    return service, setup, roots


def _bootstrap(service: AuthService, root: object) -> OpaqueCredential:
    issued = service.begin_bootstrap(root)  # type: ignore[arg-type]
    assert issued.denial is None
    assert issued.value is not None
    return issued.value


def test_session_and_replay_state_survive_clean_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "auth-restart.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    service, setup, roots = _initialized(runtime)
    bootstrap = _bootstrap(service, roots.initial_bootstrap)
    exchange = service.exchange_bootstrap(bootstrap)
    assert exchange.denial is None
    assert exchange.value is not None
    session = exchange.value.session
    runtime.close_cleanly()

    restarted = _open(database_path)
    try:
        restarted_store = SqliteAuthDecisionStore(restarted)
        restarted_service = AuthService(
            clock=FixedClock(),
            token_source=SyntheticTokenSource(),
            store=restarted_store,
            reprovision_operator_authority=setup.reprovision_operator_authority,
        )
        assert restarted_service.authenticate_session(session).denial is None
        assert restarted_service.exchange_bootstrap(bootstrap).denial is AuthDenial.REPLAYED
    finally:
        restarted.close_cleanly()


def test_concurrent_bootstrap_exchange_has_one_durable_winner(tmp_path: Path) -> None:
    database_path = tmp_path / "auth-concurrent.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    try:
        service, _setup, roots = _initialized(runtime)
        bootstrap = _bootstrap(service, roots.initial_bootstrap)
        barrier = threading.Barrier(3)
        outcomes: list[AuthOutcome[object]] = []

        def consume() -> None:
            barrier.wait()
            outcomes.append(service.exchange_bootstrap(bootstrap))

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        assert sum(outcome.denial is None for outcome in outcomes) == 1
        assert [outcome.denial for outcome in outcomes if outcome.denial] == [AuthDenial.REPLAYED]
    finally:
        runtime.close_cleanly()


def test_precommit_rolls_back_but_postcommit_is_outcome_unknown_and_not_retriable(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "auth-crash.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    try:
        service, _setup, roots = _initialized(runtime)
        bootstrap = _bootstrap(service, roots.initial_bootstrap)
        store = service._store
        assert type(store) is SqliteAuthDecisionStore

        store.arm_crash_once(DurableAuthCrashPoint.BEFORE_COMMIT)
        with pytest.raises(RuntimeError, match="before commit"):
            service.exchange_bootstrap(bootstrap)
        assert service.exchange_bootstrap(bootstrap).denial is None
    finally:
        runtime.close_cleanly()

    second_path = tmp_path / "auth-outcome-unknown.sqlite"
    _migrate(second_path)
    second_runtime = _open(second_path)
    try:
        service, _setup, roots = _initialized(second_runtime)
        bootstrap = _bootstrap(service, roots.initial_bootstrap)
        store = service._store
        assert type(store) is SqliteAuthDecisionStore
        store.arm_crash_once(DurableAuthCrashPoint.AFTER_COMMIT)
        with pytest.raises(AuthCommitOutcomeUnknown, match="do not retry"):
            service.exchange_bootstrap(bootstrap)
        assert service.exchange_bootstrap(bootstrap).denial is AuthDenial.REPLAYED
    finally:
        second_runtime.close_cleanly()


def test_persisted_state_is_canonical_digest_only_and_has_no_raw_credential(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "auth-secret-scan.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    try:
        service, _setup, roots = _initialized(runtime)
        bootstrap = _bootstrap(service, roots.initial_bootstrap)
        raw_secret = base64.b64encode(bootstrap.secret.reveal()).decode("ascii")
        operator_code = bootstrap.operator_code()
        with runtime.engine.connect() as connection:
            payload = connection.scalar(text("SELECT state_json FROM auth_decision_state"))
            authority_rows = connection.execute(
                text("SELECT handle, authority_kind, installation_id FROM auth_authority_handles")
            ).all()
        assert type(payload) is str
        parsed = json.loads(payload)
        assert set(parsed) == {
            "actors",
            "bootstraps",
            "composition_bindings",
            "grant_provenance",
            "installation_actors",
            "recoveries",
            "reprovision_ceremonies",
            "roots",
            "sessions",
            "step_ups",
        }
        assert raw_secret not in payload
        assert operator_code not in payload
        assert "OpaqueCredential" not in payload
        assert "Sensitive" not in payload
        assert "auth_secret" not in payload
        assert len(authority_rows) == 5
        assert {row.authority_kind for row in authority_rows} == {"root", "operator", "service"}
    finally:
        runtime.close_cleanly()


def test_corrupt_state_fails_closed_without_rendering_stored_content(tmp_path: Path) -> None:
    database_path = tmp_path / "auth-corrupt.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    canary = "synthetic-private-canary.invalid"
    try:
        service, _setup, _roots = _initialized(runtime)
        with runtime.unit_of_work() as unit_of_work:
            unit_of_work.session.execute(
                text("UPDATE auth_decision_state SET state_json=:payload"),
                {"payload": '{"actors":"' + canary + '"}'},
            )
            unit_of_work.commit()
        with pytest.raises(AuthStateCorrupt) as raised:
            service.garbage_collect(0)
        assert canary not in str(raised.value)
        assert canary not in repr(raised.value)
    finally:
        runtime.close_cleanly()
