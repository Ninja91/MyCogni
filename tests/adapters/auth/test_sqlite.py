"""Durability and boundary evidence for the AUTH-001A decision adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.orm import Session

from mycogni.adapters.auth import (
    AuthCommitOutcomeUnknown,
    AuthStateCorrupt,
    DurableAuthCrashPoint,
    SqliteAuthDecisionStore,
)
from mycogni.adapters.auth.sqlite import _restore, _snapshot
from mycogni.adapters.auth.volatile import VolatileAuthDecisionStore
from mycogni.adapters.persistence import FixedFilesystemProbe, SQLiteRuntime, SQLiteSettings
from mycogni.adapters.persistence.unit_of_work import SqlAlchemyUnitOfWork
from mycogni.application.auth import AuthService
from mycogni.bootstrap.auth_setup import TrustedLocalAuthSetup
from mycogni.domain import OpaqueId
from mycogni.domain.auth import AuthDenial, AuthOutcome, OpaqueCredential

REPOSITORY_ROOT = Path(__file__).parents[3]
EMPTY_GOLDEN = Path(__file__).parent / "fixtures/auth-state-v1-empty.json"
POPULATED_GOLDEN = Path(__file__).parent / "fixtures/auth-state-v1-populated.json"
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
        with pytest.raises(RuntimeError, match="not accepting|inactive"):
            service.exchange_bootstrap(bootstrap)
    finally:
        second_runtime.close_cleanly()

    restarted = _open(second_path)
    try:
        assert restarted.startup.requires_reconciliation is True
        with pytest.raises(RuntimeError, match="not accepting"):
            restarted.unit_of_work()
    finally:
        restarted.abandon()


@pytest.mark.parametrize("commit_first", [False, True])
def test_real_commit_wrapper_failure_is_redacted_latched_and_restart_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    commit_first: bool,
) -> None:
    database_path = tmp_path / f"auth-real-commit-{commit_first}.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    service, _setup, roots = _initialized(runtime)
    bootstrap = _bootstrap(service, roots.initial_bootstrap)
    real_commit = SqlAlchemyUnitOfWork.commit
    canary = "synthetic-backend-private.invalid"

    def ambiguous_commit(unit_of_work: SqlAlchemyUnitOfWork) -> None:
        if commit_first:
            real_commit(unit_of_work)
        raise RuntimeError(canary)

    monkeypatch.setattr(SqlAlchemyUnitOfWork, "commit", ambiguous_commit)
    with pytest.raises(AuthCommitOutcomeUnknown) as raised:
        service.exchange_bootstrap(bootstrap)
    assert canary not in str(raised.value)
    assert canary not in repr(raised.value)
    with pytest.raises(RuntimeError, match="not accepting|inactive"):
        runtime.unit_of_work()

    restarted = _open(database_path)
    try:
        assert restarted.startup.requires_reconciliation is True
        with pytest.raises(RuntimeError, match="not accepting"):
            restarted.unit_of_work()
    finally:
        restarted.abandon()


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
        for artifact in (database_path, Path(f"{database_path}-wal"), Path(f"{database_path}-shm")):
            if artifact.exists():
                content = artifact.read_bytes()
                assert bootstrap.secret.reveal() not in content
                assert raw_secret.encode("ascii") not in content
                assert operator_code.encode("ascii") not in content
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
        with pytest.raises(RuntimeError, match="not accepting|inactive"):
            runtime.unit_of_work()
    finally:
        runtime.close_cleanly()

    restarted = _open(database_path)
    try:
        assert restarted.startup.requires_reconciliation is True
        with pytest.raises(RuntimeError, match="not accepting"):
            restarted.unit_of_work()
    finally:
        restarted.abandon()


def test_empty_v1_snapshot_matches_checked_in_golden_and_round_trips() -> None:
    payload = _snapshot(VolatileAuthDecisionStore())
    assert payload + "\n" == EMPTY_GOLDEN.read_text(encoding="utf-8")
    assert _snapshot(_restore(payload)) == payload


def test_populated_v1_golden_decodes_and_reencodes_byte_stably() -> None:
    payload = POPULATED_GOLDEN.read_text(encoding="utf-8").rstrip("\n")
    assert _snapshot(_restore(payload)) == payload
    document = json.loads(payload)
    assert all(document[name] for name in document)
    tagged: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if type(value) is dict:
            if type(value.get("type")) is str:
                tagged.append(value)
            for item in value.values():
                visit(item)
        elif type(value) is list:
            for item in value:
                visit(item)

    visit(document)
    assert {item["type"] for item in tagged} == {
        "enum",
        "frozenset",
        "opaque_id",
        "record",
        "secret_digest",
        "utc_datetime",
    }
    assert {item["name"] for item in tagged if item["type"] == "record"} == {
        "ActorRecord",
        "AuthorityGrant",
        "BootstrapRecord",
        "CompositionBindingRecord",
        "GrantProvenanceRecord",
        "RecoveryRecord",
        "ReprovisionCeremonyRecord",
        "RootCapabilityRecord",
        "SessionRecord",
        "StepUpRecord",
    }
    assert {item["name"] for item in tagged if item["type"] == "enum"} == {
        "AuthDenial",
        "AuthPurpose",
        "AuthScope",
        "RootPurpose",
    }
    terminal_values = [
        item["fields"]["terminal_at_utc"]
        for item in tagged
        if item.get("name") == "ReprovisionCeremonyRecord"
    ]
    assert any(value is None for value in terminal_values)
    assert any(type(value) is dict for value in terminal_values)


def test_observational_ceremony_counts_do_not_rewrite_state(tmp_path: Path) -> None:
    database_path = tmp_path / "auth-read-only.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    try:
        service, _setup, _roots = _initialized(runtime)
        with runtime.engine.connect() as connection:
            before = connection.execute(
                text("SELECT revision, state_json FROM auth_decision_state")
            ).one()
        assert service.reprovision_ceremony_counts() == {
            "active": 0,
            "tombstones": 0,
            "total": 0,
        }
        with runtime.engine.connect() as connection:
            after = connection.execute(
                text("SELECT revision, state_json FROM auth_decision_state")
            ).one()
        assert after == before
    finally:
        runtime.close_cleanly()


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_object_key",
        "extra_tag_key",
        "wrong_collection_type",
        "non_utc_datetime",
        "key_handle_mismatch",
        "cross_map_mismatch",
        "bootstrap_root_mismatch",
        "future_epoch",
        "step_up_session_mismatch",
        "grant_session_mismatch",
        "ceremony_chain_mismatch",
        "unknown_enum_value",
    ],
)
def test_v1_decoder_rejects_noncanonical_and_cross_map_mutations(
    tmp_path: Path, mutation: str
) -> None:
    database_path = tmp_path / f"auth-mutation-{mutation}.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    try:
        service, _setup, _roots = _initialized(runtime)
        with runtime.engine.connect() as connection:
            payload = connection.scalar(text("SELECT state_json FROM auth_decision_state"))
        assert type(payload) is str
        if mutation == "duplicate_object_key":
            mutated = payload.replace('"actors":', '"actors":[],"actors":', 1)
        else:
            document = json.loads(payload)
            if mutation == "extra_tag_key":
                document["actors"][0][0]["extra"] = False
            elif mutation == "wrong_collection_type":
                document["roots"] = document["actors"]
            elif mutation == "non_utc_datetime":
                document["actors"][0][1]["fields"]["last_observed_utc"]["value"] = (
                    "2030-01-01T01:00:00+01:00"
                )
            elif mutation == "key_handle_mismatch":
                document["actors"][0][0]["value"] = "00000000-0000-4000-8000-000000000099"
            elif mutation == "cross_map_mismatch":
                document["installation_actors"][0][1]["value"] = (
                    "00000000-0000-4000-8000-000000000099"
                )
            else:
                document = json.loads(POPULATED_GOLDEN.read_text(encoding="utf-8"))
                if mutation == "bootstrap_root_mismatch":
                    document["bootstraps"][0][1]["fields"]["actor_id"]["value"] = (
                        "00000000-0000-4000-8000-000000000099"
                    )
                elif mutation == "future_epoch":
                    document["sessions"][0][1]["fields"]["epoch"] = 3
                elif mutation == "step_up_session_mismatch":
                    document["step_ups"][0][1]["fields"]["session_id"]["value"] = (
                        "00000000-0000-4000-8000-000000000099"
                    )
                elif mutation == "grant_session_mismatch":
                    grant = document["grant_provenance"][0][1]["fields"]["grant"]
                    grant["fields"]["session_id"]["value"] = "00000000-0000-4000-8000-000000000099"
                elif mutation == "ceremony_chain_mismatch":
                    document["reprovision_ceremonies"][0][1]["fields"]["bootstrap_handle"][
                        "value"
                    ] = "00000000-0000-4000-8000-000000000099"
                else:
                    document["grant_provenance"][0][1]["fields"]["grant"]["fields"]["purpose"][
                        "value"
                    ] = "future_purpose"
            mutated = json.dumps(document, sort_keys=True, separators=(",", ":"))
        with pytest.raises(AuthStateCorrupt):
            _restore(mutated)
    finally:
        runtime.close_cleanly()


def test_read_rejects_unsupported_schema_version_latches_and_does_not_rewrite(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "auth-version.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    service, _setup, _roots = _initialized(runtime)
    with runtime.unit_of_work() as unit_of_work:
        unit_of_work.session.execute(text("PRAGMA ignore_check_constraints=ON"))
        unit_of_work.session.execute(
            text("UPDATE auth_decision_state SET schema_version=99 WHERE singleton_id=1")
        )
        unit_of_work.commit()
    with pytest.raises(AuthStateCorrupt):
        service.reprovision_ceremony_counts()
    with pytest.raises(RuntimeError, match="not accepting|inactive"):
        runtime.unit_of_work()
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT schema_version, revision FROM auth_decision_state"
        ).fetchone() == (99, 1)


def test_revision_cas_zero_row_fails_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_path = tmp_path / "auth-cas.sqlite"
    _migrate(database_path)
    runtime = _open(database_path)
    try:
        service, _setup, _roots = _initialized(runtime)
        with runtime.engine.connect() as connection:
            before = connection.scalar(text("SELECT revision FROM auth_decision_state"))
        real_execute = Session.execute

        class ZeroRowResult:
            rowcount = 0

        def zero_update(
            session: Session, statement: object, *args: object, **kwargs: object
        ) -> object:
            rendered = str(statement)
            if "UPDATE auth_decision_state SET revision" in rendered:
                real_execute(session, statement, *args, **kwargs)  # type: ignore[arg-type]
                return ZeroRowResult()
            return real_execute(session, statement, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Session, "execute", zero_update)
        with pytest.raises(RuntimeError, match="revision changed"):
            service.garbage_collect(0)
        monkeypatch.setattr(Session, "execute", real_execute)
        with runtime.engine.connect() as connection:
            assert connection.scalar(text("SELECT revision FROM auth_decision_state")) == before
    finally:
        runtime.close_cleanly()
