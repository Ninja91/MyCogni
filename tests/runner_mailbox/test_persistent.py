"""Restart and cross-process evidence for the persistent runner mailbox adapter."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import signal
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Event, Thread
from uuid import UUID

import pytest

from services.runner_mailbox import (
    ActionBinding,
    CollectionState,
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
    MailboxLimits,
    MailboxState,
    PersistentMailboxRepository,
    RunnerMailboxService,
    Sha256CredentialDigester,
)
from services.runner_mailbox.domain import CrashPoint, InjectedCrash
from tests.runner_mailbox.conftest import (
    ACTION_KEY,
    ARTIFACT_DIGEST,
    CLAIM_CREDENTIAL,
    COLLECTION_CREDENTIAL,
    MAINTENANCE_CREDENTIAL,
    FixedCredentialSource,
    encode,
)

_STORAGE_KEY = b"s" * 32
_INSTALLATION_EPOCH = b"i" * 32
_RESTORE_EPOCH = b"e" * 32


@dataclass(slots=True)
class StaticClock:
    current: datetime

    def now(self) -> datetime:
        return self.current


@dataclass(slots=True)
class InjectOnce:
    target: CrashPoint
    fired: bool = False

    def hit(self, point: CrashPoint) -> None:
        if point is self.target and not self.fired:
            self.fired = True
            raise InjectedCrash(point)


def _repository(path: Path, injector: InjectOnce | None = None) -> PersistentMailboxRepository:
    digester = Sha256CredentialDigester()
    return PersistentMailboxRepository(
        path,
        maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
        storage_key=_STORAGE_KEY,
        installation_epoch=_INSTALLATION_EPOCH,
        restore_epoch=_RESTORE_EPOCH,
        failure_injector=injector,
    )


@dataclass(slots=True)
class ExitAtCommitBoundary:
    edge: str
    armed: bool = False

    def before_commit(self) -> None:
        if self.armed and self.edge == "before":
            os._exit(71)

    def after_commit(self) -> None:
        if self.armed and self.edge == "after":
            os._exit(72)


def _service(path: Path, clock: StaticClock, injector: InjectOnce | None = None) -> RunnerMailboxService:
    return RunnerMailboxService(
        _repository(path, injector), clock, Sha256CredentialDigester(), FixedCredentialSource()
    )


def _binding(service: RunnerMailboxService, action: bytes) -> ActionBinding:
    return service.bind_action(
        UUID("1bea5f8c-166c-46a1-ac72-99bbdd1720d1"),
        action,
        selected_artifact_digest=ARTIFACT_DIGEST,
        dispatch_epoch=0,
        claim_deadline_utc=datetime(2030, 1, 1, 0, 1, tzinfo=UTC),
    )


def _offered(path: Path, clock: StaticClock, action: bytes) -> tuple[RunnerMailboxService, ActionBinding]:
    service = _service(path, clock)
    binding = _binding(service, action)
    service.open_empty(
        binding,
        action_credential=ACTION_KEY,
        claim_credential=CLAIM_CREDENTIAL,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    service.offer(
        binding, action, action_key=ACTION_KEY, collection_credential=COLLECTION_CREDENTIAL
    )
    return service, binding


def _claim_process(
    database_path: str,
    binding: ActionBinding,
    current: datetime,
    queue: multiprocessing.Queue[tuple[str, str]],
) -> None:
    """Independent process: SQLite BEGIN IMMEDIATE chooses the one winner."""

    repository = _repository(Path(database_path))
    try:
        repository.claim(binding, Sha256CredentialDigester().digest(CLAIM_CREDENTIAL), StaticClock(current))
    except MailboxError as error:
        queue.put(("denied", error.denial.value))
    else:
        queue.put(("claimed", ""))
    finally:
        repository.close()


def _claim_and_exit_at_boundary(
    database_path: str, binding: ActionBinding, current: datetime, edge: str
) -> None:
    hook = ExitAtCommitBoundary(edge)
    digester = Sha256CredentialDigester()
    repository = PersistentMailboxRepository(
        Path(database_path),
        maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
        storage_key=_STORAGE_KEY,
        installation_epoch=_INSTALLATION_EPOCH,
        restore_epoch=_RESTORE_EPOCH,
        persistence_hook=hook,
    )
    hook.armed = True
    repository.claim(binding, digester.digest(CLAIM_CREDENTIAL), StaticClock(current))


def _result_payload(evidence: EvidenceUpload) -> bytes:
    return encode(
        {
            "protocol_version": 1,
            "action_id": "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c",
            "attempt_id": "26fc0371-5b37-4452-8569-95564cc83edb",
            "result": "candidate_observed",
            "reason_code": "name_address_match",
            "evidence": [
                {
                    "kind": evidence.kind,
                    "mailbox_object_id": str(evidence.object_id),
                    "payload_digest": evidence.payload_digest,
                    "byte_count": len(evidence.payload),
                }
            ],
            "disclosures": [{"attribute_type": "name", "destination": "broker.example.test"}],
            "next": {"kind": "user_review"},
        }
    )


def _evidence() -> EvidenceUpload:
    payload = b"synthetic-persistent-runner-canary"
    return EvidenceUpload(
        object_id=UUID("470c0e4b-ce29-4eb5-8a1f-dd672e342fac"),
        kind="sanitized_html",
        payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )


def _action() -> bytes:
    return encode(
        {
            "protocol_version": 1,
            "action_id": "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c",
            "intent_id": "00ef8ac4-3f2a-4ab7-8c7f-4b50e4d902bd",
            "attempt_id": "26fc0371-5b37-4452-8569-95564cc83edb",
            "fence": 0,
            "authorization_epoch": 0,
            "capability": "observe",
            "connector_release": "synthetic-people-search@0.1.0",
            "profile_ref": "93cb45b8-843f-4af1-8642-d70903d0919f",
            "attributes": [{"attribute_type": "name", "ciphertext": "sealed-synthetic-value"}],
            "allowed_origins": ["https://broker.example.test"],
            "deadline_utc": "2030-01-01T00:05:00Z",
            "attempt": 0,
            "budget": {"wall_seconds": 30, "response_bytes": 4096},
        }
    )


def test_offered_state_is_opaque_on_disk_and_restart_recovers_one_claim(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    action_bytes = _action()
    service, binding = _offered(path, clock, action_bytes)
    service._repository.close()  # type: ignore[attr-defined]
    wal = path.with_name(path.name + "-wal")
    disk = path.read_bytes() + (wal.read_bytes() if wal.exists() else b"")
    assert b"sealed-synthetic-value" not in disk
    resumed = _service(path, clock)
    claimed = resumed.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    assert claimed.action_key == ACTION_KEY
    resumed._repository.close()  # type: ignore[attr-defined]
    after_claim = _service(path, clock)
    with pytest.raises(MailboxError) as replay:
        after_claim.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    assert replay.value.denial is MailboxDenial.REPLAY


def test_after_commit_crash_edges_reopen_at_exact_durable_transition(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    action = _action()
    service, binding = _offered(path, clock, action)
    service._repository.close()  # type: ignore[attr-defined]
    crashing = _service(path, clock, InjectOnce(CrashPoint.AFTER_CLAIM_COMMIT))
    with pytest.raises(InjectedCrash):
        crashing.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    crashing._repository.close()  # type: ignore[attr-defined]
    recovered = _service(path, clock)
    snapshot = recovered.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.state is MailboxState.CLAIMED_ONCE
    assert snapshot.claim_material_retained is False
    recovered._repository.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("edge", "exit_code", "expected"),
    [("before", 71, MailboxState.OFFERED), ("after", 72, MailboxState.CLAIMED_ONCE)],
)
def test_subprocess_loss_on_either_side_of_sqlite_commit_is_restart_linearizable(
    tmp_path: Path, edge: str, exit_code: int, expected: MailboxState
) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    service, binding = _offered(path, clock, _action())
    service._repository.close()  # type: ignore[attr-defined]
    child = multiprocessing.get_context("spawn").Process(
        target=_claim_and_exit_at_boundary, args=(str(path), binding, clock.current, edge)
    )
    child.start()
    child.join(timeout=15)
    assert child.exitcode == exit_code
    resumed = _service(path, clock)
    snapshot = resumed.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.state is expected
    resumed._repository.close()  # type: ignore[attr-defined]


def test_commit_and_ack_survive_restart_without_replayable_payloads(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    action = _action()
    service, binding = _offered(path, clock, action)
    credential = service.claim(binding, claim_credential=CLAIM_CREDENTIAL).result_credential
    evidence = _evidence()
    service.stage_evidence(binding, result_credential=credential, evidence=evidence)
    service.commit_result(binding, _result_payload(evidence), result_credential=credential)
    service._repository.close()  # type: ignore[attr-defined]
    resumed = _service(path, clock)
    delivered = resumed.collect(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert delivered.evidence[0].payload == evidence.payload
    resumed.acknowledge_collection(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    resumed._repository.close()  # type: ignore[attr-defined]
    final = _service(path, clock)
    snapshot = final.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.collection_state is CollectionState.ACKNOWLEDGED
    assert snapshot.result_present is False
    with pytest.raises(MailboxError) as denied:
        final.collect(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert denied.value.denial is MailboxDenial.REPLAY
    final._repository.close()  # type: ignore[attr-defined]


def test_sqlite_begin_immediate_serializes_two_independent_claim_processes(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    action = _action()
    service, binding = _offered(path, clock, action)
    service._repository.close()  # type: ignore[attr-defined]
    context = multiprocessing.get_context("spawn")
    queue: multiprocessing.Queue[tuple[str, str]] = context.Queue()
    processes = [
        context.Process(target=_claim_process, args=(str(path), binding, clock.current, queue))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0
    outcomes: list[tuple[str, str]] = []
    for _ in processes:
        try:
            outcomes.append(queue.get(timeout=3))
        except Empty as error:  # pragma: no cover - explicit process regression guard
            raise AssertionError("claim worker did not report") from error
    assert sorted(outcomes) == [("claimed", ""), ("denied", MailboxDenial.REPLAY.value)]


def test_state_frame_rejects_epoch_substitution_and_sqlite_is_hardened(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    repository = _repository(path)
    repository.close()
    with pytest.raises(MailboxError) as substituted:
        PersistentMailboxRepository(
            path,
            maintenance_credential_digest=Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL),
            storage_key=_STORAGE_KEY,
            installation_epoch=_INSTALLATION_EPOCH,
            restore_epoch=b"x" * 32,
        )
    assert substituted.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    finally:
        connection.close()


def test_state_frame_rejects_subsecond_retention_policy_substitution(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    digester = Sha256CredentialDigester()
    baseline = MailboxLimits(terminal_retention=timedelta(seconds=1, microseconds=1))
    repository = PersistentMailboxRepository(
        path,
        maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
        storage_key=_STORAGE_KEY,
        installation_epoch=_INSTALLATION_EPOCH,
        restore_epoch=_RESTORE_EPOCH,
        limits=baseline,
    )
    repository.close()
    with pytest.raises(MailboxError) as substituted:
        PersistentMailboxRepository(
            path,
            maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
            storage_key=_STORAGE_KEY,
            installation_epoch=_INSTALLATION_EPOCH,
            restore_epoch=_RESTORE_EPOCH,
            limits=MailboxLimits(
                terminal_retention=timedelta(seconds=1, microseconds=2)
            ),
        )
    assert substituted.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork regression")
def test_inherited_repository_is_denied_before_child_touches_parent_sqlite_connection(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "runner.sqlite")
    child = os.fork()
    if child == 0:  # pragma: no cover - child returns its status to the parent
        try:
            repository.garbage_collect(
                Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL),
                StaticClock(datetime(2030, 1, 1, tzinfo=UTC)),
            )
        except MailboxError as error:
            os._exit(0 if error.denial is MailboxDenial.INTERNAL_UNCERTAINTY else 1)
        os._exit(1)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    repository.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork regression")
@pytest.mark.parametrize("operation", ["transition", "close"])
def test_forked_child_refuses_before_inherited_held_rlock(
    tmp_path: Path, operation: str
) -> None:
    repository = _repository(tmp_path / "runner.sqlite")
    held = Event()
    release = Event()

    def hold_lock() -> None:
        with repository._lock:  # type: ignore[attr-defined]
            held.set()
            assert release.wait(timeout=10)

    holder = Thread(target=hold_lock)
    holder.start()
    assert held.wait(timeout=3)
    child = os.fork()
    if child == 0:  # pragma: no cover - child reports by exit status
        signal.alarm(2)
        try:
            if operation == "close":
                repository.close()
            else:
                repository.garbage_collect(
                    Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL),
                    StaticClock(datetime(2030, 1, 1, tzinfo=UTC)),
                )
        except MailboxError as error:
            os._exit(0 if error.denial is MailboxDenial.INTERNAL_UNCERTAINTY else 1)
        os._exit(1)
    _, status = os.waitpid(child, 0)
    release.set()
    holder.join(timeout=3)
    assert not holder.is_alive()
    assert os.waitstatus_to_exitcode(status) == 0
    repository.close()


def test_existing_hardlink_is_rejected_before_sqlite_or_chmod_mutation(tmp_path: Path) -> None:
    source = tmp_path / "operator-file"
    source.write_bytes(b"synthetic-operator-content")
    source.chmod(0o640)
    database = tmp_path / "runner.sqlite"
    os.link(source, database)
    before = source.stat()
    with pytest.raises(MailboxError) as denied:
        _repository(database)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    after = source.stat()
    assert source.read_bytes() == b"synthetic-operator-content"
    assert after.st_mode == before.st_mode
    assert after.st_nlink == 2


def _generation(path: Path) -> int:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT generation FROM runner_mailbox_state WHERE singleton = 1"
        ).fetchone()
        assert row is not None and type(row[0]) is int
        return row[0]
    finally:
        connection.close()


def _rewrite_authenticated_frame(
    path: Path,
    repository: PersistentMailboxRepository,
    transform: Callable[[bytes], bytes],
) -> None:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT generation, nonce, ciphertext FROM runner_mailbox_state WHERE singleton = 1"
        ).fetchone()
        assert row is not None
        generation, nonce, ciphertext = row
        serialized = repository._aead.decrypt(  # type: ignore[attr-defined]
            nonce, ciphertext, repository._aad(generation)  # type: ignore[attr-defined]
        )
        mutated = transform(serialized)
        assert type(mutated) is bytes
        replacement_nonce = os.urandom(12)
        replacement = repository._aead.encrypt(  # type: ignore[attr-defined]
            replacement_nonce,
            mutated,
            repository._aad(generation),  # type: ignore[attr-defined]
        )
        connection.execute(
            "UPDATE runner_mailbox_state SET nonce = ?, ciphertext = ?, ciphertext_digest = ? "
            "WHERE singleton = 1",
            (replacement_nonce, replacement, hashlib.sha256(replacement).digest()),
        )
        connection.commit()
    finally:
        connection.close()


@pytest.mark.parametrize(
    "transform",
    [
        lambda value: value.replace(b'"version":1', b'"version":1,"version":1', 1),
        lambda value: value.replace(b'"version":1', b'"version":true', 1),
        lambda value: b" " + value,
    ],
    ids=["duplicate-key", "boolean-version", "noncanonical-whitespace"],
)
def test_authenticated_noncanonical_frames_fail_closed(
    tmp_path: Path, transform: Callable[[bytes], bytes]
) -> None:
    path = tmp_path / "runner.sqlite"
    repository = _repository(path)
    repository.close()
    _rewrite_authenticated_frame(path, repository, transform)
    with pytest.raises(MailboxError) as denied:
        _repository(path)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY


@pytest.mark.parametrize("corruption", ["lifecycle", "tombstone-time"])
def test_authenticated_semantically_impossible_frames_fail_closed(
    tmp_path: Path, corruption: str
) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    limits = MailboxLimits(
        terminal_retention=timedelta(microseconds=1),
        tombstone_retention=timedelta(days=1),
    )
    digester = Sha256CredentialDigester()
    repository = PersistentMailboxRepository(
        path,
        maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
        storage_key=_STORAGE_KEY,
        installation_epoch=_INSTALLATION_EPOCH,
        restore_epoch=_RESTORE_EPOCH,
        limits=limits,
    )
    service = RunnerMailboxService(repository, clock, digester, FixedCredentialSource())
    binding = _binding(service, _action())
    service.open_empty(
        binding,
        action_credential=ACTION_KEY,
        claim_credential=CLAIM_CREDENTIAL,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    if corruption == "lifecycle":
        service.offer(
            binding,
            _action(),
            action_key=ACTION_KEY,
            collection_credential=COLLECTION_CREDENTIAL,
        )
    else:
        service.abandon(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
        clock.current += timedelta(seconds=1)
        service.garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL)
    repository.close()

    def corrupt(value: bytes) -> bytes:
        decoded = json.loads(value)
        if corruption == "lifecycle":
            decoded["records"][0]["state"] = "empty"
        else:
            decoded["installation_last_seen_utc"] = None
            decoded["tombstones"][0]["expires_at"] = "2029-01-01T00:00:00+00:00"
        return json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()

    _rewrite_authenticated_frame(path, repository, corrupt)
    with pytest.raises(MailboxError) as denied:
        PersistentMailboxRepository(
            path,
            maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
            storage_key=_STORAGE_KEY,
            installation_epoch=_INSTALLATION_EPOCH,
            restore_epoch=_RESTORE_EPOCH,
            limits=limits,
        )
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY


def test_extreme_clock_tombstone_overflow_rolls_back_and_poison_closes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    service = _service(path, clock)
    binding = _binding(service, _action())
    service.open_empty(
        binding,
        action_credential=ACTION_KEY,
        claim_credential=CLAIM_CREDENTIAL,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    service.abandon(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    before = _generation(path)
    clock.current = datetime.max.replace(tzinfo=UTC)
    with pytest.raises(MailboxError) as denied:
        service.garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    repository = service._repository  # type: ignore[attr-defined]
    assert repository.recovery_required is True
    assert _generation(path) == before
    repository.close()
    repository.close()


def test_unchanged_unauthorized_denial_does_not_rewrite_frame(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    service, binding = _offered(path, clock, _action())
    before = _generation(path)
    with pytest.raises(MailboxError) as denied:
        service.snapshot(binding.mailbox_id, collection_credential=b"x" * 32)
    assert denied.value.denial is MailboxDenial.UNAUTHORIZED
    assert _generation(path) == before
    service._repository.close()  # type: ignore[attr-defined]


def test_begin_contention_is_finite_backpressure_and_does_not_poison(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    clock = StaticClock(datetime(2030, 1, 1, tzinfo=UTC))
    service, binding = _offered(path, clock, _action())
    blocker = sqlite3.connect(path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(MailboxError) as denied:
            service.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
        assert denied.value.denial is MailboxDenial.CONTENDED
        assert service._repository.recovery_required is False  # type: ignore[attr-defined]
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert (
        service.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL).state
        is MailboxState.OFFERED
    )
    service._repository.close()  # type: ignore[attr-defined]


@dataclass(slots=True)
class RaiseAfterCommit:
    armed: bool = False

    def before_commit(self) -> None:
        return None

    def after_commit(self) -> None:
        if self.armed:
            raise sqlite3.OperationalError("synthetic post-commit uncertainty")


def test_post_commit_uncertainty_poison_can_be_closed_idempotently(tmp_path: Path) -> None:
    hook = RaiseAfterCommit()
    digester = Sha256CredentialDigester()
    repository = PersistentMailboxRepository(
        tmp_path / "runner.sqlite",
        maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
        storage_key=_STORAGE_KEY,
        installation_epoch=_INSTALLATION_EPOCH,
        restore_epoch=_RESTORE_EPOCH,
        persistence_hook=hook,
    )
    service = RunnerMailboxService(
        repository,
        StaticClock(datetime(2030, 1, 1, tzinfo=UTC)),
        digester,
        FixedCredentialSource(),
    )
    binding = _binding(service, _action())
    hook.armed = True
    with pytest.raises(MailboxError) as uncertain:
        service.open_empty(
            binding,
            action_credential=ACTION_KEY,
            claim_credential=CLAIM_CREDENTIAL,
            collection_credential=COLLECTION_CREDENTIAL,
        )
    assert uncertain.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    assert repository.recovery_required is True
    repository.close()
    repository.close()


def test_oversize_outer_frame_fails_closed_before_authentication(tmp_path: Path) -> None:
    limits = MailboxLimits(
        max_mailboxes=1,
        max_total_active_material_bytes=1,
        max_total_evidence_bytes=1,
        max_total_committed_bytes=1,
        max_tombstones=1,
    )
    path = tmp_path / "runner.sqlite"
    digester = Sha256CredentialDigester()
    repository = PersistentMailboxRepository(
        path,
        maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
        storage_key=_STORAGE_KEY,
        installation_epoch=_INSTALLATION_EPOCH,
        restore_epoch=_RESTORE_EPOCH,
        limits=limits,
    )
    repository.close()
    oversized = b"z" * (8_388_608 + 20)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE runner_mailbox_state SET ciphertext = ?, ciphertext_digest = ? "
            "WHERE singleton = 1",
            (oversized, hashlib.sha256(oversized).digest()),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(MailboxError) as denied:
        PersistentMailboxRepository(
            path,
            maintenance_credential_digest=digester.digest(MAINTENANCE_CREDENTIAL),
            storage_key=_STORAGE_KEY,
            installation_epoch=_INSTALLATION_EPOCH,
            restore_epoch=_RESTORE_EPOCH,
            limits=limits,
        )
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY


def test_exhausted_generation_requires_operator_key_rotation(tmp_path: Path) -> None:
    path = tmp_path / "runner.sqlite"
    repository = _repository(path)
    repository.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE runner_mailbox_state SET generation = 100000000 WHERE singleton = 1"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(MailboxError) as denied:
        _repository(path)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
