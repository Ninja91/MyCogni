"""Restart and cross-process evidence for the persistent runner mailbox adapter."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty
from uuid import UUID

import pytest

from services.runner_mailbox import (
    ActionBinding,
    CollectionState,
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
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
