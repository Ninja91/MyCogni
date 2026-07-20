"""SQLite-backed, encrypted persistence for the finite runner mailbox.

This adapter deliberately reuses the source-accepted mailbox state machine rather
than making a second, subtly different protocol implementation.  Each public
operation opens a SQLite ``BEGIN IMMEDIATE`` transaction, hydrates one verified
state frame, applies exactly one volatile-domain transition, and atomically
replaces that frame before commit.  SQLite, not an in-process lock, is the
cross-process serialization boundary.

The database contains only an AEAD-authenticated opaque frame.  Action bytes,
credentials, staged evidence, result bytes, tombstones, quota counters, and
time high-water are all inside it.  The caller supplies both installation and
restore epochs; changing either one makes an old/copy-substituted frame fail
closed.  This is a local-lite adapter, not a backup, key-provider, or physical
power-loss conformance claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Literal, NoReturn, Protocol, TypeVar, overload
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from services.runner_mailbox.domain import (
    MAX_EVIDENCE_ITEMS,
    ActionBinding,
    ClaimedAction,
    CollectionState,
    CommittedBundle,
    EvidenceSeal,
    EvidenceUpload,
    InjectedCrash,
    MailboxDenial,
    MailboxError,
    MailboxLimits,
    MailboxSnapshot,
    MailboxState,
)
from services.runner_mailbox.ports import Clock, FailureInjector
from services.runner_mailbox.volatile import (
    NoFailureInjector,
    VolatileMailboxRepository,
    _CommittedEvidenceManifest,
    _Record,
    _Tombstone,
    _WrappedEvidence,
    _WrappedResult,
)

_FRAME_VERSION = 1
_FRAME_CONTEXT = b"mycogni.runner-mailbox.sqlite-frame.v1\x00"
_OUTER_KEY_CONTEXT = b"mycogni.runner-mailbox.sqlite-frame-key.v1\x00"
_INNER_KEY_CONTEXT = b"mycogni.runner-mailbox.persistent-inner-key.v1\x00"
_CONFIG_CONTEXT = b"mycogni.runner-mailbox.persistent-config.v1\x00"
_MAX_FRAME_OVERHEAD = 8_388_608
# A state-changing transition consumes one independently random 96-bit outer
# nonce and at most one new inner retained-material nonce.  Operators must rotate
# the storage key and start a reviewed new lineage before this generation.
_MAX_FRAME_GENERATION = 100_000_000
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runner_mailbox_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    frame_version INTEGER NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    ciphertext_digest BLOB NOT NULL CHECK (length(ciphertext_digest) = 32)
) STRICT
"""
_T = TypeVar("_T")


class PersistenceTransactionHook(Protocol):
    """Test-only barrier on the durable commit/reply boundary."""

    def before_commit(self) -> None: ...

    def after_commit(self) -> None: ...


class _NoPersistenceTransactionHook:
    def before_commit(self) -> None:
        return None

    def after_commit(self) -> None:
        return None


class PersistentMailboxRepository:
    """Durable mailbox state with a real SQLite writer transaction boundary.

    ``storage_key`` is a separately provisioned exact 32-byte key.  It is never
    written to SQLite.  ``installation_epoch`` and ``restore_epoch`` are exact,
    pairwise-distinct 32-byte values supplied by the trusted owner; they bind the
    opaque state frame to this installation and recovery lineage.  There is no
    implicit ephemeral fallback because that would make restart safety illusory.
    """

    def __init__(
        self,
        database_path: Path,
        *,
        maintenance_credential_digest: bytes,
        storage_key: bytes,
        installation_epoch: bytes,
        restore_epoch: bytes,
        limits: MailboxLimits | None = None,
        failure_injector: FailureInjector | None = None,
        persistence_hook: PersistenceTransactionHook | None = None,
    ) -> None:
        self._path = self._validate_path(database_path)
        self._require_secret("maintenance_credential_digest", maintenance_credential_digest)
        self._require_secret("storage_key", storage_key)
        self._require_secret("installation_epoch", installation_epoch)
        self._require_secret("restore_epoch", restore_epoch)
        if len({maintenance_credential_digest, storage_key, installation_epoch, restore_epoch}) != 4:
            raise ValueError("persistent mailbox secrets and epochs must be pairwise distinct")
        self._maintenance_credential_digest = bytes(maintenance_credential_digest)
        root_key = bytes(storage_key)
        self._installation_epoch = bytes(installation_epoch)
        self._restore_epoch = bytes(restore_epoch)
        self._limits = limits or MailboxLimits()
        self._failure = failure_injector or NoFailureInjector()
        self._persistence_hook = persistence_hook or _NoPersistenceTransactionHook()
        self._outer_storage_key = self._derive_key(root_key, _OUTER_KEY_CONTEXT)
        self._inner_storage_key = self._derive_key(root_key, _INNER_KEY_CONTEXT)
        self._config_digest = self._configuration_fingerprint()
        self._aead = AESGCM(self._outer_storage_key)
        self._lock = RLock()
        self._owner_pid = os.getpid()
        self._poisoned = False
        self._closed = False
        try:
            self._main_file_identity = self._prepare_database_file()
            self._connection = sqlite3.connect(
                str(self._path), isolation_level=None, check_same_thread=False, timeout=1.0
            )
            self._validate_managed_files()
            self._configure_connection()
            self._connection.execute(_SCHEMA)
            self._validate_managed_files()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._row()
                if row is None:
                    repository = self._new_repository()
                    self._write_repository(repository, generation=0)
                else:
                    self._load_repository(row)
                self._commit_then_reply()
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        except (OSError, sqlite3.DatabaseError, ValueError, MailboxError):
            self._close_quietly()
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None

    def close(self) -> None:
        """Idempotently close; poisoned instances skip all mutating/checkpoint work."""

        if os.getpid() != self._owner_pid:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        with self._lock:
            if os.getpid() != self._owner_pid:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            if self._closed:
                return
            if self._poisoned:
                self._close_quietly()
                return
            try:
                checkpoint = self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if checkpoint != (0, 0, 0):
                    raise sqlite3.DatabaseError("checkpoint incomplete")
                self._connection.close()
                self._closed = True
            except sqlite3.DatabaseError:
                self._poisoned = True
                self._close_quietly()
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None

    @property
    def recovery_required(self) -> bool:
        """Finite operator disposition after an ambiguous storage boundary."""

        return self._poisoned

    def create(
        self,
        binding: ActionBinding,
        action_credential_digest: bytes,
        claim_credential_digest: bytes,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        return self._transition(
            lambda repository: repository.create(
                binding,
                action_credential_digest,
                claim_credential_digest,
                collection_credential_digest,
                clock,
            )
        )

    def offer(
        self,
        binding: ActionBinding,
        envelope_json: bytes,
        action_key: bytearray,
        action_credential_digest: bytes,
        collection_credential_digest: bytes,
        result_credential: bytearray,
        result_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        return self._transition(
            lambda repository: repository.offer(
                binding,
                envelope_json,
                action_key,
                action_credential_digest,
                collection_credential_digest,
                result_credential,
                result_credential_digest,
                clock,
            )
        )

    def claim(
        self, binding: ActionBinding, claim_credential_digest: bytes, clock: Clock
    ) -> ClaimedAction:
        return self._transition(lambda repository: repository.claim(binding, claim_credential_digest, clock))

    def stage_evidence(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        evidence: EvidenceUpload,
        clock: Clock,
    ) -> MailboxSnapshot:
        return self._transition(
            lambda repository: repository.stage_evidence(
                binding, result_credential_digest, evidence, clock
            )
        )

    def commit_result(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        result_json: bytes,
        evidence_seals: tuple[EvidenceSeal, ...],
        clock: Clock,
    ) -> MailboxSnapshot:
        return self._transition(
            lambda repository: repository.commit_result(
                binding, result_credential_digest, result_json, evidence_seals, clock
            )
        )

    def collect(
        self, mailbox_id: Any, collection_credential_digest: bytes, clock: Clock
    ) -> CommittedBundle:
        return self._transition(
            lambda repository: repository.collect(mailbox_id, collection_credential_digest, clock)
        )

    def acknowledge_collection(
        self, mailbox_id: Any, collection_credential_digest: bytes, clock: Clock
    ) -> MailboxSnapshot:
        return self._transition(
            lambda repository: repository.acknowledge_collection(
                mailbox_id, collection_credential_digest, clock
            )
        )

    def abandon(
        self, mailbox_id: Any, collection_credential_digest: bytes, clock: Clock
    ) -> MailboxSnapshot:
        return self._transition(
            lambda repository: repository.abandon(mailbox_id, collection_credential_digest, clock)
        )

    def expire(self, maintenance_credential_digest: bytes, clock: Clock) -> tuple[Any, ...]:
        return self._transition(
            lambda repository: repository.expire(maintenance_credential_digest, clock)
        )

    def garbage_collect(self, maintenance_credential_digest: bytes, clock: Clock) -> tuple[Any, ...]:
        return self._transition(
            lambda repository: repository.garbage_collect(maintenance_credential_digest, clock)
        )

    def snapshot(
        self, mailbox_id: Any, collection_credential_digest: bytes, clock: Clock
    ) -> MailboxSnapshot:
        return self._transition(
            lambda repository: repository.snapshot(mailbox_id, collection_credential_digest, clock)
        )

    def _transition(self, operation: Callable[[VolatileMailboxRepository], _T]) -> _T:
        """Persist every known protocol outcome before returning it to a caller.

        The source state machine intentionally converts some denials (notably a
        deadline) into terminal state.  Persisting after both successful and
        expected exceptional outcomes preserves that transition across process
        death.  An SQLite I/O or commit failure is never retried or returned as a
        normal protocol result: callers receive the finite unknown-outcome code.
        """

        if os.getpid() != self._owner_pid:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        with self._lock:
            self._require_live_owner()
            write_attempted = False
            try:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as error:
                    if self._is_contention(error):
                        raise MailboxError(MailboxDenial.CONTENDED) from None
                    raise
                row = self._row()
                if row is None:
                    raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
                generation, repository = self._load_repository(row)
                before = self._encode_state(repository)
                pending: MailboxError | InjectedCrash | None = None
                value: _T
                try:
                    value = operation(repository)
                except (MailboxError, InjectedCrash) as error:
                    pending = error
                after = self._encode_state(repository)
                if before == after:
                    self._connection.execute("ROLLBACK")
                else:
                    write_attempted = True
                    self._write_repository(repository, generation + 1)
                    self._commit_then_reply()
                if pending is not None:
                    raise pending
                return value
            except (MailboxError, InjectedCrash) as error:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                if isinstance(error, MailboxError) and error.denial is MailboxDenial.INTERNAL_UNCERTAINTY:
                    self._poisoned = True
                raise error
            except sqlite3.OperationalError as error:
                if not write_attempted and self._is_contention(error):
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    raise MailboxError(MailboxDenial.CONTENDED) from None
                self._poisoned = True
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None
            except (OSError, sqlite3.DatabaseError, ValueError):
                if not write_attempted and self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                self._poisoned = True
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None

    def _new_repository(self) -> VolatileMailboxRepository:
        return VolatileMailboxRepository(
            self._failure,
            maintenance_credential_digest=self._maintenance_credential_digest,
            limits=self._limits,
            storage_key=self._inner_storage_key,
        )

    def _commit_then_reply(self) -> None:
        """A test can terminate the process before or after the real commit."""

        self._persistence_hook.before_commit()
        self._connection.execute("COMMIT")
        self._persistence_hook.after_commit()

    def _row(self) -> tuple[int, int, bytes, bytes, bytes] | None:
        row = self._connection.execute(
            "SELECT frame_version, generation, nonce, ciphertext, ciphertext_digest "
            "FROM runner_mailbox_state WHERE singleton = 1"
        ).fetchone()
        if row is None:
            return None
        if (
            not isinstance(row, tuple)
            or len(row) != 5
            or type(row[0]) is not int
            or type(row[1]) is not int
            or not all(type(value) is bytes for value in row[2:])
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return row

    def _load_repository(self, row: tuple[int, int, bytes, bytes, bytes]) -> tuple[int, VolatileMailboxRepository]:
        frame_version, generation, nonce, ciphertext, ciphertext_digest = row
        if (
            frame_version != _FRAME_VERSION
            or generation < 0
            or generation >= _MAX_FRAME_GENERATION
            or len(nonce) != 12
            or len(ciphertext_digest) != 32
            or not ciphertext
            or len(ciphertext) > self._max_ciphertext_bytes()
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        if hashlib.sha256(ciphertext).digest() != ciphertext_digest:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        try:
            serialized = self._aead.decrypt(nonce, ciphertext, self._aad(generation))
            state = self._decode_state(serialized)
        except (InvalidTag, UnicodeDecodeError, ValueError, TypeError):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None
        records, tombstones, last_seen, total_active, total_evidence, total_committed = state
        repository = self._new_repository()
        repository._records = records
        repository._tombstones = tombstones
        repository._installation_last_seen_utc = last_seen
        repository._total_active_material_bytes = total_active
        repository._total_evidence_bytes = total_evidence
        repository._total_committed_bytes = total_committed
        # Authenticate every retained nested frame before any public operation can
        # observe, expire, erase, or mutate it.
        for record in repository._records.values():
            repository._validated_record_material(record)
        self._validate_repository_semantics(repository)
        return generation, repository

    def _write_repository(self, repository: VolatileMailboxRepository, generation: int) -> None:
        if generation < 0 or generation >= _MAX_FRAME_GENERATION:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        self._validate_repository_semantics(repository)
        serialized = self._encode_state(repository)
        if len(serialized) > self._max_serialized_bytes():
            raise MailboxError(MailboxDenial.OVERSIZE)
        nonce = os.urandom(12)
        ciphertext = self._aead.encrypt(nonce, serialized, self._aad(generation))
        self._connection.execute(
            "INSERT INTO runner_mailbox_state "
            "(singleton, frame_version, generation, nonce, ciphertext, ciphertext_digest) "
            "VALUES (1, ?, ?, ?, ?, ?) "
            "ON CONFLICT(singleton) DO UPDATE SET frame_version=excluded.frame_version, "
            "generation=excluded.generation, nonce=excluded.nonce, ciphertext=excluded.ciphertext, "
            "ciphertext_digest=excluded.ciphertext_digest",
            (_FRAME_VERSION, generation, nonce, ciphertext, hashlib.sha256(ciphertext).digest()),
        )

    @staticmethod
    def _committed_bytes(repository: VolatileMailboxRepository) -> int:
        total = 0
        for record in repository._records.values():
            if record.committed_at is not None:
                total += (record.result_envelope.byte_count if record.result_envelope else 0) + sum(
                    item.byte_count for item in record.evidence.values()
                )
        return total

    def _aad(self, generation: int) -> bytes:
        return (
            _FRAME_CONTEXT
            + _FRAME_VERSION.to_bytes(4, "big")
            + generation.to_bytes(8, "big")
            + self._installation_epoch
            + self._restore_epoch
            + self._config_digest
        )

    @staticmethod
    def _derive_key(root_key: bytes, context: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(root_key)

    def _configuration_fingerprint(self) -> bytes:
        limits = self._limits
        payload = b"|".join(
            str(value).encode("ascii")
            for value in (
                limits.max_mailboxes,
                limits.max_total_active_material_bytes,
                limits.max_total_evidence_bytes,
                limits.max_total_committed_bytes,
                limits.terminal_retention.days,
                limits.terminal_retention.seconds,
                limits.terminal_retention.microseconds,
                limits.tombstone_retention.days,
                limits.tombstone_retention.seconds,
                limits.tombstone_retention.microseconds,
                limits.max_tombstones,
            )
        )
        return hashlib.sha256(_CONFIG_CONTEXT + self._maintenance_credential_digest + payload).digest()

    def _require_live_owner(self) -> None:
        if self._poisoned or os.getpid() != self._owner_pid:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

    def _max_serialized_bytes(self) -> int:
        return (
            self._limits.max_total_active_material_bytes
            + self._limits.max_total_evidence_bytes
            + self._limits.max_total_committed_bytes
            + _MAX_FRAME_OVERHEAD
        )

    def _max_ciphertext_bytes(self) -> int:
        return self._max_serialized_bytes() + 16

    def _encode_state(self, repository: VolatileMailboxRepository) -> bytes:
        """Canonical, bounded, non-executable persistent codec.

        This intentionally does not pickle Python objects.  The explicit schema
        keeps restart data reviewable and rejects unknown/future fields until a
        migration is added.  The outer AEAD authenticates the canonical bytes.
        """

        records = repository._records
        tombstones = repository._tombstones
        payload: dict[str, object] = {
            "version": _FRAME_VERSION,
            "records": [self._record_wire(records[key]) for key in sorted(records, key=str)],
            "tombstones": [self._tombstone_wire(key, tombstones[key]) for key in sorted(tombstones, key=str)],
            "installation_last_seen_utc": self._datetime_wire(
                repository._installation_last_seen_utc
            ),
            "total_active_material_bytes": repository._total_active_material_bytes,
            "total_evidence_bytes": repository._total_evidence_bytes,
            "total_committed_bytes": repository._total_committed_bytes,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _decode_state(
        self, encoded: bytes
    ) -> tuple[dict[UUID, _Record], dict[UUID, _Tombstone], datetime | None, int, int, int]:
        if not encoded or len(encoded) > self._max_serialized_bytes():
            raise ValueError("invalid bounded state frame")
        decoded = json.loads(
            encoded,
            object_pairs_hook=self._unique_json_object,
            parse_constant=self._reject_json_constant,
        )
        if json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8") != encoded:
            raise ValueError("non-canonical state frame")
        self._exact_mapping(
            decoded,
            {
                "version",
                "records",
                "tombstones",
                "installation_last_seen_utc",
                "total_active_material_bytes",
                "total_evidence_bytes",
                "total_committed_bytes",
            },
        )
        if type(decoded["version"]) is not int or decoded["version"] != _FRAME_VERSION:
            raise ValueError("unsupported state frame")
        if not isinstance(decoded["records"], list) or not isinstance(decoded["tombstones"], list):
            raise ValueError("invalid state collections")
        if len(decoded["records"]) > self._limits.max_mailboxes or len(decoded["tombstones"]) > self._limits.max_tombstones:
            raise ValueError("state collection limit")
        records: dict[UUID, _Record] = {}
        for item in decoded["records"]:
            record = self._record_from_wire(item)
            if record.binding.mailbox_id in records:
                raise ValueError("duplicate record")
            records[record.binding.mailbox_id] = record
        tombstones: dict[UUID, _Tombstone] = {}
        for item in decoded["tombstones"]:
            mailbox_id, tombstone = self._tombstone_from_wire(item)
            if mailbox_id in records or mailbox_id in tombstones:
                raise ValueError("duplicate tombstone")
            tombstones[mailbox_id] = tombstone
        totals = tuple(decoded[key] for key in ("total_active_material_bytes", "total_evidence_bytes", "total_committed_bytes"))
        if any(type(value) is not int or value < 0 for value in totals):
            raise ValueError("invalid quota totals")
        return (
            records,
            tombstones,
            self._datetime_from_wire(decoded["installation_last_seen_utc"], nullable=True),
            totals[0],
            totals[1],
            totals[2],
        )

    def _record_wire(self, record: _Record) -> dict[str, object]:
        return {
            "binding": self._binding_wire(record.binding),
            "created_at": self._datetime_wire(record.created_at),
            "last_seen_utc": self._datetime_wire(record.last_seen_utc),
            "action_credential_digest": self._bytes_wire(record.action_credential_digest),
            "claim_credential_digest": self._bytes_wire(record.claim_credential_digest),
            "collection_credential_digest": self._bytes_wire(record.collection_credential_digest),
            "state": record.state.value,
            "collection_state": record.collection_state.value,
            "envelope_json": self._bytes_wire(record.envelope_json),
            "action_key": self._bytes_wire(record.action_key),
            "result_credential": self._bytes_wire(record.result_credential),
            "result_credential_digest": self._bytes_wire(record.result_credential_digest),
            "evidence": [self._evidence_wire(item) for _, item in sorted(record.evidence.items(), key=lambda pair: str(pair[0]))],
            "result_envelope": self._result_wire(record.result_envelope),
            "committed_evidence_manifest": self._manifest_wire(record.committed_evidence_manifest),
            "committed_at": self._datetime_wire(record.committed_at),
            "terminal_at": self._datetime_wire(record.terminal_at),
        }

    def _record_from_wire(self, value: object) -> _Record:
        self._exact_mapping(value, {
            "binding", "created_at", "last_seen_utc", "action_credential_digest", "claim_credential_digest", "collection_credential_digest", "state", "collection_state", "envelope_json", "action_key", "result_credential", "result_credential_digest", "evidence", "result_envelope", "committed_evidence_manifest", "committed_at", "terminal_at"
        })
        assert isinstance(value, dict)
        evidence_value = value["evidence"]
        if not isinstance(evidence_value, list) or len(evidence_value) > 64:
            raise ValueError("invalid evidence collection")
        evidence: dict[UUID, _WrappedEvidence] = {}
        for raw_item in evidence_value:
            item = self._evidence_from_wire(raw_item)
            if item.object_id in evidence:
                raise ValueError("duplicate evidence")
            evidence[item.object_id] = item
        return _Record(
            binding=self._binding_from_wire(value["binding"]),
            created_at=self._datetime_from_wire(value["created_at"]),
            last_seen_utc=self._datetime_from_wire(value["last_seen_utc"]),
            action_credential_digest=self._bytes_from_wire(value["action_credential_digest"], 32, 32),
            claim_credential_digest=self._bytes_from_wire(value["claim_credential_digest"], 32, 32),
            collection_credential_digest=self._bytes_from_wire(value["collection_credential_digest"], 32, 32),
            state=MailboxState(value["state"]),
            collection_state=CollectionState(value["collection_state"]),
            envelope_json=self._bytes_from_wire(value["envelope_json"], 1, 8_388_608, nullable=True),
            action_key=(bytearray(self._bytes_from_wire(value["action_key"], 32, 32)) if value["action_key"] is not None else None),
            result_credential=(bytearray(self._bytes_from_wire(value["result_credential"], 32, 128)) if value["result_credential"] is not None else None),
            result_credential_digest=self._bytes_from_wire(value["result_credential_digest"], 32, 32, nullable=True),
            evidence=evidence,
            result_envelope=self._result_from_wire(value["result_envelope"]),
            committed_evidence_manifest=self._manifest_from_wire(value["committed_evidence_manifest"]),
            committed_at=self._datetime_from_wire(value["committed_at"], nullable=True),
            terminal_at=self._datetime_from_wire(value["terminal_at"], nullable=True),
        )

    @staticmethod
    def _binding_wire(binding: ActionBinding) -> dict[str, object]:
        return {
            "mailbox_id": str(binding.mailbox_id), "action_id": str(binding.action_id), "intent_id": str(binding.intent_id), "attempt_id": str(binding.attempt_id), "connector_release": binding.connector_release, "capability": binding.capability, "selected_artifact_digest": binding.selected_artifact_digest, "dispatch_epoch": binding.dispatch_epoch, "fence": binding.fence, "authorization_epoch": binding.authorization_epoch, "claim_deadline_utc": binding.claim_deadline_utc.isoformat(), "deadline_utc": binding.deadline_utc.isoformat(), "wall_seconds": binding.wall_seconds, "response_bytes": binding.response_bytes, "envelope_digest": binding.envelope_digest,
        }

    def _binding_from_wire(self, value: object) -> ActionBinding:
        fields = {"mailbox_id", "action_id", "intent_id", "attempt_id", "connector_release", "capability", "selected_artifact_digest", "dispatch_epoch", "fence", "authorization_epoch", "claim_deadline_utc", "deadline_utc", "wall_seconds", "response_bytes", "envelope_digest"}
        self._exact_mapping(value, fields)
        assert isinstance(value, dict)
        return ActionBinding(
            mailbox_id=self._uuid(value["mailbox_id"]), action_id=self._uuid(value["action_id"]), intent_id=self._uuid(value["intent_id"]), attempt_id=self._uuid(value["attempt_id"]), connector_release=value["connector_release"], capability=value["capability"], selected_artifact_digest=value["selected_artifact_digest"], dispatch_epoch=value["dispatch_epoch"], fence=value["fence"], authorization_epoch=value["authorization_epoch"], claim_deadline_utc=self._datetime_from_wire(value["claim_deadline_utc"]), deadline_utc=self._datetime_from_wire(value["deadline_utc"]), wall_seconds=value["wall_seconds"], response_bytes=value["response_bytes"], envelope_digest=value["envelope_digest"],
        )

    @staticmethod
    def _evidence_wire(item: _WrappedEvidence) -> dict[str, object]:
        return {"object_id": str(item.object_id), "kind": item.kind, "byte_count": item.byte_count, "storage_digest": PersistentMailboxRepository._bytes_wire(item.storage_digest), "semantic_mac": PersistentMailboxRepository._bytes_wire(item.semantic_mac), "nonce": PersistentMailboxRepository._bytes_wire(item.nonce), "wrapped_payload": PersistentMailboxRepository._bytes_wire(item.wrapped_payload)}

    def _evidence_from_wire(self, value: object) -> _WrappedEvidence:
        self._exact_mapping(value, {"object_id", "kind", "byte_count", "storage_digest", "semantic_mac", "nonce", "wrapped_payload"})
        assert isinstance(value, dict)
        if type(value["kind"]) is not str or type(value["byte_count"]) is not int:
            raise ValueError("invalid evidence metadata")
        return _WrappedEvidence(self._uuid(value["object_id"]), value["kind"], value["byte_count"], self._bytes_from_wire(value["storage_digest"], 32, 32), self._bytes_from_wire(value["semantic_mac"], 32, 32), self._bytes_from_wire(value["nonce"], 12, 12), self._bytes_from_wire(value["wrapped_payload"], 16, self._limits.max_total_evidence_bytes + 128))

    @staticmethod
    def _result_wire(item: _WrappedResult | None) -> dict[str, object] | None:
        if item is None:
            return None
        return {"byte_count": item.byte_count, "storage_digest": PersistentMailboxRepository._bytes_wire(item.storage_digest), "semantic_mac": PersistentMailboxRepository._bytes_wire(item.semantic_mac), "nonce": PersistentMailboxRepository._bytes_wire(item.nonce), "wrapped_payload": PersistentMailboxRepository._bytes_wire(item.wrapped_payload)}

    def _result_from_wire(self, value: object) -> _WrappedResult | None:
        if value is None:
            return None
        self._exact_mapping(value, {"byte_count", "storage_digest", "semantic_mac", "nonce", "wrapped_payload"})
        assert isinstance(value, dict)
        if type(value["byte_count"]) is not int:
            raise ValueError("invalid result metadata")
        return _WrappedResult(value["byte_count"], self._bytes_from_wire(value["storage_digest"], 32, 32), self._bytes_from_wire(value["semantic_mac"], 32, 32), self._bytes_from_wire(value["nonce"], 12, 12), self._bytes_from_wire(value["wrapped_payload"], 16, 1_048_576 + 128))

    @staticmethod
    def _manifest_wire(item: _CommittedEvidenceManifest | None) -> dict[str, object] | None:
        if item is None:
            return None
        return {"item_count": item.item_count, "storage_digest": PersistentMailboxRepository._bytes_wire(item.storage_digest), "semantic_mac": PersistentMailboxRepository._bytes_wire(item.semantic_mac)}

    def _manifest_from_wire(self, value: object) -> _CommittedEvidenceManifest | None:
        if value is None:
            return None
        self._exact_mapping(value, {"item_count", "storage_digest", "semantic_mac"})
        assert isinstance(value, dict)
        if type(value["item_count"]) is not int:
            raise ValueError("invalid manifest")
        return _CommittedEvidenceManifest(value["item_count"], self._bytes_from_wire(value["storage_digest"], 32, 32), self._bytes_from_wire(value["semantic_mac"], 32, 32))

    @staticmethod
    def _tombstone_wire(mailbox_id: UUID, value: _Tombstone) -> dict[str, object]:
        return {"mailbox_id": str(mailbox_id), "created_at": value.created_at.isoformat(), "expires_at": value.expires_at.isoformat()}

    def _tombstone_from_wire(self, value: object) -> tuple[UUID, _Tombstone]:
        self._exact_mapping(value, {"mailbox_id", "created_at", "expires_at"})
        assert isinstance(value, dict)
        return self._uuid(value["mailbox_id"]), _Tombstone(self._datetime_from_wire(value["created_at"]), self._datetime_from_wire(value["expires_at"]))

    @staticmethod
    def _bytes_wire(value: bytes | bytearray | None) -> str | None:
        return None if value is None else b64encode(bytes(value)).decode("ascii")

    @overload
    @staticmethod
    def _bytes_from_wire(
        value: object, lower: int, upper: int, *, nullable: Literal[False] = False
    ) -> bytes: ...

    @overload
    @staticmethod
    def _bytes_from_wire(
        value: object, lower: int, upper: int, *, nullable: Literal[True]
    ) -> bytes | None: ...

    @staticmethod
    def _bytes_from_wire(value: object, lower: int, upper: int, *, nullable: bool = False) -> bytes | None:
        if value is None and nullable:
            return None
        if type(value) is not str:
            raise ValueError("invalid byte encoding")
        try:
            decoded = b64decode(value, validate=True)
        except (BinasciiError, ValueError):
            raise ValueError("invalid byte encoding") from None
        if not lower <= len(decoded) <= upper:
            raise ValueError("invalid byte bound")
        return decoded

    @staticmethod
    def _datetime_wire(value: datetime | None) -> str | None:
        return None if value is None else value.isoformat()

    @overload
    @staticmethod
    def _datetime_from_wire(value: object, *, nullable: Literal[False] = False) -> datetime: ...

    @overload
    @staticmethod
    def _datetime_from_wire(value: object, *, nullable: Literal[True]) -> datetime | None: ...

    @staticmethod
    def _datetime_from_wire(value: object, *, nullable: bool = False) -> datetime | None:
        if value is None and nullable:
            return None
        if type(value) is not str:
            raise ValueError("invalid datetime")
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() != UTC.utcoffset(parsed):
            raise ValueError("non-UTC datetime")
        return parsed

    @staticmethod
    def _uuid(value: object) -> UUID:
        if type(value) is not str:
            raise ValueError("invalid UUID")
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError("invalid UUID")
        return parsed

    @staticmethod
    def _exact_mapping(value: object, expected: set[str]) -> None:
        if type(value) is not dict or set(value) != expected:
            raise ValueError("unexpected state fields")

    @staticmethod
    def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate state field")
            value[key] = item
        return value

    @staticmethod
    def _reject_json_constant(value: str) -> NoReturn:
        del value
        raise ValueError("non-finite state number")

    def _validate_repository_semantics(self, repository: VolatileMailboxRepository) -> None:
        """Reject authenticated but impossible lifecycle, time and quota state."""

        active = evidence = committed = 0
        observed_credentials: set[bytes] = {self._maintenance_credential_digest}
        installation_high_water = repository._installation_last_seen_utc
        if (repository._records or repository._tombstones) and installation_high_water is None:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        for record in repository._records.values():
            if record.created_at > record.last_seen_utc or (
                installation_high_water is not None
                and record.last_seen_utc > installation_high_water
            ):
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            if record.created_at >= record.binding.claim_deadline_utc:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            for instant in (record.committed_at, record.terminal_at):
                if instant is not None and not record.created_at <= instant <= record.last_seen_utc:
                    raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

            credentials = (
                record.action_credential_digest,
                record.claim_credential_digest,
                record.collection_credential_digest,
            ) + ((record.result_credential_digest,) if record.result_credential_digest else ())
            if len(set(credentials)) != len(credentials) or any(
                credential in observed_credentials for credential in credentials
            ):
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            observed_credentials.update(credentials)

            active_material = (
                record.envelope_json,
                record.action_key,
                record.result_credential,
            )
            active += sum(len(value) for value in active_material if value is not None)
            evidence_bytes = sum(item.byte_count for item in record.evidence.values())
            evidence += evidence_bytes
            if record.committed_at is not None:
                committed += (record.result_envelope.byte_count if record.result_envelope else 0) + evidence_bytes
            if len(record.evidence) > MAX_EVIDENCE_ITEMS or evidence_bytes > record.binding.response_bytes:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

            no_active = all(value is None for value in active_material)
            no_committed = (
                record.result_envelope is None
                and record.committed_evidence_manifest is None
                and record.committed_at is None
            )
            if record.state is MailboxState.EMPTY:
                valid = (
                    record.collection_state is CollectionState.NONE
                    and no_active
                    and record.result_credential_digest is None
                    and not record.evidence
                    and no_committed
                    and record.terminal_at is None
                )
            elif record.state is MailboxState.OFFERED:
                valid = (
                    record.collection_state is CollectionState.NONE
                    and all(value is not None for value in active_material)
                    and record.result_credential_digest is not None
                    and not record.evidence
                    and no_committed
                    and record.terminal_at is None
                )
            elif record.state is MailboxState.CLAIMED_ONCE:
                valid = (
                    record.collection_state is CollectionState.NONE
                    and no_active
                    and record.result_credential_digest is not None
                    and no_committed
                    and record.terminal_at is None
                )
            elif record.state in {MailboxState.EXPIRED, MailboxState.ABANDONED}:
                valid = (
                    record.collection_state is CollectionState.NONE
                    and no_active
                    and record.result_credential_digest is None
                    and not record.evidence
                    and no_committed
                    and record.terminal_at is not None
                )
            else:
                valid = (
                    record.state is MailboxState.RESULT_COMMITTED
                    and record.collection_state
                    in {CollectionState.READY, CollectionState.DELIVERING, CollectionState.ACKNOWLEDGED}
                    and no_active
                    and record.result_credential_digest is None
                    and record.committed_at is not None
                    and (
                        record.collection_state is CollectionState.ACKNOWLEDGED
                    )
                    == (record.terminal_at is not None)
                )
                if (
                    valid
                    and record.collection_state is not CollectionState.ACKNOWLEDGED
                    and record.result_envelope is not None
                    and record.result_envelope.byte_count + evidence_bytes
                    > record.binding.response_bytes
                ):
                    valid = False
            if not valid:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

        for tombstone in repository._tombstones.values():
            if (
                tombstone.created_at >= tombstone.expires_at
                or tombstone.expires_at - tombstone.created_at
                != self._limits.tombstone_retention
                or installation_high_water is None
                or tombstone.created_at > installation_high_water
            ):
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        actual = (
            repository._total_active_material_bytes,
            repository._total_evidence_bytes,
            repository._total_committed_bytes,
        )
        if (
            actual != (active, evidence, committed)
            or active < 0
            or evidence < 0
            or committed < 0
            or active > self._limits.max_total_active_material_bytes
            or evidence > self._limits.max_total_evidence_bytes
            or committed > self._limits.max_total_committed_bytes
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

    def _configure_connection(self) -> None:
        statements = (
            "PRAGMA foreign_keys = ON",
            "PRAGMA journal_mode = WAL",
            "PRAGMA synchronous = FULL",
            "PRAGMA busy_timeout = 1000",
            "PRAGMA trusted_schema = OFF",
            "PRAGMA secure_delete = ON",
            "PRAGMA temp_store = MEMORY",
        )
        for statement in statements:
            self._connection.execute(statement)
        values = {
            "foreign_keys": 1,
            "journal_mode": "wal",
            "synchronous": 2,
            "trusted_schema": 0,
            "secure_delete": 1,
            "temp_store": 2,
        }
        for name, expected in values.items():
            row = self._connection.execute(f"PRAGMA {name}").fetchone()
            if row is None or row[0] != expected:
                raise sqlite3.DatabaseError("required SQLite pragma was not accepted")
        quick_check = self._connection.execute("PRAGMA quick_check").fetchone()
        if quick_check != ("ok",):
            raise sqlite3.DatabaseError("SQLite integrity check failed")

    def _prepare_database_file(self) -> tuple[int, int]:
        """Create or verify the main file before SQLite can open or mutate it."""

        self._validate_private_ancestors()
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        flags = os.O_RDWR | nofollow
        try:
            descriptor = os.open(self._path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = os.open(self._path, flags)
        try:
            info = os.fstat(descriptor)
            path_info = self._path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
            ):
                raise OSError("unsafe database file")
            return info.st_dev, info.st_ino
        finally:
            os.close(descriptor)

    def _validate_private_ancestors(self) -> None:
        parent = self._path.parent
        for candidate in (parent, *parent.parents):
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise OSError("unsafe database ancestor")
        parent_info = parent.stat()
        if parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o077:
            raise OSError("unsafe database directory")

    def _validate_managed_files(self) -> None:
        """Reject path substitution before and after SQLite configuration.

        This is intentionally narrower than the application-wide SQLite owner
        lease: runner state is its own sidecar store, so one transaction writer
        may be selected by SQLite across processes.  It still requires a private
        non-symlink parent and current-user-owned regular database sidecars.
        """

        self._validate_private_ancestors()
        for path in (self._path, self._path.with_name(self._path.name + "-wal"), self._path.with_name(self._path.name + "-shm")):
            if not path.exists():
                continue
            info = path.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise OSError("unsafe database file")
            if path == self._path and (info.st_dev, info.st_ino) != self._main_file_identity:
                raise OSError("database file changed identity")

    @staticmethod
    def _require_secret(name: str, value: bytes) -> None:
        if type(value) is not bytes or len(value) != 32:
            raise ValueError(f"{name} must be exact immutable 32-byte material")

    @staticmethod
    def _validate_path(value: Path) -> Path:
        if not isinstance(value, Path) or not value.is_absolute() or value.name in {"", ".", ".."}:
            raise ValueError("database_path must be an absolute file path")
        return value

    @staticmethod
    def _is_contention(error: sqlite3.Error) -> bool:
        code = getattr(error, "sqlite_errorcode", None)
        return type(code) is int and code & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}

    def _close_quietly(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None and not self._closed:
            with suppress(sqlite3.Error):
                connection.close()
        self._closed = True
