"""Validated application service for the pure SPIKE-RUNNER mailbox protocol."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from pydantic import ValidationError

from connector_protocol import ActionEnvelope, ResultEnvelope
from services.runner_mailbox.domain import (
    ACTION_KEY_BYTES,
    MAX_ACTION_ENVELOPE_BYTES,
    MAX_CREDENTIAL_BYTES,
    MAX_EVIDENCE_BYTES,
    MAX_RESULT_ENVELOPE_BYTES,
    MIN_CREDENTIAL_BYTES,
    ActionBinding,
    ClaimedAction,
    CommittedBundle,
    EvidenceSeal,
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
    MailboxSnapshot,
)
from services.runner_mailbox.ports import (
    Clock,
    CredentialDigester,
    CredentialSource,
    MailboxRepository,
)


class RunnerMailboxService:
    """Fail-closed boundary with no network, filesystem, runtime, or outcome authority."""

    def __init__(
        self,
        repository: MailboxRepository,
        clock: Clock,
        credential_digester: CredentialDigester,
        credential_source: CredentialSource,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._credential_digester = credential_digester
        self._credential_source = credential_source

    @staticmethod
    def bind_action(
        mailbox_id: UUID,
        action_json: bytes,
        *,
        selected_artifact_digest: str,
        dispatch_epoch: int,
    ) -> ActionBinding:
        """Validate and independently bind exact canonical action bytes to an artifact."""

        action, canonical = RunnerMailboxService._parse_action(action_json)
        try:
            return ActionBinding(
                mailbox_id=mailbox_id,
                action_id=action.action_id,
                intent_id=action.intent_id,
                attempt_id=action.attempt_id,
                connector_release=action.connector_release,
                capability=action.capability.value,
                selected_artifact_digest=selected_artifact_digest,
                dispatch_epoch=dispatch_epoch,
                fence=action.fence,
                authorization_epoch=action.authorization_epoch,
                deadline_utc=action.deadline_utc,
                wall_seconds=action.budget.wall_seconds,
                response_bytes=action.budget.response_bytes,
                envelope_digest=RunnerMailboxService._sha256(canonical),
            )
        except (TypeError, ValueError):
            raise MailboxError(MailboxDenial.INVALID_INPUT) from None

    def open_empty(
        self,
        binding: ActionBinding,
        *,
        claim_credential: bytes,
        collection_credential: bytes,
    ) -> MailboxSnapshot:
        self._require_binding_type(binding)
        self._require_credential(claim_credential)
        self._require_credential(collection_credential)
        self._require_distinct_credentials(claim_credential, collection_credential)
        now = self._now()
        if now >= binding.deadline_utc:
            raise MailboxError(MailboxDenial.EXPIRED)
        return self._repository.create(
            binding,
            self._credential_digester.digest(claim_credential),
            self._credential_digester.digest(collection_credential),
            now,
        )

    def offer(
        self,
        binding: ActionBinding,
        action_json: bytes,
        *,
        action_key: bytes,
    ) -> MailboxSnapshot:
        self._require_binding_type(binding)
        action, canonical = self._parse_action(action_json)
        self._require_action_binding(binding, action, canonical)
        if type(action_key) is not bytes or len(action_key) != ACTION_KEY_BYTES:
            raise MailboxError(MailboxDenial.INVALID_INPUT)
        result_credential = self._credential_source.issue()
        self._require_credential(result_credential)
        self._require_distinct_credentials(action_key, result_credential)
        now = self._now()
        if now >= binding.deadline_utc:
            self._repository.expire(now)
            raise MailboxError(MailboxDenial.EXPIRED)
        return self._repository.offer(
            binding,
            canonical,
            bytearray(action_key),
            bytearray(result_credential),
            self._credential_digester.digest(result_credential),
            now,
        )

    def claim(
        self,
        binding: ActionBinding,
        *,
        claim_credential: bytes,
    ) -> ClaimedAction:
        self._require_binding_type(binding)
        self._require_credential(claim_credential)
        return self._repository.claim(
            binding,
            self._credential_digester.digest(claim_credential),
            self._now(),
        )

    def stage_evidence(
        self,
        binding: ActionBinding,
        *,
        result_credential: bytes,
        evidence: EvidenceUpload,
    ) -> MailboxSnapshot:
        self._require_binding_type(binding)
        self._require_credential(result_credential)
        if type(evidence) is not EvidenceUpload:
            raise MailboxError(MailboxDenial.INVALID_INPUT)
        if len(evidence.ciphertext) > MAX_EVIDENCE_BYTES:
            raise MailboxError(MailboxDenial.OVERSIZE)
        if self._sha256(evidence.ciphertext) != evidence.ciphertext_digest:
            raise MailboxError(MailboxDenial.DIGEST_MISMATCH)
        return self._repository.stage_evidence(
            binding,
            self._credential_digester.digest(result_credential),
            evidence,
            self._now(),
        )

    def commit_result(
        self,
        binding: ActionBinding,
        result_json: bytes,
        *,
        result_credential: bytes,
    ) -> MailboxSnapshot:
        self._require_binding_type(binding)
        self._require_credential(result_credential)
        result, canonical = self._parse_result(result_json)
        if result.action_id != binding.action_id or result.attempt_id != binding.attempt_id:
            raise MailboxError(MailboxDenial.RESULT_MISMATCH)
        seals = tuple(
            EvidenceSeal(
                object_id=item.mailbox_object_id,
                kind=item.kind,
                ciphertext_digest=item.ciphertext_digest,
                byte_count=item.byte_count,
            )
            for item in result.evidence
        )
        return self._repository.commit_result(
            binding,
            self._credential_digester.digest(result_credential),
            canonical,
            seals,
            self._now(),
        )

    def collect(
        self,
        mailbox_id: UUID,
        *,
        collection_credential: bytes,
    ) -> CommittedBundle:
        self._require_mailbox_id(mailbox_id)
        self._require_credential(collection_credential)
        return self._repository.collect(
            mailbox_id,
            self._credential_digester.digest(collection_credential),
        )

    def abandon(
        self,
        mailbox_id: UUID,
        *,
        collection_credential: bytes,
    ) -> MailboxSnapshot:
        self._require_mailbox_id(mailbox_id)
        self._require_credential(collection_credential)
        return self._repository.abandon(
            mailbox_id,
            self._credential_digester.digest(collection_credential),
            self._now(),
        )

    def expire_due(self) -> tuple[UUID, ...]:
        return self._repository.expire(self._now())

    def snapshot(self, mailbox_id: UUID) -> MailboxSnapshot:
        self._require_mailbox_id(mailbox_id)
        return self._repository.snapshot(mailbox_id)

    @staticmethod
    def _parse_action(action_json: bytes) -> tuple[ActionEnvelope, bytes]:
        if type(action_json) is not bytes:
            raise MailboxError(MailboxDenial.INVALID_INPUT)
        if not action_json or len(action_json) > MAX_ACTION_ENVELOPE_BYTES:
            raise MailboxError(MailboxDenial.OVERSIZE)
        try:
            action = ActionEnvelope.model_validate_json(action_json, strict=True)
        except ValidationError:
            raise MailboxError(MailboxDenial.INVALID_INPUT) from None
        return action, action.model_dump_json().encode("utf-8")

    @staticmethod
    def _parse_result(result_json: bytes) -> tuple[ResultEnvelope, bytes]:
        if type(result_json) is not bytes:
            raise MailboxError(MailboxDenial.INVALID_INPUT)
        if not result_json or len(result_json) > MAX_RESULT_ENVELOPE_BYTES:
            raise MailboxError(MailboxDenial.OVERSIZE)
        try:
            result = ResultEnvelope.model_validate_json(result_json, strict=True)
        except ValidationError:
            raise MailboxError(MailboxDenial.INVALID_INPUT) from None
        return result, result.model_dump_json().encode("utf-8")

    @staticmethod
    def _require_action_binding(
        binding: ActionBinding,
        action: ActionEnvelope,
        canonical: bytes,
    ) -> None:
        if (
            action.action_id != binding.action_id
            or action.intent_id != binding.intent_id
            or action.attempt_id != binding.attempt_id
            or action.connector_release != binding.connector_release
            or action.capability.value != binding.capability
            or action.fence != binding.fence
            or action.authorization_epoch != binding.authorization_epoch
            or action.deadline_utc != binding.deadline_utc
            or action.budget.wall_seconds != binding.wall_seconds
            or action.budget.response_bytes != binding.response_bytes
            or RunnerMailboxService._sha256(canonical) != binding.envelope_digest
        ):
            raise MailboxError(MailboxDenial.BINDING_MISMATCH)

    @staticmethod
    def _require_credential(credential: bytes) -> None:
        if (
            type(credential) is not bytes
            or not MIN_CREDENTIAL_BYTES <= len(credential) <= MAX_CREDENTIAL_BYTES
        ):
            raise MailboxError(MailboxDenial.INVALID_INPUT)

    @staticmethod
    def _require_distinct_credentials(first: bytes, second: bytes) -> None:
        if first == second:
            raise MailboxError(MailboxDenial.INVALID_INPUT)

    @staticmethod
    def _require_binding_type(binding: ActionBinding) -> None:
        if type(binding) is not ActionBinding:
            raise MailboxError(MailboxDenial.INVALID_INPUT)

    @staticmethod
    def _require_mailbox_id(mailbox_id: UUID) -> None:
        if type(mailbox_id) is not UUID or mailbox_id.version != 4:
            raise MailboxError(MailboxDenial.INVALID_INPUT)

    def _now(self) -> datetime:
        now = self._clock.now()
        if type(now) is not datetime or now.utcoffset() != UTC.utcoffset(now):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return now

    @staticmethod
    def _sha256(value: bytes) -> str:
        return "sha256:" + hashlib.sha256(value).hexdigest()
