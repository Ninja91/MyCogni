"""Validated application service for the finite runner mailbox protocol."""

from __future__ import annotations

import hashlib
from datetime import datetime
from uuid import UUID

from pydantic import ValidationError

from connector_protocol import ActionEnvelope, Capability, ResultEnvelope
from connector_protocol.result import NextStepKind, ResultCode
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

_RESULTS_BY_CAPABILITY: dict[Capability, frozenset[ResultCode]] = {
    Capability.OBSERVE: frozenset(
        {
            ResultCode.NO_CANDIDATE,
            ResultCode.CANDIDATE_OBSERVED,
            ResultCode.AMBIGUOUS_CANDIDATES,
            ResultCode.CHALLENGE,
            ResultCode.INCONCLUSIVE,
            ResultCode.FAILED,
        }
    ),
    Capability.PREPARE: frozenset(
        {
            ResultCode.PAYLOAD_PREPARED,
            ResultCode.CHALLENGE,
            ResultCode.INCONCLUSIVE,
            ResultCode.FAILED,
        }
    ),
    Capability.SUBMIT: frozenset(
        {
            ResultCode.TRANSPORT_RECEIPT,
            ResultCode.BROKER_ACKNOWLEDGED,
            ResultCode.BROKER_PROCESSING,
            ResultCode.BROKER_ASSERTED_COMPLETE,
            ResultCode.PARTIAL_RESPONSE,
            ResultCode.BROKER_DENIED,
            ResultCode.CHALLENGE,
            ResultCode.INCONCLUSIVE,
            ResultCode.FAILED,
        }
    ),
    Capability.POLL: frozenset(
        {
            ResultCode.BROKER_PROCESSING,
            ResultCode.BROKER_ASSERTED_COMPLETE,
            ResultCode.PARTIAL_RESPONSE,
            ResultCode.BROKER_DENIED,
            ResultCode.CHALLENGE,
            ResultCode.INCONCLUSIVE,
            ResultCode.FAILED,
        }
    ),
    Capability.VERIFY: frozenset(
        {
            ResultCode.NO_CANDIDATE,
            ResultCode.CANDIDATE_OBSERVED,
            ResultCode.AMBIGUOUS_CANDIDATES,
            ResultCode.BROKER_PROCESSING,
            ResultCode.BROKER_ASSERTED_COMPLETE,
            ResultCode.PARTIAL_RESPONSE,
            ResultCode.BROKER_DENIED,
            ResultCode.CHALLENGE,
            ResultCode.INCONCLUSIVE,
            ResultCode.FAILED,
        }
    ),
}

_NEXT_BY_RESULT: dict[ResultCode, frozenset[NextStepKind]] = {
    ResultCode.NO_CANDIDATE: frozenset({NextStepKind.NONE}),
    ResultCode.CANDIDATE_OBSERVED: frozenset({NextStepKind.NONE, NextStepKind.USER_REVIEW}),
    ResultCode.AMBIGUOUS_CANDIDATES: frozenset({NextStepKind.USER_REVIEW}),
    ResultCode.PAYLOAD_PREPARED: frozenset({NextStepKind.NONE, NextStepKind.USER_REVIEW}),
    ResultCode.TRANSPORT_RECEIPT: frozenset({NextStepKind.NONE}),
    ResultCode.BROKER_ACKNOWLEDGED: frozenset({NextStepKind.NONE}),
    ResultCode.BROKER_PROCESSING: frozenset({NextStepKind.NONE}),
    ResultCode.BROKER_ASSERTED_COMPLETE: frozenset({NextStepKind.NONE, NextStepKind.USER_REVIEW}),
    ResultCode.PARTIAL_RESPONSE: frozenset({NextStepKind.NONE, NextStepKind.USER_REVIEW}),
    ResultCode.BROKER_DENIED: frozenset(
        {NextStepKind.NONE, NextStepKind.USER_REVIEW, NextStepKind.REAUTHORIZE}
    ),
    ResultCode.CHALLENGE: frozenset({NextStepKind.USER_REVIEW, NextStepKind.REAUTHORIZE}),
    ResultCode.INCONCLUSIVE: frozenset({NextStepKind.NONE, NextStepKind.USER_REVIEW}),
    ResultCode.FAILED: frozenset(
        {NextStepKind.NONE, NextStepKind.USER_REVIEW, NextStepKind.REAUTHORIZE}
    ),
}

# Import-time completeness prevents a newly added wire enum from failing open.
if set(_RESULTS_BY_CAPABILITY) != set(Capability) or set(_NEXT_BY_RESULT) != set(ResultCode):
    raise RuntimeError("runner result policy is not exhaustive")


class RunnerMailboxService:
    """Fail-closed boundary with distinct connector and trusted-core faces."""

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
        claim_deadline_utc: datetime,
    ) -> ActionBinding:
        """Bind canonical action bytes plus a separate earlier claim deadline."""

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
                claim_deadline_utc=claim_deadline_utc,
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
        action_credential: bytes,
        claim_credential: bytes,
        collection_credential: bytes,
    ) -> MailboxSnapshot:
        self._require_binding_type(binding)
        credentials = (action_credential, claim_credential, collection_credential)
        self._require_pairwise_credentials(credentials)
        if len(action_credential) != ACTION_KEY_BYTES:
            raise MailboxError(MailboxDenial.INVALID_INPUT)
        return self._repository.create(
            binding,
            self._credential_digester.digest(action_credential),
            self._credential_digester.digest(claim_credential),
            self._credential_digester.digest(collection_credential),
            self._clock,
        )

    def offer(
        self,
        binding: ActionBinding,
        action_json: bytes,
        *,
        action_key: bytes,
        collection_credential: bytes,
    ) -> MailboxSnapshot:
        """Credential-scoped trusted-core offer face."""

        self._require_binding_type(binding)
        action, canonical = self._parse_action(action_json)
        self._require_action_binding(binding, action, canonical)
        self._require_credential(action_key)
        if len(action_key) != ACTION_KEY_BYTES:
            raise MailboxError(MailboxDenial.INVALID_INPUT)
        self._require_credential(collection_credential)
        result_credential = self._credential_source.issue()
        self._require_pairwise_credentials((action_key, collection_credential, result_credential))
        return self._repository.offer(
            binding,
            canonical,
            bytearray(action_key),
            self._credential_digester.digest(action_key),
            self._credential_digester.digest(collection_credential),
            bytearray(result_credential),
            self._credential_digester.digest(result_credential),
            self._clock,
        )

    def claim(self, binding: ActionBinding, *, claim_credential: bytes) -> ClaimedAction:
        self._require_binding_type(binding)
        self._require_credential(claim_credential)
        return self._repository.claim(
            binding, self._credential_digester.digest(claim_credential), self._clock
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
        if len(evidence.payload) > MAX_EVIDENCE_BYTES:
            raise MailboxError(MailboxDenial.OVERSIZE)
        if self._sha256(evidence.payload) != evidence.payload_digest:
            raise MailboxError(MailboxDenial.DIGEST_MISMATCH)
        return self._repository.stage_evidence(
            binding,
            self._credential_digester.digest(result_credential),
            evidence,
            self._clock,
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
        self._require_result_policy(binding, result)
        seals = tuple(
            EvidenceSeal(
                object_id=item.mailbox_object_id,
                kind=item.kind,
                payload_digest=item.payload_digest,
                byte_count=item.byte_count,
            )
            for item in result.evidence
        )
        return self._repository.commit_result(
            binding,
            self._credential_digester.digest(result_credential),
            canonical,
            seals,
            self._clock,
        )

    def collect(self, mailbox_id: UUID, *, collection_credential: bytes) -> CommittedBundle:
        """Begin or resume idempotent delivery; data remains until explicit ack."""

        self._require_mailbox_id(mailbox_id)
        self._require_credential(collection_credential)
        return self._repository.collect(
            mailbox_id, self._credential_digester.digest(collection_credential), self._clock
        )

    def acknowledge_collection(
        self, mailbox_id: UUID, *, collection_credential: bytes
    ) -> MailboxSnapshot:
        self._require_mailbox_id(mailbox_id)
        self._require_credential(collection_credential)
        return self._repository.acknowledge_collection(
            mailbox_id, self._credential_digester.digest(collection_credential), self._clock
        )

    def abandon(self, mailbox_id: UUID, *, collection_credential: bytes) -> MailboxSnapshot:
        self._require_mailbox_id(mailbox_id)
        self._require_credential(collection_credential)
        return self._repository.abandon(
            mailbox_id, self._credential_digester.digest(collection_credential), self._clock
        )

    def expire_due(self, *, maintenance_credential: bytes) -> tuple[UUID, ...]:
        self._require_credential(maintenance_credential)
        return self._repository.expire(
            self._credential_digester.digest(maintenance_credential), self._clock
        )

    def garbage_collect(self, *, maintenance_credential: bytes) -> tuple[UUID, ...]:
        self._require_credential(maintenance_credential)
        return self._repository.garbage_collect(
            self._credential_digester.digest(maintenance_credential), self._clock
        )

    def snapshot(self, mailbox_id: UUID, *, collection_credential: bytes) -> MailboxSnapshot:
        """Credential-scoped trusted-core diagnostics face."""

        self._require_mailbox_id(mailbox_id)
        self._require_credential(collection_credential)
        return self._repository.snapshot(
            mailbox_id, self._credential_digester.digest(collection_credential)
        )

    @staticmethod
    def _require_result_policy(binding: ActionBinding, result: ResultEnvelope) -> None:
        capability = Capability(binding.capability)
        if result.result not in _RESULTS_BY_CAPABILITY[capability]:
            raise MailboxError(MailboxDenial.CAPABILITY_MISMATCH)
        if result.next.kind not in _NEXT_BY_RESULT[result.result]:
            raise MailboxError(MailboxDenial.CAPABILITY_MISMATCH)
        # RETRY_LATER is intentionally absent: reconciliation/retry belongs to
        # trusted core after it evaluates possible effect and uncertainty.

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
        binding: ActionBinding, action: ActionEnvelope, canonical: bytes
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

    @classmethod
    def _require_pairwise_credentials(cls, credentials: tuple[bytes, ...]) -> None:
        for credential in credentials:
            cls._require_credential(credential)
        if len(set(credentials)) != len(credentials):
            raise MailboxError(MailboxDenial.INVALID_INPUT)

    @staticmethod
    def _require_binding_type(binding: ActionBinding) -> None:
        if type(binding) is not ActionBinding:
            raise MailboxError(MailboxDenial.INVALID_INPUT)

    @staticmethod
    def _require_mailbox_id(mailbox_id: UUID) -> None:
        if type(mailbox_id) is not UUID or mailbox_id.version != 4:
            raise MailboxError(MailboxDenial.INVALID_INPUT)

    @staticmethod
    def _sha256(value: bytes) -> str:
        return "sha256:" + hashlib.sha256(value).hexdigest()
