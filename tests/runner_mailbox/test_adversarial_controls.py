"""Adversarial controls added after independent runner review."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from threading import Event, current_thread
from typing import Any
from uuid import UUID, uuid4

import pytest

from connector_protocol import ActionEnvelope, ResultEnvelope
from connector_protocol.manifest import Capability
from connector_protocol.result import NextStepKind, ResultCode
from services.runner_mailbox import (
    CollectionState,
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
    MailboxLimits,
    MailboxState,
    RunnerMailboxService,
    Sha256CredentialDigester,
    VolatileMailboxRepository,
)
from services.runner_mailbox.domain import ActionBinding, CrashPoint, InjectedCrash
from tests.runner_mailbox.conftest import (
    ACTION_KEY,
    ARTIFACT_DIGEST,
    CLAIM_CREDENTIAL,
    COLLECTION_CREDENTIAL,
    MAINTENANCE_CREDENTIAL,
    RESULT_CREDENTIAL,
    FakeClock,
    FixedCredentialSource,
    encode,
)

_REASON: dict[ResultCode, str] = {
    ResultCode.NO_CANDIDATE: "no_candidate",
    ResultCode.CANDIDATE_OBSERVED: "exact_match",
    ResultCode.AMBIGUOUS_CANDIDATES: "multiple_candidates",
    ResultCode.PAYLOAD_PREPARED: "preparation_complete",
    ResultCode.TRANSPORT_RECEIPT: "transport_accepted",
    ResultCode.BROKER_ACKNOWLEDGED: "broker_accepted",
    ResultCode.BROKER_PROCESSING: "broker_pending",
    ResultCode.BROKER_ASSERTED_COMPLETE: "broker_assertion",
    ResultCode.PARTIAL_RESPONSE: "partial_completion",
    ResultCode.BROKER_DENIED: "request_denied",
    ResultCode.CHALLENGE: "captcha_required",
    ResultCode.INCONCLUSIVE: "timeout",
    ResultCode.FAILED: "connector_error",
}

_ALLOWED_RESULTS: dict[Capability, frozenset[ResultCode]] = {
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

_ALLOWED_NEXT: dict[ResultCode, frozenset[NextStepKind]] = {
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


def _credentials(seed: int) -> tuple[bytes, bytes, bytes, bytes]:
    return tuple(bytes([seed + offset]) * 32 for offset in range(4))  # type: ignore[return-value]


def _repository(
    *, limits: MailboxLimits | None = None, failure: Any = None
) -> VolatileMailboxRepository:
    return VolatileMailboxRepository(
        failure,
        maintenance_credential_digest=Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL),
        limits=limits,
        storage_key=b"s" * 32,
    )


def test_maintenance_authority_is_mandatory_exact_and_never_implicitly_generated() -> None:
    with pytest.raises(TypeError):
        VolatileMailboxRepository()  # type: ignore[call-arg]
    for malformed in (None, bytearray(b"m" * 32), b"m" * 31, b"m" * 33):
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            VolatileMailboxRepository(
                maintenance_credential_digest=malformed,  # type: ignore[arg-type]
            )


def test_storage_key_is_generated_only_for_explicit_none() -> None:
    repository = VolatileMailboxRepository(
        maintenance_credential_digest=Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL),
        storage_key=None,
    )
    assert repository._records == {}  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "malformed",
    (
        b"",
        bytearray(),
        False,
        0,
        "",
        (),
        [],
        {},
        set(),
        memoryview(b""),
        b"x" * 31,
        b"x" * 33,
        bytearray(b"x" * 32),
        memoryview(b"x" * 32),
    ),
)
def test_falsey_or_malformed_explicit_storage_key_never_falls_back_to_generation(
    malformed: object,
) -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        VolatileMailboxRepository(
            maintenance_credential_digest=Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL),
            storage_key=malformed,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("role_index", (0, 1, 2, 3))
def test_maintenance_authority_is_separate_from_every_action_role_before_mutation(
    action_payload: dict[str, Any], clock: FakeClock, role_index: int
) -> None:
    credentials = (ACTION_KEY, CLAIM_CREDENTIAL, COLLECTION_CREDENTIAL, RESULT_CREDENTIAL)
    repository = VolatileMailboxRepository(
        maintenance_credential_digest=Sha256CredentialDigester().digest(credentials[role_index]),
        storage_key=b"s" * 32,
    )
    if role_index < 3:
        with pytest.raises(MailboxError) as denied:
            _configure(
                action_payload,
                clock,
                repository=repository,
                credentials=credentials,
                offer=False,
            )
        assert denied.value.denial is MailboxDenial.INVALID_INPUT
        assert repository._records == {}  # type: ignore[attr-defined]
    else:
        service, binding, _, _, collection_credential, _ = _configure(
            action_payload,
            clock,
            repository=repository,
            credentials=credentials,
            offer=False,
        )
        with pytest.raises(MailboxError) as denied:
            service.offer(
                binding,
                encode(action_payload),
                action_key=ACTION_KEY,
                collection_credential=collection_credential,
            )
        assert denied.value.denial is MailboxDenial.INVALID_INPUT
        assert (
            service.snapshot(binding.mailbox_id, collection_credential=collection_credential).state
            is MailboxState.EMPTY
        )


def _configure(
    action_payload: dict[str, Any],
    clock: FakeClock,
    *,
    repository: VolatileMailboxRepository | None = None,
    mailbox_id: UUID | None = None,
    credentials: tuple[bytes, bytes, bytes, bytes] = (
        ACTION_KEY,
        CLAIM_CREDENTIAL,
        COLLECTION_CREDENTIAL,
        RESULT_CREDENTIAL,
    ),
    offer: bool = True,
) -> tuple[RunnerMailboxService, ActionBinding, bytes, bytes, bytes, bytes]:
    action_key, claim_credential, collection_credential, result_credential = credentials
    service = RunnerMailboxService(
        repository or _repository(),
        clock,
        Sha256CredentialDigester(),
        FixedCredentialSource(result_credential),
    )
    action_json = encode(action_payload)
    binding = service.bind_action(
        mailbox_id or uuid4(),
        action_json,
        selected_artifact_digest=ARTIFACT_DIGEST,
        dispatch_epoch=0,
        claim_deadline_utc=clock.current + timedelta(minutes=1),
    )
    service.open_empty(
        binding,
        action_credential=action_key,
        claim_credential=claim_credential,
        collection_credential=collection_credential,
    )
    if offer:
        service.offer(
            binding,
            action_json,
            action_key=action_key,
            collection_credential=collection_credential,
        )
    return (
        service,
        binding,
        action_key,
        claim_credential,
        collection_credential,
        result_credential,
    )


def _result(binding: ActionBinding, result: ResultCode, next_kind: NextStepKind) -> bytes:
    return encode(
        {
            "protocol_version": 1,
            "action_id": str(binding.action_id),
            "attempt_id": str(binding.attempt_id),
            "result": result.value,
            "reason_code": _REASON[result],
            "evidence": [],
            "disclosures": [],
            "next": {"kind": next_kind.value},
        }
    )


def _result_with_evidence(binding: ActionBinding, evidence: tuple[EvidenceUpload, ...]) -> bytes:
    return encode(
        {
            "protocol_version": 1,
            "action_id": str(binding.action_id),
            "attempt_id": str(binding.attempt_id),
            "result": "candidate_observed",
            "reason_code": "exact_match",
            "evidence": [
                {
                    "kind": item.kind,
                    "mailbox_object_id": str(item.object_id),
                    "payload_digest": item.payload_digest,
                    "byte_count": len(item.payload),
                }
                for item in evidence
            ],
            "disclosures": [],
            "next": {"kind": "user_review"},
        }
    )


@pytest.mark.parametrize("capability", tuple(Capability))
@pytest.mark.parametrize("result", tuple(ResultCode))
@pytest.mark.parametrize("next_kind", tuple(NextStepKind))
def test_exhaustive_capability_result_next_matrix_is_fail_closed_and_nonmutating(
    action_payload: dict[str, Any],
    clock: FakeClock,
    capability: Capability,
    result: ResultCode,
    next_kind: NextStepKind,
) -> None:
    payload = deepcopy(action_payload)
    payload["capability"] = capability.value
    service, binding, _, claim_credential, collection_credential, result_credential = _configure(
        payload, clock
    )
    claim = service.claim(binding, claim_credential=claim_credential)
    expected = result in _ALLOWED_RESULTS[capability] and next_kind in _ALLOWED_NEXT[result]
    if expected:
        snapshot = service.commit_result(
            binding,
            _result(binding, result, next_kind),
            result_credential=claim.result_credential,
        )
        assert snapshot.state is MailboxState.RESULT_COMMITTED
    else:
        with pytest.raises(MailboxError) as denied:
            service.commit_result(
                binding,
                _result(binding, result, next_kind),
                result_credential=result_credential,
            )
        assert denied.value.denial is MailboxDenial.CAPABILITY_MISMATCH
        snapshot = service.snapshot(binding.mailbox_id, collection_credential=collection_credential)
        assert snapshot.state is MailboxState.CLAIMED_ONCE
        assert not snapshot.result_present


def test_blocked_repository_samples_deadline_after_lock_and_does_not_offer_stale_work(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    service, binding, action_key, _, collection_credential, _ = _configure(
        action_payload, clock, repository=repository, offer=False
    )
    started = Event()

    def blocked_offer() -> MailboxDenial | None:
        started.set()
        try:
            service.offer(
                binding,
                encode(action_payload),
                action_key=action_key,
                collection_credential=collection_credential,
            )
        except MailboxError as exc:
            return exc.denial
        return None

    repository._lock.acquire()  # type: ignore[attr-defined]
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(blocked_offer)
            assert started.wait(timeout=1)
            clock.current = binding.claim_deadline_utc
            repository._lock.release()  # type: ignore[attr-defined]
            assert future.result(timeout=2) is MailboxDenial.EXPIRED
    finally:
        # RLock has no portable ownership query; reacquire/release only if the
        # earlier release did not execute because the test raised.
        if not future.done():  # type: ignore[possibly-undefined]
            repository._lock.release()  # type: ignore[attr-defined]
    snapshot = service.snapshot(binding.mailbox_id, collection_credential=collection_credential)
    assert snapshot.state is MailboxState.EXPIRED
    assert not snapshot.claim_material_retained


@pytest.mark.parametrize(
    "credentials",
    [
        (ACTION_KEY, ACTION_KEY, COLLECTION_CREDENTIAL),
        (ACTION_KEY, CLAIM_CREDENTIAL, ACTION_KEY),
        (CLAIM_CREDENTIAL, CLAIM_CREDENTIAL, COLLECTION_CREDENTIAL),
    ],
)
def test_action_claim_collection_roles_are_pairwise_distinct_before_mutation(
    service: RunnerMailboxService,
    binding: ActionBinding,
    credentials: tuple[bytes, bytes, bytes],
) -> None:
    with pytest.raises(MailboxError) as denied:
        service.open_empty(
            binding,
            action_credential=credentials[0],
            claim_credential=credentials[1],
            collection_credential=credentials[2],
        )
    assert denied.value.denial is MailboxDenial.INVALID_INPUT


def test_exact_result_plus_evidence_budget_is_enforced_at_commit(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    evidence_id = uuid4()
    evidence_payload = b"0123456789"
    evidence_digest = "sha256:" + hashlib.sha256(evidence_payload).hexdigest()
    probe_payload = deepcopy(action_payload)
    probe_payload["budget"]["response_bytes"] = 4096
    probe_service, probe_binding, _, _, _, _ = _configure(probe_payload, clock)
    result_payload = {
        "protocol_version": 1,
        "action_id": str(probe_binding.action_id),
        "attempt_id": str(probe_binding.attempt_id),
        "result": "candidate_observed",
        "reason_code": "exact_match",
        "evidence": [
            {
                "kind": "raw_response",
                "mailbox_object_id": str(evidence_id),
                "payload_digest": evidence_digest,
                "byte_count": len(evidence_payload),
            }
        ],
        "disclosures": [],
        "next": {"kind": "user_review"},
    }
    canonical = (
        ResultEnvelope.model_validate_json(encode(result_payload), strict=True)
        .model_dump_json()
        .encode()
    )
    del probe_service

    for delta, allowed in ((0, True), (-1, False)):
        payload = deepcopy(action_payload)
        payload["budget"]["response_bytes"] = len(canonical) + len(evidence_payload) + delta
        service, binding, _, claim_credential, collection_credential, result_credential = (
            _configure(payload, clock)
        )
        service.claim(binding, claim_credential=claim_credential)
        upload = EvidenceUpload(
            object_id=evidence_id,
            kind="raw_response",
            payload_digest=evidence_digest,
            payload=evidence_payload,
        )
        service.stage_evidence(binding, result_credential=result_credential, evidence=upload)
        result_payload["action_id"] = str(binding.action_id)
        result_payload["attempt_id"] = str(binding.attempt_id)
        if allowed:
            service.commit_result(
                binding,
                encode(result_payload),
                result_credential=result_credential,
            )
        else:
            with pytest.raises(MailboxError) as denied:
                service.commit_result(
                    binding,
                    encode(result_payload),
                    result_credential=result_credential,
                )
            assert denied.value.denial is MailboxDenial.EVIDENCE_LIMIT
            assert (
                service.snapshot(
                    binding.mailbox_id, collection_credential=collection_credential
                ).state
                is MailboxState.CLAIMED_ONCE
            )


def test_scoped_core_faces_reject_wrong_credentials_without_state_mutation(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    service, binding, _, _, collection_credential, _ = _configure(action_payload, clock)
    with pytest.raises(MailboxError) as hidden:
        service.snapshot(binding.mailbox_id, collection_credential=b"x" * 32)
    assert hidden.value.denial is MailboxDenial.UNAUTHORIZED
    with pytest.raises(MailboxError) as sweep:
        service.expire_due(maintenance_credential=b"x" * 32)
    assert sweep.value.denial is MailboxDenial.UNAUTHORIZED
    assert (
        service.snapshot(binding.mailbox_id, collection_credential=collection_credential).state
        is MailboxState.OFFERED
    )


def test_cross_action_credential_reuse_is_rejected_installation_wide(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    _configure(
        action_payload,
        clock,
        repository=repository,
        credentials=_credentials(10),
        offer=False,
    )
    reused = (_credentials(10)[0], _credentials(20)[1], _credentials(20)[2], _credentials(20)[3])
    with pytest.raises(MailboxError) as denied:
        _configure(
            action_payload,
            clock,
            repository=repository,
            credentials=reused,
            offer=False,
        )
    assert denied.value.denial is MailboxDenial.REPLAY


def test_maintenance_separation_applies_to_later_cross_mailbox_provisioning(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    later = _credentials(30)
    repository = VolatileMailboxRepository(
        maintenance_credential_digest=Sha256CredentialDigester().digest(later[1]),
        storage_key=b"s" * 32,
    )
    first = _configure(
        action_payload,
        clock,
        repository=repository,
        credentials=_credentials(10),
        offer=False,
    )
    with pytest.raises(MailboxError) as denied:
        _configure(
            action_payload,
            clock,
            repository=repository,
            credentials=later,
            offer=False,
        )
    assert denied.value.denial is MailboxDenial.INVALID_INPUT
    service, binding, _, _, collection_credential, _ = first
    assert (
        service.snapshot(binding.mailbox_id, collection_credential=collection_credential).state
        is MailboxState.EMPTY
    )


def test_concurrent_evidence_saturation_has_one_winner_and_no_overcommit(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository(
        limits=MailboxLimits(
            max_mailboxes=2,
            max_total_evidence_bytes=20,
            max_total_committed_bytes=4096,
        )
    )
    configured = [
        _configure(
            action_payload,
            clock,
            repository=repository,
            credentials=_credentials(seed),
        )
        for seed in (10, 20)
    ]
    claims = [
        service.claim(binding, claim_credential=claim_credential)
        for service, binding, _, claim_credential, _, _ in configured
    ]

    def stage(index: int) -> MailboxDenial | None:
        service, binding, _, _, _, _ = configured[index]
        payload = bytes([index + 1]) * 20
        try:
            service.stage_evidence(
                binding,
                result_credential=claims[index].result_credential,
                evidence=EvidenceUpload(
                    object_id=uuid4(),
                    kind="raw_response",
                    payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
                    payload=payload,
                ),
            )
        except MailboxError as exc:
            return exc.denial
        return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(stage, (0, 1)))
    assert outcomes.count(None) == 1
    assert outcomes.count(MailboxDenial.QUOTA_EXCEEDED) == 1
    assert repository._total_evidence_bytes == 20  # type: ignore[attr-defined]


def test_concurrent_active_material_saturation_is_linearized_and_released_on_claim(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    canonical = (
        ActionEnvelope.model_validate_json(encode(action_payload), strict=True)
        .model_dump_json()
        .encode()
    )
    one_offer_bytes = len(canonical) + 64
    repository = _repository(
        limits=MailboxLimits(
            max_mailboxes=2,
            max_total_active_material_bytes=one_offer_bytes,
            max_total_evidence_bytes=1024,
            max_total_committed_bytes=4096,
        )
    )
    configured = [
        _configure(
            action_payload,
            clock,
            repository=repository,
            credentials=_credentials(seed),
            offer=False,
        )
        for seed in (10, 20)
    ]

    def offer(index: int) -> MailboxDenial | None:
        service, binding, action_key, _, collection_credential, _ = configured[index]
        try:
            service.offer(
                binding,
                encode(action_payload),
                action_key=action_key,
                collection_credential=collection_credential,
            )
        except MailboxError as exc:
            return exc.denial
        return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(offer, (0, 1)))
    assert outcomes.count(None) == 1
    assert outcomes.count(MailboxDenial.QUOTA_EXCEEDED) == 1
    assert repository._total_active_material_bytes == one_offer_bytes  # type: ignore[attr-defined]
    winner = outcomes.index(None)
    service, binding, _, claim_credential, _, _ = configured[winner]
    service.claim(binding, claim_credential=claim_credential)
    assert repository._total_active_material_bytes == 0  # type: ignore[attr-defined]


def test_small_host_default_limits_bound_every_installation_byte_pool() -> None:
    limits = MailboxLimits()
    assert limits.max_mailboxes == 64
    assert limits.max_total_active_material_bytes == 16_777_216
    assert limits.max_total_evidence_bytes == 67_108_864
    assert limits.max_total_committed_bytes == 67_108_864


def test_scoped_snapshot_samples_time_under_lock_and_expires_stale_offer(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    service, binding, _, _, collection_credential, _ = _configure(action_payload, clock)
    clock.current = binding.claim_deadline_utc
    snapshot = service.snapshot(binding.mailbox_id, collection_credential=collection_credential)
    assert snapshot.state is MailboxState.EXPIRED
    assert snapshot.observed_at_utc == clock.current
    assert snapshot.claim_deadline_utc == binding.claim_deadline_utc
    assert snapshot.result_deadline_utc == binding.deadline_utc


def test_gc_advances_survivor_time_high_water_and_rejects_rollback_claim(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    service, binding, _, claim_credential, collection_credential, _ = _configure(
        action_payload, clock
    )
    observed = binding.claim_deadline_utc + timedelta(seconds=1)
    clock.current = observed
    assert service.garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL) == ()
    clock.current = binding.claim_deadline_utc - timedelta(seconds=1)
    with pytest.raises(MailboxError) as rollback:
        service.claim(binding, claim_credential=claim_credential)
    assert rollback.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    clock.current = observed
    assert (
        service.snapshot(binding.mailbox_id, collection_credential=collection_credential).state
        is MailboxState.EXPIRED
    )


def test_empty_installation_gc_high_water_rejects_new_mailbox_clock_rollback(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    service = RunnerMailboxService(
        repository,
        clock,
        Sha256CredentialDigester(),
        FixedCredentialSource(),
    )
    observed = clock.current + timedelta(minutes=1)
    clock.current = observed
    assert service.garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL) == ()
    clock.current = observed - timedelta(seconds=1)
    with pytest.raises(MailboxError) as rollback:
        _configure(action_payload, clock, repository=repository, offer=False)
    assert rollback.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    assert repository._records == {}  # type: ignore[attr-defined]


@dataclass(slots=True)
class _GatedGcClock:
    current: datetime
    gc_observation: datetime
    rollback: datetime
    gc_entered: Event
    release_gc: Event
    gated: bool = False

    def now(self) -> datetime:
        if self.gated and current_thread().name.startswith("gc-sweep"):
            self.gc_entered.set()
            assert self.release_gc.wait(timeout=2)
            return self.gc_observation
        if self.gated:
            return self.rollback
        return self.current


def test_concurrent_gc_linearizes_high_water_before_waiting_rollback_claim(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    gated = _GatedGcClock(
        current=clock.current,
        gc_observation=clock.current + timedelta(seconds=30),
        rollback=clock.current + timedelta(seconds=1),
        gc_entered=Event(),
        release_gc=Event(),
    )
    service, binding, _, claim_credential, collection_credential, _ = _configure(
        action_payload,
        gated,  # type: ignore[arg-type]
    )
    gated.gated = True

    def sweep() -> tuple[UUID, ...]:
        return service.garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL)

    def claim() -> MailboxDenial | None:
        try:
            service.claim(binding, claim_credential=claim_credential)
        except MailboxError as exc:
            return exc.denial
        return None

    with (
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="gc-sweep") as sweeper,
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="rollback-claim") as claimer,
    ):
        sweep_future = sweeper.submit(sweep)
        assert gated.gc_entered.wait(timeout=1)
        claim_future = claimer.submit(claim)
        gated.release_gc.set()
        assert sweep_future.result(timeout=2) == ()
        assert claim_future.result(timeout=2) is MailboxDenial.INTERNAL_UNCERTAINTY

    gated.gated = False
    gated.current = gated.gc_observation
    snapshot = service.snapshot(binding.mailbox_id, collection_credential=collection_credential)
    assert snapshot.observed_at_utc == gated.gc_observation


def test_months_idle_unacknowledged_result_is_never_silently_collected_by_gc(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository(
        limits=MailboxLimits(
            max_mailboxes=1,
            max_total_evidence_bytes=1024,
            max_total_committed_bytes=4096,
            terminal_retention=timedelta(seconds=1),
            tombstone_retention=timedelta(minutes=1),
        )
    )
    service, binding, _, claim_credential, collection_credential, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    committed_json = _result(binding, ResultCode.CANDIDATE_OBSERVED, NextStepKind.USER_REVIEW)
    service.commit_result(
        binding,
        committed_json,
        result_credential=result_credential,
    )
    clock.current += timedelta(days=180)
    assert service.garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL) == ()
    visible = service.snapshot(binding.mailbox_id, collection_credential=collection_credential)
    assert visible.collection_state is CollectionState.READY
    assert visible.result_present
    redelivered = service.collect(binding.mailbox_id, collection_credential=collection_credential)
    expected = (
        ResultEnvelope.model_validate_json(committed_json, strict=True).model_dump_json().encode()
    )
    assert redelivered.result_json == expected
    assert repository._total_committed_bytes > 0  # type: ignore[attr-defined]


def test_sensitive_payload_is_wrapped_immediately_and_collection_requires_ack(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    service, binding, _, claim_credential, collection_credential, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    canary = b"raw-name-address-phone-pii-canary"
    upload = EvidenceUpload(
        object_id=uuid4(),
        kind="raw_response",
        payload_digest="sha256:" + hashlib.sha256(canary).hexdigest(),
        payload=canary,
    )
    service.stage_evidence(binding, result_credential=result_credential, evidence=upload)
    record = repository._records[binding.mailbox_id]  # type: ignore[attr-defined]
    wrapped = next(iter(record.evidence.values()))
    assert canary not in repr(record).encode()
    assert canary not in wrapped.wrapped_payload

    result_payload = {
        "protocol_version": 1,
        "action_id": str(binding.action_id),
        "attempt_id": str(binding.attempt_id),
        "result": "candidate_observed",
        "reason_code": "exact_match",
        "evidence": [
            {
                "kind": upload.kind,
                "mailbox_object_id": str(upload.object_id),
                "payload_digest": upload.payload_digest,
                "byte_count": len(upload.payload),
            }
        ],
        "disclosures": [],
        "next": {"kind": "user_review"},
    }
    result_json = encode(result_payload)
    service.commit_result(binding, result_json, result_credential=result_credential)
    assert record.result_envelope is not None
    assert result_json not in repr(record).encode()
    assert result_json not in record.result_envelope.wrapped_payload
    canonical_result = (
        ResultEnvelope.model_validate_json(result_json, strict=True).model_dump_json().encode()
    )
    plaintext_result_digest = hashlib.sha256(canonical_result).digest()
    retained_result = (
        record.result_envelope.storage_digest
        + record.result_envelope.semantic_mac
        + record.result_envelope.wrapped_payload
    )
    assert plaintext_result_digest not in retained_result
    assert plaintext_result_digest.hex().encode() not in retained_result
    first = service.collect(binding.mailbox_id, collection_credential=collection_credential)
    second = service.collect(binding.mailbox_id, collection_credential=collection_credential)
    assert first == second
    assert first.evidence[0].payload == canary
    before_ack = service.snapshot(binding.mailbox_id, collection_credential=collection_credential)
    assert before_ack.collection_state is CollectionState.DELIVERING
    assert before_ack.result_present
    after_ack = service.acknowledge_collection(
        binding.mailbox_id, collection_credential=collection_credential
    )
    assert after_ack.collection_state is CollectionState.ACKNOWLEDGED
    assert not after_ack.result_present
    assert after_ack.staged_evidence_count == 0


@pytest.mark.parametrize("tamper", ("wrapped_body", "storage_digest", "semantic_mac"))
def test_wrapped_result_authentication_detects_body_or_metadata_tampering(
    action_payload: dict[str, Any], clock: FakeClock, tamper: str
) -> None:
    repository = _repository()
    service, binding, _, claim_credential, collection_credential, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    service.commit_result(
        binding,
        _result(binding, ResultCode.CANDIDATE_OBSERVED, NextStepKind.USER_REVIEW),
        result_credential=result_credential,
    )
    wrapped = repository._records[binding.mailbox_id].result_envelope  # type: ignore[attr-defined]
    assert wrapped is not None
    if tamper == "wrapped_body":
        wrapped.wrapped_payload = (
            bytes([wrapped.wrapped_payload[0] ^ 1]) + wrapped.wrapped_payload[1:]
        )
        wrapped.storage_digest = hashlib.sha256(wrapped.wrapped_payload).digest()
    elif tamper == "storage_digest":
        wrapped.storage_digest = b"0" * 32
    else:
        wrapped.semantic_mac = b"0" * 32
    with pytest.raises(MailboxError) as denied:
        service.collect(binding.mailbox_id, collection_credential=collection_credential)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY


@pytest.mark.parametrize("tamper", ("wrapped_body", "storage_digest", "semantic_mac"))
def test_wrapped_evidence_authentication_detects_body_or_metadata_tampering(
    action_payload: dict[str, Any], clock: FakeClock, tamper: str
) -> None:
    repository = _repository()
    service, binding, _, claim_credential, _, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    payload = b"predictable-sensitive-evidence"
    upload = EvidenceUpload(
        object_id=uuid4(),
        kind="raw_response",
        payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )
    service.stage_evidence(binding, result_credential=result_credential, evidence=upload)
    wrapped = repository._records[binding.mailbox_id].evidence[upload.object_id]  # type: ignore[attr-defined]
    if tamper == "wrapped_body":
        wrapped.wrapped_payload = (
            bytes([wrapped.wrapped_payload[0] ^ 1]) + wrapped.wrapped_payload[1:]
        )
        wrapped.storage_digest = hashlib.sha256(wrapped.wrapped_payload).digest()
    elif tamper == "storage_digest":
        wrapped.storage_digest = b"0" * 32
    else:
        wrapped.semantic_mac = b"0" * 32
    result_payload = {
        "protocol_version": 1,
        "action_id": str(binding.action_id),
        "attempt_id": str(binding.attempt_id),
        "result": "candidate_observed",
        "reason_code": "exact_match",
        "evidence": [
            {
                "kind": upload.kind,
                "mailbox_object_id": str(upload.object_id),
                "payload_digest": upload.payload_digest,
                "byte_count": len(upload.payload),
            }
        ],
        "disclosures": [],
        "next": {"kind": "user_review"},
    }
    with pytest.raises(MailboxError) as denied:
        service.commit_result(binding, encode(result_payload), result_credential=result_credential)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY


def test_low_entropy_dictionary_guesses_do_not_match_retained_sensitive_metadata(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    service, binding, _, claim_credential, _, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    canary = b"john smith|123 main street"
    upload = EvidenceUpload(
        object_id=uuid4(),
        kind="raw_response",
        payload_digest="sha256:" + hashlib.sha256(canary).hexdigest(),
        payload=canary,
    )
    service.stage_evidence(binding, result_credential=result_credential, evidence=upload)
    record = repository._records[binding.mailbox_id]  # type: ignore[attr-defined]
    wrapped = record.evidence[upload.object_id]
    retained = (
        repr(record).encode()
        + wrapped.storage_digest
        + wrapped.semantic_mac
        + wrapped.wrapped_payload
    )
    guesses = (
        b"john smith",
        b"123 main street",
        b"john smith|123 main street",
        b"jane smith|123 main street",
    )
    for guess in guesses:
        digest = hashlib.sha256(guess).digest()
        assert digest not in retained
        assert digest.hex().encode() not in retained
    assert upload.payload_digest.encode() not in retained


def test_moved_evidence_slot_and_alias_result_reference_fail_before_result_mutation(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    service, binding, _, claim_credential, _, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    payload = b"alias-sensitive-evidence"
    upload = EvidenceUpload(
        object_id=uuid4(),
        kind="raw_response",
        payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )
    service.stage_evidence(binding, result_credential=result_credential, evidence=upload)
    record = repository._records[binding.mailbox_id]  # type: ignore[attr-defined]
    alias = uuid4()
    record.evidence[alias] = record.evidence.pop(upload.object_id)
    aliased_upload = EvidenceUpload(
        object_id=alias,
        kind=upload.kind,
        payload_digest=upload.payload_digest,
        payload=upload.payload,
    )
    with pytest.raises(MailboxError) as denied:
        service.commit_result(
            binding,
            _result_with_evidence(binding, (aliased_upload,)),
            result_credential=result_credential,
        )
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    assert record.state is MailboxState.CLAIMED_ONCE
    assert record.result_envelope is None


def test_swapping_two_authenticated_evidence_slots_fails_before_result_mutation(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    service, binding, _, claim_credential, _, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    uploads = tuple(
        EvidenceUpload(
            object_id=uuid4(),
            kind="raw_response",
            payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
            payload=payload,
        )
        for payload in (b"first-sensitive-evidence", b"second-sensitive-evidence")
    )
    for upload in uploads:
        service.stage_evidence(binding, result_credential=result_credential, evidence=upload)
    record = repository._records[binding.mailbox_id]  # type: ignore[attr-defined]
    first, second = uploads
    record.evidence[first.object_id], record.evidence[second.object_id] = (
        record.evidence[second.object_id],
        record.evidence[first.object_id],
    )
    with pytest.raises(MailboxError) as denied:
        service.commit_result(
            binding,
            _result_with_evidence(binding, uploads),
            result_credential=result_credential,
        )
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    assert record.state is MailboxState.CLAIMED_ONCE
    assert record.result_envelope is None


def test_collect_rejects_post_commit_evidence_slot_alias_without_delivery_mutation(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    service, binding, _, claim_credential, collection_credential, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    payload = b"collect-consistency-evidence"
    upload = EvidenceUpload(
        object_id=uuid4(),
        kind="raw_response",
        payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )
    service.stage_evidence(binding, result_credential=result_credential, evidence=upload)
    service.commit_result(
        binding,
        _result_with_evidence(binding, (upload,)),
        result_credential=result_credential,
    )
    record = repository._records[binding.mailbox_id]  # type: ignore[attr-defined]
    record.evidence[uuid4()] = record.evidence.pop(upload.object_id)
    with pytest.raises(MailboxError) as denied:
        service.collect(binding.mailbox_id, collection_credential=collection_credential)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    assert record.collection_state is CollectionState.READY
    assert record.result_envelope is not None


def test_wrapped_result_cannot_move_between_mailboxes_or_change_bundle_binding(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository()
    configured = tuple(
        _configure(
            action_payload,
            clock,
            repository=repository,
            credentials=_credentials(seed),
        )
        for seed in (10, 20)
    )
    for service, binding, _, claim_credential, _, _ in configured:
        result_credential = service.claim(
            binding, claim_credential=claim_credential
        ).result_credential
        service.commit_result(
            binding,
            _result(
                binding,
                ResultCode.CANDIDATE_OBSERVED,
                NextStepKind.USER_REVIEW,
            ),
            result_credential=result_credential,
        )
    first_service, first_binding, _, _, first_collection, _ = configured[0]
    first_bundle = first_service.collect(
        first_binding.mailbox_id, collection_credential=first_collection
    )
    assert first_bundle.binding == first_binding

    second_service, second_binding, _, _, second_collection, _ = configured[1]
    first_record = repository._records[first_binding.mailbox_id]  # type: ignore[attr-defined]
    second_record = repository._records[second_binding.mailbox_id]  # type: ignore[attr-defined]
    original_second_result = second_record.result_envelope
    second_record.result_envelope = first_record.result_envelope
    with pytest.raises(MailboxError) as denied:
        second_service.collect(second_binding.mailbox_id, collection_credential=second_collection)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    assert second_record.collection_state is CollectionState.READY

    second_record.result_envelope = original_second_result
    second_record.binding = replace(second_binding, fence=second_binding.fence + 1)
    with pytest.raises(MailboxError) as denied:
        second_service.collect(second_binding.mailbox_id, collection_credential=second_collection)
    assert denied.value.denial is MailboxDenial.INTERNAL_UNCERTAINTY
    assert second_record.collection_state is CollectionState.READY


def test_installation_mailbox_quota_authenticated_gc_and_tombstone_replay(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    limits = MailboxLimits(
        max_mailboxes=1,
        max_total_evidence_bytes=1024,
        max_total_committed_bytes=1024,
        terminal_retention=timedelta(seconds=1),
        tombstone_retention=timedelta(minutes=5),
        max_tombstones=2,
    )
    repository = _repository(limits=limits)
    first_id = uuid4()
    first = _configure(
        action_payload,
        clock,
        repository=repository,
        mailbox_id=first_id,
        offer=False,
        credentials=_credentials(10),
    )
    with pytest.raises(MailboxError) as full:
        _configure(
            action_payload,
            clock,
            repository=repository,
            mailbox_id=uuid4(),
            offer=False,
            credentials=_credentials(20),
        )
    assert full.value.denial is MailboxDenial.QUOTA_EXCEEDED

    service, binding, _, _, collection_credential, _ = first
    clock.current = binding.claim_deadline_utc
    service.expire_due(maintenance_credential=MAINTENANCE_CREDENTIAL)
    clock.current += timedelta(seconds=1)
    with pytest.raises(MailboxError) as unauthorized:
        service.garbage_collect(maintenance_credential=b"x" * 32)
    assert unauthorized.value.denial is MailboxDenial.UNAUTHORIZED
    assert service.garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL) == (first_id,)
    with pytest.raises(MailboxError) as replay:
        service.open_empty(
            binding,
            action_credential=_credentials(30)[0],
            claim_credential=_credentials(30)[1],
            collection_credential=_credentials(30)[2],
        )
    assert replay.value.denial is MailboxDenial.REPLAY
    with pytest.raises(MailboxError) as gone:
        service.snapshot(first_id, collection_credential=collection_credential)
    assert gone.value.denial is MailboxDenial.REPLAY


def test_tombstone_capacity_never_shortens_configured_mailbox_replay_horizon(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository(
        limits=MailboxLimits(
            max_mailboxes=2,
            max_total_active_material_bytes=4096,
            max_total_evidence_bytes=1024,
            max_total_committed_bytes=4096,
            terminal_retention=timedelta(seconds=1),
            tombstone_retention=timedelta(days=30),
            max_tombstones=1,
        )
    )
    configured = [
        _configure(
            action_payload,
            clock,
            repository=repository,
            mailbox_id=uuid4(),
            credentials=_credentials(seed),
            offer=False,
        )
        for seed in (10, 20)
    ]
    clock.current = configured[0][1].claim_deadline_utc
    configured[0][0].expire_due(maintenance_credential=MAINTENANCE_CREDENTIAL)
    clock.current += timedelta(seconds=1)
    removed = configured[0][0].garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL)
    assert len(removed) == 1
    assert configured[0][0].garbage_collect(maintenance_credential=MAINTENANCE_CREDENTIAL) == ()

    removed_id = removed[0]
    retained = next(item for item in configured if item[1].mailbox_id != removed_id)
    with pytest.raises(MailboxError) as tombstoned:
        configured[0][0].snapshot(
            removed_id,
            collection_credential=next(
                item[4] for item in configured if item[1].mailbox_id == removed_id
            ),
        )
    assert tombstoned.value.denial is MailboxDenial.REPLAY
    assert (
        retained[0].snapshot(retained[1].mailbox_id, collection_credential=retained[4]).state
        is MailboxState.EXPIRED
    )
    assert len(repository._tombstones) == 1  # type: ignore[attr-defined]
    assert len(repository._records) == 1  # type: ignore[attr-defined]


@dataclass(slots=True)
class _AckCrash:
    fired: bool = False

    def hit(self, point: CrashPoint) -> None:
        if point is CrashPoint.AFTER_COLLECTION_ACK and not self.fired:
            self.fired = True
            raise InjectedCrash(point)


def test_post_ack_crash_is_idempotently_recoverable_without_redelivery(
    action_payload: dict[str, Any], clock: FakeClock
) -> None:
    repository = _repository(failure=_AckCrash())
    service, binding, _, claim_credential, collection_credential, _ = _configure(
        action_payload, clock, repository=repository
    )
    result_credential = service.claim(binding, claim_credential=claim_credential).result_credential
    service.commit_result(
        binding,
        _result(binding, ResultCode.CANDIDATE_OBSERVED, NextStepKind.USER_REVIEW),
        result_credential=result_credential,
    )
    service.collect(binding.mailbox_id, collection_credential=collection_credential)
    with pytest.raises(InjectedCrash):
        service.acknowledge_collection(
            binding.mailbox_id, collection_credential=collection_credential
        )
    recovered = service.acknowledge_collection(
        binding.mailbox_id, collection_credential=collection_credential
    )
    assert recovered.collection_state is CollectionState.ACKNOWLEDGED
    with pytest.raises(MailboxError) as replay:
        service.collect(binding.mailbox_id, collection_credential=collection_credential)
    assert replay.value.denial is MailboxDenial.REPLAY


def test_wall_budget_is_metadata_while_claim_and_result_deadlines_are_distinct(
    binding: ActionBinding,
) -> None:
    assert binding.claim_deadline_utc < binding.deadline_utc
    assert binding.wall_seconds == 30
    assert binding.deadline_utc - binding.claim_deadline_utc == timedelta(minutes=4)
