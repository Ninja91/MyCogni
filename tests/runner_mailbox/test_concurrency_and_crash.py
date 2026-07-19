"""Atomic single-claim/commit behavior under concurrency and injected crashes."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest

from services.runner_mailbox import (
    EvidenceUpload,
    MailboxError,
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
    EVIDENCE_ID,
    MAILBOX_ID,
    MAINTENANCE_CREDENTIAL,
    FakeClock,
    FixedCredentialSource,
    encode,
)


class OneShotCrash:
    def __init__(self, target: CrashPoint) -> None:
        self.target = target
        self.triggered = False

    def hit(self, point: CrashPoint) -> None:
        if point is self.target and not self.triggered:
            self.triggered = True
            raise InjectedCrash(point)


def _configured_service(
    action_json: bytes,
    clock: FakeClock,
    point: CrashPoint,
) -> tuple[RunnerMailboxService, ActionBinding]:
    service = RunnerMailboxService(
        VolatileMailboxRepository(
            OneShotCrash(point),
            maintenance_credential_digest=Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL),
        ),
        clock,
        Sha256CredentialDigester(),
        FixedCredentialSource(),
    )
    binding = service.bind_action(
        UUID(MAILBOX_ID),
        action_json,
        selected_artifact_digest=ARTIFACT_DIGEST,
        dispatch_epoch=0,
        claim_deadline_utc=clock.current.replace(minute=1),
    )
    service.open_empty(
        binding,
        action_credential=ACTION_KEY,
        claim_credential=CLAIM_CREDENTIAL,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    service.offer(
        binding,
        action_json,
        action_key=ACTION_KEY,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    return service, binding


def _evidence() -> EvidenceUpload:
    payload = b"untrusted crash-boundary evidence"
    return EvidenceUpload(
        object_id=UUID(EVIDENCE_ID),
        kind="sanitized_html",
        payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )


def _result(evidence: EvidenceUpload) -> bytes:
    return encode(
        {
            "protocol_version": 1,
            "action_id": "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c",
            "attempt_id": "26fc0371-5b37-4452-8569-95564cc83edb",
            "result": "candidate_observed",
            "reason_code": "exact_match",
            "evidence": [
                {
                    "kind": evidence.kind,
                    "mailbox_object_id": str(evidence.object_id),
                    "payload_digest": evidence.payload_digest,
                    "byte_count": len(evidence.payload),
                }
            ],
            "disclosures": [],
            "next": {"kind": "user_review"},
        }
    )


def test_concurrent_claim_has_exactly_one_winner_and_no_secret_aliases(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    def attempt() -> object:
        try:
            return offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
        except MailboxError as exc:
            return exc.denial

    with ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(lambda _: attempt(), range(64)))
    winners = [item for item in outcomes if not isinstance(item, str)]
    # StrEnum is also str; successful values are the only non-string outcomes.
    assert len(winners) == 1
    assert (
        offered.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL).state
        is MailboxState.CLAIMED_ONCE
    )
    assert winners[0].action_key == ACTION_KEY  # type: ignore[union-attr]


def test_concurrent_result_commit_has_exactly_one_winner(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    claim = offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    evidence = _evidence()
    offered.stage_evidence(
        binding,
        result_credential=claim.result_credential,
        evidence=evidence,
    )
    result = _result(evidence)

    def attempt() -> object:
        try:
            return offered.commit_result(
                binding,
                result,
                result_credential=claim.result_credential,
            )
        except MailboxError as exc:
            return exc.denial

    with ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(lambda _: attempt(), range(64)))
    winners = [item for item in outcomes if not isinstance(item, str)]
    assert len(winners) == 1
    assert winners[0].state is MailboxState.RESULT_COMMITTED  # type: ignore[union-attr]
    assert (
        offered.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL).state
        is MailboxState.RESULT_COMMITTED
    )


@pytest.mark.parametrize(
    ("point", "expected_state", "material_retained"),
    [
        (CrashPoint.BEFORE_CLAIM_COMMIT, MailboxState.OFFERED, True),
        (CrashPoint.AFTER_CLAIM_COMMIT, MailboxState.CLAIMED_ONCE, False),
    ],
)
def test_claim_crash_edges_are_fail_closed_and_never_create_result(
    action_json: bytes,
    clock: FakeClock,
    point: CrashPoint,
    expected_state: MailboxState,
    material_retained: bool,
) -> None:
    service, binding = _configured_service(action_json, clock, point)
    with pytest.raises(InjectedCrash):
        service.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    snapshot = service.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.state is expected_state
    assert snapshot.claim_material_retained is material_retained
    assert not snapshot.result_present
    if expected_state is MailboxState.CLAIMED_ONCE:
        # The caller received no key after the post-commit crash; only core can abandon.
        abandoned = service.abandon(
            binding.mailbox_id,
            collection_credential=COLLECTION_CREDENTIAL,
        )
        assert abandoned.state is MailboxState.ABANDONED


@pytest.mark.parametrize(
    ("point", "evidence_count"),
    [
        (CrashPoint.BEFORE_EVIDENCE_COMMIT, 0),
        (CrashPoint.AFTER_EVIDENCE_COMMIT, 1),
    ],
)
def test_evidence_upload_crash_edges_are_atomic(
    action_json: bytes,
    clock: FakeClock,
    point: CrashPoint,
    evidence_count: int,
) -> None:
    service, binding = _configured_service(action_json, clock, point)
    claim = service.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    with pytest.raises(InjectedCrash):
        service.stage_evidence(
            binding,
            result_credential=claim.result_credential,
            evidence=_evidence(),
        )
    snapshot = service.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.state is MailboxState.CLAIMED_ONCE
    assert snapshot.staged_evidence_count == evidence_count
    assert not snapshot.result_present


@pytest.mark.parametrize(
    ("point", "expected_state", "result_present"),
    [
        (CrashPoint.BEFORE_RESULT_COMMIT, MailboxState.CLAIMED_ONCE, False),
        (CrashPoint.AFTER_RESULT_COMMIT, MailboxState.RESULT_COMMITTED, True),
    ],
)
def test_result_commit_crash_edges_preserve_authoritative_mailbox_truth(
    action_json: bytes,
    clock: FakeClock,
    point: CrashPoint,
    expected_state: MailboxState,
    result_present: bool,
) -> None:
    service, binding = _configured_service(action_json, clock, point)
    claim = service.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    evidence = _evidence()
    service.stage_evidence(
        binding,
        result_credential=claim.result_credential,
        evidence=evidence,
    )
    with pytest.raises(InjectedCrash):
        service.commit_result(
            binding,
            _result(evidence),
            result_credential=claim.result_credential,
        )
    snapshot = service.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.state is expected_state
    assert snapshot.result_present is result_present
    if expected_state is MailboxState.RESULT_COMMITTED:
        bundle = service.collect(
            binding.mailbox_id,
            collection_credential=COLLECTION_CREDENTIAL,
        )
        assert bundle.evidence == (evidence,)
