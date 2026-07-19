"""Finite mailbox transitions, immutable binding, and cleanup semantics."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from services.runner_mailbox import (
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
    MailboxState,
    RunnerMailboxService,
    Sha256CredentialDigester,
    VolatileMailboxRepository,
)
from services.runner_mailbox.domain import ActionBinding, MailboxSnapshot
from tests.runner_mailbox.conftest import (
    ACTION_KEY,
    ARTIFACT_DIGEST,
    CLAIM_CREDENTIAL,
    COLLECTION_CREDENTIAL,
    EVIDENCE_ID,
    MAILBOX_ID,
    MAINTENANCE_CREDENTIAL,
    RESULT_CREDENTIAL,
    FakeClock,
    FixedCredentialSource,
    encode,
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _evidence() -> EvidenceUpload:
    payload = b"untrusted deterministic simulator evidence"
    return EvidenceUpload(
        object_id=UUID(EVIDENCE_ID),
        kind="sanitized_html",
        payload_digest=_digest(payload),
        payload=payload,
    )


def _result(evidence: EvidenceUpload, *, action_id: str | None = None) -> bytes:
    return encode(
        {
            "protocol_version": 1,
            "action_id": action_id or "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c",
            "attempt_id": "26fc0371-5b37-4452-8569-95564cc83edb",
            "result": "candidate_observed",
            "reason_code": "name_address_match",
            "external_reference": "synthetic-reference",
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


def _assert_denial(expected: MailboxDenial, error: pytest.ExceptionInfo[MailboxError]) -> None:
    assert error.value.denial is expected


def test_full_one_time_state_machine_and_collection(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    assert (
        offered.snapshot(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL).state
        is MailboxState.OFFERED
    )

    claim = offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    assert claim.action_key == ACTION_KEY
    assert claim.result_credential == RESULT_CREDENTIAL
    claimed = offered.snapshot(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL)
    assert claimed.state is MailboxState.CLAIMED_ONCE
    assert not claimed.claim_material_retained
    assert not claimed.result_credential_material_retained

    evidence = _evidence()
    staged = offered.stage_evidence(
        binding,
        result_credential=claim.result_credential,
        evidence=evidence,
    )
    assert (staged.staged_evidence_count, staged.staged_evidence_bytes) == (
        1,
        len(evidence.payload),
    )

    committed = offered.commit_result(
        binding,
        _result(evidence),
        result_credential=claim.result_credential,
    )
    assert committed.state is MailboxState.RESULT_COMMITTED
    assert committed.result_present

    bundle = offered.collect(
        UUID(MAILBOX_ID),
        collection_credential=COLLECTION_CREDENTIAL,
    )
    assert bundle.binding == binding
    assert bundle.evidence == (evidence,)
    final = offered.snapshot(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL)
    assert final.state is MailboxState.RESULT_COMMITTED
    assert final.collection_state.value == "delivering"
    assert final.result_present
    repeated = offered.collect(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL)
    assert repeated == bundle
    acknowledged = offered.acknowledge_collection(
        UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL
    )
    assert acknowledged.collection_state.value == "acknowledged"
    assert not acknowledged.result_present
    assert acknowledged.staged_evidence_count == 0


def test_claim_and_offer_replay_fail_closed(
    offered: RunnerMailboxService,
    binding: ActionBinding,
    action_json: bytes,
) -> None:
    with pytest.raises(MailboxError) as second_offer:
        offered.offer(
            binding,
            action_json,
            action_key=ACTION_KEY,
            collection_credential=COLLECTION_CREDENTIAL,
        )
    _assert_denial(MailboxDenial.REPLAY, second_offer)
    offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    with pytest.raises(MailboxError) as second_claim:
        offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    _assert_denial(MailboxDenial.REPLAY, second_claim)


@pytest.mark.parametrize(
    "replacement",
    [
        {"selected_artifact_digest": "sha256:" + "b" * 64},
        {"connector_release": "another-connector@0.1.0"},
        {"capability": "prepare"},
        {"dispatch_epoch": 1},
        {"fence": 1},
        {"authorization_epoch": 1},
        {"claim_deadline_utc": datetime(2030, 1, 1, 0, 2, tzinfo=UTC)},
        {"deadline_utc": datetime(2030, 1, 1, 0, 4, tzinfo=UTC)},
        {"wall_seconds": 31},
        {"response_bytes": 4097},
        {"envelope_digest": "sha256:" + "b" * 64},
    ],
    ids=[
        "artifact",
        "release",
        "capability",
        "dispatch-epoch",
        "fence",
        "authority-epoch",
        "claim-deadline",
        "deadline",
        "wall-budget",
        "byte-budget",
        "envelope-digest",
    ],
)
def test_every_immutable_binding_dimension_is_checked_on_claim(
    offered: RunnerMailboxService,
    binding: ActionBinding,
    replacement: dict[str, object],
) -> None:
    altered = replace(binding, **replacement)
    with pytest.raises(MailboxError) as denied:
        offered.claim(altered, claim_credential=CLAIM_CREDENTIAL)
    _assert_denial(MailboxDenial.BINDING_MISMATCH, denied)
    assert (
        offered.snapshot(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL).state
        is MailboxState.OFFERED
    )


def test_wrong_and_cross_action_credentials_fail_without_consuming_offer(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    with pytest.raises(MailboxError) as wrong:
        offered.claim(binding, claim_credential=b"x" * 32)
    _assert_denial(MailboxDenial.UNAUTHORIZED, wrong)
    assert (
        offered.snapshot(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL).state
        is MailboxState.OFFERED
    )

    other = replace(binding, mailbox_id=uuid4())
    with pytest.raises(MailboxError) as absent:
        offered.claim(other, claim_credential=CLAIM_CREDENTIAL)
    _assert_denial(MailboxDenial.NOT_FOUND, absent)


def test_expiry_is_terminal_and_never_manufactures_a_result(
    offered: RunnerMailboxService,
    binding: ActionBinding,
    clock: FakeClock,
) -> None:
    clock.current = binding.deadline_utc
    assert offered.expire_due(maintenance_credential=MAINTENANCE_CREDENTIAL) == (UUID(MAILBOX_ID),)
    snapshot = offered.snapshot(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.state is MailboxState.EXPIRED
    assert not snapshot.result_present
    assert snapshot.staged_evidence_count == 0
    assert not snapshot.claim_material_retained
    with pytest.raises(MailboxError) as denied:
        offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    _assert_denial(MailboxDenial.EXPIRED, denied)


def test_abandon_claimed_orphan_clears_logically_retained_material(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    claim = offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    offered.stage_evidence(
        binding,
        result_credential=claim.result_credential,
        evidence=_evidence(),
    )
    abandoned = offered.abandon(
        UUID(MAILBOX_ID),
        collection_credential=COLLECTION_CREDENTIAL,
    )
    assert abandoned.state is MailboxState.ABANDONED
    assert abandoned.staged_evidence_count == 0
    assert not abandoned.claim_material_retained
    assert not abandoned.result_credential_material_retained
    with pytest.raises(MailboxError) as replay:
        offered.abandon(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL)
    _assert_denial(MailboxDenial.INVALID_STATE, replay)


def test_result_committed_before_deadline_remains_collectable_by_core_after_deadline(
    offered: RunnerMailboxService,
    binding: ActionBinding,
    clock: FakeClock,
) -> None:
    claim = offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    evidence = _evidence()
    offered.stage_evidence(binding, result_credential=claim.result_credential, evidence=evidence)
    offered.commit_result(
        binding,
        _result(evidence),
        result_credential=claim.result_credential,
    )
    clock.current = binding.deadline_utc + timedelta(days=1)
    assert offered.expire_due(maintenance_credential=MAINTENANCE_CREDENTIAL) == ()
    bundle = offered.collect(
        UUID(MAILBOX_ID),
        collection_credential=COLLECTION_CREDENTIAL,
    )
    assert bundle.binding == binding


@pytest.mark.parametrize("field_name", ["dispatch_epoch", "fence", "authorization_epoch"])
def test_zero_monotonic_values_are_valid_but_bool_is_rejected(
    binding: ActionBinding,
    field_name: str,
) -> None:
    assert getattr(binding, field_name) == 0
    with pytest.raises(ValueError, match="non-negative integer"):
        replace(binding, **{field_name: True})


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("connector_release", "bad\nrelease@0.1.0"),
        ("connector_release", "x" * 194),
        ("capability", "observe\nforged"),
        ("capability", "x" * 33),
    ],
)
def test_binding_metadata_is_canonical_and_bounded(
    binding: ActionBinding,
    field_name: str,
    value: str,
) -> None:
    with pytest.raises(ValueError, match="canonical and bounded"):
        replace(binding, **{field_name: value})


def test_public_snapshots_are_frozen_and_validate_exact_scalar_types(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    snapshot = offered.snapshot(UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL)
    with pytest.raises(FrozenInstanceError):
        snapshot.result_present = True
    with pytest.raises(ValueError, match="exact bool"):
        MailboxSnapshot(
            mailbox_id=binding.mailbox_id,
            state=MailboxState.EMPTY,
            collection_state=offered.snapshot(
                UUID(MAILBOX_ID), collection_credential=COLLECTION_CREDENTIAL
            ).collection_state,
            staged_evidence_count=0,
            staged_evidence_bytes=0,
            result_present=1,  # type: ignore[arg-type]
            claim_material_retained=False,
            result_credential_material_retained=False,
        )


def test_open_rejects_reused_or_weak_credentials(
    service: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    with pytest.raises(MailboxError) as reused:
        service.open_empty(
            binding,
            action_credential=ACTION_KEY,
            claim_credential=CLAIM_CREDENTIAL,
            collection_credential=CLAIM_CREDENTIAL,
        )
    _assert_denial(MailboxDenial.INVALID_INPUT, reused)
    with pytest.raises(MailboxError) as weak:
        service.open_empty(
            binding,
            action_credential=ACTION_KEY,
            claim_credential=b"short",
            collection_credential=COLLECTION_CREDENTIAL,
        )
    _assert_denial(MailboxDenial.INVALID_INPUT, weak)


@pytest.mark.parametrize("result_credential", [CLAIM_CREDENTIAL, COLLECTION_CREDENTIAL, ACTION_KEY])
def test_offer_rejects_cross_role_secret_reuse(
    binding: ActionBinding,
    action_json: bytes,
    clock: FakeClock,
    result_credential: bytes,
) -> None:
    service = RunnerMailboxService(
        VolatileMailboxRepository(
            maintenance_credential_digest=Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL)
        ),
        clock,
        Sha256CredentialDigester(),
        FixedCredentialSource(result_credential),
    )
    service.open_empty(
        binding,
        action_credential=ACTION_KEY,
        claim_credential=CLAIM_CREDENTIAL,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    with pytest.raises(MailboxError) as reused:
        service.offer(
            binding,
            action_json,
            action_key=ACTION_KEY,
            collection_credential=COLLECTION_CREDENTIAL,
        )
    _assert_denial(MailboxDenial.INVALID_INPUT, reused)


def test_untrusted_clock_failure_fails_closed(
    service: RunnerMailboxService,
    binding: ActionBinding,
    action_json: bytes,
    clock: FakeClock,
) -> None:
    service.open_empty(
        binding,
        action_credential=ACTION_KEY,
        claim_credential=CLAIM_CREDENTIAL,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    clock.current = datetime(2030, 1, 1)  # type: ignore[assignment]
    with pytest.raises(MailboxError) as uncertainty:
        service.offer(
            binding,
            action_json,
            action_key=ACTION_KEY,
            collection_credential=COLLECTION_CREDENTIAL,
        )
    _assert_denial(MailboxDenial.INTERNAL_UNCERTAINTY, uncertainty)


def test_clock_rollback_cannot_extend_an_offered_mailbox(
    offered: RunnerMailboxService,
    binding: ActionBinding,
    clock: FakeClock,
) -> None:
    clock.current -= timedelta(seconds=1)
    with pytest.raises(MailboxError) as uncertainty:
        offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    _assert_denial(MailboxDenial.INTERNAL_UNCERTAINTY, uncertainty)
    snapshot = offered.snapshot(binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL)
    assert snapshot.state is MailboxState.OFFERED
    assert not snapshot.result_present


def test_artifact_digest_is_independent_input_not_manifest_trust(
    service: RunnerMailboxService,
    action_json: bytes,
) -> None:
    first = service.bind_action(
        UUID(MAILBOX_ID),
        action_json,
        selected_artifact_digest=ARTIFACT_DIGEST,
        dispatch_epoch=0,
        claim_deadline_utc=datetime(2030, 1, 1, 0, 1, tzinfo=UTC),
    )
    second = service.bind_action(
        UUID(MAILBOX_ID),
        action_json,
        selected_artifact_digest="sha256:" + "b" * 64,
        dispatch_epoch=0,
        claim_deadline_utc=datetime(2030, 1, 1, 0, 1, tzinfo=UTC),
    )
    assert first.envelope_digest == second.envelope_digest
    assert first.selected_artifact_digest != second.selected_artifact_digest
