"""Fail-closed result/evidence validation and deterministic simulator-facing facts."""

from __future__ import annotations

from copy import deepcopy
from uuid import UUID, uuid4

import pytest

from services.runner_mailbox import (
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
    RunnerMailboxService,
)
from services.runner_mailbox.domain import ActionBinding
from tests.runner_mailbox.conftest import (
    CLAIM_CREDENTIAL,
    COLLECTION_CREDENTIAL,
    EVIDENCE_ID,
    RESULT_CREDENTIAL,
    encode,
)


def _claim(offered: RunnerMailboxService, binding: ActionBinding) -> bytes:
    return offered.claim(binding, claim_credential=CLAIM_CREDENTIAL).result_credential


def _upload(*, payload: bytes = b"untrusted deterministic simulator evidence") -> EvidenceUpload:
    import hashlib

    return EvidenceUpload(
        object_id=UUID(EVIDENCE_ID),
        kind="sanitized_html",
        payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )


def _result_payload(evidence: EvidenceUpload) -> dict[str, object]:
    return {
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


def test_deterministic_synthetic_result_round_trip_preserves_fact_not_outcome(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    offered.stage_evidence(binding, result_credential=credential, evidence=evidence)
    result_json = encode(_result_payload(evidence))
    offered.commit_result(binding, result_json, result_credential=credential)
    bundle = offered.collect(
        binding.mailbox_id,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    assert b"candidate_observed" in bundle.result_json
    assert b"verified_removed" not in bundle.result_json
    assert bundle.evidence[0].payload == evidence.payload


def test_evidence_digest_mismatch_fails_before_repository_mutation(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    altered = EvidenceUpload(
        object_id=evidence.object_id,
        kind=evidence.kind,
        payload_digest="sha256:" + "f" * 64,
        payload=evidence.payload,
    )
    with pytest.raises(MailboxError) as denied:
        offered.stage_evidence(binding, result_credential=credential, evidence=altered)
    assert denied.value.denial is MailboxDenial.DIGEST_MISMATCH
    assert (
        offered.snapshot(
            binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL
        ).staged_evidence_count
        == 0
    )


def test_evidence_object_replay_and_wrong_result_credential_fail_closed(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    with pytest.raises(MailboxError) as wrong:
        offered.stage_evidence(binding, result_credential=b"x" * 32, evidence=evidence)
    assert wrong.value.denial is MailboxDenial.UNAUTHORIZED
    offered.stage_evidence(binding, result_credential=credential, evidence=evidence)
    with pytest.raises(MailboxError) as replay:
        offered.stage_evidence(binding, result_credential=credential, evidence=evidence)
    assert replay.value.denial is MailboxDenial.REPLAY


def test_action_response_budget_caps_staged_sensitive_payload(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload(payload=b"x" * (binding.response_bytes + 1))
    with pytest.raises(MailboxError) as over_budget:
        offered.stage_evidence(binding, result_credential=credential, evidence=evidence)
    assert over_budget.value.denial is MailboxDenial.EVIDENCE_LIMIT
    assert (
        offered.snapshot(
            binding.mailbox_id, collection_credential=COLLECTION_CREDENTIAL
        ).staged_evidence_count
        == 0
    )


def test_result_must_reference_every_staged_object_exactly_once(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    offered.stage_evidence(binding, result_credential=credential, evidence=evidence)
    payload = _result_payload(evidence)
    payload["evidence"] = []
    with pytest.raises(MailboxError) as unreferenced:
        offered.commit_result(binding, encode(payload), result_credential=credential)
    assert unreferenced.value.denial is MailboxDenial.EVIDENCE_UNREFERENCED


def test_result_rejects_missing_or_metadata_mismatched_evidence(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    missing_payload = _result_payload(evidence)
    missing_payload["evidence"][0]["mailbox_object_id"] = str(uuid4())  # type: ignore[index]
    with pytest.raises(MailboxError) as missing:
        offered.commit_result(binding, encode(missing_payload), result_credential=credential)
    assert missing.value.denial is MailboxDenial.EVIDENCE_MISSING

    offered.stage_evidence(binding, result_credential=credential, evidence=evidence)
    mismatch_payload = _result_payload(evidence)
    mismatch_payload["evidence"][0]["byte_count"] = len(evidence.payload) + 1  # type: ignore[index]
    with pytest.raises(MailboxError) as mismatch:
        offered.commit_result(binding, encode(mismatch_payload), result_credential=credential)
    assert mismatch.value.denial is MailboxDenial.DIGEST_MISMATCH


@pytest.mark.parametrize("field", ["action_id", "attempt_id"])
def test_result_identity_must_match_claimed_action(
    offered: RunnerMailboxService,
    binding: ActionBinding,
    field: str,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    payload = _result_payload(evidence)
    payload[field] = str(uuid4())
    with pytest.raises(MailboxError) as mismatch:
        offered.commit_result(binding, encode(payload), result_credential=credential)
    assert mismatch.value.denial is MailboxDenial.RESULT_MISMATCH


def test_protocol_unknown_fields_and_invalid_fact_reason_fail_closed(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    payload = _result_payload(evidence)
    payload["future_authority"] = True
    with pytest.raises(MailboxError) as unknown:
        offered.commit_result(binding, encode(payload), result_credential=credential)
    assert unknown.value.denial is MailboxDenial.INVALID_INPUT

    invalid = deepcopy(_result_payload(evidence))
    invalid["reason_code"] = "broker_assertion"
    with pytest.raises(MailboxError) as reason:
        offered.commit_result(binding, encode(invalid), result_credential=credential)
    assert reason.value.denial is MailboxDenial.INVALID_INPUT


def test_result_commit_is_single_use_and_burns_result_credential(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    credential = _claim(offered, binding)
    evidence = _upload()
    offered.stage_evidence(binding, result_credential=credential, evidence=evidence)
    result = encode(_result_payload(evidence))
    offered.commit_result(binding, result, result_credential=credential)
    with pytest.raises(MailboxError) as replay:
        offered.commit_result(binding, result, result_credential=credential)
    assert replay.value.denial is MailboxDenial.REPLAY


def test_collection_secret_cannot_upload_or_abandon_another_role(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    _claim(offered, binding)
    evidence = _upload()
    with pytest.raises(MailboxError) as role_confusion:
        offered.stage_evidence(
            binding,
            result_credential=COLLECTION_CREDENTIAL,
            evidence=evidence,
        )
    assert role_confusion.value.denial is MailboxDenial.UNAUTHORIZED
    with pytest.raises(MailboxError) as wrong_core:
        offered.abandon(binding.mailbox_id, collection_credential=RESULT_CREDENTIAL)
    assert wrong_core.value.denial is MailboxDenial.UNAUTHORIZED
