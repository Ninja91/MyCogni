"""Protocol-v1 parsing, rejection, and serialization contract tests."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from connector_protocol import ActionEnvelope, ConnectorManifest, ResultEnvelope

UUIDS = {
    "action": "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c",
    "intent": "00ef8ac4-3f2a-4ab7-8c7f-4b50e4d902bd",
    "attempt": "26fc0371-5b37-4452-8569-95564cc83edb",
    "profile": "93cb45b8-843f-4af1-8642-d70903d0919f",
    "mailbox": "470c0e4b-ce29-4eb5-8a1f-dd672e342fac",
}
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


@pytest.fixture
def manifest_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "connector_id": "synthetic-people-search",
        "release_version": "0.1.0",
        "broker_id": "synthetic-broker",
        "source_digest": DIGEST_A,
        "artifact_digest": DIGEST_B,
        "capabilities": ["observe"],
        "transports": ["declarative_http"],
        "allowed_origins": ["https://broker.example.test"],
        "disclosures": [
            {
                "attribute_type": "name",
                "destination": "broker.example.test",
                "purpose": "candidate-search",
            }
        ],
        "reviewed_at_utc": "2030-01-01T00:00:00Z",
        "expires_at_utc": "2030-02-01T00:00:00Z",
    }


@pytest.fixture
def action_payload() -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "action_id": UUIDS["action"],
        "intent_id": UUIDS["intent"],
        "attempt_id": UUIDS["attempt"],
        "fence": 0,
        "authorization_epoch": 0,
        "capability": "observe",
        "connector_release": "synthetic-people-search@0.1.0",
        "profile_ref": UUIDS["profile"],
        "attributes": [{"attribute_type": "name", "ciphertext": "sealed-test-value"}],
        "allowed_origins": ["https://broker.example.test"],
        "deadline_utc": "2030-01-01T00:01:00Z",
        "attempt": 0,
        "budget": {"wall_seconds": 30, "response_bytes": 4096},
    }


@pytest.fixture
def result_payload() -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "action_id": UUIDS["action"],
        "attempt_id": UUIDS["attempt"],
        "result": "candidate_found",
        "reason_code": "name_address_match",
        "external_reference": "sealed-external-reference",
        "evidence": [
            {
                "kind": "sanitized_html",
                "mailbox_object_id": UUIDS["mailbox"],
                "ciphertext_digest": DIGEST_A,
                "byte_count": 256,
            }
        ],
        "disclosures": [{"attribute_type": "name", "destination": "broker.example.test"}],
        "next": {"kind": "user_review"},
    }


@pytest.mark.parametrize(
    ("model", "fixture_name"),
    [
        (ConnectorManifest, "manifest_payload"),
        (ActionEnvelope, "action_payload"),
        (ResultEnvelope, "result_payload"),
    ],
)
def test_wire_json_round_trip_is_stable(
    model: type[ConnectorManifest] | type[ActionEnvelope] | type[ResultEnvelope],
    fixture_name: str,
    request: pytest.FixtureRequest,
) -> None:
    payload = request.getfixturevalue(fixture_name)
    first = model.model_validate_json(json.dumps(payload))
    encoded = first.model_dump_json()
    second = model.model_validate_json(encoded)
    assert second == first
    assert (
        json.loads(encoded)[
            "protocol_version" if model is not ConnectorManifest else "schema_version"
        ]
        == 1
    )


@pytest.mark.parametrize("model_name", ["manifest_payload", "action_payload", "result_payload"])
def test_unknown_fields_fail_closed(model_name: str, request: pytest.FixtureRequest) -> None:
    model = {
        "manifest_payload": ConnectorManifest,
        "action_payload": ActionEnvelope,
        "result_payload": ResultEnvelope,
    }[model_name]
    payload = deepcopy(request.getfixturevalue(model_name))
    payload["future_authority"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("model", "fixture_name", "version_field"),
    [
        (ConnectorManifest, "manifest_payload", "schema_version"),
        (ActionEnvelope, "action_payload", "protocol_version"),
        (ResultEnvelope, "result_payload", "protocol_version"),
    ],
)
@pytest.mark.parametrize("version", [0, 2, -1])
def test_unknown_protocol_versions_fail(
    model: type[ConnectorManifest] | type[ActionEnvelope] | type[ResultEnvelope],
    fixture_name: str,
    version_field: str,
    version: int,
    request: pytest.FixtureRequest,
) -> None:
    payload = request.getfixturevalue(fixture_name)
    payload[version_field] = version
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "origin",
    [
        "http://broker.example.test",
        "https://user@broker.example.test",
        "https://broker.example.test/privacy",
        "https://*.example.test",
        "https://127.0.0.1",
        "https://broker.example.test:0",
        "https://broker.example.test?next=elsewhere",
        "https://BROKER.example.test",
    ],
)
def test_adversarial_origins_fail(origin: str, action_payload: dict[str, Any]) -> None:
    action_payload["allowed_origins"] = [origin]
    with pytest.raises(ValidationError):
        ActionEnvelope.model_validate_json(json.dumps(action_payload))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fence", -1),
        ("authorization_epoch", -1),
        ("attempt", -1),
    ],
)
def test_negative_monotonic_values_fail(
    field: str, value: int, action_payload: dict[str, Any]
) -> None:
    action_payload[field] = value
    with pytest.raises(ValidationError):
        ActionEnvelope.model_validate_json(json.dumps(action_payload))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wall_seconds", 0),
        ("wall_seconds", 3_601),
        ("response_bytes", 0),
        ("response_bytes", 67_108_865),
    ],
)
def test_nonpositive_or_excessive_budgets_fail(
    field: str, value: int, action_payload: dict[str, Any]
) -> None:
    action_payload["budget"][field] = value
    with pytest.raises(ValidationError):
        ActionEnvelope.model_validate_json(json.dumps(action_payload))


@pytest.mark.parametrize("field", ["capabilities", "transports", "allowed_origins", "disclosures"])
def test_duplicate_signed_declarations_fail(field: str, manifest_payload: dict[str, Any]) -> None:
    manifest_payload[field] *= 2
    with pytest.raises(ValidationError, match="unique"):
        ConnectorManifest.model_validate_json(json.dumps(manifest_payload))


def test_disclosure_identity_cannot_be_redeclared_with_a_new_purpose(
    manifest_payload: dict[str, Any],
) -> None:
    duplicate = deepcopy(manifest_payload["disclosures"][0])
    duplicate["purpose"] = "another-purpose"
    manifest_payload["disclosures"].append(duplicate)
    with pytest.raises(ValidationError, match="unique"):
        ConnectorManifest.model_validate_json(json.dumps(manifest_payload))


def test_non_utc_or_reversed_manifest_expiry_fails(manifest_payload: dict[str, Any]) -> None:
    manifest_payload["expires_at_utc"] = "2029-12-31T16:00:00-08:00"
    with pytest.raises(ValidationError, match="UTC"):
        ConnectorManifest.model_validate_json(json.dumps(manifest_payload))


def test_non_utc_action_deadline_fails(action_payload: dict[str, Any]) -> None:
    action_payload["deadline_utc"] = "2029-12-31T16:01:00-08:00"
    with pytest.raises(ValidationError, match="UTC"):
        ActionEnvelope.model_validate_json(json.dumps(action_payload))


def test_non_uuid4_identifiers_fail(action_payload: dict[str, Any]) -> None:
    action_payload["action_id"] = "550e8400-e29b-11d4-a716-446655440000"
    with pytest.raises(ValidationError):
        ActionEnvelope.model_validate_json(json.dumps(action_payload))


def test_bad_digest_and_zero_evidence_size_fail(result_payload: dict[str, Any]) -> None:
    result_payload["evidence"][0]["ciphertext_digest"] = "sha256:not-a-digest"
    result_payload["evidence"][0]["byte_count"] = 0
    with pytest.raises(ValidationError):
        ResultEnvelope.model_validate_json(json.dumps(result_payload))


def test_reason_must_match_result(result_payload: dict[str, Any]) -> None:
    result_payload["reason_code"] = "captcha_required"
    with pytest.raises(ValidationError, match="invalid for result"):
        ResultEnvelope.model_validate_json(json.dumps(result_payload))


def test_models_are_frozen(action_payload: dict[str, Any]) -> None:
    action = ActionEnvelope.model_validate_json(json.dumps(action_payload))
    with pytest.raises(ValidationError, match="frozen_instance"):
        action.fence = 2
