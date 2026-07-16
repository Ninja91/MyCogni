"""Import and construction smoke tests using only synthetic reserved data."""

from connector_protocol import (
    ActionBudget,
    ActionEnvelope,
    ConnectorManifest,
    DisclosureRecord,
    EvidenceReference,
    ResultEnvelope,
    SealedAttribute,
)


def test_minimal_protocol_records_are_separately_constructible() -> None:
    manifest = ConnectorManifest(
        schema_version=1,
        connector_id="synthetic-people-search",
        release_version="0.0.0-test",
        broker_id="broker.example.test",
        capabilities=("observe",),
        transports=("declarative_http",),
        allowed_origins=("https://broker.example.test",),
        expires_at_utc="2030-01-01T00:00:00Z",
    )
    action = ActionEnvelope(
        protocol_version=1,
        action_id="opaque-action",
        intent_id="opaque-intent",
        attempt_id="opaque-attempt",
        fence=1,
        authorization_epoch=1,
        capability="observe",
        connector_release=f"{manifest.connector_id}@{manifest.release_version}",
        profile_ref="opaque-per-action-profile",
        attributes=(SealedAttribute(attribute_type="name", ciphertext="sealed-test-value"),),
        allowed_origins=manifest.allowed_origins,
        deadline_utc="2030-01-01T00:01:00Z",
        budget=ActionBudget(wall_seconds=30, response_bytes=4096),
    )
    result = ResultEnvelope(
        protocol_version=action.protocol_version,
        action_id=action.action_id,
        attempt_id=action.attempt_id,
        result="candidate_found",
        reason_code="synthetic_match",
        evidence=(
            EvidenceReference(
                kind="sanitized_html",
                mailbox_object_id="opaque-mailbox-object",
                ciphertext_digest="sha256:synthetic-digest",
                byte_count=256,
            ),
        ),
        disclosures=(DisclosureRecord(attribute_type="name", destination="broker.example.test"),),
    )

    assert result.action_id == action.action_id
    assert result.evidence[0].mailbox_object_id == "opaque-mailbox-object"
