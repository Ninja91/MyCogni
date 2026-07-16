# Data model and lifecycle

## Core records

### Profile and identity

- `profile`: one natural person, jurisdiction and lifecycle metadata;
- `profile_key`: independently random wrapped profile DEK, key version, wrapping provider, creation/rotation status;
- `key_catalog_backup`: recoverability boundary, contained profile-key versions, created/expiry/sanitized state;
- `identity_attribute`: encrypted value, normalized blind index where necessary, type, validity range, source, confidence, and retention class;
- `actor`: authenticated local/cloud identity and assurance method;
- `authority_grant`: actor, represented profile, authority evidence, scope, expiry, and revocation epoch;
- `authorization`: actor/grant, represented profile, scope, legal basis, plan-policy boundary, versioned text hash, signed time, expiry, revocation epoch, and encrypted artifact;
- `session`: actor, authentication time/method, step-up time, expiry, and revocation;
- `consent_event`: append-only record for collection, disclosure, integration grants, and revocation.

No database row stores a readable name, address, email, phone, date of birth, or identity document. Searchable equality uses keyed blind indexes only where a concrete workflow requires it. High-entropy values remain encrypted without indexes.

### Broker and connector

- `broker`: stable internal organization identity, aliases, category, jurisdiction;
- `broker_endpoint`: domain, path/purpose, transport, provenance, last observed, expiry;
- `connector_release`: immutable code/manifest digest, capabilities, review state, fixtures, known limitations;
- `connector_artifact`: OCI/WASI digest, SBOM/provenance, runtime class, signature/threshold trust, expiry/revocation;
- `disclosure_schema`: required/optional attribute types for a capability and reason;
- `policy_binding`: connector capability allowed for a jurisdiction/profile policy.

### Finding and case

- `observation_run`: connector, profile, start/end, result, error class, budget;
- `finding`: candidate record reference, encrypted evidence, match score, explanation, user disposition;
- `case`: profile + broker + right/action intent, current projection, owner and dates;
- `request_plan`: immutable version of destination, legal basis, released fields, message/attachment hashes, and risk result;
- `approval`: actor, plan hash, decision, scope, expiry;
- `external_intent`: immutable plan/authorization binding, destination/disclosure, current fence and journal state;
- `submission_attempt`: intent ID, attempt ID, fence, connector digest, start/end, redacted request digest, transport proof or unknown reason;
- `verification`: method, policy version, observed time, assurance (`asserted`, `observed_absent_once`, `corroborated`, `inconclusive`), result, evidence;
- `resurfacing_occurrence`: new finding linked to a prior verified case;
- `task`: explicit user/maintainer action with blocking reason and due date;
- `case_event`: encrypted/authenticated event with previous-event hash and checkpoint epoch;
- `integrity_checkpoint`: keyed/signed monotonic event-chain head stored outside the primary database;
- `advisory_suggestion`: optional encrypted untrusted output, supporting spans, artifact/runtime/prompt/input digests, validation, and expiry.

## Status semantics

Events remain the source of truth. Status is stored/projected on separate axes per finding/occurrence and right; one flat `case.status` is prohibited because it would merge identity, request, evidence and blockage truth.

- `match_state`: `candidate | ambiguous | confirmed | rejected`;
- `request_state`: `none | planned | authorized | submitted | acknowledged | processing | closed`;
- `dispatch_state`: `none | ready | claimed | cancelled_before_send | failed_before_send | dispatch_started | transport_proven | outcome_unknown | send_proven | no_send_proven | abandoned`;
- `assurance_state`: `none | asserted | observed_absent_once | corroborated | inconclusive | resurfaced`;
- `work_state`: `active | paused | needs_user | overdue | failed | closed_unverified | revoked`.

A case summary is a rebuildable user-facing projection over these axes and all current occurrences. `transport_proven` affects request evidence only; it is not acknowledgement or compliance. `verified_removed` is rendered only for an identified occurrence whose `assurance_state=corroborated` satisfies the versioned verification policy. One verified occurrence never upgrades the entire broker case or another unresolved occurrence.

## Evidence model

Evidence has three layers:

1. searchable metadata: type, creation time, connector/version, case ID, retention class, MIME type, size, ciphertext/storage hash, and keyed plaintext MAC for semantic integrity; predictable plaintext PII is never exposed through an unkeyed hash;
2. encrypted content: screenshot, HTML excerpt, email, receipt, or structured response;
3. redacted derivative: safe preview/report representation generated locally, preferring structured field-category differences over retained screenshots.

The store may be filesystem-backed locally and S3-compatible in cloud-small. Database rows contain encrypted object locators and hashes. Event chains are keyed/signed and periodically anchored to a monotonic checkpoint outside the primary database. They provide tamper evidence only relative to a trusted checkpoint; a compromised host/key or missing checkpoint can recompute/truncate history.

Screenshots and hostile page bodies are optional, encrypted, bounded, and short-lived. Public reports use redacted categories and verification method. Third-party PII is removed or masked before display/export.

## Retention defaults

| Class | Default | Rationale |
| --- | --- | --- |
| Authorization | life of active authority + jurisdictional audit window | prove lawful scope |
| Raw finding evidence | 90 days after verified removal, with an absolute maximum configured in the retention ADR for never-verified/abandoned cases | minimize exposed page content without indefinite retention |
| Redacted verification evidence | 24 months | detect and explain resurfacing |
| Request/response bodies | 24 months or until profile deletion | disputes and deadlines |
| Browser session state | shortest connector-valid period, max 30 days by default | high credential risk |
| Operational logs | 30 days | diagnostics without long-lived metadata |
| Aggregate metrics | indefinite if non-identifying | effectiveness history |
| Advisory suggestion | 30 days by default; no prompt body | optional review aid, not case truth |
| Model weights | explicit cache, not a user-data backup | reproducible artifact, separately licensed |
| Wrapped-key catalog backup | operator policy with visible profile-deletion horizon | recovery versus deletion truth |

Users may shorten retention unless it would make a pending request unauditable. Profile deletion first pauses the profile, invalidates permits, cancels pre-dispatch work and reconciles every started/unknown attempt. The user must step up and explicitly accept lost reconciliation before forced abandonment. Only then does finalization destroy the live random profile DEK and sweep dependent jobs, envelopes, indexes, evidence and session material. Reports cover cryptographic inaccessibility in the live installation and known managed backups, list horizons separately, and warn that external snapshots/operator copies are outside MyCogni's inventory.

## Migration rules

- Migrations are forward-only in normal operation and rehearsed against encrypted fixtures.
- Every migration has a restore point and a documented maximum supported downgrade/rollback path.
- Connector and policy versions are immutable; new versions never rewrite historical cases.
- A backup is not considered valid until a scheduled restore test verifies schema, object hashes, and key separation.
