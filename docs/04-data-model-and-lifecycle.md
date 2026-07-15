# Data model and lifecycle

## Core records

### Profile and identity

- `profile`: one natural person, jurisdiction and lifecycle metadata;
- `identity_attribute`: encrypted value, normalized blind index where necessary, type, validity range, source, confidence, and retention class;
- `authorization`: signer, represented profile, scope, legal basis, versioned text hash, signed time, expiry, revocation, and encrypted artifact;
- `consent_event`: append-only record for collection, disclosure, integration grants, and revocation.

No database row stores a readable name, address, email, phone, date of birth, or identity document. Searchable equality uses keyed blind indexes only where a concrete workflow requires it. High-entropy values remain encrypted without indexes.

### Broker and connector

- `broker`: stable internal organization identity, aliases, category, jurisdiction;
- `broker_endpoint`: domain, path/purpose, transport, provenance, last observed, expiry;
- `connector_release`: immutable code/manifest digest, capabilities, review state, fixtures, known limitations;
- `disclosure_schema`: required/optional attribute types for a capability and reason;
- `policy_binding`: connector capability allowed for a jurisdiction/profile policy.

### Finding and case

- `observation_run`: connector, profile, start/end, result, error class, budget;
- `finding`: candidate record reference, encrypted evidence, match score, explanation, user disposition;
- `case`: profile + broker + right/action intent, current projection, owner and dates;
- `request_plan`: immutable version of destination, legal basis, released fields, message/attachment hashes, and risk result;
- `approval`: actor, plan hash, decision, scope, expiry;
- `submission_attempt`: transport, idempotency key, connector version, redacted request digest, response class;
- `verification`: method, policy version, observed time, result, confidence, evidence;
- `resurfacing_occurrence`: new finding linked to a prior verified case;
- `task`: explicit user/maintainer action with blocking reason and due date;
- `case_event`: append-only event with previous-event hash.

## Status semantics

`case.status` is a rebuildable projection. Events remain the source of truth.

- `candidate`: possible record, not confirmed as the user;
- `confirmed_present`: user or high-confidence policy confirmed a match;
- `planned`: exact disclosure and request rendered;
- `awaiting_approval`: an exception external action is blocked on user review/consent;
- `approved`: the immutable plan hash is covered by setup authorization or an explicit exception approval;
- `submitted`: transport evidence confirms transmission, not receipt or compliance;
- `acknowledged`: the broker or transport confirmed receipt;
- `in_progress`: broker processing or legal window active;
- `needs_user_action`: verification, CAPTCHA, MFA, ambiguity, document, or account step;
- `broker_asserted_removed`: broker claims compliance without independent verification;
- `verified_removed`: a post-request method found the confirmed record absent under the verification policy;
- `partially_completed`: some matched records or rights remain;
- `denied_or_exempt`: broker gave a reason requiring review/escalation;
- `overdue`: expected response/action date passed;
- `failed`: bounded attempts exhausted or connector invalid;
- `resurfaced`: a later observation found a confirmed matching record again;
- `closed_unverified`: user ended work without verification;
- `revoked`: user revoked an unsent or revocable case.

## Evidence model

Evidence has three layers:

1. searchable metadata: type, creation time, connector/version, case ID, retention class, MIME type, size, content hash;
2. encrypted content: screenshot, HTML excerpt, email, receipt, or structured response;
3. redacted derivative: safe preview/report representation generated locally.

The store may be filesystem-backed locally and S3-compatible in cloud-small. Database rows contain encrypted object locators and hashes. A Merkle-style event chain detects deletion or reordering but is not marketed as third-party notarization.

## Retention defaults

| Class | Default | Rationale |
| --- | --- | --- |
| Authorization | life of active authority + jurisdictional audit window | prove lawful scope |
| Raw finding evidence | 90 days after verified removal | minimize exposed page content |
| Redacted verification evidence | 24 months | detect and explain resurfacing |
| Request/response bodies | 24 months or until profile deletion | disputes and deadlines |
| Browser session state | shortest connector-valid period, max 30 days by default | high credential risk |
| Operational logs | 30 days | diagnostics without long-lived metadata |
| Aggregate metrics | indefinite if non-identifying | effectiveness history |

Users may shorten retention unless it would make a pending request unauditable. Profile deletion destroys profile data keys first, then queues best-effort physical cleanup and reports undeleted backup/object expiries.

## Migration rules

- Migrations are forward-only in normal operation and rehearsed against encrypted fixtures.
- Every migration has a restore point and a documented maximum supported downgrade/rollback path.
- Connector and policy versions are immutable; new versions never rewrite historical cases.
- A backup is not considered valid until a scheduled restore test verifies schema, object hashes, and key separation.
