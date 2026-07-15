# Connector SDK and broker registry

## Goal

Broker procedures are the most volatile and adversarial part of MyCogni. The connector SDK treats every adapter as a capability-scoped, expiring integration with provenance and tests—not as a script that inherits the application's authority.

## Package shape

```text
connectors/<connector_id>/
  manifest.yaml
  connector.py
  fixtures/
  tests/
  CHANGELOG.md
```

The initial repository includes a JSON Schema and synthetic example under `broker-registry/`. No real broker automation is included in the architecture commit.

## Manifest requirements

A manifest declares:

- immutable connector ID, version, broker ID, maintainers, and source digest;
- exact destination domains and redirect policy;
- supported jurisdictions and rights;
- independent capability levels: `observe`, `prepare`, `submit`, `poll`, `verify`;
- transport: email, web form, authenticated portal, protocol API, or guided manual;
- required and optional identity attribute types with reasons;
- authorization/attachment requirements;
- match and verification semantics;
- rate limit, retry, timeout, and scheduling policy;
- provenance URL, terms/privacy URL, observed date, review date, and expiry;
- known manual steps, CAPTCHA/MFA behavior, and limitations;
- fixture and contract-test versions.

## Runtime contract

Input is a signed, short-lived action envelope:

```json
{
  "action_id": "opaque-uuid",
  "capability": "observe",
  "connector": "example-people-search@0.1.0",
  "profile_ref": "opaque-per-action-reference",
  "attributes": [{"type": "name", "ciphertext": "action-key-sealed-value"}],
  "allowed_origins": ["https://privacy.example.test"],
  "deadline": "2026-07-15T20:00:00Z",
  "attempt": 1
}
```

The runner receives the one-time action key through a separate channel. Output is structured and bounded:

```json
{
  "result": "candidate_found",
  "reason_code": "name_address_match",
  "external_reference": "sealed-value",
  "evidence": [{"kind": "sanitized_html", "path": "runner-local-object"}],
  "disclosures": [{"attribute_type": "name", "destination": "privacy.example.test"}],
  "next": {"kind": "user_review"}
}
```

Free-form external content is stored as untrusted evidence and never interpreted as instructions.

## Connector lifecycle

1. **Proposed:** metadata and sources only.
2. **Observe sandbox:** synthetic fixtures and read-only checks.
3. **Canary:** explicit maintainer-run test with a consenting synthetic/controlled identity.
4. **Prepare enabled:** generate disclosures without sending.
5. **Submit reviewed:** live submission behind per-user approval.
6. **Trusted automation:** only after sustained pass rate, no material workflow drift, and policy approval.
7. **Quarantined:** unexpected egress, disclosure, terms, DOM, response, or error change.
8. **Retired:** procedure removed or no longer supportable.

There is no automatic promotion from a successful test to unattended submission.

## Change detection

- fingerprint form structure and privacy text without storing unnecessary page content;
- run scheduled synthetic contract checks conservatively;
- compare required fields, destinations, redirects, and terms hashes;
- quarantine `submit` when a material field or destination changes;
- allow `observe` to remain active only if its own safety contract still passes;
- show users the old/new disclosure diff before reapproval.

## Testing contract

Each capability requires:

- success, not-found, ambiguous, rate-limit, timeout, and unexpected-response fixtures;
- SSRF and redirect tests;
- PII disclosure assertions;
- idempotency and duplicate-attempt tests;
- sanitized evidence tests;
- selector/response drift tests;
- proof that observe cannot invoke submit paths;
- proof that challenge detection stops rather than bypasses.

CI never contacts a real broker. Live canaries run manually in a separately authorized environment and write only redacted results to CI metadata.

## Community registry governance

- factual changes require a source and access date;
- high-risk capability changes require two maintainers when available;
- maintainers may emergency-disable a connector version through a signed revocation list that users can opt to fetch;
- the application shows whether registry updates are local, community-signed, stale, or user-modified;
- user modifications never silently inherit community trust.
