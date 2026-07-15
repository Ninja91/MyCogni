# Connector SDK and broker registry

## Goal

Broker procedures are the most volatile and adversarial part of MyCogni. The connector SDK treats every adapter as a capability-scoped, expiring integration with provenance and tests—not as a script that inherits the application's authority.

## Package shape

```text
connectors/<connector_id>/
  manifest.yaml
  src/                    # separate artifact implementation
  Containerfile           # or constrained WASI build definition
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
- artifact digest, build provenance/SBOM, runtime class, signature/threshold role, and revocation metadata;
- allowed methods/protocols, redirect depth, response byte/time budget, and browser feature policy.

## Runtime contract

The connector is never imported into or packaged inside the trusted core image. It runs as a separately verified digest-pinned artifact. Input is a signed, short-lived action envelope:

```json
{
  "action_id": "opaque-uuid",
  "intent_id": "opaque-stable-intent",
  "attempt_id": "opaque-attempt",
  "fence": 42,
  "authorization_epoch": 7,
  "capability": "observe",
  "connector": "example-people-search@0.1.0",
  "profile_ref": "opaque-per-action-reference",
  "attributes": [{"type": "name", "ciphertext": "action-key-sealed-value"}],
  "allowed_origins": ["https://privacy.example.test"],
  "deadline": "2026-07-15T20:00:00Z",
  "attempt": 1,
  "budget": {"wall_seconds": 30, "response_bytes": 262144}
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

## Runtime and egress contract

Every action runs non-root/rootless with a read-only root filesystem, tmpfs work directory, dropped capabilities, `no-new-privileges`, syscall policy, PID/CPU/RAM/time limits, and no core image, database, vault, wrapped-key catalog, Docker socket, host network, other connector session, or reusable core credential.

The artifact has no direct network path. Every outbound connection crosses the egress gateway, which validates the current fence, authorization epoch, pause state, connector digest/capability, method/protocol, manifest origin, resolved public IP, redirect, exact disclosure plan, and byte/time budget. It denies private/loopback/link-local/metadata ranges, DNS rebinding, WebSocket/QUIC/DoH, undeclared destinations, downloads, and over-budget responses.

The gateway cannot prevent a legitimate allowed broker from misusing the fields it receives. The permanent disclosure ledger and observe-before-disclose policy remain required.

## Connector lifecycle

1. **Experimental:** metadata, sources, and synthetic fixtures only.
2. **Observe-tested:** read-only contract passes; no submit authority.
3. **Submission-candidate:** prepare/submit artifact and controlled canary evidence exist; explicit pre-release opt-in only.
4. **Trusted:** capability has fresh sources, sustained contract/canary results, policy approval, artifact/provenance verification, and two qualified reviewers.
5. **Quarantined:** unexpected egress, disclosure, terms, destination, DOM, response, error, provenance, or expiry change.
6. **Retired:** procedure removed, unsafe, abandoned, or no longer supportable.

Maturity is per capability. There is no automatic promotion from a successful test to unattended submission. During bootstrap, one maintainer cannot grant `trusted` live submit authority.

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
- proof that the artifact cannot read `/proc` secrets, core/host mounts, environment credentials, Docker socket, host metadata, other sessions, or private destinations;
- DNS rebinding, redirect, WebSocket/QUIC/DoH, byte-budget, allowed-origin exfiltration, stale-fence, and revoked-epoch tests;
- crash/kill tests at dispatch claim/start/proof/unknown boundaries.

CI never contacts a real broker. Live canaries run manually in a separately authorized environment and write only redacted results to CI metadata.

## Community registry governance

- factual changes require a source and access date;
- high-risk capability changes require two maintainers when available;
- maintainers may emergency-disable a connector version through a signed revocation list that users can opt to fetch;
- update metadata must be versioned, expiring, rollback/freeze-resistant, delegated per capability, and linked to artifact digest/SBOM/build provenance;
- the application shows whether registry updates are local, community-signed, stale, or user-modified;
- user modifications never silently inherit community trust.
- generated public support data shows maturity, expiry, exact disclosure, human steps, evidence method, and recent test/canary age rather than one coverage count.

Broker facts, connector source, built artifacts, fixtures, and imported datasets each keep separate license/provenance metadata. Public visibility is not permission to relicense a directory into Apache-2.0.
