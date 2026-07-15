# Testing and quality strategy

## Test pyramid

### Domain unit tests

Pure tests cover state transitions, deadline calculations, setup-authorization scope, disclosure minimization, plan-hash binding, exception approval, retries, retention, and status projections with a fake clock. Property tests exercise idempotency, event ordering, and invariant preservation.

### Contract tests

Ports and connectors share versioned test suites. Connector fixtures represent success, absent, ambiguous, throttled, challenged, redirected, changed-form, and malicious-content cases. All identities use reserved domains and synthetic addresses.

### Integration tests

- SQLite and PostgreSQL run the same repository and migration contract;
- queue crash/lease recovery and scheduler catch-up;
- vault encryption, rotation, wrong-key, and cryptographic deletion;
- filesystem and S3-compatible evidence backends;
- SMTP/IMAP test server correlation;
- connector subprocess isolation and egress policy;
- API/CLI parity and authorization.

### Synthetic end-to-end tests

A project-owned broker simulator implements web form, email, portal, challenge, denial, delayed acknowledgement, removal, and resurfacing scenarios. It is the only submission target in CI. Tests assert the UI, events, disclosure ledger, evidence, verification semantics, and notifications.

### Live canaries

Live canaries are not CI. They require a consenting controlled identity and a maintainer-run environment. Results are locally reviewed; only redacted pass/failure metadata may be published. A canary failure can quarantine but never auto-fix or auto-promote a connector.

## Security testing

- SAST, dependency audit, secret scan, SBOM and container scan;
- SSRF and DNS-rebinding cases;
- malicious redirects, oversized responses, decompression bombs, hostile downloads;
- prompt-injection content proving assistants cannot gain tools or PII;
- PII canary leakage scan over every diagnostic surface;
- object authorization and cross-profile isolation tests;
- fuzzing of connector envelopes, registry manifests, mail parsers, and evidence metadata;
- backup confidentiality and restore integrity;
- key rotation under interrupted execution.

## Connector quality scorecard

Capability trust is based on separately visible facts:

- provenance freshness;
- fixture coverage;
- last synthetic contract result;
- last controlled canary result and age;
- confirmed-match precision;
- submission transport success;
- independent verification success;
- challenge/manual-intervention rate;
- unexpected disclosure or destination changes;
- maintainer and review status.

There is no single opaque “severity” or “quality” number used to authorize actions.

## Release gates

### Read-only alpha

- no external submission code reachable;
- vault/key threat model reviewed;
- redaction and cross-profile tests pass;
- local-lite install, backup, and restore documented;
- at least five synthetic observe connectors pass contracts.

### Automatic-submission beta

- exact request preview and plan-hash binding to setup authorization or exception approval;
- email and browser transports pass simulator scenarios;
- emergency stop and unknown-outcome runbooks tested;
- two real broker connectors complete controlled canaries;
- external security review findings triaged.

### Stable v1

- cloud-small hardening and restore drills;
- signed images/SBOM/provenance;
- connector signing, expiry, and revocation;
- independent verified-removal reporting;
- documented legal review and jurisdiction support matrix;
- accessibility audit and performance budgets met;
- no unresolved critical/high vulnerability without expiring acceptance.

## Definition of done

A feature is done only when its requirements and threat cases are tested, migrations and rollback are documented, diagnostics are redacted, CLI and UI behaviors are consistent where applicable, user documentation describes limits, and the feature is disabled safely when its dependencies become stale.
