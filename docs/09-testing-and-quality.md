# Testing and quality strategy

## Test pyramid

### Domain unit tests

Pure tests cover state transitions, deadline calculations, setup-authorization scope, disclosure minimization, plan-hash binding, exception approval, retries, retention, and status projections with a fake clock. Property tests exercise idempotency, event ordering, and invariant preservation.

External-side-effect tests distinguish immutable intent from attempts/fences and never assume database idempotency produces exactly-once network delivery.

### Contract tests

Ports and connectors share versioned test suites. Connector fixtures represent success, absent, ambiguous, throttled, challenged, redirected, changed-form, and malicious-content cases. All identities use reserved domains and synthetic addresses.

### Integration tests

- SQLite and PostgreSQL run the same repository and migration contract;
- queue crash/lease recovery and scheduler catch-up;
- vault encryption, rotation, wrong-key, and cryptographic deletion;
- random profile-key catalog, old-catalog backup restore after deletion, tombstone/expiry, interrupted rotation, nonce uniqueness, and associated-data substitution;
- filesystem and S3-compatible evidence backends;
- SMTP/IMAP test server correlation;
- connector artifact isolation and mandatory gateway policy;
- API/CLI parity and authorization.
- authenticated local bootstrap/session/step-up plus cloud passkey/OIDC contract;
- dispatch journal/fencing/reconciliation across SQLite and PostgreSQL;
- optional no-op intelligence and sanitized task/output contracts without a model dependency.

### Synthetic end-to-end tests

A project-owned broker simulator implements web form, email, portal, challenge, denial, delayed acknowledgement, removal, and resurfacing scenarios. It is the only submission target in CI. Tests assert the UI, events, disclosure ledger, evidence, verification semantics, and notifications.

### Live canaries

Live canaries are not CI. They require a consenting controlled identity and a maintainer-run environment. Results are locally reviewed; only redacted pass/failure metadata may be published. A canary failure can quarantine but never auto-fix or auto-promote a connector.

## Security testing

- SAST, dependency audit, secret scan, SBOM and container scan;
- SSRF and DNS-rebinding cases;
- malicious connector attempts to read `/proc`, environment, core/DB/evidence/key volumes, Docker socket, host metadata, another session, and private networks;
- redirect, WebSocket, QUIC, DoH, byte-budget, allowed-origin exfiltration, stale-fence, and revoked-epoch attempts;
- malicious redirects, oversized responses, decompression bombs, hostile downloads;
- prompt-injection content proving assistants cannot gain tools or PII;
- model/advisory content proving suggestions cannot mutate identity, policy, authorization, disclosure, trust, status, retry, or submission;
- PII canary leakage scan over every diagnostic surface;
- object authorization and cross-profile isolation tests;
- fuzzing of connector envelopes, registry manifests, mail parsers, and evidence metadata;
- backup confidentiality and restore integrity;
- key rotation under interrupted execution.
- CSRF, Host/Origin abuse, localhost DNS rebinding, session theft/rotation, cross-profile authority, and stale grant replay;
- process kill/crash at every journal transition, lease loss during send, duplicate scheduler, connector upgrade mid-intent, delayed response, and pre-submission backup restore.

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

The public support matrix is generated from these facts. A metadata row is never counted as equivalent to a trusted submit/verify capability.

## Optional intelligence evaluation

No model runs in v1 CI. The port/null adapter and security invariants are tested. A future task-specific shadow suite requires:

- 100% schema and supporting-span validation or abstention;
- zero PII canaries in model input/output/log/trace/bundle surfaces;
- zero authority, tool, network, or state mutation under adversarial output;
- re-evaluation for every model/quantization/runtime/prompt/schema/redactor change;
- task-specific accuracy/recall/abstention plus p50/p95 latency, peak RSS, disk/CPU and limitations;
- the PMF gate of at least 30% manual-time reduction without safety, semantic, disclosure, or false-positive regression.

## Release gates

### Read-only alpha

- no external submission code reachable;
- vault/key threat model reviewed;
- redaction and cross-profile tests pass;
- local-lite install, backup, and restore documented;
- authenticated local control plane and key-catalog deletion semantics pass adversarial tests;
- at least five synthetic observe connectors pass contracts.

### Automatic-submission beta

- exact request preview and plan-hash binding to setup authorization or exception approval;
- email and browser transports pass simulator scenarios;
- separate connector artifacts and mandatory egress gateway pass the malicious-connector suite;
- immutable intent/fenced dispatch passes kill/revoke/restore/reconciliation scenarios;
- emergency stop and unknown-outcome runbooks tested;
- two real broker connectors complete controlled canaries;
- external security review findings triaged.
- proof/disclosure comprehension gate passes for pilot users.

### Stable v1

- cloud-small hardening and restore drills;
- signed images/SBOM/provenance;
- connector signing, expiry, and revocation;
- independent verified-removal reporting;
- documented legal review and jurisdiction support matrix;
- accessibility audit and performance budgets met;
- no unresolved critical/high vulnerability without expiring acceptance.
- public support matrix and profile-specific conformance results match tested artifacts/configurations;
- twelve-week beta reports precision, verified outcomes, disclosure cost, manual burden, recurrence, and unknown outcomes with denominators.

## Definition of done

A feature is done only when its requirements and threat cases are tested, migrations and rollback are documented, diagnostics are redacted, CLI and UI behaviors are consistent where applicable, user documentation describes limits, and the feature is disabled safely when its dependencies become stale.
