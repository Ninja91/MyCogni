# Observability and operations

## Observability philosophy

Operators need to know whether privacy work is progressing without turning diagnostics into a shadow identity database. Telemetry uses opaque per-installation IDs, broker IDs where safe, connector versions, state/reason codes, durations, and counts. It excludes profile identifiers that correlate across exports, identity values, URLs containing search terms, page titles, message bodies, selectors containing PII, screenshots, and authorization text.

No remote telemetry is enabled by default. TEL-001 implements the initial typed, local-only
contract described in [the V1 diagnostics specification](v1/TEL-001-DIAGNOSTICS.md); it does not
yet compose a production server, browser, proxy, mailer, retention system, or support bundle.

Generic HTTP auto-instrumentation is disabled unless an allowlist processor proves that query strings, headers, peer IPs, exception text, URLs, page titles, and request/response bodies are removed before any exporter or local store. Prefer hand-authored safe spans at domain boundaries.

## Structured events

Operational logs use an allowlisted schema:

```text
time, level, component, action, result_code, connector_id,
connector_version, duration_ms, retry_number, job_id, trace_id
```

The log API does not accept arbitrary domain objects. Its action/result values and exception
categories are finite, event fields are catalog-bound, and correlations require opaque UUIDv4
IDs. Sensitive values implement a type that renders as `[REDACTED:<category>]`, but even redacted
domain values are not accepted as diagnostic fields. CI seeds synthetic canary names, emails,
phones, URLs, headers, HTML, mail, proxy/browser content, and secrets and fails if they appear in
the local JSON sink. Uvicorn access/default logs and future proxy/browser/mail automatic logs are
deny-by-default; a later composition package must prove it applies those settings.

## Metrics

### Reliability

- ready jobs by type and age;
- lease expirations and duplicate-suppression events;
- connector result/error class and latency;
- scheduler lag and catch-up budget;
- mail correlation failures;
- evidence write/hash failures;
- submission-journal states, stale-fence denials, and `outcome_unknown` age;
- egress-gateway denial class without raw destination/query data;
- backup age and last successful restore verification.

### Product effectiveness

- confirmed finding precision;
- verified removal rate and time;
- asserted-but-not-verified age;
- resurfacing rate and time to re-removal;
- manual-intervention rate and reason;
- connector staleness/quarantine rate;
- disclosed attribute count per successful case.
- assertion/one-absence/corroborated/inconclusive counts by verification method;
- optional assist validation/abstention/latency/resource class, never prompt bodies.

Metrics are local per installation. Public project metrics, if introduced, require explicit export of aggregates reviewed by the user.

## Health model

- **Liveness:** process event loop responds; no external dependency check.
- **Readiness:** schema current, key accessible, database/evidence store writable, no required policy incompatibility.
- **Worker capacity:** lease loop healthy and queue not administratively paused.
- **Scheduler leadership:** exactly one active leader in cloud-small.
- **Degraded:** core available but mail, connector class, browser, registry update, or notifications unavailable.

The UI names the degraded dependency and the work it affects.

## Runbooks

### Emergency stop

1. Activate global external-action pause; observation can be paused separately.
2. Revoke outstanding connector capability tokens and browser sessions.
3. Allow in-flight transports to record a terminal/unknown outcome; never blindly retry.
4. Snapshot redacted diagnostics and encrypted state.
5. Review the disclosure ledger and destination audit.

### Suspected connector compromise

1. Quarantine the exact connector release and block its destinations.
2. Identify action envelopes and disclosed attribute categories—not raw values—from the audit log.
3. Rotate connector-specific credentials/session state.
4. Review evidence in the local trusted UI.
5. Publish a signed revocation and incident note without user data.
6. Require reapproval before any replacement submit capability.

### Unknown submission outcome

Do not retry automatically. Mark `submission_outcome_unknown`, poll using a non-mutating channel if available, ask the user to inspect their inbox/portal, and deduplicate against external reference or payload digest before a new attempt.

The immutable intent survives connector upgrade/restart. A new attempt may be created only after reconciliation proves `failed_before_send` or a user performs a step-up reviewed exception with the duplicate-disclosure risk displayed.

### Broker workflow drift

Quarantine changed capabilities, preserve observe only if its contract passes, create maintainer/user tasks, diff the requested disclosure and destinations, update fixtures and sources, and require review before promotion.

### Key loss

Stop all actions. Restore KEK/recovery material from the separate operator source; the wrapped catalog comes from the managed archive. If recovery material is unavailable, encrypted PII/evidence is unrecoverable by design. Do not reset the key and attempt to continue against old ciphertext.

### Database restore

Restore into isolation, supply separate KEK/recovery material, load the archive's wrapped catalog, run migrations in dry-run, verify event/evidence integrity against the checkpoint statement, and rebuild projections. Before any connector/gateway starts, rotate the external installation dispatch epoch, invalidate all mailboxes/permits, keep actions disabled, mark every restored nonterminal external intent `reconciliation_required` regardless of creation time, reconcile gateway facts/receipts/mail/portals, review leases/cases, then step up and explicitly resume.

### Optional assist failure

Cancel inference, discard invalid/uncited output, release the heavy-work lease, record `assist_unavailable` with model/runtime/task digests, and continue the deterministic task. Do not acquire/update a model or retry repeatedly during catch-up.

## Notifications

Notifications contain counts, reason codes, and a deep link, not names, broker findings, addresses, or request bodies. Digests collapse repeated connector failures and provide quiet hours. Security alerts bypass quiet hours only for actual disclosure/key/integrity events.
