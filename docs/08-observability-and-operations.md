# Observability and operations

## Observability philosophy

Operators need to know whether privacy work is progressing without turning diagnostics into a shadow identity database. Telemetry uses opaque per-installation IDs, broker IDs where safe, connector versions, state/reason codes, durations, and counts. It excludes profile identifiers that correlate across exports, identity values, URLs containing search terms, page titles, message bodies, selectors containing PII, screenshots, and authorization text.

No remote telemetry is enabled by default.

## Structured events

Operational logs use an allowlisted schema:

```text
time, level, component, action, result_code, connector_id,
connector_version, duration_ms, retry_number, job_id, trace_id
```

The log API does not accept arbitrary domain objects. Sensitive values implement a type that renders as `[REDACTED:<category>]`. CI seeds canary names/emails/phones and fails if they appear in logs, traces, metrics, error pages, or diagnostic bundles.

## Metrics

### Reliability

- ready jobs by type and age;
- lease expirations and duplicate-suppression events;
- connector result/error class and latency;
- scheduler lag and catch-up budget;
- mail correlation failures;
- evidence write/hash failures;
- backup age and last successful restore verification.

### Product effectiveness

- confirmed finding precision;
- verified removal rate and time;
- asserted-but-not-verified age;
- resurfacing rate and time to re-removal;
- manual-intervention rate and reason;
- connector staleness/quarantine rate;
- disclosed attribute count per successful case.

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

### Broker workflow drift

Quarantine changed capabilities, preserve observe only if its contract passes, create maintainer/user tasks, diff the requested disclosure and destinations, update fixtures and sources, and require review before promotion.

### Key loss

Stop all actions. Restore the key from the separate operator backup. If unavailable, encrypted PII/evidence is unrecoverable by design. Do not reset the key and attempt to continue against old ciphertext.

### Database restore

Restore into isolation, supply key separately, run migrations in dry-run, verify event/evidence hashes, rebuild projections, disable external actions, review active leases/cases, then explicitly resume.

## Notifications

Notifications contain counts, reason codes, and a deep link, not names, broker findings, addresses, or request bodies. Digests collapse repeated connector failures and provide quiet hours. Security alerts bypass quiet hours only for actual disclosure/key/integrity events.
