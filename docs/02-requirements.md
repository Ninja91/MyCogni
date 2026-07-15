# Requirements

Requirement keywords use MUST, SHOULD, and MAY in their usual normative sense. IDs are stable references for plans, tests, and ADRs.

## Functional requirements

### Identity and authorization

- **ID-01** The system MUST support multiple people while cryptographically and operationally isolating each profile.
- **ID-02** A profile MUST support current and historical names, emails, phone numbers, and addresses with validity ranges and provenance.
- **ID-03** The system MUST record jurisdiction, age/guardianship status, consent, and authorization scope before preparing an external request.
- **ID-04** Family members MUST be separate profiles; adding a person to one identity record is prohibited.
- **ID-05** The vault MUST allow per-profile export and cryptographic deletion.

### Broker registry and discovery

- **BR-01** Every broker record MUST include provenance, observed date, review date, jurisdiction, domains, organization identity, and capability-specific confidence.
- **BR-02** Broker facts MUST expire and become ineligible for unattended automation until revalidated.
- **BR-03** Scans MUST distinguish not checked, checked/not found, candidate found, confirmed match, ambiguous match, and check failed.
- **BR-04** Match reasoning MUST be explainable at the attribute level without exposing unrelated third-party PII.
- **BR-05** Custom URLs MUST enter an untrusted intake path and require review before scripts or credentials are used.

### Request orchestration

- **RQ-01** Observe, prepare, approve, submit, receive, follow up, escalate, and verify MUST be separate auditable actions.
- **RQ-02** Every proposed submission MUST show destination, legal/policy basis, transport, disclosed attributes, attachments, and risk warnings.
- **RQ-03** Default policy MUST automatically submit through a fresh trusted connector when the action fits the profile's active setup authorization, match policy, destination allowlist, and maximum disclosure schema.
- **RQ-03A** The system MUST suspend automatic submission and require review after a material connector/destination/disclosure/legal-policy change, an ambiguous match, or a request for an attribute outside the setup authorization.
- **RQ-04** Requests MUST be idempotent and carry a stable internal case ID without leaking a globally correlatable user identifier.
- **RQ-05** The system MUST calculate deadlines from versioned jurisdiction policy and show the policy source/version.
- **RQ-06** Retry policies MUST use broker-specific rate limits, bounded backoff, and duplicate suppression.
- **RQ-07** CAPTCHA, MFA, identity challenge, account login, ambiguous match, changed terms, or unexpected disclosure MUST suspend automation and create a user task.
- **RQ-08** A user MUST be able to revoke an unsent request, disable a broker, pause all external actions, and rotate credentials.

### Evidence and verification

- **EV-01** Submission evidence MUST capture a timestamp, connector version, redacted payload summary, destination, and response digest.
- **EV-02** Broker acknowledgement and independent absence verification MUST use different states.
- **EV-03** `verified_removed` MUST require post-submission evidence and a verification policy that defines timing and method.
- **EV-04** Negative scan evidence MUST include enough context to reproduce the check while minimizing storage of page content.
- **EV-05** Resurfacing MUST create a new occurrence linked to the prior case, not rewrite history.
- **EV-06** Evidence integrity MUST be detectable with content hashes and an append-only event chain.

### Experience and reporting

- **UX-01** Dashboard and CLI MUST show current state, blocking reason, owner, last action, next action, and next date.
- **UX-02** Reports MUST separate public exposure, private-broker requests, manual tasks, assertions, verified removals, failures, and resurfacing.
- **UX-03** The user MUST be able to preview every released identity field per broker.
- **UX-04** Digests MUST be useful after sporadic/offline operation and avoid notification spam.
- **UX-05** The UI SHOULD meet WCAG 2.2 AA and support keyboard-only completion of setup-authorization and exception-review flows.
- **UX-06** The system SHOULD provide privacy-hygiene guidance without claiming that tools such as VPNs prevent data brokerage.

### Integrations

- **IN-01** SMTP/IMAP or provider adapters MUST use scoped credentials and separate message bodies from logs.
- **IN-02** Assistant integrations MUST default to metadata-only read access.
- **IN-03** An assistant MUST NOT approve disclosure, access raw PII/evidence, or submit externally without a separately enabled capability and a current user confirmation policy.
- **IN-04** All external integrations MUST have a kill switch and auditable grants.

## Quality attributes

- **SEC-01** Raw PII MUST be field-encrypted at rest and protected in transit.
- **SEC-02** The master key MUST remain outside the application database and backups.
- **SEC-03** Logs, metrics, traces, support bundles, and notifications MUST be PII-redacted by construction.
- **SEC-04** Connector execution SHOULD be isolated with a destination allowlist, ephemeral filesystem, memory/CPU/time limits, and no access to the full vault.
- **PRV-01** Data collection and retention MUST be purpose-limited, user-visible, and configurable within safe minimums.
- **REL-01** Queue actions MUST be durable, idempotent, lease-based, and recoverable after process termination.
- **REL-02** Local-lite MUST tolerate being offline for months and safely calculate catch-up work.
- **OPS-01** Backup/restore MUST be documented and automatically testable without putting the master key in the backup archive.
- **OPS-02** Every schema and broker-manifest change MUST be versioned and migratable.
- **PERF-01** Idle local-lite SHOULD use less than 250 MiB RAM excluding an active browser and near-zero CPU.
- **PERF-02** Browser workers MUST start on demand and shut down after a bounded idle period.
- **PORT-01** The same versioned OCI image MUST support local-lite and cloud-small roles on amd64 and arm64.
- **PORT-02** Core workflows MUST not depend on a commercial AI, CAPTCHA, email, or cloud service.
- **GEO-01** Stable v1 MUST support United States privacy workflows only and MUST NOT imply legal coverage for other jurisdictions.
- **TEST-01** No connector may submit to a real broker in CI.
- **TEST-02** Release gates MUST include migration, restore, redaction, connector contract, and synthetic end-to-end tests.

## Explicitly deferred

Business accounts, identity insurance, credit monitoring, dark-web monitoring, generalized content moderation, public-record source correction, mobile apps, fully autonomous AI connector generation, and a hosted multi-tenant SaaS are not initial requirements.
