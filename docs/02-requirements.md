# Requirements

Requirement keywords use MUST, SHOULD, and MAY in their usual normative sense. IDs are stable references for plans, tests, and ADRs.

Unless tagged otherwise, a requirement applies to stable V1. `AU-03`, `OPS-04`, and `PORT-01` are **POST-V1 cloud-small** requirements. `IN-02` through `IN-04` and `AI-02` through `AI-08` are **POST-V1 integration/assist** constraints retained to prevent unsafe architectural shortcuts; `AI-01` applies to V1 and requires the null/no-model path. Post-V1 requirements do not gate local-lite stable V1.

## Functional requirements

### Identity and authorization

- **ID-01** The domain and storage model MUST support multiple people while cryptographically and operationally isolating each profile; stable v1 product support is one consenting adult per installation until household authority is reviewed.
- **ID-02** A profile MUST support current and historical names, emails, phone numbers, and addresses with validity ranges and provenance.
- **ID-03** The system MUST record jurisdiction, age/guardianship status, consent, and authorization scope before preparing an external request.
- **ID-04** Family members MUST be separate profiles; adding a person to one identity record is prohibited.
- **ID-05** The vault MUST allow per-profile export and cryptographic deletion.
- **ID-06** Every profile MUST use an independent random wrapped data-encryption key; purpose keys MAY be derived below it, but the profile key MUST NOT be reproducible from an installation root after deletion.
- **ID-07** A profile deletion report MUST disclose known managed wrapped-key-catalog archive horizons, MUST NOT claim live/managed cryptographic inaccessibility while one can restore the profile key, and MUST warn that external filesystem snapshots/operator copies are outside MyCogni's inventory.

### Actor authentication and authority

- **AU-01** Local and cloud control planes MUST authenticate actors; loopback, LAN, VPN, or private-network location alone is insufficient.
- **AU-02** Web control planes MUST enforce Host/Origin policy, CSRF protection, secure session/cookie policy, clickjacking protection, and session rotation/revocation.
- **AU-03** Cloud-small MUST support a phishing-resistant authentication reference profile using passkeys/WebAuthn or narrowly configured OIDC.
- **AU-04** Setup-authorization changes, external-action resume, exception submission, key export/recovery changes, profile deletion, and destructive restore MUST require step-up authentication.
- **AU-05** Every grant MUST bind actor, represented profile, authority evidence, scope, expiry, and revocation epoch.
- **AU-06** Self-attestation MUST be distinct from verified-control evidence. Each automatic capability MUST define an independently reviewed authority method; a workflow that accepts arbitrary typed identity without credible self-authority control MUST remain guided/manual.

### Broker registry and discovery

- **BR-01** Every broker record MUST include provenance, observed date, review date, jurisdiction, domains, organization identity, and capability-specific confidence.
- **BR-02** Broker facts MUST expire and become ineligible for unattended automation until revalidated.
- **BR-03** Scans MUST distinguish not checked, checked/not found, candidate found, confirmed match, ambiguous match, and check failed.
- **BR-04** Match reasoning MUST be explainable at the attribute level without exposing unrelated third-party PII.
- **BR-05** Custom URLs MUST enter an untrusted intake path and require review before scripts or credentials are used.

### Request orchestration

- **RQ-01** Observe, prepare, approve, submit, receive, follow up, escalate, and verify MUST be separate auditable actions.
- **RQ-02** Every proposed submission MUST show destination, legal/policy basis, transport, disclosed attributes, attachments, and risk warnings.
- **RQ-03** All external actions MUST default globally paused. An eligible action MAY submit automatically only after a dedicated, non-preselected, step-up-authenticated automation ceremony and only within the exact active authorization, named capability/destination class, disclosure ceiling, expiry, pause behavior, and challenge behavior. Onboarding, profile creation, preview, and renewal MUST NOT silently enable automation.
- **RQ-03A** The system MUST suspend automatic submission and require review after a material connector/destination/disclosure/legal-policy change, an ambiguous match, or a request/value outside the dedicated automation authorization.
- **RQ-04** Each exact authorized external action MUST have an immutable `intent_id` independent of connector version or attempt; each execution MUST have a distinct `attempt_id`, neither leaking a globally correlatable user identifier.
- **RQ-05** The system MUST calculate deadlines from versioned jurisdiction policy and show the policy source/version.
- **RQ-06** Retry policies MUST use broker-specific rate limits, bounded backoff, and duplicate suppression.
- **RQ-07** CAPTCHA, MFA, identity challenge, account login, ambiguous match, changed terms, or unexpected disclosure MUST suspend automation and create a user task.
- **RQ-08** A user MUST be able to revoke an unsent request, disable a broker, pause all external actions, and rotate credentials.
- **RQ-09** External dispatch MUST use a fenced journal with explicit `ready`, `dispatch_claimed`, `dispatch_started`, `transport_proven`, `outcome_unknown`, and `failed_before_send` semantics.
- **RQ-10** The final dispatch transaction and egress gateway MUST revalidate authorization epoch, plan hash, match policy, connector digest/freshness, destination/disclosure, and all global/profile/broker pauses before the first outbound byte.
- **RQ-11** Once dispatch has started, timeout/crash/cancellation MUST produce `outcome_unknown`; automatic retry is prohibited until reconciliation proves no send.
- **RQ-12** A real observation scan or custom fetch that discloses identity attributes is an external action even when it sends no removal request. It MUST have separate consent, an exact disclosure preview/record, a current pause epoch, a fenced journal entry and gateway authorization. Preview consent MUST NOT imply removal authorization.
- **RQ-13** Every first-byte permit MUST include an installation dispatch epoch held outside data backups and MUST use an online `authorize_and_start` decision. Restore MUST rotate the epoch, invalidate outstanding mailboxes/permits, pause external actions and require reconciliation of every restored nonterminal intent regardless of intent creation time.

### Evidence and verification

- **EV-01** Submission evidence MUST capture a timestamp, connector version, redacted payload summary, destination, and response digest.
- **EV-02** Broker acknowledgement and independent absence verification MUST use different states.
- **EV-03** `verified_removed` MUST require post-submission corroboration satisfying a versioned verification policy that defines timing, method, independence, and inconclusive conditions.
- **EV-04** Negative scan evidence MUST include enough context to reproduce the check while minimizing storage of page content.
- **EV-05** Resurfacing MUST create a new occurrence linked to the prior case, not rewrite history.
- **EV-06** Evidence integrity MUST use content hashes plus keyed/signed event chaining and an external monotonic checkpoint, and MUST state the assurance boundary honestly.
- **EV-07** Reports MUST distinguish broker assertion, `observed_absent_once`, `verified_removed`, and `inconclusive`; rate limits, CAPTCHA, access denial, ambiguous search, geolocation/personalization uncertainty, and missing evidence are inconclusive.
- **EV-08** Tamper-evidence claims MUST be relative to a trusted keyed/signed checkpoint outside the primary database; an unkeyed recomputable chain MUST NOT be described as append-only proof.

### Experience and reporting

- **UX-01** Dashboard and CLI MUST show current state, blocking reason, owner, last action, next action, and next date.
- **UX-02** Reports MUST separate public exposure, private-broker requests, manual tasks, assertions, verified removals, failures, and resurfacing.
- **UX-03** The user MUST be able to preview every released identity field per broker.
- **UX-04** Digests MUST be useful after sporadic/offline operation and avoid notification spam.
- **UX-05** Every supported V1 UI flow MUST meet WCAG 2.2 AA and support keyboard-only completion, accessible reauthentication and errors, focus restoration, timeout extension, non-color status, high contrast, reduced motion, and 200%/400% zoom.
- **UX-06** The system SHOULD provide privacy-hygiene guidance without claiming that tools such as VPNs prevent data brokerage.
- **UX-07** Every nonterminal case MUST show reason, owner, last evidence, next action, and next date; an unexplained spinner or generic “processing” label is prohibited.
- **UX-08** The generated support matrix MUST expose capability, maturity, freshness/expiry, jurisdiction basis, required disclosure categories, human steps, verification method, and recent test/canary age per connector.
- **UX-09** The product MUST provide pause, export, backup status, uninstall/scheduler-disable, key deletion, and residual-backup-horizon guidance.
- **UX-10** Product claims MUST preserve denominators and MUST NOT market broker count, requests sent, acknowledgement, or one absence observation as verified effectiveness.

### Integrations

- **IN-01** SMTP/IMAP or provider adapters MUST use scoped credentials and separate message bodies from logs.
- **IN-02** Assistant integrations MUST default to metadata-only read access.
- **IN-03** An assistant MUST NOT approve disclosure, access raw PII/evidence, or submit externally without a separately enabled capability and a current user confirmation policy.
- **IN-04** All external integrations MUST have a kill switch and auditable grants.

### Optional local intelligence

- **AI-01** The product MUST be fully functional with a no-op intelligence adapter and MUST NOT bundle, download, or require a model in v1.
- **AI-02** `IntelligencePort` MUST return only a schema-validated `UntrustedSuggestion` with supporting spans; it MUST NOT create a command or mutate domain state.
- **AI-03** A model MUST NOT receive raw PII/evidence, a vault/database/connector handle, tools, network access, authorization, reusable conversation, or credentials.
- **AI-04** A model MUST NOT decide identity match, legal eligibility/policy, deadline, authorization, disclosure, destination, connector trust, verification/outcome, retry, or external action.
- **AI-05** Model input MUST be deterministically selected, normalized, redacted, bounded, and canary-tested; prompt bodies MUST NOT be retained.
- **AI-06** Model, quantization, runtime, prompt, schema, and redactor versions MUST be immutable, license/provenance reviewed, digest-pinned, revocable, and re-evaluated per task.
- **AI-07** Invalid, unsupported, unavailable, timed-out, OOM, or uncited output MUST abstain and MUST NOT fail or delay deterministic broker work.
- **AI-08** No assist task may leave shadow mode without published task accuracy/safety/resource results and a measured user-time benefit; remote fallback, per-user fine-tuning, and RAG over vault/evidence are prohibited.

## Quality attributes

- **SEC-01** Raw PII MUST be field-encrypted at rest and protected in transit.
- **SEC-02** The installation/cloud key-encryption key MUST remain outside application data/evidence backups; the recoverable wrapped-profile-key catalog MUST be classified, separately protected, inventoried, and included in deletion truth.
- **SEC-03** Logs, metrics, traces, support bundles, and notifications MUST be PII-redacted by construction.
- **SEC-04** Connector execution MUST use a separate digest-pinned artifact with a rootless/non-root identity, read-only root filesystem, tmpfs workspace, dropped capabilities, `no-new-privileges`, syscall and resource limits, and no core image, database, vault, key catalog, Docker socket, host network, or unrelated session.
- **SEC-05** All connector/browser egress MUST traverse a mandatory fail-closed policy gateway. For gateway-owned declarative HTTP and mail, it MUST originate the exact typed request or message. For opaque browser TLS it MUST enforce the current online action permit, connector/capability, origin, resolved public IP, port, new redirects, protocol, and byte/time budget, and MUST NOT claim visibility into method, path, body, or response semantics. Core minimization limits connector plaintext; the allowed-origin exfiltration residual risk MUST be disclosed.
- **SEC-06** Registry/update metadata MUST provide expiry, monotonic version/rollback protection, delegated capability trust, revocation, artifact digest verification, and build provenance; a signature alone is insufficient.
- **PRV-01** Data collection and retention MUST be purpose-limited, user-visible, and configurable within safe minimums.
- **REL-01** Queue actions MUST be durable, idempotent, lease-based, and recoverable after process termination.
- **REL-02** Local-lite MUST tolerate being offline for months and safely calculate catch-up work.
- **OPS-01** Backup/restore MUST be documented and automatically testable without putting the installation/cloud KEK in the application data/evidence archive.
- **OPS-02** Every schema and broker-manifest change MUST be versioned and migratable.
- **OPS-03** Restore MUST rotate the installation dispatch epoch, invalidate outstanding mailboxes/permits, leave external actions paused, and reconcile every restored nonterminal external intent regardless of creation time before step-up resume.
- **OPS-04** Local-lite and cloud-small MUST publish separate conformance results for database queueing, keys, evidence, sandbox, auth, backup, restore, and upgrades; common domain code MUST NOT be presented as equivalent security behavior.
- **PERF-01** Idle local-lite SHOULD use less than 250 MiB RAM excluding an active browser and near-zero CPU.
- **PERF-02** Browser workers MUST start on demand and shut down after a bounded idle period.
- **PERF-03** Local-lite MUST grant one shared heavy-work lease to browser or optional inference, with memory preflight and deterministic external-deadline work taking priority.
- **PERF-04** Optional inference MUST use concurrency one and bounded input/output/time/CPU/RAM/tmp/queue budgets; active inference is reported separately from the core idle target.
- **PORT-01** The same versioned OCI image MUST support local-lite and cloud-small roles on amd64 and arm64.
- **PORT-02** Core workflows MUST not depend on a commercial AI, CAPTCHA, email, or cloud service.
- **GEO-01** Stable v1 MUST support United States privacy workflows only and MUST NOT imply legal coverage for other jurisdictions.
- **TEST-01** No connector may submit to a real broker in CI.
- **TEST-02** Release gates MUST include migration, restore, redaction, connector contract, and synthetic end-to-end tests.
- **TEST-03** Release gates for external actions MUST kill execution at every dispatch-journal edge and test stale fences, revocation-after-claim, duplicate schedulers, connector upgrades, delayed receipts, and pre-submission backup restore.
- **TEST-04** Connector isolation tests MUST attempt forbidden filesystem/environment/socket/metadata access, DNS rebinding, redirects, WebSocket/QUIC/DoH, byte-budget violations, and allowed-origin exfiltration.
- **TEST-05** Control-plane tests MUST cover CSRF, DNS rebinding against localhost, Host abuse, session theft/rotation, cross-profile authorization, and stale grant replay.
- **GOV-01** A live unattended `submit` capability MUST NOT receive `trusted` maturity from one bootstrap maintainer; two qualified reviewers or an equivalent approved governance change are required.
- **GOV-02** Imported broker facts, datasets, fixtures, connector code, and model artifacts MUST retain source, license/terms, review, transformation, and expiry provenance.
- **GOV-03** Stable V1 MUST have zero unresolved P0 findings and no unresolved P1 on an enabled capability. A P1 surface may be deferred only by disabling/removing it from stable artifacts and support claims; compensating controls do not permit an enabled P0/P1 stable surface.

## Explicitly deferred

Business accounts, family/guardian administration, identity insurance, credit monitoring, dark-web monitoring, generalized content moderation, public-record source correction, mobile apps, fully autonomous AI connector generation, arbitrary-site automatic custom removal, non-U.S. legal support, and a hosted multi-tenant SaaS are not initial requirements.
