# System architecture

## Architectural choice

MyCogni begins as a Python modular monolith for trusted domain logic, with untrusted/volatile connectors and optional intelligence outside the core image and process. This keeps one local installation understandable and inexpensive while establishing real security boundaries where hostile content and selected PII meet extensible code.

Proposed baseline:

- Python 3.12+, FastAPI with server-rendered HTML, and a Typer CLI;
- SQLAlchemy/Alembic; SQLite with one worker in local-lite, PostgreSQL in cloud-small;
- database-backed durable jobs, transactional outbox, fenced submission journal, and event-sourced case history;
- separate digest-pinned OCI or constrained WASI connector artifacts;
- Playwright/Chromium only in an ephemeral browser artifact with its sandbox enabled;
- a mandatory egress policy gateway for every connector/browser byte;
- independent random profile keys wrapped by an external installation/cloud key;
- hand-authored PII-safe diagnostics; generic HTTP capture disabled;
- no mandatory Redis, message broker, Kubernetes, cloud, email vendor, CAPTCHA service, or AI runtime.

One core image exposes `serve`, `worker`, `scheduler`, and local `all-in-one` roles. Connector/browser images and any future model runtime are separate artifacts. ADR-0001 records the modular-monolith decision; ADRs 0007–0011 record the review-driven boundaries.

## Trusted domain modules

| Module | Responsibility | Must not do |
| --- | --- | --- |
| Identity Vault | profiles, aliases, authority, random profile keys, field release, deletion state | make network calls or expose a general vault API |
| Actor and Session | bootstrap/cloud authentication, sessions, step-up, revocation epochs | trust loopback/private network alone |
| Broker Registry | broker identity, procedures, capability maturity, provenance, expiry, revocation | store user PII or silently import external lists |
| Discovery | schedule scans, classify deterministic findings, calculate attribute explanations | submit requests or use an LLM for match truth |
| Case Management | cases, immutable plans, tasks, deadlines, state/evidence ladder | execute connector/model code in-process |
| Policy Engine | state/jurisdiction facts, disclosure, automation, retry and deadline gates | infer law/policy from external text or a model |
| Orchestrator | jobs, leases, outbox, catch-up, fences, submission journal | claim exactly-once network effects or bypass final gates |
| Resource Budget Manager | shared heavy-work lease, memory preflight, priority, budgets | allow optional assist to starve deadline/browser work |
| Evidence Store | encrypted artifacts, assurance method, keyed checkpoints, retention | infer truth from HTTP success or broker assertion |
| Reporting | dashboard projections, support matrix, exports, digests, PMF measures | blend denominators or expose PII in diagnostics |
| Integration Gateway | mail, notifications, metadata-only OpenClaw-compatible tools | grant implicit vault/submit authority |
| Intelligence Task Builder | deterministic sanitization and optional advisory invocation | pass raw PII/evidence or turn suggestions into commands |

## Ports and adapters

Domain code depends on typed ports:

- `VaultPort`: release a policy-approved attribute bundle by opaque action reference;
- `SecretPort`: wrap/unwrap independent profile keys without persisting the install/cloud KEK;
- `ActorPort`: authenticate, step up, and validate actor/profile/scope/revocation epoch;
- `BrokerRegistryPort`: resolve versioned, monotonic, unexpired capability metadata;
- `ConnectorPort`: invoke one digest-pinned artifact action;
- `EgressPolicyPort`: validate fence, authority, destination, public IP, redirect, method, protocol, disclosure, and budget;
- `EvidencePort`: write/read encrypted objects, verification method, and trusted checkpoint metadata;
- `MailPort`: create drafts, send exact intents, and ingest bounded correlated replies;
- `ClockPort`: deterministic deadline, retry, and expiry tests;
- `EventPort`: append keyed/signed events and update projections;
- `ResourceBudgetPort`: lease browser/inference-heavy work under profile-specific limits;
- `NotificationPort`: emit PII-free tasks/digests;
- `IntelligencePort`: return only `UntrustedSuggestion`; the default is a no-op.

SQLite/PostgreSQL, filesystem/object store, host keychain/KMS, connector runtime, mail provider, and optional local model are adapters with separate conformance results. Sharing a domain port does not imply identical security/failure behavior.

## Actor and command path

A UI/CLI/assistant request becomes a domain command containing authenticated actor, represented profile, scope, revocation epoch, intent, and idempotency key. Local browser sessions require bootstrap authentication, Host/Origin/CSRF checks, secure cookies/session rotation, and step-up for high-risk actions. Cloud-small uses TLS plus passkeys/WebAuthn or narrowly configured OIDC. CLI uses a permissioned authenticated local channel, never direct database access.

Policy returns allow, deny, or require-review. A plan eligible for automatic submission must fit a dedicated default-off step-up per-capability automation authorization, exact destination/disclosure, authority method, match threshold, connector digest/capability/freshness, jurisdiction fact, and all pause states. General setup/preview consent cannot enable send. Authorization binds the immutable plan hash and is rechecked at dispatch, not only at enqueue time.

## Durable jobs and external side effects

Ordinary jobs are at-least-once, lease-based, and idempotent at the domain boundary. PostgreSQL claims rows with locking; SQLite permits one worker and one scheduler. A transactional outbox keeps database events, projections, notifications, and job creation consistent.

External transmission uses a separate model:

- `intent_id` identifies the exact authorized side effect and never changes across connector versions or attempts;
- `attempt_id` identifies one execution;
- a monotonically increasing fence proves the current dispatch claim;
- journal states are `ready`, `dispatch_claimed`, `dispatch_started`, `transport_proven`, `outcome_unknown`, and `failed_before_send`.

The final dispatch transaction revalidates actor/profile authority, revocation epoch, plan/authorization hash, match, connector digest/freshness, destination/disclosure, and global/profile/broker pause. Immediately before dialing, the gateway calls online `authorize_and_start`; the core durably records `dispatch_started` under the current installation dispatch epoch before permission is returned. Verifier or persistence uncertainty fails closed. A crash/timeout/cancel after `dispatch_started` is `outcome_unknown`; no automatic retry occurs until authoritative reconciliation proves no send. Restore rotates the external dispatch epoch, invalidates mailboxes and reconciles every nonterminal external intent.

After downtime the scheduler calculates one bounded catch-up decision per broker/profile instead of replaying missed intervals. Restore rotates the external installation dispatch epoch, invalidates mailboxes/permits, leaves all external actions paused, and reconciles every restored nonterminal external intent regardless of creation time.

## Connector artifact and network boundary

Each connector capability is an immutable separately built artifact. It receives a short-lived action envelope, one-time decrypt key, sealed minimum attributes, destination/policy budget, fence, and no reusable core credential. It runs rootless/non-root with read-only root filesystem, tmpfs, dropped capabilities, syscall and PID/CPU/RAM/time limits, and no core image, DB/vault/key catalog, Docker socket, host network, or unrelated profile/session.

All network flows pass through the mandatory gateway. It revalidates origin and resolved public IP for every connection/redirect and denies private/link-local/loopback/metadata ranges, rebinding, undeclared protocols, WebSocket/QUIC/DoH, downloads, and byte/time overflow. Browser sessions use an ephemeral dedicated user/context and stop for CAPTCHA, MFA, terms/disclosure drift, or account controls.

Signatures identify reviewed artifacts; they do not create trust by themselves. Registry metadata is versioned, expiring, rollback-resistant, delegated per capability, revocable, and linked to artifact digest/SBOM/build provenance. Trusted automatic submit requires governance promotion and recent canary evidence.

## Evidence and outcome assurance

Transport receipt, acknowledgement, processing, broker assertion, one absence observation, corroborated verification, partial/denied, inconclusive, and resurfaced are distinct facts. `observed_absent_once` does not imply `verified_removed`. A versioned verification policy defines independent method, delay, number of observations, ambiguity/block handling, and acceptable corroboration.

Events and objects are content-hashed. Sensitive event chains are keyed/signed, with periodic monotonic checkpoints outside the primary DB. This is tamper evidence relative to a trusted checkpoint, not proof against a host/key compromise or broker deception.

## Optional local intelligence

V1 has a null `IntelligencePort` and no model runtime or weights. A later opt-in adapter receives only a deterministic sanitized bounded task and returns a schema-validated `UntrustedSuggestion` with supporting spans. It has no vault/database/network/tools/connector/authorization/command capability and cannot determine identity, policy, deadline, disclosure, destination, trust, verification, retry, or submission.

`ResourceBudgetManager` grants one heavy-work lease in minimum local-lite; browser/deadline work outranks advisory inference. Local model failure becomes `assist_unavailable` and cannot delay deterministic work. See `docs/16-local-intelligence-architecture.md` and ADR-0011.

## Assistant integration boundary

The Integration Gateway exposes opaque case and summary identifiers, not DB/vault access. Initial OpenClaw-compatible tools remain metadata-only: status, attention items, safe custom-case draft, observe proposal, and a deep link to the trusted local review UI. Submission, evidence bodies, identity fields, model sessions, and approval are absent. Any future write needs an actor/profile/case/action grant, step-up policy, expiry, and revocation epoch.

## Failure containment

- A broken connector affects one capability/digest, not the core or other sessions.
- A stale fence or revoked authorization cannot emit the first byte through the gateway.
- A missing/ambiguous evidence object produces inconclusive, never success.
- A failed notification cannot roll back a recorded send.
- A corrupted projection is rebuilt from authenticated events and checked against the external checkpoint.
- A model failure removes an advisory suggestion only.
- A policy/registry revocation pauses affected queued and claimed work before dispatch.

See the [diagram index](diagrams/README.md) for context, components, trust/PII, request sequence, lifecycle, data, deployment, and decision-authority views.
