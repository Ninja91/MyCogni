# System architecture

## Architectural choice

MyCogni begins as a modular monolith with explicit ports between domain modules and external connectors. This keeps a local installation understandable and inexpensive while preserving a clean path to split connector workers or scale API/worker roles independently. The system uses one OCI image and no mandatory Redis, message broker, Kubernetes cluster, or AI service.

Proposed baseline:

- Python 3.12+
- FastAPI with server-rendered HTML and small progressive enhancements
- Typer CLI using the same application services as the API
- SQLAlchemy and Alembic
- SQLite in single-instance local-lite; PostgreSQL in cloud-small
- a database-backed durable job queue with leases and an outbox
- Playwright only inside isolated browser-capable connector workers
- OpenTelemetry-compatible structured diagnostics with local exporters disabled by default

The specific libraries remain replaceable behind ports. ADR-0001 records why this shape is preferred over microservices and a desktop-only application.

## Domain modules

| Module | Responsibility | Must not do |
| --- | --- | --- |
| Identity Vault | profiles, aliases, authorization, field encryption, attribute release | make network calls |
| Broker Registry | broker identity, domains, procedures, capabilities, provenance, expiry | store user PII |
| Discovery | schedule scans, classify findings, calculate match explanations | submit deletion requests |
| Case Management | cases, request plans, approvals, tasks, deadlines, events | execute arbitrary connector code in-process |
| Policy Engine | jurisdiction rules, disclosure and automation gates, retry/deadline decisions | infer legal rules from an LLM |
| Orchestrator | durable jobs, idempotency, leases, outbox, catch-up scheduling | bypass policy gates |
| Connector Runtime | invoke reviewed connector capabilities with minimum scoped data | access the full database or key store |
| Evidence Store | encrypted artifacts, hashes, retention, verification comparisons | call a finding “removed” without policy evidence |
| Reporting | dashboard projections, exports, digests, effectiveness measures | expose raw PII in telemetry |
| Integration Gateway | email, webhooks, OpenClaw/MCP-compatible tools | grant implicit write authority |

## Ports and adapters

Domain code depends on typed ports:

- `VaultPort`: retrieve a policy-approved attribute bundle by opaque profile reference;
- `BrokerRegistryPort`: resolve a versioned broker manifest;
- `ConnectorPort`: observe, prepare, submit, poll, and verify capabilities;
- `EvidencePort`: write/read encrypted artifacts and integrity metadata;
- `MailPort`: create drafts, send approved mail, and ingest correlated replies;
- `ClockPort`: deterministic deadline and retry testing;
- `EventPort`: append domain events and update projections;
- `SecretPort`: retrieve keys and connector credentials without persisting them in the database;
- `NotificationPort`: emit PII-free task/digest notifications.

The connector protocol is versioned JSON over a subprocess boundary initially. Cloud-small may replace the local subprocess transport with mutually authenticated internal HTTP without changing the domain port.

## Command path and data path

A user command or scheduled case becomes a domain command with an actor/automation principal, profile scope, intent, and idempotency key. Policy produces an allow, deny, or require-review decision. A trusted connector action is allowed automatically only when it is covered by the profile's active setup authorization and its plan hash fits the current destination and disclosure policy. Allowed work becomes a durable job. The worker creates a one-time capability token listing the connector, allowed action, destination domains, encrypted attribute bundle, expiry, and maximum attempts. The isolated runtime performs that single action and returns a structured result plus encrypted evidence references.

Connectors never receive a reusable vault API credential. Browser session state is connector- and profile-specific, encrypted, and not mounted into unrelated runs.

## Durable execution

Jobs use explicit state and renewable leases. PostgreSQL workers claim with row locking; SQLite supports exactly one active worker and scheduler. Every external action uses a deterministic idempotency key derived from case, action type, connector version, and attempt generation. A transactional outbox keeps events, notifications, and job creation consistent.

After downtime the scheduler does not replay every missed interval. It computes one catch-up decision per broker/profile from the latest completed observation, legal deadline, priority, and backoff state. Global and per-domain budgets prevent a thundering herd.

## Read/write capability model

Capabilities are monotonic in risk:

1. `catalog`: read public broker metadata;
2. `observe`: search or check for a record without submitting;
3. `prepare`: construct a proposed disclosure and request;
4. `submit`: transmit an approved request;
5. `poll`: check an existing case status;
6. `verify`: independently recheck presence/absence;
7. `escalate`: prepare a regulator complaint or custom follow-up, always reviewed initially.

A connector is approved separately for each capability and profile policy. Capability approval expires when destination, required PII, legal terms, selectors, or verification semantics materially change.

## Assistant integration boundary

The Integration Gateway exposes opaque case and summary identifiers, not direct database access. Initial OpenClaw-compatible tools are:

- `privacy_status`: counts and deadline summary with no raw PII;
- `list_attention_items`: user tasks and reasons;
- `draft_custom_case(url)`: safe intake only;
- `request_run(mode=observe)`: create an observe proposal;
- `open_mycogni_review(case_id)`: deep-link to the local exception-review UI.

Submission, evidence-body access, and vault reads are absent from the default tool surface. Any future mutating tool requires a short-lived grant bound to an actor, profile, case, and action.

## Failure containment

- A broken connector can fail one broker, not the scheduler or vault.
- A compromised connector gets only its one-time scoped input and destination allowlist.
- A failed notification cannot roll back an already recorded external submission.
- A corrupted projection can be rebuilt from domain events.
- A missing evidence object prevents `verified_removed`; it does not silently downgrade proof requirements.
- A policy update can pause affected jobs before execution.

See the [diagram index](diagrams/README.md) for component, trust-boundary, sequence, lifecycle, data, and deployment views.
