# Independent implementation-planner synthesis

Review date: 2026-07-15.

> Historical planning input: the later independent adversarial review rejected the week-18/week-24 schedule and several boundary assumptions. Current decisions are in the [implementation plan](../IMPLEMENTATION_PLAN.md) and [adversarial disposition](02-adversarial-review.md).

Three independent agent tracks inspected the same canonical repository before seeing this synthesis:

1. Principal Product/UX implementation planner;
2. Principal Backend/Domain implementation planner;
3. Principal Platform/Security implementation planner.

They are AI-assisted role analyses, not human staffing, legal advice, security certification, or connector approval. The orchestrator interface did not expose a model-selection field, so the requested “Luna” model assignment could not be attested; the tracks were separated by task, context and review order instead.

## Convergence

All three tracks independently concluded:

- the repository is architecture-only and runtime implementation has not started;
- stable V1 must stay one-adult, local-lite, U.S.-only and deliberately small;
- cloud-small, a model runtime and dynamic connector installation must move after stable V1;
- the 18-week stable claim conflicts with the required twelve-week recurring pilot;
- three experienced lanes can target a week-18 release candidate and week-24 earliest stable gate; a solo implementation is roughly 28–36 weeks plus external latency;
- connector services should be predeclared by digest so the core never receives a Docker socket;
- external effects need immutable intents, separate attempts, a fenced journal, first-byte reauthorization and explicit unknown outcomes;
- qualified human legal/security/connector review remains required for live trusted capabilities; adversarial agents cannot approve them;
- work must begin with executable P0 spikes, a deterministic simulator, locked dependencies, architecture boundaries and synthetic-only CI.

## Council disposition

| Topic | Product track | Backend track | Platform track | Decision |
| --- | --- | --- | --- | --- |
| Stable timing | week 24 earliest | 28–36 weeks solo | 28–36 weeks solo | M5 RC week 18; M6 stable evidence gate week 24 earliest |
| Core language | Python/FastAPI/Typer | Python modular monolith | Python 3.12 modular monolith | Python 3.12 baseline, 3.13 CI; patch versions frozen in M0 |
| Persistence | SQLite/Alembic | SQLite UoW; early PostgreSQL awareness | SQLite WAL local-lite | SQLite only supported in V1; cloud implementation deferred |
| UI | accessible server-rendered | shared API/application handlers | FastAPI server-rendered | Jinja + project-owned JS; no SPA framework |
| Egress | mandatory boundary | narrow egress port/protocol | separate Go service recommended | executable M0 spike; separate service is mandatory, Go is reference choice |
| Connector launch | 2–5 trusted | predeclared Compose services | static digest-pinned services | accepted; no dynamic supervisor or Docker socket |
| Local authentication | bootstrap/session/step-up | passkey possibility needs spike | terminal bootstrap + CLI step-up | no required passkey in local V1; M0 ceremony/recovery spike |
| ID type | not specified | UUIDv7 | not specified | UUIDv4 opaque IDs in V1; no clock/extra-library dependency |
| AI | no runtime | null port only | no model/runtime | accepted; post-V1 experiment only |
| Worktrees | core/product/boundary | up to four conceptual lanes | four conceptual lanes | maximum three physical worktrees; product rotates through integration lane |

## Preserved dissent and uncertainty

- A separate Go egress service reduces privilege and packaging size, but it adds a second language. M0 must compare enforcement, auditability, failure behavior and operator cost; the service boundary is mandatory even if Go is rejected.
- The backend track suggested WebAuthn enrollment for local V1. Product and platform tracks identified headless/NAS recovery risk. V1 instead starts with terminal bootstrap, opaque server sessions and CLI-minted step-up; passkeys remain an optional later ADR.
- Early PostgreSQL tests reduce future lock-in but can disguise an unsupported cloud profile. The V1 program requires portable ports/migrations where inexpensive but publishes no PostgreSQL/cloud claim or gate.
- Browser TLS enforcement cannot prove content-level minimum disclosure without interception. V1 documents the residual risk that a malicious trusted connector can misuse its minimum bundle at an allowed origin.
- Exact first brokers, transport-proof semantics, local key-provider ergonomics and external reviewer availability remain decision gates rather than invented assumptions.

## Changes caused by the planner wave

- corrected stable timing and added M6 evidence hold;
- split execution into six gated milestones plus a living completion matrix;
- added an exact reference stack, repository layout and interface freeze;
- narrowed V1 to local-lite/SQLite/predeclared connectors;
- added issue-sized work packages with dependencies and acceptance evidence;
- added a maximum-three-worktree orchestration and adversarial disposition loop;
- made human reviewer availability an explicit controlled-automation dependency;
- moved local auth, KEK, egress/TLS, connector launch and backup format into executable M0 spikes.
