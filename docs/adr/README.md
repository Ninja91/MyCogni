# Architecture decision records

ADRs capture decisions that constrain implementation or materially affect privacy, security, external actions, legal authority, deployment, or project governance.

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-modular-monolith-and-durable-db-queue.md) | Accepted for initial build | modular monolith and database-backed jobs |
| [0002](0002-local-custody-and-envelope-encryption.md) | Accepted for initial build | local custody and envelope encryption |
| [0003](0003-capability-scoped-connector-sandbox.md) | Accepted for initial build | isolated capability-scoped connectors |
| [0004](0004-evidence-based-outcome-semantics.md) | Accepted for initial build | evidence-based status semantics |
| [0005](0005-license-and-project-identity.md) | Accepted | Apache-2.0 and working-name review |
| [0006](0006-automatic-trusted-external-actions.md) | Accepted | setup-authorized automatic trusted actions |
| [0007](0007-key-hierarchy-and-deletion-semantics.md) | Accepted for initial build | random profile keys, recovery catalog, and honest deletion |
| [0008](0008-connector-artifacts-and-egress-enforcement.md) | Accepted for initial build | separate artifacts and mandatory fenced egress gateway |
| [0009](0009-external-side-effect-journal.md) | Accepted for initial build | immutable intent, fenced dispatch, and unknown outcomes |
| [0010](0010-control-plane-authentication.md) | Accepted for initial build | authenticated local/cloud control planes and step-up |
| [0011](0011-advisory-local-intelligence.md) | Accepted as a boundary; runtime deferred until post-v1 evidence | optional local models return untrusted suggestions only |
| [0012](0012-sqlite-local-lite-durability.md) | Accepted for initial build | one SQLite owner, exact-target code review accepted, storage eligibility, dirty recovery and fail-closed readiness; host qualification pending |

New ADRs use: context, decision, consequences, alternatives, security/privacy impact, and review trigger.
