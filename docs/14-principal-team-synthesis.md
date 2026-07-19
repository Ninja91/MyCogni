# Principal-team synthesis and architecture disposition

Decision date: 2026-07-15.

After the independent role reviews, a role-based decision council re-evaluated every P0/P1 finding. The roles are decision responsibilities, not claims that named human staff have joined the project.

## Decision council

| Role | Decision responsibility |
| --- | --- |
| Principal engineer | implementation feasibility, external-effect correctness, operational recovery |
| Principal product manager | v1 wedge, trust experience, user research, scope and PMF gates |
| Principal software architect | boundaries, capability model, ADR consistency, deployment profiles |
| Principal scientist | evidence quality, measurement, local-intelligence evaluation and uncertainty |
| Senior open-source contributor | governance, contribution safety, provenance, sustainability and public claims |

## Accepted decisions

| Finding | Council disposition | Architecture/plan change | Owner lens |
| --- | --- | --- | --- |
| Subprocess-only connectors inherit too much authority | Accepted, P0 | separate digest-pinned artifacts; mandatory egress gateway; no core image/mount/network inheritance; ADR-0008 | engineer + architect |
| Root-derived profile keys undermine deletion | Accepted, P0 | random wrapped profile DEKs; purpose keys below; key-catalog/tombstone/backup-expiry semantics; ADR-0007 | architect + engineer |
| Queue idempotency cannot make an external send exactly once | Accepted, P0 | immutable intent vs attempts; fenced dispatch journal; no retry after dispatch without reconciliation; ADR-0009 | engineer |
| Loopback/private network is not authentication | Accepted, P0 | bootstrap auth, Host/Origin/CSRF/session controls, cloud passkey/OIDC, step-up, revocation epochs; ADR-0010 | engineer + architect |
| “Optional AI” can become implicit authority | Accepted, P0 before any AI | typed `IntelligencePort`, no-op default, `UntrustedSuggestion`, no tools/vault/network/state mutation; ADR-0011 | scientist + architect |
| One absence observation is not removal proof | Accepted, P1 | evidence ladder adds `observed_absent_once`, `inconclusive`, policy-defined corroboration for `verified_removed` | product + scientist |
| Product scope is too broad | Accepted, P1 | stable v1 is one consenting adult, small public set, guided flows, 2–5 automatic capabilities | product |
| Coverage count creates bad incentives | Accepted, P1 | generated per-capability support matrix; precision/proof/burden/disclosure metrics | product + OSS |
| Product reviews have promotional/astroturf risk | Accepted, P1 | source grading A/B/C; community evidence remains hypothesis input | scientist + product |
| Browser and inference can exhaust a small host | Accepted, P1 | shared `ResourceBudgetManager`; one heavy-work lease; deterministic work priority | engineer + scientist |
| Signed metadata can be stale or rolled back | Accepted, P1 | expiring versioned metadata, monotonic versions, delegated/threshold trust, artifact provenance | OSS + architect |
| Volunteer connector review capacity is finite | Accepted, P1 | maturity ladder, second reviewer for trusted submit, demote/retire on expiry | OSS |
| Custom removal is valuable | Accepted with boundary | v1 safe intake and guided draft; arbitrary automatic custom removal deferred | product + architect |
| Local LLM could reduce unstructured triage | Deferred experiment | no runtime/model in v1; build seam/harness; post-v1 shadow test needs 30% time reduction | scientist + product |

## Principal engineer response

The durable queue remains appropriate, but the plan no longer uses “exactly once” language for external side effects. `intent_id` survives connector upgrades and retries; `attempt_id` records execution. A fenced journal and gateway final-check protect the first outbound byte. Recovery turns uncertain post-backup or post-crash intents into explicit reconciliation work.

The engineer also rejects local/cloud equivalence as a security claim. Both profiles implement the same domain contract, but each earns conformance separately across queue behavior, key provider, object durability, sandbox, auth, and restore.

## Principal product manager response

The first value is an exposure preview and evidence comprehension, not automatic breadth. The wedge is “proof-first and locally held,” not “commercial clone.” The roadmap now contains adoption, precision, comprehension, burden, recurrence, and switching gates. Acute high-risk populations are not the primary alpha segment until the project can support failure escalation.

## Principal software architect response

The modular monolith remains, but connectors and optional intelligence are separate trust zones. New ports are `EgressPolicyPort`, `ResourceBudgetPort`, and `IntelligencePort`. The core owns all policy and state transitions. No extensibility mechanism can directly acquire a vault handle, database connection, external-action capability, or reusable key.

## Principal scientist response

The project will preserve denominators and abstentions. Anonymous product commentary cannot establish prevalence; benchmarks must match the task. The local-intelligence plan records artifact/runtime/prompt versions, literal supporting spans, canary leakage, classification metrics, safety-category recall, abstention, resource use, and manual-time outcome. No one aggregate “AI score” authorizes a feature.

## Senior open-source contributor response

Public participation starts with synthetic, observable work. Connector authority is earned per capability; a single routine PR cannot create trusted submission. Governance, DCO, CODEOWNERS, structured forms, support boundaries, and a zero-real-PII contributor path are present before runtime code. Imported facts and model artifacts keep separate provenance/licenses.

## Preserved dissent

- The scientist prefers deferring even the intelligence runtime seam until manual-work evidence exists. The architect accepts implementing a null port and evaluation contract during v1 because it prevents future privilege creep; both oppose a shipped model.
- Product would like a one-adult v1 for focus. The architecture retains profile isolation and multi-profile data modeling so a future household release does not require unsafe shared identity records.
- Local deployments cannot guarantee the same isolation as a VM/gVisor/Kata cloud runner. Documentation must state the residual shared-kernel risk rather than imply equivalence.

## Residual risks

Some private brokers remain unverifiable; browser automation and email remain brittle; a crash after network transmission can remain unknowable; local key loss is permanent; backups extend deletion timelines; laws and broker procedures drift; volunteer review capacity can collapse; open-source forks can remove safeguards; and a trusted destination can still misuse legitimately disclosed PII. Stable v1 must present these limits in-product.
