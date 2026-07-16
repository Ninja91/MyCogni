# Stable V1 completion matrix

Snapshot date: 2026-07-15. This is a living evidence index, not a forecast. The current repository contains an architecture pack and interactive walkthrough, but no remover runtime, Docker image, database migration, simulator or connector.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| `NOT_STARTED` | no integrated implementation evidence |
| `IN_PROGRESS` | implementation or planning has begun, but the deliverable is not complete |
| `BLOCKED` | a named dependency prevents safe progress |
| `COMPLETE` | integrated implementation and package acceptance checks exist |
| `VERIFIED` | milestone-level evidence has been independently reproduced |

Documentation describing a future component is not implementation evidence for that component.

## Program summary

| Area | Status | Current evidence | Missing before V1 |
| --- | --- | --- | --- |
| Product/research architecture | `VERIFIED` | `README.md`, `docs/00`–`16`, source-graded research, requirements and threat model | keep synchronized with implementation findings |
| Interactive architecture walkthrough | `VERIFIED` | static `site/`, local static-server smoke tests, published Pages workflow | keep release status architecture-only until runtime evidence exists |
| Detailed V1 delivery plan | `VERIFIED` | integrated commit `115e367`; 106-package acyclic DAG; three independent re-reviews report zero P0/P1 plan blockers; links, Mermaid, JS, static HTTP and diff checks pass on 2026-07-15 | keep synchronized with implementation evidence |
| Runtime/project skeleton | `IN_PROGRESS` | PF-001/PF-CORE/PF-BOUNDARY/CI-001 and DB-001 independently accepted; frozen 55-package lock, four import contracts and 56 tests pass on Python 3.12.12 on 2026-07-15 | PF-002 needs real two-architecture build evidence |
| Synthetic simulator/network-deny harness | `NOT_STARTED` | architecture fixtures only | SIM-001/NET-001 |
| Auth/key/data/durable kernel | `NOT_STARTED` | design/ADRs only | M1 packages and failure evidence |
| Preview/guided product | `NOT_STARTED` | UX specification only | M2/M3 implementation and learning gates |
| Automatic connectors/egress | `NOT_STARTED` | protocols/threat model only | M4 plus qualified human reviews and canaries |
| Release artifacts/operations | `NOT_STARTED` | deployment specification only | M5 signed artifacts and drills |
| Recurring evidence/stable claim | `NOT_STARTED` | experiment design only | M6 twelve-week evidence hold and all gates |

## M0 — executable foundation

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Root locked toolchain | PF-001 | `COMPLETE` | `7602e59`, `50c57b9`; exact uv/Python/build constraints and clean-clone frozen bootstrap/check independently reproduced | await milestone-level verification with the rest of M0 |
| Trusted-core boundaries | PF-CORE | `COMPLETE` | `8980735`, `50c57b9`; four import contracts, absolute/relative prohibited-edge fixtures and separate core wheel independently reproduced | preserve graph as real imports arrive |
| Connector protocol boundary | PF-BOUNDARY | `COMPLETE` | `5c51d23`, `cef7b0b`; isolated typed package plus independently reproduced legal/package artifact inspection | validation and enforcement remain CT-001/RUN-001 work |
| Multi-architecture build skeleton | PF-002 | `IN_PROGRESS` | `bbf3735`, `8990fc4`, `564b091`; pinned indexes, semantic hardening/shebang checks and build-attempt record | Docker engine must produce successful amd64/arm64 build and runtime-inspection logs before `COMPLETE` |
| PR CI, frozen inputs and safety/claim guards | CI-001 | `COMPLETE` | `73c097a`, `56f40e6`; Python 3.12.12/3.13.11, immutable Actions and 12 negative CI fixtures independently reproduced | retain full-SHA Actions and update claim baseline explicitly |
| Safe diagnostics and traceability catalog | TEL-001, THREAT-CATALOG-001, GOV-001 | `NOT_STARTED` | — | CI foundation is accepted |
| SQLite and migration baseline | DB-001 | `COMPLETE` | `4b8e154`, `da7f406`; fail-closed physical-file/WAL/FULL/FK/timeout policy and Alembic round trips independently reproduced | locking/backup/filesystem qualification remain later packages |
| Shared contracts | CT-001 | `NOT_STARTED` | — | freeze before parallel adapters |
| Synthetic corpus and deterministic simulator | SIM-001 | `NOT_STARTED` | — | create reserved-domain fixtures |
| Network-deny proof | NET-001 | `NOT_STARTED` | — | depends on CI and simulator |
| Auth/key/egress/runner/browser/backup spikes | SPIKE-* | `NOT_STARTED` | — | execute and record ADRs |
| SQLite/process durability contract | SQLITE-DUR-001 | `NOT_STARTED` | — | filesystem/process/write model must be frozen |
| Synthetic-only authenticated shell | UX-001 | `NOT_STARTED` | — | depends on auth/contracts |
| M0 milestone | all M0 | `IN_PROGRESS` | plan and first three foundation packages integrated | complete remaining M0 packages and independently reproduce evidence |

## M1 — secure local kernel

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Local authentication and authority | AUTH-001–003 | `NOT_STARTED` | — | M0 auth ADR/contracts |
| Profile keys, encrypted identity and deletion | KEY-001–002, DATA-001 | `NOT_STARTED` | — | M0 key spike |
| Events, checkpoint, jobs and catch-up | EVT-001, CHECKPOINT-001, JOB-STATE-001, OUTBOX-001, SCHED-001 | `NOT_STARTED` | — | DB/contracts/key foundation |
| Evidence, migration and backup/restore verification | EVD-001, MIG-001, BAK-001, BAK-RESTORE-001 | `NOT_STARTED` | — | backup-format and checkpoint decisions |
| Consent and generic outbound-action safety | CONSENT-001, ACTION-001, GATEWAY-BASE-001, RESTORE-INTENT-001 | `NOT_STARTED` | — | required before any real observation network action |
| Independent reviewer recruitment | REVIEWER-RECRUIT-001 | `NOT_STARTED` | — | reviewer availability remains an external lead-time risk |
| Setup/health experience | OPS-001, UX-002 | `NOT_STARTED` | — | secure kernel APIs |
| M1 milestone | all M1 | `NOT_STARTED` | — | M0 must be `VERIFIED` |

## M2 — zero-removal-request preview alpha

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Registry and honest support matrix | REG-001–002 | `NOT_STARTED` | — | stable registry contracts |
| Signed read-only artifacts, trust freshness, scan authorization, isolation and egress | CON-001, TRUST-001, UPDATE-001, ARTIFACT-VERIFY-001, RUN-001, OBS-AUTH-001 | `NOT_STARTED` | — | identity-disclosing observation requires current signed trust and artifact verification |
| Observations, matching and cases | OBS-001, MATCH-001, CASE-001 | `NOT_STARTED` | — | M1 durable kernel |
| Preview/evidence/task UI | UX-003 | `NOT_STARTED` | — | cases and support matrix |
| Research protocol, local ledger and preview cohort | RESEARCH-001, PMF-001, ALPHA-001, PILOT-PREVIEW | `NOT_STARTED` | — | working authorized preview and participant recruitment |
| M2 milestone | all M2 + preview LG-1 | `NOT_STARTED` | — | zero removal submissions; preview precision cannot authorize automation |

## M3 — guided request beta

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Policy, self-authority and setup authorization | POL-001, AUTHORITY-001, AUTHZ-001 | `NOT_STARTED` | — | qualified source/authority review scope |
| Minimum-disclosure plans and ledger | PLAN-001–002 | `NOT_STARTED` | — | policy + confirmed matches |
| Scoped credential lifecycle | CRED-001 | `NOT_STARTED` | — | required only for credential-bearing transports; no reusable-secret leakage |
| Guided/manual/custom guidance | GUIDE-001, CUSTOM-001 | `NOT_STARTED` | — | exact plans; submit remains absent |
| Proof, resistance cases, attention and pre-submit offboarding | PROOF-001, CASE-RESP-001, DIGEST-001, OFF-PRE-001, OFF-002 | `NOT_STARTED` | — | durable cases/backup; full journal restore is later |
| Simulator verification and guided cohort | VER-SIM-001, PILOT-GUIDED | `NOT_STARTED` | — | independent state axes and working guided flows |
| Null intelligence seam | AI-001 | `NOT_STARTED` | — | contracts only; no model dependency |
| Guided learning gates | BETA-001 | `NOT_STARTED` | — | pilot participants and working flows |
| M3 milestone | all M3 + LG-2/LG-3 | `NOT_STARTED` | — | comprehension gates must pass |

## M4 — controlled automation beta

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Submit-capability trust enforcement | TRUST-001, UPDATE-001, ARTIFACT-VERIFY-001 | `NOT_STARTED` | — | reuse M2 trust plumbing with stricter per-submit review/promotion |
| Dedicated automation consent, intents, permits and pause epochs | AUTO-CONSENT-001, INTENT-001, PERMIT-001, PAUSE-001 | `NOT_STARTED` | — | general setup/preview grants can never enable send |
| Typed gateway and transports | GW-001, MAIL-001, BROW-001 | `NOT_STARTED` | — | browser has explicit opaque-TLS residual risk |
| Unknown-outcome reconciliation | REC-BASE-001, REC-MAIL-001, REC-BROWSER-001 | `NOT_STARTED` | — | transport proof contracts; capability depends only on its adapter |
| First 2–5 capability selection | CONN-SEL | `NOT_STARTED` | — | maintainer choice after policy/terms/source review |
| Automatic eligibility and qualified human reviews | AUTO-ELIGIBILITY-001, EXT-PRE-AUTO, HUMAN-001 | `NOT_STARTED` | — | shared-boundary plus capability reviewers required |
| Controlled-identity canaries and automatic cohort | CANARY-001, PILOT-AUTO | `NOT_STARTED` | — | explicit maintainer authorization; 12 weeks/day-90 before stable |
| M4 milestone | all M4 | `NOT_STARTED` | — | no AI review substitutes for human approval |

## M5 — local release candidate

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Verification, recurrence and resurfacing | VER-001–002 | `NOT_STARTED` | — | simulator semantics precede controlled capability results |
| Honest reports | DIG-001 | `NOT_STARTED` | — | recurring denominator data |
| Restore/deletion reconciliation | BAK-002, DELETE-PREFLIGHT-001, DELETE-FINALIZE-001 | `NOT_STARTED` | — | reconcile or explicitly abandon unknown actions before key destruction |
| Signed multiarch artifacts and runbooks | REL-001, UPG-001 | `NOT_STARTED` | — | complete runtime components |
| Resilience and accessibility drills | RES-001, A11Y-001 | `NOT_STARTED` | — | integrated release candidate |
| External security/policy review | EXT-001 | `NOT_STARTED` | — | reviewer availability and evidence bundle |
| Release candidate | RC-001 | `NOT_STARTED` | — | all M5 gates; may set only `release_candidate` |

## M6 — stable evidence hold

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Preview/guided/automatic cohort maturity | PILOT-PREVIEW, PILOT-GUIDED, PILOT-AUTO | `NOT_STARTED` | — | automatic cohort alone must reach 12 weeks and mature day 90 |
| Safety and product-viability analysis | CLAIM-001 | `NOT_STARTED` | — | complete denominator-preserving data by gate class |
| OSS/name/support sustainability | OSS-001 | `NOT_STARTED` | — | maintainer/contributor and trademark/confusion review |
| Stable release | STABLE-001 | `NOT_STARTED` | — | every stable gate must be `VERIFIED` |

## Known future decisions and external dependencies

These do not block M0 foundation work, but they block their named milestones:

| Dependency | Needed by | Owner | Current state |
| --- | --- | --- | --- |
| Reference local host priority: macOS laptop vs NAS/Linux parity | M1 release statement | maintainer | decision requested before M1 verification |
| Email credential/draft policy | M3/M4 mail path | maintainer + security reviewer | draft-only default until decided |
| First 2–5 broker capabilities | M3 selection/M4 beta | maintainer + product/policy team | must be sourced; no invented list |
| Qualified crypto/connector/U.S. policy reviewers | M4/M5 | maintainer/orchestrator | availability not yet confirmed |
| MyCogni name/trademark/confusion disposition | stable V1 | maintainer + qualified counsel if needed | unresolved |

## Next executable slice

Current next slice after the accepted toolchain, boundary, CI and database packages:

1. restore a responsive Docker engine and capture successful PF-002 amd64/arm64 build and inspection logs;
2. freeze CT-001 before adapters diverge;
3. start TEL-001/THREAT-CATALOG-001/GOV-001 and the deterministic SIM-001 corpus;
4. land NET-001 before any HTTP/browser/mail adapter can enter CI;
5. run the auth/key/egress/runner/browser/backup P0 spikes and update this matrix with ADR/test evidence.
