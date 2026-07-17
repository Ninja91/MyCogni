# Stable V1 completion matrix

Snapshot date: 2026-07-17. This is a living evidence index, not a forecast. The current repository contains an architecture pack, interactive walkthrough, executable project skeleton, SQLite baseline, versioned connector contracts, typed local-diagnostics boundary, selected machine-checked threat catalog, a deterministic synthetic-only simulator, and a network-deny harness awaiting independent acceptance. It does not yet contain a remover runtime, accepted Docker image, accepted network-deny proof or live connector.

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
| Interactive architecture walkthrough | `IN_PROGRESS` | `reviews/11-site-adversarial-review.md`; source/offline ACCEPT with zero P0/P1/P2, pinned Pages workflow, matrix/deployment-linked guard and eight mutation tests | browser-backed keyboard/responsive/WCAG inspection, remote links and actual Pages publication remain open |
| Detailed V1 delivery plan | `VERIFIED` | integrated commit `115e367`; 106-package acyclic DAG; three independent re-reviews report zero P0/P1 plan blockers; links, Mermaid, JS, static HTTP and diff checks pass on 2026-07-15 | keep synchronized with implementation evidence |
| Runtime/project skeleton | `IN_PROGRESS` | implementation evidence and selected review records exist, but machine governance has not closed structured attestations and prerequisite chains; frozen lock and dual-Python checks remain active | PF-002 needs real two-architecture build evidence; structured M0 acceptance and remaining packages are open |
| Synthetic simulator/network-deny harness | `IN_PROGRESS` | SIM-001 and NET-001 have final code-level ACCEPT with zero P0/P1/P2; NET supplies exact authority provenance, revocable leases and a pre-import guarded launcher; 133 focused/935 dual-runtime lane tests plus 240-test final review | merged dual-runtime reproduction after active auth remediation; optional Linux namespace reproduction and authenticated attestations remain open |
| Auth/key/data/durable kernel | `NOT_STARTED` | design/ADRs only | M1 packages and failure evidence |
| Preview/guided product | `NOT_STARTED` | UX specification only | M2/M3 implementation and learning gates |
| Automatic connectors/egress | `NOT_STARTED` | protocols/threat model only | M4 plus qualified human reviews and canaries |
| Release artifacts/operations | `NOT_STARTED` | deployment specification only | M5 signed artifacts and drills |
| Recurring evidence/stable claim | `NOT_STARTED` | experiment design only | M6 twelve-week evidence hold and all gates |

## M0 — executable foundation

| Deliverable | Packages | Status | Evidence link | Blocker/next action |
| --- | --- | --- | --- | --- |
| Root locked toolchain | PF-001 | `IN_PROGRESS` | `7602e59`, `50c57b9`; executable evidence exists, but no structured commit-bound acceptance attestation is registered | add typed acceptance criteria and independent attestation before `COMPLETE` |
| Trusted-core boundaries | PF-CORE | `IN_PROGRESS` | `8980735`, `50c57b9`; executable evidence exists, but no structured commit-bound acceptance attestation is registered | add typed acceptance criteria and independent attestation before `COMPLETE` |
| Connector protocol boundary | PF-BOUNDARY | `IN_PROGRESS` | `5c51d23`, `cef7b0b`; executable evidence exists, but no structured commit-bound acceptance attestation is registered | add typed acceptance criteria and independent attestation before `COMPLETE` |
| Multi-architecture build skeleton | PF-002 | `IN_PROGRESS` | `bbf3735`, `8990fc4`, `564b091`; pinned indexes, semantic hardening/shebang checks and build-attempt record | Docker engine must produce successful amd64/arm64 build and runtime-inspection logs before `COMPLETE` |
| PR CI, frozen inputs and safety/claim guards | CI-001 | `IN_PROGRESS` | `73c097a`, `56f40e6`; executable evidence exists, but no structured commit-bound acceptance attestation is registered | add typed acceptance criteria and independent attestation before `COMPLETE` |
| Typed local diagnostics | TEL-001 | `IN_PROGRESS` | executable criterion evidence exists; no authenticated acceptance attestation exists | complete prerequisite and protected-review authorization before package completion |
| Selected threat/test catalog | THREAT-CATALOG-001 | `IN_PROGRESS` | executable criterion evidence exists; no authenticated acceptance attestation exists | complete prerequisite and protected-review authorization; selected catalog remains non-exhaustive |
| Full traceability validator | GOV-001 | `IN_PROGRESS` | `d1af517` plus `reviews/08-gov001-v4-adversarial-review.md`; final code-level ACCEPT with zero P0/P1/P2 after two rejected cycles | external history-disjoint trust root and authenticated reviewer attestations are intentionally unconfigured, so formal promotion remains impossible |
| SQLite and migration baseline | DB-001 | `IN_PROGRESS` | `4b8e154`, `da7f406`; executable evidence exists, but no structured commit-bound acceptance attestation is registered | add typed acceptance criteria and independent attestation before `COMPLETE` |
| Shared contracts | CT-001 | `IN_PROGRESS` | executable criterion evidence exists; no authenticated acceptance attestation exists | complete prerequisites and protected-review authorization before package completion |
| Synthetic corpus and deterministic simulator | SIM-001 | `IN_PROGRESS` | `fadaad6` plus remediation and `reviews/07-sim001-adversarial-review.md`; canonical reserved-domain corpus/scenario goldens, synchronized transactional clock/web/mail protocol and final code-level ACCEPT with zero P0/P1/P2 | authenticated independent attestation is still absent; NET-001 remains separate |
| Network-deny proof | NET-001 | `IN_PROGRESS` | `362795e`, `docs/v1/NET-001-NETWORK-DENY.md`, `reviews/09-net001-adversarial-review.md`; final code-level ACCEPT, 133 focused/87 simulator/935 dual-runtime lane tests and 240-test review evidence | authenticated attestation and optional Linux namespace reproduction remain open; OS-level hostile-code containment remains a nonclaim |
| Auth/key/egress/runner/browser/backup spikes | SPIKE-* | `IN_PROGRESS` | `1931d20`, `docs/v1/spikes/SPIKE-AUTH.md`, `reviews/12-spike-auth-adversarial-review.md`; 84 focused/949 dual-runtime lane tests followed by product/operator and backend REJECT | fix recovery/rebootstrap/root authority/transcript/operator gaps plus canonical recovery binding, record immutability, input typing and structural secret-retention evidence; then complete three-hat re-review |
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

Current next slice after the implemented toolchain, boundary, CI, database and shared-contract foundations:

1. restore a responsive Docker engine and capture successful PF-002 amd64/arm64 build and inspection logs;
2. complete GOV-001 and independently review the deterministic SIM-001 corpus/simulator;
3. land NET-001 before any non-simulator HTTP/browser/mail adapter can enter CI;
4. run the auth/key/egress/runner/browser/backup P0 spikes and update this matrix with ADR/test evidence;
5. add connector SDK minimum/latest Pydantic compatibility coverage before any public SDK release.

## Canonical work-package inventory

Every work package has a machine-equal status row; detailed evidence remains in the milestone sections above.

| Scope | Work package | Status | Evidence | Remaining |
| --- | --- | --- | --- | --- |
| Canonical inventory: A11Y-001 | A11Y-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: ACTION-001 | ACTION-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: ALPHA-001 | ALPHA-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: ARTIFACT-VERIFY-001 | ARTIFACT-VERIFY-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: AUTH-001 | AUTH-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: AUTH-002 | AUTH-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: AUTH-003 | AUTH-003 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: AUTHORITY-001 | AUTHORITY-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: AUTHZ-001 | AUTHZ-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: AUTO-CONSENT-001 | AUTO-CONSENT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: AUTO-ELIGIBILITY-001 | AUTO-ELIGIBILITY-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: BAK-001 | BAK-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: BAK-002 | BAK-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: BAK-RESTORE-001 | BAK-RESTORE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: BROW-001 | BROW-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: CANARY-001 | CANARY-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: CASE-001 | CASE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: CASE-RESP-001 | CASE-RESP-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: CHECKPOINT-001 | CHECKPOINT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: CON-001 | CON-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: CONSENT-001 | CONSENT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: CUSTOM-001 | CUSTOM-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: DATA-001 | DATA-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: DELETE-FINALIZE-001 | DELETE-FINALIZE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: DELETE-PREFLIGHT-001 | DELETE-PREFLIGHT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: DIGEST-001 | DIGEST-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: EVD-001 | EVD-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: EVT-001 | EVT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: EXT-PRE-AUTO | EXT-PRE-AUTO | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: GATEWAY-BASE-001 | GATEWAY-BASE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: GUIDE-001 | GUIDE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: GW-001 | GW-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: HUMAN-001 | HUMAN-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: INTENT-001 | INTENT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: JOB-STATE-001 | JOB-STATE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: KEY-001 | KEY-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: KEY-002 | KEY-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: MAIL-001 | MAIL-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: MATCH-001 | MATCH-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: MIG-001 | MIG-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: OBS-001 | OBS-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: OBS-AUTH-001 | OBS-AUTH-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: OFF-002 | OFF-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: OFF-PRE-001 | OFF-PRE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: OPS-001 | OPS-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: OUTBOX-001 | OUTBOX-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PAUSE-001 | PAUSE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PERMIT-001 | PERMIT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PILOT-AUTO | PILOT-AUTO | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PILOT-GUIDED | PILOT-GUIDED | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PILOT-PREVIEW | PILOT-PREVIEW | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PLAN-001 | PLAN-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PLAN-002 | PLAN-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PMF-001 | PMF-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: POL-001 | POL-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: PROOF-001 | PROOF-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: REC-BASE-001 | REC-BASE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: REC-BROWSER-001 | REC-BROWSER-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: REC-MAIL-001 | REC-MAIL-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: REG-001 | REG-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: REG-002 | REG-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: REL-001 | REL-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: RES-001 | RES-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: RESEARCH-001 | RESEARCH-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: RESTORE-INTENT-001 | RESTORE-INTENT-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: RUN-001 | RUN-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: SCHED-001 | SCHED-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: SPIKE-AUTH | SPIKE-AUTH | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: SPIKE-BACKUP | SPIKE-BACKUP | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: SPIKE-BROWSER | SPIKE-BROWSER | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: SPIKE-EGRESS | SPIKE-EGRESS | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: SPIKE-KEY | SPIKE-KEY | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: SPIKE-RUNNER | SPIKE-RUNNER | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: TRUST-001 | TRUST-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: UPDATE-001 | UPDATE-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: UPG-001 | UPG-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: UX-002 | UX-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: VER-001 | VER-001 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: VER-002 | VER-002 | `NOT_STARTED` | — | follow work-package dependency order |
| Canonical inventory: VER-SIM-001 | VER-SIM-001 | `NOT_STARTED` | — | follow work-package dependency order |
