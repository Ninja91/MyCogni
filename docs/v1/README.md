# Stable V1 delivery control plane

This directory is the execution source of truth for MyCogni stable V1. It turns the architecture pack into an issue-ready, evidence-gated program while preserving the honest boundary that the repository has no working remover yet.

## Documents

| Document | Purpose |
| --- | --- |
| [Implementation plan](IMPLEMENTATION_PLAN.md) | V1 definition, reference stack, milestones, dependency chain, gates, and critical decisions |
| [Work packages](WORK_PACKAGES.md) | issue-sized backlog with dependencies, estimates, acceptance evidence, and ownership lane |
| [Orchestration and review](ORCHESTRATION.md) | agent roles, three-worktree ceiling, integration protocol, and adversarial review loop |
| [Completion matrix](COMPLETION_MATRIX.md) | living milestone/deliverable status with evidence and explicit blockers |
| [SQLite durability evidence](SQLITE-DUR-001.md) | local-lite writer/storage/dirty-shutdown decision, executable evidence and residual host qualification |
| [SPIKE-KEY evidence](spikes/SPIKE-KEY.md) | explicit local KEK, strict profile-key wrap/AAD, owner-only provider and open host-conformance rows |
| [Implementation-planner synthesis](reviews/01-implementation-planner-synthesis.md) | independent product, backend, and platform planning findings and council disposition |
| [Adversarial review disposition](reviews/02-adversarial-review.md) | independent product, security/platform, and backend/OSS findings plus applied corrections |
| [SPIKE-KEY exact-target review](reviews/17-spike-key-exact-target-adversarial-review.md) | initial rejection, required remediation and repeat-review gate |
| [AUTH-001A durable state](AUTH-001A-DURABLE-STATE.md) | digest-only SQLite decision state, atomic one-use boundaries and explicit remaining blockers |
| [AUTH-001B host-secret custody](AUTH-001B-HOST-SECRET-CUSTODY.md) | owner-file custody for composition-held authentication authority |
| [AUTH-001C operator terminal](AUTH-001C-OPERATOR-TERMINAL.md) | native `/dev/tty`, no-echo restoration and partial-disclosure semantics |

## Current program state

- **Program state:** M0 implementation is active; executable foundations and a deterministic reserved-domain simulator exist, but there is no working remover.
- **Current milestone:** M0 — executable foundation; accepted-source foundations are integrated. After six rejected targets, SPIKE-KEY exact target `35eda23` has three clean code-level ACCEPT verdicts and 106 focused tests. Host/provider conformance, durable accounting/recovery and authenticated external attestations are still required, so formal package promotion remains fail-closed.
- **Current public claim:** architecture plus synthetic developer-foundation evidence only; no accepted Docker image, live connector, real-broker submission, verified removal, or supported deployment.
- **Planning envelope for a release candidate:** week 32 with three experienced implementation lanes, subject to M0 velocity and reviewer/canary latency.
- **Earliest stable V1 eligibility:** week 40 or later, after at least twelve weeks and a mature day-90 denominator for the automatic cohort.
- **Supported V1 deployment:** local-lite, one consenting U.S. adult, one core worker/scheduler, 2–5 separately reviewed automatic connector capabilities.
- **Explicitly post-V1:** cloud-small, household administration, arbitrary custom automation, dynamic connector installation, OpenClaw write authority, and any local/remote model runtime.

Milestone status changes only when the acceptance evidence in the completion matrix exists. Calendar time, code volume, requests sent, and connector count cannot substitute for a gate.
