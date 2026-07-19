# V1 independent adversarial review and disposition

Review date: 2026-07-15. Draft reviewed: the first detailed V1 plan and 72-package backlog.

Three reviewers were launched against the same draft before the orchestrator used any conclusion:

1. product, misuse, claims, accessibility and research validity;
2. platform, security, supply chain, containers and deployment;
3. backend, state-machine recovery, data lifecycle and OSS sustainability.

`Sol` is a role label only. The collaboration interface did not expose a model-selection or attestation field. These were independent-prompt AI reviews, not legal advice, security certification, blinded research or the qualified human review required before live action.

## Result

The draft was rejected as an implementation source of truth. The reviewers identified 23 P0 findings before clustering. They converged on four fundamental failures:

- a “read-only” preview still transmits identity data and therefore needs consent, disclosure, a journal, pause epoch and fail-closed gateway;
- restore, revocation and offline permits could replay or enable stale external actions;
- a generic proxy cannot enforce exact content inside opaque browser TLS or originate trustworthy mail semantics;
- the package dependencies and cohort clocks made week-18 RC/week-24 stable mathematically unsupported.

The revised plan accepts those failures, expands the backlog to more than 100 dependency-checked packages, moves the generic external-action boundary before live observation, and changes the planning envelope to week 32 RC/week 40 or later for stable eligibility with three experienced lanes. No runtime package is yet complete or verified.

## P0 disposition

| Cluster | Failure story | Disposition and changed evidence |
| --- | --- | --- |
| Observation is an external disclosure | M2 could send names/locations while calling itself “zero-send,” before authority/journal/gateway existed | **Accepted-fixed in plan.** M2 is “zero-removal-request”; `CONSENT-001`, `ACTION-001`, `GATEWAY-BASE-001`, `OBS-AUTH-001` and `RQ-12` precede real scans. LG-1 allows zero removal submissions, not zero network bytes. |
| Stable cohort clock | Preview evidence cannot validate later automatic disclosure, unknown outcomes or resurfacing; one pilot depended on RC and still claimed week 24 | **Accepted-fixed.** `PILOT-PREVIEW`, `PILOT-GUIDED` and `PILOT-AUTO` are separate. Stable requires the automatic cohort to run at least twelve weeks and mature through day 90. Earliest planning eligibility is week 40 or later. |
| Unsupported schedule | More than 300 ideal days and serial core dependencies contradicted week 18 | **Accepted-fixed.** Dependency-derived M0–M5 envelope is weeks 0–32; solo estimate is 75–90 weeks. M0 velocity must reforecast it. |
| Automation consent | Broad or preselected setup authorization could silently enable sends | **Accepted-fixed.** `RQ-03` now globally pauses external actions and requires a dedicated, non-preselected, step-up ceremony naming capability, destination class, disclosure ceiling, expiry, pause and challenge behavior. |
| Self-authority | An operator could type another adult's identity and request removal | **Accepted-fixed in plan.** `AU-06` and `AUTHORITY-001` distinguish self-attestation from verified control; unproven capability authority stays guided/manual and receives policy/legal review. |
| Match safety | A 10–15-user PMF pilot and 95% point estimate cannot authorize unattended wrong-person actions | **Accepted-fixed.** Preview precision is usability evidence only. `AUTO-ELIGIBILITY-001` requires a per-capability preregistered corpus, denominator/confidence bound, collisions/ambiguity and zero known wrong-person canaries. |
| Exact disclosure UX | Field categories could hide the historical value, body or attachment actually sent | **Accepted-fixed.** `PLAN-002` shows exact revealable values, current/history rationale, origin/path/transport, rendered message/attachments and diff; the sealed envelope must match. |
| Pause race truth | “Paused/cancelled” could be shown after dispatch began | **Accepted-fixed in contract.** `PAUSE-001` drives product projections for prevented-before-send, already-started and unknown states; no cancelled claim follows `dispatch_started`. |
| Flat case status | One status mixed match, request, assurance and work/blockage truth | **Accepted-fixed in plan.** `VER-SIM-001` implements independent axes at occurrence/right level; case status is a projection and never upgrades an entire case from one occurrence. |
| Restore replay | A restored pre-backup `ready` intent may actually have been sent after the backup | **Accepted-fixed in contract.** `RQ-13`, `ACTION-001` and `RESTORE-INTENT-001` add an external installation dispatch epoch, invalidate mailboxes and require reconciliation for every restored nonterminal intent, regardless of creation time. |
| Offline permit | A signed cached permit could outlive pause/revocation/restore state | **Accepted-fixed.** No offline permit mode. The gateway calls online `authorize_and_start`; core durably records gateway begin before dial; unavailable verifier or uncertain persistence fails closed. |
| Incomplete dispatch state machine | Lease expiry, no-send proof, attempt/intent terminality and reconciliation were ambiguous | **Accepted-fixed in plan, implementation evidence pending.** `ACTION-001`, `INTENT-001` and `REC-BASE-001` own the normative state machine; gateway begin/no-begin is conservative authority and transport proof is not outcome proof. |
| Deletion during unknown outcome | Destroying a profile key could erase evidence needed to reconcile a disclosure | **Accepted-fixed.** `DELETE-PREFLIGHT-001` pauses/cancels/reconciles, then `DELETE-FINALIZE-001` destroys/sweeps; forced abandonment requires step-up and an explicit loss-of-reconciliation report. |
| Opaque TLS overclaim | CONNECT cannot see browser path/body and generic proxying cannot enforce mail recipient/body | **Accepted-fixed.** The transport matrix separates gateway-owned declarative HTTP, trusted mailer, browser origin/IP/port/budget enforcement and guided/manual. Browser allowed-origin exfiltration remains a disclosed residual risk. |
| Emergency revocation | An offline host could wake with a known-compromised connector and no trusted freshness path | **Accepted-fixed in plan.** `UPDATE-001` adds offline-pinned threshold trust, signed monotonic timestamp/snapshot/targets-equivalent metadata, expiry/revocation and fail-closed automatic catch-up. |
| Artifact identity | Digest-pinned Compose did not establish signer/provenance or verify rendered deployment | **Accepted-fixed in plan.** `ARTIFACT-VERIFY-001` verifies signer, digest, SBOM/provenance and saves a signed deployment inventory; wrong/stale/revoked/mismatched artifacts fail. |
| Backup/catalog ambiguity | Excluding the catalog made restore impossible; including secrets could defeat separation/deletion claims | **Accepted-fixed in contract.** Archive includes wrapped-DEK catalog and encrypted state/evidence plus schema/manifest/checkpoint/journal boundary; it excludes KEK/recovery and signing secrets, live dispatch epoch and plaintext. SQLite online backup is required. |
| Deletion overclaim | MyCogni cannot inventory Time Machine, snapshots or operator copies | **Accepted-fixed.** Claims are limited to cryptographic inaccessibility in the live installation and known managed backups, with external-backup caveats. |
| Pre-canary shared review | Capability review did not necessarily review shared auth/key/backup/gateway/journal boundaries | **Accepted-fixed in plan.** `EXT-PRE-AUTO` is required before `CANARY-001`; `HUMAN-001` remains capability-specific. Reviewer recruitment starts in M1. |
| Unresolved P0/P1 stable policy | Draft allowed an expiring compensating control for P0/P1 despite calling P0 release-stopping | **Accepted-fixed.** `GOV-03` requires zero P0 and no P1 on any enabled stable capability. A P1 surface must be fixed or removed/disabled; compensation does not enable it. |
| Cloud MUST conflict | Local V1 excluded cloud while normative requirements still required cloud behavior | **Accepted-fixed.** Requirements now carry applicability: cloud and assistant behavior is post-V1 and does not gate local-lite V1. |
| SQLite/WAL durability | `FULL` alone does not prove durability on Docker Desktop/NAS or coordinate multiple writers/backups | **Accepted-fixed in plan.** `SQLITE-DUR-001`, `MIG-001`, online backup, dirty-shutdown pause/reconcile and filesystem conformance precede live actions. |

“Accepted-fixed” above means the implementation plan/requirement/backlog contradiction was corrected. It does not mean the runtime control exists; the completion matrix remains `NOT_STARTED` until executable evidence is produced.

## P1 disposition

### Accepted into named work

- Root lockfile ownership moved to integration; `PF-CORE` and `PF-BOUNDARY` allow three lanes to start without conflicting writers.
- `SPIKE-BROWSER` must prove a project-owned non-root sandboxed image with private shared memory, pinned seccomp, no `SYS_ADMIN`/host IPC, and Linux Engine/Docker Desktop amd64/arm64 evidence.
- `TEL-001` disables unsafe default access/proxy/browser logs and tests PII canaries across URL, header, error, HTML, mail and proxy paths.
- `THREAT-CATALOG-001` creates stable threat/test IDs before `GOV-001` enforces traceability.
- Jobs were split into `JOB-STATE-001`, `OUTBOX-001` and `SCHED-001`; removal mail is prohibited from the generic outbox.
- `MIG-001`, `CHECKPOINT-001`, `BAK-001` and `BAK-RESTORE-001` distinguish migration, authenticated checkpoint, integrity-only verification and actual isolated restore proof.
- The one-adult V1 invariant is enforced through UI/CLI/API/import/restore, while internal profile isolation remains future-compatible.
- Setup is progressive; attributes are labeled local/disclosed/unused and optional historical values can be skipped or deleted.
- `RESEARCH-001` preregisters recruitment, acute-risk exclusion, consent/withdrawal, retention, incentives, publication and adverse-event handling.
- `CASE-RESP-001` covers denial, exemption, partial completion, overdue response, contradicted assertion, follow-up and `closed_unverified`.
- `DIGEST-001` moves attention/unknown/overdue visibility before automation.
- Reconciliation is common plus transport-specific (`REC-BASE`, `REC-MAIL`, `REC-BROWSER`), so a capability does not depend on an unused transport.
- Verification state machinery is simulator-proven before canaries (`VER-SIM-001`); live policies activate later.
- Resource claims cover all idle application services, browser peak, disk/cache, backup scratch and upgrade coexistence, not only core RSS.
- Build language now says repeatable, digest-pinned, signed and provenance-attested until bit-for-bit reproducibility is demonstrated.
- Qualified reviewer records include qualifications, independence/conflicts, scope, reviewed digest, date, expiry and triggers.

### Accepted as M0/M1 ADR or test detail

- bootstrap material is interactive CLI-only, one-use/short-lived/hashed, never logged, and protected from referrer/history leakage;
- choose one local KEK path and document Docker Desktop/Linux permission and recovery behavior without calling Compose file secrets encrypted at rest;
- define AES-GCM nonce generation, per-key budget/rotation and collision response, subject to pre-live cryptography review;
- define one application process/Uvicorn worker with bounded worker/scheduler components, serialized journal writes and signal-edge tests;
- publish explicit host-loopback Compose mapping and reject wildcard/extra ports, host network/PID/IPC, privileged mode, host gateway, Docker socket and added capabilities;
- use monotonic elapsed time where possible and recorded UTC plus skew confidence for persisted/legal deadlines; uncertainty pauses external action;
- define raw evidence maximum horizons, keyed plaintext MAC versus ciphertext hash, and sealed evidence transfer rather than cross-container paths;
- treat checkpoint assurance as DB-only/accidental tamper evidence relative to an independently retained checkpoint, not full-host compromise resistance.

### Deferred with rationale

- A machine-readable package manifest is deferred to `GOV-001`; until then Markdown is the reviewed planning source and cannot automatically promote status.
- California DROP remains candidate guidance, not promised V1 behavior, until selected and independently reviewed.
- Cloud-small, OpenClaw and optional intelligence beyond the null port remain post-V1.
- Exact first capabilities remain a decision gate; inventing a list before demand, terms, authority, disclosure, verification and maintenance review would be false precision.

## P2 corrections and tracked follow-ups

- Package rows over five days are explicitly planning epics and must split before `Ready`.
- Lifecycle status uses only `PLANNED`, `READY`, `IN_PROGRESS`, `IN_REVIEW`, `BLOCKED`, `DONE`, and `VERIFIED`.
- “Reversible canary” was replaced with bounded consenting controlled-identity canary; removal may be irreversible.
- Preview setup time, usefulness, cohort/attrition, proof tasks and deadline/legal-information wording must be preregistered rather than inferred after results.
- Public matrices count organizations, endpoints, artifacts, transports and capabilities separately; capability count is never marketed as broker count.
- Connector trust includes a maintenance owner, cadence, expiry, revocation path, supported protocol/core range and abandonment behavior.
- Release work must add changelog, support/compatibility table, upgrade path and end-of-support policy.

## Residual blockers before implementation status can advance

The plan pack may be integrated after reviewer re-check, but the following M0/M1 packages remain executable blockers rather than paper decisions:

- auth, KEK, transport/egress, runner, browser and backup spikes;
- SQLite/process/filesystem and migration ADRs;
- generic action/restore epoch and online first-byte protocol tests;
- signed update/revocation and artifact-verification design;
- named qualified human reviewers and accepted scopes;
- first-capability selection and match/authority corpus.

No live observation, custom fetch, automatic transport, controlled canary or stable-date claim may proceed merely because this disposition exists.

## Independent re-review verdict

After the corrections above, the same three independent-prompt roles re-read the current repository rather than relying on the disposition summary:

| Review hat | Remaining P0 | Remaining P1 blocking plan integration | Verdict |
| --- | ---: | ---: | --- |
| Product/misuse/claims/accessibility | 0 | 0 | integrate the plan; runtime remains `NOT_STARTED` |
| Platform/security/supply chain | 0 | 0 | integrate the plan; no runtime/security certification |
| Backend/recovery/OSS | 0 | 0 | integrate the plan; no live-action authorization |

The final re-review specifically confirmed the dedicated `AUTO-CONSENT-001` ceremony, five independent status axes, all-nonterminal restore reconciliation, managed-archive catalog model, pre-observation signed trust/artifact verification, transport-specific disclosure limits, scoped credentials, full accessibility dependency set, post-V1 cloud scope, automatic-cohort clock, and zero-P0/no-enabled-P1 stable rule.
