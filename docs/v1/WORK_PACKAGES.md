# Stable V1 work packages

This backlog is the issue source for stable V1. Estimates are ideal engineering days for an experienced contributor and exclude external review, pilot recruitment, broker response time, and remediation. A package is `Done` only when its acceptance evidence is linked from the completion matrix.

## Rules of use

- P0, consent, authority, action-journal, gateway, restore-epoch, qualified-review, canary and stable-gate dependencies are not waivable. Only P2/non-safety scheduling dependencies may be waived by ADR with an owner and expiry.
- Only the core/data lane authors Alembic migrations. Other lanes submit schema proposals.
- Live submit/canary packages remain simulator-only until `GOV-01` human gates pass. A real observation additionally requires `CONSENT-001`, `ACTION-001`, `GATEWAY-BASE-001`, `OBS-AUTH-001` and the M2 gates.
- An issue must name requirement IDs, threat/test IDs, expected evidence, rollback, and documentation impact before it becomes `Ready`.
- Estimates are sizing aids, not delivery promises. Split packages when one independent acceptance boundary can be reviewed separately; estimates above five days are planning epics that must be decomposed before `Ready`.

Lane codes: `I` integration/product, `C` core/data/security, `B` boundary/platform. `X` is an orchestrator-owned cross-lane gate.

## M0 — executable foundation

| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |
| --- | --- | --- | --- | ---: | --- |
| PF-001 | I | Own root `uv` project, lockfile and shared developer/CI commands | — | 2 | locked clean-clone build and single-writer ownership rule |
| PF-CORE | C | Scaffold domain/application/adapters/entrypoint boundaries against the root project | PF-001 | 2 | import-boundary and strict type checks pass |
| PF-BOUNDARY | B | Scaffold connector protocol, egress and simulator service boundaries | PF-001 | 2 | protocol/build skeleton without core imports or privileged mounts |
| PF-002 | B | Pin base images/toolchain and produce repeatable amd64/arm64 build skeleton | PF-BOUNDARY | 2 | digest inventory and two-architecture build logs |
| CI-001 | B | Add PR CI, frozen dependency checks, secret/PII canaries and architecture status guard | PF-001 | 3 | failing fixtures prove every guard; architecture claim cannot be promoted accidentally |
| DB-001 | C | Create SQLite configuration, SQLAlchemy UoW and Alembic migration harness | PF-CORE | 3 | migrate fresh/previous fixtures; transaction and rollback tests |
| CT-001 | C | Freeze shared value types, ports, result/reason codes and connector-protocol schemas | PF-CORE, PF-BOUNDARY | 4 | contract tests and dependency graph; versioning rules documented |
| SIM-001 | I | Build deterministic synthetic identity corpus and broker web/mail simulator | PF-001 | 5 | seeded scenarios cover happy, ambiguous, challenge, timeout and drift cases; reserved domains only |
| NET-001 | B | Deny real broker/custom network access in CI and test harnesses | CI-001, SIM-001 | 3 | attempted DNS/IP/TLS/redirect escapes fail and emit PII-safe diagnostics |
| SPIKE-AUTH | C | Prototype bootstrap, opaque sessions, CLI step-up and lost-session/headless recovery | CT-001 | 3 | threat tests plus accepted ADR or named blocker |
| SPIKE-KEY | C | Prototype KEK provider on macOS, Linux and rootless Docker | CT-001 | 3 | permissions/restart/recovery matrix plus accepted ADR or named blocker |
| SPIKE-EGRESS | B | Prototype separate egress boundary, TLS/redirect/fence and verifier-unavailable behavior | CT-001, NET-001 | 5 | adversarial packet/redirect/DNS suite and language ADR |
| SPIKE-RUNNER | B | Prototype predeclared digest-pinned connector service and one-time mailbox | CT-001 | 4 | replay, volume, environment and network isolation tests |
| SPIKE-BROWSER | B | Prove project-owned non-root Playwright image, sandbox/seccomp/private-shm and runtime matrix | PF-002, SPIKE-RUNNER | 5 | sandbox self-test on amd64/arm64 Linux Engine and Docker Desktop; no host IPC/`SYS_ADMIN` |
| SPIKE-BACKUP | C | Select audited streaming authenticated backup format | SPIKE-KEY | 3 | wrong-key, truncate, interrupt, large-object and metadata-leak results plus ADR |
| SQLITE-DUR-001 | C | Freeze process/writer model, PRAGMAs, filesystem support and dirty-shutdown behavior | DB-001 | 4 | lock/WAL/power/disk-full tests and supported-filesystem ADR |
| TEL-001 | B | Define allowlisted typed diagnostics and disable unsafe default access/proxy/browser logs | CI-001 | 3 | canaries in URL/header/error/HTML/mail/proxy paths never appear; no remote exporter |
| THREAT-CATALOG-001 | X | Assign stable threat/test IDs and structured traceability metadata | CI-001 | 3 | immutable threat/test catalog and broken-reference CI fixtures |
| GOV-001 | X | Add requirement/work-package/ADR/test/evidence traceability validator | THREAT-CATALOG-001 | 3 | intentionally broken links fail CI; generated coverage report |
| UX-001 | I | Add synthetic-only authenticated shell and release-status banner | SPIKE-AUTH, CT-001 | 3 | keyboard/zoom smoke test; every page says developer preview/synthetic only |

M0 gate: all packages above are complete, every spike has a disposition, and no external submit/mail/browser implementation is present outside the simulator.

## M1 — secure local kernel

| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |
| --- | --- | --- | --- | ---: | --- |
| AUTH-001 | C | Implement terminal bootstrap, actor/session store, rotation, expiry and revocation | SPIKE-AUTH, DB-001 | 4 | replay/theft/expiry/restart test report |
| AUTH-002 | I | Enforce exact Host/Origin, CSRF, cookie, clickjacking and step-up UX | AUTH-001, UX-001 | 4 | `TEST-05` matrix and accessible ceremony recording |
| AUTH-003 | C | Implement permissioned CLI channel, grant/revocation epochs and cross-profile denial | AUTH-001 | 4 | stale-grant and confused-deputy suite |
| KEY-001 | C | Implement external KEK port, independent profile DEKs, catalog and versioned AAD | SPIKE-KEY, DB-001 | 5 | ciphertext substitution, plaintext scan and key-separation tests |
| KEY-002 | C | Implement rotation, interrupted recovery and cryptographic deletion skeleton | KEY-001 | 5 | crash-at-every-stage and old-catalog horizon evidence |
| DATA-001 | C | Implement one-active-adult profile invariant, progressive attributes, provenance, validity and authority records | DB-001, KEY-001, CT-001 | 5 | UI/CLI/API/import/restore reject a second active person; isolation and deletion tests |
| MIG-001 | C | Define migration/upgrade/rollback/AAD/event/protocol compatibility contract | DB-001, KEY-001, CT-001 | 4 | N/N-1 matrix, maintenance lock, space preflight and backup-before-migrate tests |
| EVT-001 | C | Implement case-event stream, keyed chain and projections/upcasts | DB-001, KEY-001 | 5 | mutation/truncation/rollback/upcast suite; original authenticated bytes preserved |
| CHECKPOINT-001 | C | Implement authenticated aggregate stream-head checkpoint and crash/restore semantics | EVT-001, KEY-001 | 4 | pending/ahead/behind/missing/rollback/new-host tests with honest host-compromise boundary |
| JOB-STATE-001 | C | Implement durable queued/leased/running/retry/dead/cancelled jobs and deduplication | SQLITE-DUR-001, EVT-001 | 4 | duplicate-worker, lease expiry, starvation and crash tests |
| OUTBOX-001 | C | Implement non-external-action notification/event outbox | JOB-STATE-001 | 3 | exactly-once projection and at-least-once delivery tests; removal mail prohibited |
| SCHED-001 | C | Implement scheduler leadership and bounded current-decision catch-up | JOB-STATE-001 | 4 | months-offline, duplicate leader and clock-jump tests |
| EVD-001 | C | Implement encrypted evidence staging/store, keyed semantic MAC, ciphertext hash, derivatives, retention and sweep | KEY-001, DB-001 | 5 | dictionary-leak, corruption, abandoned-object, PII and absolute-horizon tests |
| BAK-001 | C | Implement online consistent backup and `verify-integrity` without KEK | SPIKE-BACKUP, CHECKPOINT-001, EVD-001, MIG-001 | 5 | wrapped catalog/data/evidence/manifest/checkpoint/journal inventory; no plaintext temp |
| BAK-RESTORE-001 | C | Implement isolated `restore-test` with KEK/catalog and projection/evidence verification | BAK-001, KEY-002 | 5 | wrong/lost key, decrypt, rebuild and checkpoint recovery evidence; never mislabeled by integrity-only check |
| OPS-001 | B | Add configuration/secret lint, health contract and resource-budget probes | PF-002, KEY-001, SCHED-001 | 3 | supported-host matrix and failure diagnostics |
| UX-002 | I | Build progressive setup, aliases, authority, key/backup health and destructive-flow UI | AUTH-002, DATA-001, BAK-RESTORE-001 | 5 | attributes labeled local/disclosed/unused; optional history skippable; WCAG E2E |
| CONSENT-001 | I | Separate local collection, observation disclosure, evidence retention, product-event and research-export consent | UX-002, AUTH-003 | 4 | revocation stops new scans; retained/exported data consequences are explicit |
| ACTION-001 | C | Implement generic outbound-action intent/attempt/fence/pause model for observe, custom and submit | SCHED-001, AUTH-003, EVT-001 | 6 | normative state-machine/property suite; removal mail cannot use generic outbox |
| GATEWAY-BASE-001 | B | Implement fail-closed online first-byte authorization and external dispatch epoch | ACTION-001, SPIKE-EGRESS, SPIKE-RUNNER | 6 | core durably records begin before dial; unavailable verifier and restored epoch fail closed |
| RESTORE-INTENT-001 | C | Rotate dispatch epoch, invalidate mailboxes and reconcile every restored nonterminal intent | ACTION-001, BAK-RESTORE-001, GATEWAY-BASE-001 | 5 | restored ready/claimed/started intents cannot auto-resume or duplicate |
| REVIEWER-RECRUIT-001 | X | Recruit independent shared-boundary, policy/legal and capability reviewers | GOV-001 | external | qualifications, conflicts, scope and target windows accepted |

## M2 — zero-removal-request preview alpha

| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |
| --- | --- | --- | --- | ---: | --- |
| REG-001 | C | Implement versioned broker registry, provenance, expiry, maturity and revocation | EVT-001, CT-001 | 5 | rollback/expiry/tamper tests and source inventory |
| REG-002 | I | Generate honest capability/support matrix from registry state | REG-001 | 3 | golden snapshots prove observe is never rendered as submit |
| CON-001 | B | Build signed synthetic and approved read-only connector artifacts | SPIKE-RUNNER, REG-001 | 5 | digest/SBOM manifest and protocol conformance |
| TRUST-001 | C | Implement per-capability promotion, owner, test cadence, expiry, quarantine and abandonment | REG-001, CON-001 | 5 | stale/revoked/unowned/rollback artifacts denied |
| UPDATE-001 | B | Implement signed monotonic trust/revocation metadata with offline threshold root and freshness UI | TRUST-001, SCHED-001 | 6 | freeze/rollback/expired-root/revoked-digest/mirror/offline tests |
| ARTIFACT-VERIFY-001 | B | Verify signer, digest, SBOM/provenance and render signed deployment inventory | CON-001, UPDATE-001 | 5 | wrong signer, substitution, missing attestation and revoked artifact denied |
| RUN-001 | B | Implement isolated sealed evidence/result mailbox and read-only egress policy | CON-001, GATEWAY-BASE-001, SPIKE-BROWSER, ARTIFACT-VERIFY-001 | 5 | malicious connector `TEST-04`; no path crossing; bounded ciphertext transfer |
| OBS-AUTH-001 | I | Implement exact scan-disclosure preview, consent and revocation separate from removal authority | CONSENT-001, REG-002, ACTION-001 | 4 | every real query shows values/destination/purpose; zero preconsent network bytes |
| OBS-001 | C | Implement authorized observation action/run/result ingestion and finding-signal taxonomy | REG-001, EVD-001, SCHED-001, OBS-AUTH-001, RUN-001 | 5 | no-preconsent-byte, duplicate/crash/schema-drift contract tests |
| MATCH-001 | C | Implement deterministic broker-specific matching and user dispositions | OBS-001, DATA-001 | 5 | synthetic precision corpus; name-only never auto-confirms |
| CASE-001 | C | Implement cases, occurrences, tasks, reasons, owners, dates and state projection | MATCH-001, EVT-001 | 5 | transition/property tests and unexplained-state guard |
| UX-003 | I | Build preview dashboard, match explanation, case timeline, evidence and tasks | CASE-001, REG-002, UX-002 | 5 | keyboard E2E and participant comprehension script |
| PMF-001 | I | Add short-retention encrypted local product-event ledger and explicit redacted research export | UX-003, EVD-001, CONSENT-001 | 3 | coarse allowlisted events contain no URL/free text/PII; separate export opt-in |
| RESEARCH-001 | I | Preregister recruitment, inclusion/exclusion, consent, withdrawal, retention, incentives and adverse-event protocol | CONSENT-001 | 4 | approved pilot protocol, acute-risk exclusion and publication thresholds |
| ALPHA-001 | X | Run 10–15-user zero-removal-request preview and publish denominators | UX-003, PMF-001, OBS-AUTH-001, RESEARCH-001, BAK-001 | 10 | preview-usability LG-1 report; zero removal submissions and stop/go disposition |
| PILOT-PREVIEW | I | Maintain preview recurrence, setup, matching, comprehension and attrition cohort | ALPHA-001 | ongoing | enrolled/activated/eligible/withdrawn/lost/scheduler-active denominators and cohort age |

## M3 — guided request beta

| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |
| --- | --- | --- | --- | ---: | --- |
| POL-001 | C | Model versioned voluntary/state policy facts, sources and actor authority | REG-001, DATA-001 | 5 | stale/contradictory policy fixtures and provenance report |
| AUTHZ-001 | I | Implement setup-authorization explainer, bounded grant and revocation UX | POL-001, AUTH-003 | 5 | comprehension test; scope/expiry/epoch visible |
| AUTHORITY-001 | C | Separate self-attestation from verified-control evidence and capability authority rules | POL-001, DATA-001 | 4 | arbitrary typed third-party identity cannot become unattended authority |
| CONN-SEL | X | Select 2–5 candidate capabilities using demand, authority, disclosure, verification, fallback and maintenance criteria | POL-001, ALPHA-001, AUTHORITY-001 | 5 | public selection rationale, distinct organization/capability counts and residual risk |
| PLAN-001 | C | Implement deterministic minimum-disclosure request/execution plans and canonical hashes | POL-001, MATCH-001, AUTHORITY-001, DATA-001, REG-001 | 6 | identity/registry/capability/message/attachment versions bind deterministically |
| PLAN-002 | I | Implement exact destination/path/transport/value/message/attachment diff and disclosure ledger | PLAN-001, AUTHZ-001 | 6 | masked revealable exact values; optional removal; sealed envelope matches rendered plan |
| GUIDE-001 | I | Build guided manual workflow and simulator-only email draft/reply contract | PLAN-002, SIM-001 | 5 | no-send artifact test and correlation corpus |
| CUSTOM-001 | B | Route consented custom URLs through the action journal and reviewed guidance-only egress path | GATEWAY-BASE-001, ACTION-001, PLAN-001 | 4 | exact disclosure, SSRF/redirect/credential-denial suite; submit absent |
| PROOF-001 | I | Implement proof ladder, reason/deadline vocabulary and action-based comprehension guardrails | CASE-001, POL-001 | 4 | realistic retry/wait/challenge/close tasks; assertion/absence never rendered verified |
| CASE-RESP-001 | C | Model denial, exemption, partial, overdue, contradicted assertion, follow-up and `closed_unverified` | PROOF-001, CASE-001 | 5 | each state has source, owner, deadline, next action and limits |
| DIGEST-001 | I | Implement PII-free local attention digest, overdue/unknown count and offline catch-up | CASE-RESP-001, OUTBOX-001 | 4 | deduplication, urgency, silence-window and keyboard tests |
| OFF-PRE-001 | C | Implement pre-external-submit pause/revoke, export, deletion horizon and restore-paused semantics | BAK-001, AUTHZ-001, SCHED-001 | 5 | pre-submit destructive and restore E2E; no claim of journal reconciliation |
| OFF-002 | I | Build pause/export/delete/restore/uninstall guidance UI | OFF-PRE-001, PROOF-001 | 4 | keyboard/step-up/user-comprehension evidence |
| VER-SIM-001 | C | Implement separate match/request/dispatch/assurance/work axes and simulator verification/resurfacing | CASE-RESP-001, SCHED-001 | 6 | unknown/pre-send/transport truth stays distinct; case summary never collapses axes |
| AI-001 | C | Add no-authority `IntelligencePort` with null adapter only | CT-001 | 2 | architecture test proves no model/runtime/dependency and no command output |
| CRED-001 | C | Implement step-up scoped credential enroll/test/rotate/revoke and capability pause | AUTHZ-001, KEY-001 | 5 | purpose binding, encrypted storage, no-log/export, stale denial and recovery tests |
| BETA-001 | X | Run guided comprehension/disclosure learning gates | PLAN-002, GUIDE-001, PROOF-001, OFF-002, RESEARCH-001 | 8 | LG-2/LG-3 report and stop/go disposition |
| PILOT-GUIDED | I | Maintain guided disclosure, comprehension, burden and offboarding cohort | BETA-001 | ongoing | preregistered cohort ages, withdrawals, manual minutes and failure denominators |

## M4 — controlled automation beta

| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |
| --- | --- | --- | --- | ---: | --- |
| INTENT-001 | C | Specialize the generic action journal into exact authorized submit intents and attempts | PLAN-001, ACTION-001, AUTHZ-001 | 7 | normative state/property tests and immutable canonical fixtures |
| AUTO-CONSENT-001 | I | Implement dedicated default-off, non-preselected per-capability automation enable/renew/revoke ceremony | AUTHZ-001, CONN-SEL, PLAN-002, TRUST-001, AUTH-002 | 5 | exact capability/destination/values/expiry/pause/challenge/unknown behavior; general grants cannot enable send |
| PERMIT-001 | C | Implement final transaction reauthorization and signed first-byte permit | INTENT-001, AUTO-CONSENT-001, TRUST-001 | 5 | every stale/pause/drift condition denies permit |
| GW-001 | B | Complete typed HTTP, trusted mailer and browser-limited gateway transports | GATEWAY-BASE-001, PERMIT-001 | 7 | transport-specific DNS/redirect/protocol/body/byte/time/fence suite |
| MAIL-001 | B | Implement declarative mail transport through simulator, then reviewed canary path | GW-001, GUIDE-001, CRED-001 | 5 | crash/timeout/correlation proof taxonomy; scoped credential tests |
| BROW-001 | B | Implement isolated Playwright transport and challenge stop | GW-001, SIM-001, RUN-001, TRUST-001, SPIKE-BROWSER, CRED-001 | 7 | CAPTCHA/MFA/login/drift/download/proxy-bypass/alternate-protocol stop suite |
| REC-BASE-001 | C | Implement common unknown-outcome reconciliation with authoritative gateway begin/no-begin facts | INTENT-001, GATEWAY-BASE-001 | 5 | kill-at-every-edge corpus yields only approved proof/unknown states |
| REC-MAIL-001 | C | Implement mail-specific receipt/reply reconciliation | REC-BASE-001, MAIL-001 | 4 | timeout/duplicate/correlation corpus |
| REC-BROWSER-001 | C | Implement browser-specific reconciliation without blind retry | REC-BASE-001, BROW-001 | 4 | crash/challenge/provider-state corpus |
| PAUSE-001 | C | Project global/profile/broker/capability pause races truthfully into product state | PERMIT-001, GW-001, ACTION-001 | 4 | UI distinguishes prevented, already-started and unknown at every race edge |
| AUTO-ELIGIBILITY-001 | X | Preregister and independently review per-capability match/authority eligibility corpus | CONN-SEL, MATCH-001, AUTHORITY-001 | 5 | minimum denominator/confidence bound, collision cases and zero known wrong-person canaries |
| EXT-PRE-AUTO | X | Obtain independent shared auth/key/backup/runner/gateway/journal/restore review | REVIEWER-RECRUIT-001, GW-001, REC-BASE-001, RESTORE-INTENT-001 | external | attributed digest-bound report; all P0 and enabled-surface P1 fixed |
| HUMAN-001 | X | Obtain independent policy/legal and second connector/security review per capability | CONN-SEL, TRUST-001, GW-001, AUTO-ELIGIBILITY-001, REVIEWER-RECRUIT-001 | external | qualifications/conflicts/scope/digest/expiry recorded; AI review does not count |
| CANARY-001 | X | Run bounded consenting controlled-identity canaries and publish per-capability disposition | EXT-PRE-AUTO, HUMAN-001, PAUSE-001, ARTIFACT-VERIFY-001, AUTO-CONSENT-001 | external | canary log, disclosure evidence, incident/quarantine decision |
| PILOT-AUTO | I | Maintain automatic disclosure/outcome/verification/unknown/burden/resurfacing cohort | CANARY-001 | 12 weeks minimum | mature day-90 denominator, cohort age, incidents, attrition and per-capability results |

## M5 — local release candidate

| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |
| --- | --- | --- | --- | ---: | --- |
| VER-001 | C | Activate versioned capability-specific live verification policy over simulator-proven state axes | VER-SIM-001, CANARY-001 | 5 | timing/method/independence/inconclusive policy tests |
| VER-002 | C | Operate resurfacing as new linked occurrence and recurring scheduler | VER-001, SCHED-001 | 4 | months-offline and resurface-history tests |
| DIG-001 | I | Build denominator-preserving effectiveness, disclosure and burden reporting | VER-002, PMF-001 | 5 | golden report rejects broker/request-count inflation |
| DELETE-PREFLIGHT-001 | C | Pause profile, cancel pre-dispatch work and reconcile started/unknown attempts before key destruction | OFF-PRE-001, REC-BASE-001, RESTORE-INTENT-001 | 5 | no key destruction while reconcilable action remains unless step-up forced-abandon is explicit |
| DELETE-FINALIZE-001 | C | Destroy key and sweep jobs/envelopes/indexes/evidence/session material with managed-backup horizon report | DELETE-PREFLIGHT-001, KEY-002 | 4 | live/known-managed-backup inaccessibility plus external-backup caveat |
| BAK-002 | C | Complete journal-boundary restore, gateway high-water reconciliation and guarded resume | RESTORE-INTENT-001, REC-BASE-001 | 6 | pre/post-send restore, dirty-shutdown and old-catalog drills |
| REL-001 | B | Produce signed multi-architecture artifacts, complete SBOM and provenance | PF-002, GW-001, CON-001, BROW-001, UPDATE-001, ARTIFACT-VERIFY-001 | 6 | signature/preflight verification and clean-machine install |
| UPG-001 | B | Test install, upgrade, backup-restore rollback, pause, uninstall and key-loss runbooks | REL-001, BAK-002, MIG-001 | 6 | recorded amd64/arm64 operator drills and free-space preflight |
| RES-001 | X | Run disk-full, OOM, clock-skew, power-loss, migration, restore and compromise exercises | UPG-001, VER-002 | 6 | public failure matrix and dispositions |
| A11Y-001 | I | Complete the full `UX-05` WCAG 2.2 AA conformance review | DIG-001, OFF-002, AUTO-CONSENT-001, PAUSE-001, REC-BASE-001, DELETE-PREFLIGHT-001, DELETE-FINALIZE-001 | 5 | integrated RC digest; named screen-reader/browser matrix, keyboard, focus/error/step-up status, timeout, contrast, motion and 200%/400% reflow |
| EXT-001 | X | Obtain final integrated crypto/auth/gateway/journal/restore and U.S. policy review | RES-001, A11Y-001, EXT-PRE-AUTO | external | attributed digest-bound report; zero P0 and no enabled-capability P1 |
| RC-001 | X | Generate current support/conformance/claim matrix and sign `v1.0.0-rc` | EXT-001, REL-001, DIG-001 | 3 | release evidence bundle; status remains release candidate |

## M6 — stable evidence hold

| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |
| --- | --- | --- | --- | ---: | --- |
| CLAIM-001 | I | Evaluate safety gates, product viability, disclosure, precision, outcomes and resurfacing by cohort | PILOT-PREVIEW, PILOT-GUIDED, PILOT-AUTO, DIG-001 | 5 | reproducible analysis with method/age/withdrawal denominators and gate class |
| OSS-001 | X | Complete contributor, support, release, trademark/confusion and sustainability review | RC-001 | 5 | maintainer/contributor disposition and support limits |
| STABLE-001 | X | Re-run every stable gate and sign `v1.0.0` only if all safety and viability gates pass | CLAIM-001, OSS-001, EXT-001 | 3 | auto cohort at least 12 weeks/day-90 mature; zero P0/P1 enabled; signed claim matrix |

## Dependency and readiness checks

The orchestrator must reject an issue from `Ready` when:

- a dependency is not `COMPLETE` or `VERIFIED`;
- acceptance evidence cannot be produced without real PII or unauthorized traffic;
- the change merges product status with transport or verification status;
- rollback, migration, key/deletion, or documentation effects are unspecified;
- live connector work lacks named qualified reviewers;
- an implementation lane would need direct database, vault, Docker-socket or arbitrary-egress access outside its boundary.
