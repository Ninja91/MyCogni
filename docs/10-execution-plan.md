# Execution plan

The plan favors a proof-first vertical slice over broker breadth. The release-level summary below is subordinate to the issue-ready [stable V1 control pack](v1/README.md). Its planning envelope assumes three experienced lanes; the 300-plus ideal-day backlog implies roughly 75–90 weeks for one experienced full-time maintainer before external latency.

## Release 0 — foundation and P0 closure (weeks 0–4)

Deliver:

- Python package/toolchain, architecture dependency rules, CI, DCO/governance/templates;
- requirement-to-threat-to-test traceability;
- synthetic identity corpus and broker simulator skeleton;
- implementable designs for random profile-key catalog/deletion, connector artifact + egress gateway, external-intent journal, and authenticated control plane;
- one-adult v1 support statement and product interview script.

Exit: ADRs 0007–0011 accepted; no real PII/live traffic; reproducible environment; P0 test plans executable; public docs do not claim runtime availability.

## Release 1 — secure local kernel and preview alpha (weeks 4–14)

Workstreams:

- encrypted profile/current/historical alias management for one adult;
- independent random profile DEK, wrapped-key catalog, export/delete/tombstone UI;
- authenticated local bootstrap, sessions, Host/Origin/CSRF controls, step-up skeleton, permissioned CLI channel;
- broker registry provenance/expiry/maturity and generated support matrix;
- event store/projections, durable jobs, scheduler catch-up, external checkpoint;
- separate observe-only artifact, exact scan authorization/disclosure, generic external-action journal and mandatory online egress gateway;
- local-lite Docker packaging, read-only exposure preview, evidence viewer, backup dry-run;
- shared resource-budget manager; no browser/model runtime needed for activation.

Exit: synthetic and selected read-only workflows survive restart, explain candidates, store encrypted bounded evidence, pass malicious-connector/auth/key tests, and cannot reach removal submit. Real scans are external disclosures and require their own consent, journal, pause epoch and gateway permit.

Learning gate: the preregistered 10–15-person preview pilot measures setup, participant-confirmed precision and usefulness with denominators and zero removal submissions. It never authorizes automatic matching; each automatic capability needs a separate independently reviewed match/authority corpus.

## Release 2 — guided beta (weeks 14–19)

- sourced U.S. policy framework separating voluntary/state/agent/official paths;
- actor/profile authority and setup-authorization records with epochs;
- deterministic minimum-disclosure and exact request plan;
- plan hash, exception-review, step-up, destination/field preview;
- guided manual and email-draft flows only;
- disclosure ledger, deadlines, proof ladder, reason/owner/next-action/date UX;
- backup/export/delete/restore and residual key-catalog horizon flows;
- `IntelligencePort`, deterministic redactor contract, null adapter, and synthetic evaluation harness only.

Exit: complete requests/evidence are prepared without transmission; every field/destination/basis is visible; user can pause/export/delete/restore; AI absence changes nothing.

Learning gate: nobody mistakes acknowledgement/assertion/one absence for verified removal; at least 80% identify next action unaided; all automatic-onboarding participants identify destination/transport, exact current/historical values, message/attachments, purpose and changes since prior authorization.

## Release 3 — controlled automatic submission (weeks 19–26)

- immutable external intent, separate attempts, monotonic fences, full journal state machine;
- installation dispatch epoch outside backups, online first-byte authorization and mandatory typed-transport gateway enforcement;
- signed monotonic update/revocation metadata and runtime artifact/signature/provenance verification;
- SMTP/browser transports through isolated artifacts, with unknown-outcome reconciliation;
- browser dedicated user/sandbox, challenge stop, downloads/alternate protocols denied;
- kill switches, registry expiry/rollback protection, artifact digest/SBOM/provenance;
- select 2–5 high-impact automatic capabilities with clear voluntary/legal paths and controlled canaries;
- independent shared-boundary review plus capability-specific policy/legal and connector/security review before canaries.

Exit: a current dedicated per-capability automation authorization can transmit an exact plan through a trusted capability; general setup/preview grants cannot enable send; stale fence/revocation/pause cannot emit a byte; every crash edge produces proven/unknown/pre-send semantics; no blind retry.

Governance gate: a second qualified reviewer approves each `trusted` live submit capability. One-maintainer experiments remain `submission-candidate` and outside stable claims.

## Release 4 — local release candidate (weeks 26–32)

- time/method-correlated verification, one-absence/inconclusive UX, resurfacing occurrences;
- disclosure/effectiveness/burden measures with denominators;
- signed amd64/arm64 core/connector/browser images, SBOM and provenance;
- old-key-catalog deletion drill, pre-send backup restore/reconciliation drill, upgrade/rollback;
- accessibility/performance/security audit and incident runbooks;
- generated support and conformance matrices;
- local install/uninstall/scheduler pause/offboarding documentation.

Exit: release-candidate gates pass for one U.S. adult, local-lite, and the deliberately small trusted capability set. Zero P0 findings and no P1 on an enabled capability remain. The release remains `v1.0.0-rc`, not stable.

Learning evidence continues accumulating; it cannot be compressed into this four-week hardening interval.

## Release 5 — stable evidence hold (weeks 32–40 or later)

- maintain separate preview, guided and automatic cohorts; the automatic cohort must run at least twelve weeks after the first eligible canary and reach a mature day-90 denominator;
- report day-30/day-90 scheduler retention, confirmed precision, 30/60/90-day verified outcomes by method/age, manual minutes, disclosure cost, resurfacing, connector quarantine, unknown outcomes, restore and offboarding;
- rerun current product-comprehension, security, policy, accessibility, OSS and release gates;
- generate the final capability/support/claim matrix from current evidence.

Exit: stable `v1.0.0` is signed only when every gate passes. Initial hypotheses are under ten manual minutes per active month and at least 60% day-90 retention; they are not marketing promises.

## Release 6 — cloud-small conformance (post-v1)

- PostgreSQL queue/journal and object-store backends;
- role separation, scheduler leadership, TLS ingress, passkey/WebAuthn or OIDC reference profile;
- KMS/secret provider and separate key-catalog recovery;
- isolated browser/connector jobs and higher-assurance sandbox option;
- backup RPO/RTO plus external-journal reconciliation drill;
- profile-specific configuration lint, cost/resource and conformance matrix.

Exit: one single-tenant cloud reference profile restores and upgrades safely, meets auth/sandbox/egress/journal requirements, and makes no parity or multi-tenancy claim.

## Release 7 — optional assist and ecosystem experiments (post-v1)

- instrument manual task reasons/minutes first;
- shadow one sanitized reply-classification or explanation task;
- digest/license-reviewed local artifact and process-owned adapter;
- schema/supporting-span/PII-canary/authority/resource evaluation;
- metadata-only OpenClaw tools after separate grant/security review;
- connector author kit, threshold registry governance, DRP compatibility only with real participation.

Exit for any assist preview: at least 30% task-time reduction, no safety/semantic/disclosure/false-positive regression, published evaluation/resource card, and complete deterministic fallback. Otherwise keep the null adapter.

## First 30 implementation issues

1. Establish Python package boundaries and dependency lint.
2. Build synthetic identity corpus and broker simulator.
3. Define actor/profile/authority/session records.
4. Implement authenticated bootstrap, Host/Origin/CSRF/session policy.
5. Define random profile DEK and separate key catalog.
6. Implement field/object encryption and associated-data contract.
7. Test rotation, old-catalog restore, and profile deletion.
8. Define domain events, keyed chain, and external checkpoint.
9. Implement SQLite durable jobs/outbox/leases.
10. Keep persistence ports cloud-aware without adding an unsupported PostgreSQL runtime.
11. Implement scheduler bounded catch-up.
12. Define immutable external intent, attempts, and fences.
13. Build kill-at-every-journal-edge simulator tests.
14. Define separate connector artifact manifest/build.
15. Implement rootless/read-only/tmpfs/resource runner policy.
16. Build mandatory egress gateway and DNS/redirect/public-IP policy.
17. Add malicious connector and allowed-origin exfiltration tests.
18. Implement encrypted evidence and redacted derivatives.
19. Add verification assurance and inconclusive taxonomy.
20. Implement registry provenance/expiry/maturity and generated support matrix.
21. Build CLI read-only workflow over authenticated application service.
22. Build minimal dashboard for findings/tasks/proof ladder.
23. Add PII canary diagnostics/support harness.
24. Implement backup create/verify/restore/reconcile dry-run.
25. Build authorization and minimum-disclosure plan.
26. Implement step-up exception review and disclosure ledger.
27. Add SMTP draft and synthetic reply correlation.
28. Add isolated Playwright simulator runner and challenge stops.
29. Add `IntelligencePort`, null adapter, sanitizer, and no-authority tests.
30. Automate requirement/threat/test/ADR traceability checks.

## Maintainer gates

- Before preview alpha: confirm one-adult support and reference local host.
- Before guided beta: choose qualified U.S. policy/legal review scope.
- Before automation: select 2–5 candidate capabilities and independent reviewers.
- Before stable v1: resolve working-name review and publish security/legal dispositions.
- Before cloud-small (post-v1): choose the reference cloud/VM, ingress identity, KMS, and evidence store.
- Before optional assist: choose one measured task, tested hardware tier, and model/runtime license.
