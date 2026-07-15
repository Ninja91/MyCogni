# Execution plan

The plan favors a narrow, trustworthy vertical slice over a large broker count. Estimates assume one experienced full-time engineer; a part-time open-source effort should treat them as relative sizing, not dates.

## Phase 0 — project foundation (1 week)

Deliver:

- record the confirmed Apache-2.0, U.S.-only, trusted-connector automation, Playwright, and CLI-first decisions; retain the working-name review;
- create Python package, quality toolchain, ADR process, CI, issue templates;
- build synthetic identity fixtures and broker simulator skeleton;
- create traceability from requirement IDs to tests/issues.

Exit criteria: reproducible development environment, CI passes on macOS/Linux, no real PII or live broker traffic.

## Phase 1 — local read-only kernel (3–4 weeks)

Workstreams:

- encrypted vault and profile/alias management;
- broker registry schema, provenance, expiry, and synthetic entries;
- event store, projections, durable jobs, scheduler catch-up;
- observe-only connector subprocess protocol;
- CLI plus minimal local dashboard for findings and tasks;
- backup create/verify/restore dry-run.

Exit criteria: local-lite periodically finds synthetic records, explains matches, stores encrypted evidence, survives restart, and has no reachable submit capability.

## Phase 2 — request planning and authorization (2–3 weeks)

- versioned jurisdiction policy framework with U.S. initial policy reviewed as guidance;
- authorization/consent records;
- minimum-disclosure computation;
- immutable request plan and plan-hash authorization/exception-review ceremony;
- email draft and guided-manual transports;
- case lifecycle, deadlines, and detailed reports.

Exit criteria: user can prepare complete requests and evidence without MyCogni transmitting them; every field and destination is visible.

## Phase 3 — controlled submission beta (4–6 weeks)

- SMTP send/reply correlation and browser runner isolation;
- idempotent submission, unknown-outcome handling, backoff, rate limits;
- broker simulator end-to-end suite;
- first two controlled live connectors selected for stability and clear legal process;
- global/profile/broker kill switches;
- security review of vault, SSRF, connector sandbox, and setup-authorization binding.

Exit criteria: a valid setup authorization automatically sends an exact plan through trusted controlled connectors, captures evidence, stops on challenges or policy drift, and recovers safely from crashes.

## Phase 4 — verification and resurfacing (3–4 weeks)

- independent post-request checks;
- broker assertion vs verified removal UI;
- adaptive recheck scheduling and resurfacing occurrences;
- effectiveness metrics, disclosure accounting, and richer exports;
- connector canary/quarantine lifecycle.

Exit criteria: claims are evidence-correct, rechecks are visible, and a simulated resurfaced record triggers a bounded re-removal workflow.

## Phase 5 — production hardening and cloud-small (3–4 weeks)

- PostgreSQL and object-store backends;
- role-separated deployment and scheduler leadership;
- OCI multi-arch build, signed images, SBOM/provenance;
- authentication, TLS deployment guidance, secret-provider integrations;
- restore drill, upgrade/rollback, incident runbooks, accessibility/performance audit.

Exit criteria: stable v1 release gates in the testing strategy are satisfied for one supported jurisdiction and a deliberately small trusted connector set.

## Phase 6 — ecosystem and personal assistants (ongoing)

- connector author kit, registry signatures, review automation;
- official-registry ingestion with license/source review;
- DRP compatibility where real network participation exists;
- metadata-only OpenClaw/MCP-compatible tools and exception-review deep links;
- optional user-visible local explanation/drafting models with raw-PII prohibition;
- broaden jurisdictions only with legal/policy maintainers.

Exit criteria: integrations cannot weaken setup authorization or exception gates, connector facts remain governed, and the U.S. support matrix remains honest.

## First 20 implementation issues

1. Establish package/module boundaries and dependency rules.
2. Build synthetic broker simulator and identity corpus.
3. Define domain events and case projection.
4. Implement envelope encryption/key-provider port.
5. Implement profile attributes and cryptographic deletion.
6. Implement broker registry schema validation and expiry.
7. Implement durable queue/outbox/leases for SQLite.
8. Implement scheduler catch-up budgets.
9. Define connector action envelope and subprocess runner.
10. Add runner timeout, filesystem, and egress containment.
11. Implement encrypted evidence store and redacted derivatives.
12. Implement observe result/match explanation.
13. Build CLI read-only workflow.
14. Build dashboard finding/task views.
15. Add PII canary redaction test harness.
16. Implement backup create/verify/restore dry-run.
17. Add PostgreSQL contract test early to avoid SQLite lock-in.
18. Create authorization and consent model.
19. Implement disclosure policy/preview.
20. Implement immutable request-plan authorization binding and exception review.

## Work sequencing

Security work is not a final phase. Vault/key design, synthetic fixtures, redaction, connector isolation, and backup recovery begin before live connectors. Cloud scale and assistant integrations wait until the single-user core proves correct.

## Decision gates requiring the maintainer

- before Phase 1: resolve the working-name review; license, jurisdiction, automation, Playwright, and CLI/UI priority are decided;
- before Phase 2: legal review scope and authorized-agent posture;
- before Phase 3: select the first real connector targets and approve their trust/promotion evidence;
- before Phase 5: supported deployment/security statement;
- before Phase 6: OpenClaw permission model and registry governance.
