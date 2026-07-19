# Adversarial review and design refinement

Review date: 2026-07-15.

Five independent role tracks reviewed the same architecture from ML, backend/infra/security, edge, product, and experienced open-source perspectives. Their reports are in [`docs/reviews/`](reviews/README.md). A principal-role decision council then accepted, modified, deferred, or rejected findings in [`docs/14-principal-team-synthesis.md`](14-principal-team-synthesis.md).

These are AI-assisted adversarial reviews, not external human security/cryptography/legal audits. Required independent reviews remain release gates.

## P0 findings accepted

### 1. Subprocess connectors were not isolated

**Attack:** a Python connector subprocess in the core image inherits UID, mounts, environment, network, and kernel surface; a domain allowlist cannot stop rebinding or alternate-protocol exfiltration.

**Change:** separate digest-pinned OCI/WASI artifacts; rootless/read-only/tmpfs/capability/syscall/resource containment; mandatory gateway revalidating fence, authorization epoch, pauses, artifact/capability, method/protocol/origin/public IP/redirect, disclosure and byte/time budget. ADR-0008.

### 2. Root-derived profile keys made deletion reversible

**Attack:** if a profile key is deterministically derived from a persistent root, deleting it does not erase it. A retained key-catalog backup can also resurrect a destroyed live key.

**Change:** independent random profile DEKs wrapped by the external install/cloud KEK; purpose keys below the profile DEK; separately protected/inventoried key catalog; deletion remains pending until recoverable catalog backups expire/sanitize. ADR-0007.

### 3. Queue idempotency could duplicate external sends

**Attack:** database commit and HTTP/email send are not atomic. Attempt/connector-version-derived keys change across retry and upgrade. A timeout may be a successful send with a lost response.

**Change:** immutable `intent_id`, separate attempts, monotonic fence, explicit dispatch journal, final reauthorization, and no retry after `dispatch_started` until reconciliation proves no send. ADR-0009.

### 4. Loopback/private networking was treated as authentication

**Attack:** DNS rebinding, CSRF, another local user, browser extension, stolen session, or cloud lateral movement reaches a dossier-and-submit control plane.

**Change:** local bootstrap/session auth, strict Host/Origin/CSRF/cookie/session policy, permissioned CLI channel; cloud passkey/WebAuthn or narrow OIDC; step-up and actor/profile/scope/expiry/revocation epochs. ADR-0010.

### 5. Optional AI had no enforceable authority floor

**Attack:** “explain or draft” can grow into a model deciding match, policy, disclosure, status, or submission; local endpoints/logs can still leak PII.

**Change:** no model in v1; typed null `IntelligencePort`; deterministic redaction; isolated no-network/no-tools runtime only after post-v1 gates; schema/supporting spans; output remains `UntrustedSuggestion` and cannot create a command. ADR-0011.

## P1 product and assurance findings accepted

| Attack | Change |
| --- | --- |
| One clean search is called proof | add assertion → one absence → corroborated verification → inconclusive ladder; blocks/ambiguity never imply absence |
| Unkeyed event hash chain is called append-only | keyed/signed events and external monotonic checkpoint; claim only tamper evidence relative to checkpoint |
| Product tries to cover too much | stable v1 becomes one adult, small public preview, guided flows, 2–5 trusted automatic capabilities |
| Coverage count hides capability gaps | generated support matrix by capability, maturity, expiry, disclosure, human steps, evidence, recent tests |
| Stalled cases create opaque trust | reason, owner, last evidence, next action, and next date are mandatory |
| Browser and inference collide on small host | shared heavy-work lease/resource preflight; deterministic deadline work has priority |
| Registry signature permits stale rollback | expiring monotonic metadata, delegated/threshold trust, revocation, artifact/SBOM/provenance |
| Local/cloud same-code claim hides failure differences | profile-specific conformance and threat statements |
| Restore can replay post-backup sends | external actions pause; journal-boundary intents become unknown and reconcile before resume |
| Community reviews look synthetic/promotional | evidence grading A/B/C; anonymous/vendor material used as hypotheses, not effectiveness truth |
| Volunteer ecosystem cannot review everything | maturity ladder, second reviewer for trusted submit, demotion/retirement on expiry/capacity |

## Product changes after review

The wedge is now explicit: auditable proof-first recurring U.S. removal for technical self-hosters, not a commercial clone or “largest coverage” promise. Product-market-fit gates cover install/activation, match precision, proof/disclosure comprehension, switching, manual burden, 30/90-day recurrence, connector health, and disclosure cost.

Custom URL intake remains valuable but v1 only produces a safe guided draft. Family/guardian administration, blanket private-broker outreach, arbitrary custom automation, multi-tenant SaaS, non-U.S. support, and an AI dependency are deferred.

## Residual risks preserved

- Some private brokers cannot be independently verified.
- Browser/email transports remain brittle and an allowed broker can misuse disclosed PII.
- A crash after transmission may remain unknowable.
- Local shared-kernel isolation is weaker than higher-assurance VM/gVisor/Kata profiles.
- Key loss is permanent and retained recovery catalogs extend deletion time.
- Laws, destinations, and procedures drift.
- Volunteer review capacity can collapse; forks can remove safeguards.
- Removal does not erase public records, downstream copies, breach data, or future recollection.

## Required external reviews

Before live automatic submission: independent cryptographic/key-catalog review, actor/setup-authorization review, connector/egress/SSRF review, dispatch-journal/restore review, and qualified U.S. legal/authorized-agent review. Before stable v1: accessibility, deployment hardening, signed supply chain, proof/disclosure user comprehension, privacy/retention/offboarding, and a 12-week user study. Findings and dispositions are published without user PII.
