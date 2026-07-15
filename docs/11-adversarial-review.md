# Adversarial review and design refinement

Review date: 2026-07-15. This is an internal architecture red team, not a substitute for independent security, privacy, legal, accessibility, or operational review.

## Review method

The draft was attacked from five perspectives: privacy engineer, application-security red team, skeptical user/product reviewer, data-rights/legal operator, and tiny-system SRE. Findings were ranked by impact and used to change the proposed architecture.

## Critical challenges

### 1. “Local-first” can still become a perfect dossier

**Attack:** A stolen laptop, volume snapshot, cloud backup, or support bundle reveals the user's current and historical identity plus every broker relationship.

**Refinement:** field/object envelope encryption; master key outside DB/backups; per-profile keys; logs and support bundles built from allowlists; retention classes; cryptographic deletion; restore tests. Local custody is not presented as sufficient by itself.

### 2. A community connector is remote code execution with PII

**Attack:** A contributor adds a harmless-looking selector update that sends identity data to a lookalike domain or reads another connector's session.

**Refinement:** connectors are untrusted-by-default, capability-scoped, reviewed and expiring; exact destination allowlists; one-time action envelopes; no vault/database access; per-connector/profile session state; signed releases and revocation; disclosure ledger; quarantine on drift.

### 3. Automatic deletion can target the wrong person

**Attack:** Common names produce a false match. The system removes or modifies another person's record and exposes more PII while trying.

**Refinement:** candidate vs confirmed states; attribute-level match explanation; ambiguity task; minimum thresholds per connector; no high-risk submit from name-only discovery; user correction feedback; precision is a primary metric.

### 4. “Removed” is a marketing state, not an observed fact

**Attack:** The transport returned 200 or a broker emailed “done,” so the dashboard claims success even while the page remains.

**Refinement:** submitted, acknowledged, in-progress, broker-asserted, and independently verified states; post-request timing policy; immutable verification evidence; resurfacing history; no missing-evidence fallback to success.

### 5. The tool may confirm or enrich the user's identity to brokers

**Attack:** Blanket requests broadcast a clean current identity profile to brokers that had stale or no data, increasing correlation.

**Refinement:** no blanket broadcast mode; observe public sources first; private-broker outreach gets a disclosure-risk preview and broker-specific minimum bundle; record every disclosed category; support official aggregate paths such as DROP through user guidance rather than automating around verification.

## High challenges

### 6. Browser automation will rot and can violate controls

**Refinement:** browser automation is optional, isolated, visible for human challenges, and versioned separately. CAPTCHA/MFA/terms/required-field changes stop execution. Guided manual completion is a supported outcome, not failure.

### 7. Sporadic operation can cause retry storms and duplicate requests

**Refinement:** compute one bounded catch-up decision rather than replaying intervals; per-domain budgets and jitter; leases/idempotency; unknown submission outcomes never auto-retry.

### 8. Jurisdiction rules will be wrong or stale

**Refinement:** versioned sourced policy facts with effective/review/expiry dates; uncertainty requires review; scope claims stay narrow; qualified legal review before authorized-agent positioning.

### 9. Assistant integration expands the prompt-injection blast radius

**Refinement:** metadata-only default tools; external text never becomes instructions; no raw evidence/PII in model context; no submit or approval tool initially; short-lived actor/profile/case grants for any future write.

### 10. SQLite and one container could be sold as “production ready” too early

**Refinement:** two explicit deployment profiles and honest release gates. SQLite is single-worker local-lite; cloud-small uses PostgreSQL and role separation. Initial commit states that it is architecture, not a runnable release.

### 11. A giant broker count encourages bad incentives

**Refinement:** publish capability and recent quality per broker; optimize verified-removal precision, intervention cost, and PII disclosed; begin with a small trusted connector set.

### 12. Evidence can retain third-party PII and hostile content

**Refinement:** encrypted evidence, sanitized derivatives, bounded capture, raw-evidence retention limits, download prohibition, no active rendering outside isolated viewer, content hashes.

## Medium challenges

- **Email threads are hard to correlate:** use per-case aliases/tokens where provider permits, message IDs, sender/domain checks, and manual review for ambiguous mail.
- **Authorization can outlive consent:** explicit scope/expiry/revocation and job cancellation on revocation.
- **Backups can be unrecoverable or too recoverable:** separate key backup with strong warnings; scheduled restore verification; no wrapping key in archives.
- **Family mode invites coercion:** separate profiles and audit; no silent shared identity; guardian flows deferred until legally reviewed.
- **Custom URLs enable SSRF:** parse-first, private-range denial, redirect/DNS revalidation, no credentials, strict byte/time/content bounds.
- **Metrics leak relationship data:** local-only defaults and opaque/aggregate schemas.
- **Open directories have license/provenance traps:** import only after license review; preserve provenance; initial repo contains synthetic data only.
- **Project name may create affiliation/trademark confusion:** working-name disclaimer and pre-launch review.

## Residual risks accepted for planning

- Some brokers cannot be independently verified because their databases are private.
- Some legal requests require users to disclose sensitive attributes or identification.
- Removal does not prevent copies, public records, new collection, breach data, or unlawful brokers.
- Browser and email workflows remain brittle despite governance.
- Self-hosting shifts operational/key-loss risk to the user.
- A volunteer project cannot promise legal representation or response SLAs.

## Required independent reviews

Before automatic live submission: cryptography/key management, setup-authorization binding, connector sandbox/SSRF, and data-rights legal posture. Before stable v1: accessibility, deployment hardening, backup recovery, privacy notice/retention, and one end-to-end user study. Findings and resulting ADRs should be published without user PII.

## Design changes made after this review

The architecture was tightened to add: no blanket broadcast mode; exact semantic outcome states; one-time connector capabilities; separate browser image; profile-specific keys and cryptographic deletion; unknown-outcome no-retry; official-platform guidance boundary; hard distinction between single-tenant cloud and multi-tenant SaaS; provenance expiry; and an explicit assistant capability floor.
