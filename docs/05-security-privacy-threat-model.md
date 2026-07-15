# Security, privacy, and threat model

## Assets and harms

Highest-value assets: current/historical identity attributes, relationship graph, authorization/authority evidence, profile/key catalog, connector/browser/email credentials, findings/evidence, case history, wrapping/profile keys, and external-action authority.

Confidentiality, integrity, and availability all matter. A compromise can expose a dossier, submit for the wrong person, enrich a broker, spam destinations, falsify proof, make deletion unrecoverable, or miss a deadline.

## Adversaries

- opportunistic malware, malicious extension, or another local user;
- cloud account, ingress, database, object store, KMS, or backup compromise;
- malicious/compromised connector contributor, build/signing key, or model artifact;
- broker-controlled hostile HTML, redirects, files, service workers, mail, or misleading responses;
- custom URL/email sender attempting SSRF, prompt injection, decompression/Unicode sponge, or parser exploit;
- compromised assistant/OpenClaw plugin or another client of a local model server;
- malicious household administrator or stale authorized actor;
- curious operator/diagnostics recipient;
- supply-chain or container/kernel compromise;
- broker that legitimately receives the minimum bundle and then misuses it.

## Trust zones

1. **Authenticated user control plane:** UI/CLI, bootstrap/cloud identity, setup authorization, step-up, exception review.
2. **Trusted deterministic core:** domain, policy, orchestration, external-intent journal, resource budget, projections.
3. **Vault/key boundary:** encrypted fields/evidence, random wrapped profile keys, separately protected key catalog, external install/cloud KEK.
4. **Connector/browser artifact boundary:** one untrusted action, ephemeral filesystem, strict runtime limits, no core mounts.
5. **Egress policy gateway:** final fence/authority/origin/IP/protocol/disclosure/budget enforcement.
6. **External network/content:** brokers, mail, registries, public procedures, hostile responses.
7. **Optional local intelligence:** sanitized bounded input, no tools/network/vault, untrusted suggestions.
8. **Low-trust integrations/diagnostics:** OpenClaw, notifications, support bundles, optional exports.

## Major threats and controls

| Threat | Preventive controls | Detective/recovery controls |
| --- | --- | --- |
| Database/evidence backup theft | random profile DEKs; external KEK; field/object encryption; encrypted/pseudonymized relationship metadata | key rotation; inventory; isolated restore; cryptographic deletion report |
| Key deletion falsely claimed | profile DEK not root-derived; key-catalog backup inventory and tombstone horizons | restore old catalog after deletion in tests; visible pending-backup state |
| Localhost/cloud account takeover | bootstrap auth; Host/Origin/CSRF/session/cookie controls; passkey/OIDC cloud profile; step-up and epochs | session audit/revocation; cross-profile and stale-grant tests |
| Raw PII in logs/traces | typed allowlisted diagnostics; generic HTTP capture off; no domain-object interpolation | PII canaries over logs, traces, error pages, bundles, notifications |
| Connector reads core secrets | separate artifact; no core image/mounts/socket/host network; rootless/read-only/tmpfs/cap/seccomp/resource policy | malicious-artifact suite; runtime audit; kill/quarantine |
| Connector exfiltrates or rebinds | mandatory gateway; fence/authority/disclosure; origin + resolved public IP every connection; protocol/redirect/byte limits | destination/disclosure ledger; gateway denial metrics; signed revocation |
| Hostile browser content | Chromium sandbox/dedicated user; ephemeral context; no downloads/clipboard/WebRTC/DoH/QUIC; bounded content | sanitized failure evidence; destroy context; higher-assurance cloud sandbox |
| SSRF/custom URL | parse first; public-IP validation on each resolution/redirect; no credentials; byte/time/MIME limits | gateway audit; quarantine; fuzz/redirect/rebinding suite |
| Wrong-person removal | attribute explanation; high connector-specific threshold; no name-only automatic confirmation; ambiguity review | precision by connector; incident/rollback; user correction |
| Stale or unauthorized submit | immutable plan; actor/profile/scope/epoch; final dispatch recheck; monotonic fence; kill switches | journal/fence audit; revoke grants; no retry after start |
| Crash creates duplicate send | immutable intent, separate attempts, `dispatch_started` and `outcome_unknown` | receipt/portal/mail reconciliation; kill-at-every-edge tests |
| Restore replays old work | external actions paused; journal boundary; restore-time unknown marking and reconciliation | restore drill from pre-send backup; explicit resume step-up |
| False proof | assertion/one-absence/corroborated/inconclusive ladder; independent timed policy | resurfacing; method-specific evidence; proof-comprehension test |
| Event history rewritten | keyed/signed event chain; monotonic checkpoint outside primary DB | checkpoint mismatch alert; projection rebuild; disclose assurance limit |
| Registry rollback/compromise | expiring monotonic metadata; delegated capability roles; threshold root; digest/SBOM/provenance; no auto-promotion | persisted version floor; revocation; reproducible verification |
| Prompt injection/model leak | deterministic redaction and caps; no raw PII; isolated local runtime; no tools/network/state authority | canaries; supporting-span/schema validation; abstain/disable |
| Resource exhaustion | shared heavy-work lease; memory preflight; CPU/RAM/tmp/time/token caps; deterministic priority | cancellation, unload, `assist_unavailable`, capacity metrics |
| Unauthorized household request | one-adult v1; isolated profile/authority model; no implicit shared consent | consent/authority history; epoch revocation; defer guardian flows |

## Cryptographic design

- Generate a random installation/cloud key-encryption key (KEK) at setup and hold it in OS keychain, mounted secret, or KMS—not application data/evidence backups.
- Generate an independent random profile data-encryption key (DEK) per profile; never derive it from the KEK.
- Wrap each profile DEK with the KEK; classify and separately back up the wrapped-key catalog.
- Derive field, evidence, blind-index, session, and event-authentication keys below the profile DEK with context-bound HKDF.
- Encrypt with a reviewed authenticated-encryption library/algorithm selected during implementation review; AES-256-GCM with unique nonces is the portability baseline, XChaCha20-Poly1305 a candidate.
- Bind ciphertext to tenant/install, table/object, record, profile, schema version, field/purpose, and key version as associated data.
- Rotation rewraps profile DEKs first; purpose/algorithm changes may re-encrypt. Interrupted rotation is resumable and versioned.
- Profile deletion destroys the live wrapped DEK and indexes/session keys. It is reported incomplete while any key-catalog backup can recover that DEK.

Do not invent cryptography. Use reviewed libraries/test vectors and obtain independent review before live submission.

## Authentication and authority model

Local-lite binds loopback by default but still authenticates. Setup uses a random bootstrap secret/ceremony, then rotates into an authenticated session. Strict Host/Origin validation, anti-CSRF token, `SameSite=Strict`, secure cookies where TLS applies, clickjacking defense, and session rotation/revocation are mandatory. CLI uses a permissioned Unix socket or equivalent authenticated API.

Cloud-small requires HTTPS and a phishing-resistant passkey/WebAuthn or narrowly configured OIDC reference profile. Step-up is required for setup-authorization changes, resume, exception submit, key export/recovery change, profile deletion, and destructive restore. Every authorization/grant binds actor, represented profile, evidence, scope, expiry, plan boundary, and revocation epoch.

A fully compromised host remains outside the protection claim.

## Connector/browser and egress policy

Connectors are not plugins. They are separate digest-pinned artifacts with no core imports/mounts/network. The runtime is non-root/rootless, read-only except tmpfs, capability/syscall constrained, resource/time bounded, and cannot access DB/vault/key catalog/Docker socket/host metadata/other sessions.

The mandatory egress gateway is the only connector path to the network. It verifies the current action token/fence, authority epoch, all pause states, connector digest/capability, allowed method/protocol/origin/public IP, redirect, byte/time budget, and authorized disclosure before first and subsequent connections. Browser challenge/terms/disclosure drift stops.

Local container isolation shares the host kernel and is lower assurance than a properly configured VM/gVisor/Kata tier; documentation and support matrix must state this.

## Evidence assurance

`submitted` proves transport evidence, not receipt. `acknowledged` proves acknowledgement. `broker_asserted_removed` is the broker's claim. `observed_absent_once` records one clean post-request observation. `verified_removed` requires the versioned policy's independent time/method corroboration. Rate-limit, block, challenge, personalization/geolocation difference, ambiguous result, or missing evidence is `inconclusive`.

Screenshots are not automatically “gold standard”: they can capture third-party PII, hostile content, or a transient result. Prefer structured redacted derivatives, encrypt/bound raw captures, record method/context/time, and retain minimally.

## Local intelligence policy

V1 ships no model. A future local adapter follows ADR-0011: deterministic sanitized bounded inputs; digest-pinned license-reviewed artifacts; no raw PII/evidence, tools, network, vault/database, connectors, authority, reusable conversation, fine-tuning, or vault RAG. Output is an encrypted `UntrustedSuggestion` with schema/supporting spans and cannot mutate state. Remote fallback is prohibited.

## Security release gates

Before any live automatic submission:

- independent review of key hierarchy/catalog/deletion and implementation crypto;
- actor/session/step-up and setup-authorization binding review;
- connector artifact + egress gateway threat review and malicious-connector suite;
- dispatch-journal crash/fence/revocation/restore tests;
- canary PII scans of every diagnostic/support/AI surface;
- backup, key-loss, old-catalog deletion, restore and reconciliation drills;
- SBOM/container/artifact/provenance verification;
- broker simulator end-to-end tests; no real broker in CI;
- incident, emergency disable, unknown-outcome, and registry rollback runbooks;
- qualified U.S. legal/authorized-agent review for the claimed connectors/policies.

Before stable v1: accessibility, proof/disclosure comprehension, local deployment hardening, signed images, registry rollback protection, one 12-week user study, and no unresolved P0/P1 without public expiring acceptance.

## Legal and abuse boundary

MyCogni supports lawful user-directed requests; it does not decide that a right always applies or provide legal representation. U.S.-only is not one policy: voluntary opt-out, state rights, agent authority, and official mechanisms are versioned separately. California DROP remains guided/user-completed. Unknown applicability requires review.

Open-source forks can remove safeguards. The official project will not support unauthorized-person requests, mass/bulk outreach, CAPTCHA/rate-limit evasion, harassment, record tampering, or deceptive effectiveness claims.
