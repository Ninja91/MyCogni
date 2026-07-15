# Security, privacy, and threat model

## Assets

The highest-value assets are identity attributes, historical aliases/addresses, authorization documents, broker findings, browser and email credentials, evidence, case history, encryption keys, and the relationship graph connecting a person to brokers.

Availability and integrity matter too: a compromised connector could submit unauthorized requests, delete the wrong person's record, spam brokers, falsify evidence, or cause a user to miss a deadline.

## Adversaries

- opportunistic malware or another local user;
- cloud account or backup compromise;
- a malicious or compromised connector contributor;
- a broker serving hostile HTML, redirects, files, or misleading responses;
- an attacker who can submit a custom URL;
- a compromised assistant/OpenClaw plugin or prompt-injected page;
- a malicious household administrator targeting another person;
- a curious operator or diagnostics recipient;
- supply-chain compromise of dependencies or container images.

## Trust zones

1. **User control plane:** UI/CLI, setup authorization, and exception-review ceremony.
2. **Core trusted process:** domain, policy, orchestration, projections.
3. **PII vault/key boundary:** encrypted fields and external master key.
4. **Connector sandbox:** untrusted-by-default code with scoped capabilities.
5. **External network:** brokers, mail, registries, and hostile content.
6. **Integration zone:** assistants and notifications with metadata-only defaults.

## Major threats and controls

| Threat | Preventive controls | Detective/recovery controls |
| --- | --- | --- |
| Database/backup theft | envelope encryption; key outside DB/backups; field-level keys per profile | key rotation; restore audit; cryptographic erasure |
| Raw PII leakage in logs | typed redacted values; no string interpolation of domain objects; log allowlist | redaction tests; canary PII scans in CI/support bundles |
| Connector exfiltrates full profile | minimum attribute bundle; one-time capability; egress allowlist; isolated process | disclosure ledger; unusual destination/volume alerts; kill switch |
| SSRF/custom URL attacks | parse without fetch first; DNS/IP checks; deny private/link-local/metadata ranges; redirect revalidation | destination audit and alert; connector quarantine |
| Hostile browser content | isolated browser context; downloads disabled; no clipboard; no core cookies; bounded time/memory | capture sanitized failure evidence; destroy context |
| Wrong-person deletion | attribute explanation; minimum match threshold; ambiguity review; broker-specific identifiers | post-action review; incident classification and connector rollback |
| Unauthorized household request | separate profiles; stored authority; actor-bound approvals; no shared implicit consent | consent/authorization event history; revoke all grants |
| Replay/duplicate submission | idempotency keys; immutable approved plan hash; nonce/expiry | duplicate detector; case timeline |
| Prompt injection via page/email | deterministic parser; external text is data; no raw content sent to assistant; tools lack submission authority | assistant audit log; capability revocation |
| Key exposed through environment/process | file descriptor or secret provider preferred; restricted permissions; never print config | startup self-check; rotation runbook |
| Supply-chain compromise | locked hashes; SBOM; signed images; minimal images; connector signing and review | vulnerability scans; provenance verification; rapid connector disable |
| False proof of removal | semantic states; independent verifier; evidence policy | resurfacing scan; evidence integrity checks |
| Denial of service / broker blocking | per-domain rate limits; randomized scheduling; no mass broadcast | backoff; circuit breaker; manual fallback |

## Cryptographic design

- Generate a random root data-encryption key at first setup.
- Wrap it with a key-encryption key held in macOS Keychain, Linux Secret Service/file with strict permissions, or a cloud KMS/secret manager.
- Derive independent per-profile and per-purpose keys with HKDF.
- Encrypt fields and objects with a misuse-resistant authenticated encryption construction selected during implementation security review; AES-256-GCM with unique nonces is the portability baseline, while XChaCha20-Poly1305 is preferred when the dependency choice is accepted.
- Bind ciphertext to table, record ID, profile ID, schema version, and field name as associated data.
- Store key version and nonce with ciphertext, never the wrapping key.
- Rotation rewraps data keys first; full re-encryption is an explicit background job.

Do not invent cryptography. Use reviewed libraries and test vectors.

## Privacy model

Privacy is enforced as data-flow policy, not a settings page:

- identity attributes are classified by sensitivity and purpose;
- connector manifests declare a maximum disclosure schema;
- policy computes the minimum bundle for the selected right and jurisdiction;
- the setup-authorization and exception-review UI shows every released category and warns on novel/high-risk fields;
- every actual release becomes a disclosure event;
- optional remote integrations receive opaque IDs and aggregates unless separately granted;
- telemetry is off by default and never includes broker/profile identifiers if later added.

## Browser and CAPTCHA policy

MyCogni will not bypass CAPTCHAs or access controls. A connector may detect a challenge, preserve safe state, and create a user task. User-completed challenges occur in a visible isolated browser session. Third-party CAPTCHA-solving services are outside the supported threat model because they disclose task content and encourage evasion.

## Security release gates

Before the first live submission release:

- external review of cryptographic/key management design;
- threat-model review of the connector protocol and SSRF defenses;
- redaction tests using seeded canary PII;
- restore and key-loss drills;
- dependency/SBOM/container scans;
- permission tests proving read-only integrations cannot mutate;
- a broker-owned or synthetic staging target for end-to-end submission tests;
- incident response and emergency connector-disable runbooks.

## Legal boundary

This architecture supports lawful user-directed requests; it does not decide that a right always applies. Jurisdiction rules are versioned policy facts with sources and review dates. Uncertainty produces a reviewed task. The project must obtain qualified legal review before representing itself as an authorized agent service or enabling unattended submissions across jurisdictions.
