# Independent backend, infrastructure, and security adversarial review

Perspective: principal backend/infrastructure engineer with application-security and privacy focus.

## Verdict

The design has strong intentions but four P0 gaps block unattended live automation: a subprocess is not connector isolation; the described key derivation cannot support honest cryptographic deletion; external idempotency conflates intent and attempts; and local/cloud authentication is not an acceptance contract.

## P0 findings

### Connector isolation is not a boundary

Non-browser connectors cannot live in the core image or inherit its UID, mounts, environment, kernel privileges, or network. Package each immutable connector as a separate digest-pinned OCI or constrained WASI artifact. Per action require a rootless/non-root identity, read-only root filesystem, tmpfs workspace, dropped capabilities, `no-new-privileges`, syscall policy, PID/CPU/RAM/time limits, no Docker socket, no core volumes, no host network, and a one-time sealed bundle.

All outbound bytes must traverse a mandatory egress gateway that revalidates action token, monotonic fence, authorization epoch, kill switches, capability, method, origin, resolved public IP, redirect, byte/time budget, and disclosure plan before first transmission. Domain allowlists alone do not stop DNS rebinding, service workers, WebSocket/QUIC/DoH, redirect, or allowed-domain covert exfiltration.

### Key hierarchy contradicts cryptographic deletion

A profile key derived only from a persistent install root can be recreated after “deletion.” Generate a random profile data-encryption key, wrap it with the install/cloud key-encryption key, and use HKDF only below that profile key for purpose separation. Deletion destroys the profile key and creates a tombstone; it is not complete while any recoverable key-catalog backup still contains that key. The relationship graph and case metadata are sensitive too.

### External-action idempotency is mis-specified

Connector version and attempt generation cannot define external identity. Separate immutable `intent_id` from `attempt_id`. Persist a fenced journal:

`ready → dispatch_claimed → dispatch_started → transport_proven | outcome_unknown | failed_before_send`.

Re-evaluate authorization, match, connector freshness, destination, and global/profile/broker pause in the final dispatch transaction. The gateway rejects stale fences before the first byte. Once `dispatch_started`, do not retry unless reconciliation proves no send. Queue/outbox durability does not make HTTP/email atomic.

### Control-plane authentication is under-specified

Loopback is not authentication. Local requires a random bootstrap ceremony, authenticated session, strict Host/Origin checks, CSRF tokens, `SameSite=Strict`, clickjacking protection, session rotation, and Unix-socket permissions for CLI access. Cloud requires phishing-resistant authentication such as WebAuthn/passkeys or narrowly configured OIDC. Step-up applies to authorization changes, resume, key export, profile deletion, and exception submission. Grants bind actor, represented profile, scope, expiry, and revocation epoch.

## P1 findings

- **Evidence integrity:** an unkeyed hash chain can be recomputed or truncated by a database attacker. Use keyed/signed events plus an external monotonic checkpoint and call it tamper evidence relative to that checkpoint.
- **Verification confidence:** one clean lookup can be a rate limit, CAPTCHA, geolocation/personalization difference, or temporary absence. Record `observed_absent_once`; reserve `verified_removed` for policy-defined corroboration across time or method. Blocks are inconclusive.
- **Registry freshness:** signing without rollback/freeze protection is insufficient. Use versioned expiring metadata, delegated capability roles, threshold root keys, persisted monotonic versions, artifact verification, and provenance.
- **Diagnostics:** generic HTTP instrumentation can capture query strings, headers, IPs, exception text, or URLs. Permit hand-authored safe spans or enforce an allowlist before storage/export.
- **Restore:** a 24-hour database RPO can lose proof of an already sent request. External actions remain paused after restore; intents newer than the backup boundary become `outcome_unknown` until reconciled.
- **Profile parity:** SQLite/filesystem/host secrets and PostgreSQL/object store/KMS have different failure and security behavior. Publish a conformance matrix, not a blanket parity claim.
- **U.S. policy:** distinguish voluntary opt-outs, state rights, agent authority, and official portals. DROP remains guided; eligibility and verification are user-completed.

## Required tests

Malicious connectors must fail to read `/proc` secrets, DB/evidence paths, environment, Docker socket, host metadata, another connector's session, or private network. Test DNS rebinding, redirect loops, WebSocket/QUIC/DoH, byte smuggling, and exfiltration to an allowed origin. Kill processes at every dispatch-journal edge, lose leases during send, revoke after claim, upgrade a connector mid-case, duplicate a scheduler, restore a pre-send backup, and reconcile delayed receipts.

Cryptographic tests cover nonce uniqueness, associated-data substitution, interrupted rotation, wrong-key/cross-profile decryption, old key-catalog backup restore after deletion, and independent profile deletion. Authentication tests cover CSRF, DNS rebinding against localhost, Host abuse, session theft/rotation, cross-profile authorization, and stale grant replay.

## Sources

- [Playwright Docker security guidance](https://playwright.dev/docs/docker)
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST cryptographic erase glossary](https://csrc.nist.gov/glossary/term/cryptographic_erase)
- [The Update Framework metadata](https://theupdateframework.io/docs/metadata/)
- [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [SLSA build levels](https://slsa.dev/spec/v1.0/levels)
- [OpenTelemetry sensitive-data guidance](https://opentelemetry.io/docs/security/handling-sensitive-data/)
- [CPPA DROP and data-broker information](https://cppa.ca.gov/data_brokers/)
