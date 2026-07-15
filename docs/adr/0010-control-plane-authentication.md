# ADR-0010: Control-plane authentication and step-up policy

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

Loopback binding and private networks do not authenticate a person or stop DNS rebinding, CSRF, session theft, another local user, or a compromised browser extension. MyCogni stores a dossier and can submit externally, so actor/profile authority must be explicit.

## Decision

Local setup performs a random bootstrap ceremony and establishes an authenticated session. The web control plane enforces strict Host and Origin policy, anti-CSRF tokens, `SameSite=Strict` secure cookies where applicable, clickjacking protection, session rotation/invalidation, and loopback-only default. CLI access uses a permissioned Unix socket or an authenticated local channel rather than database access.

Cloud-small requires phishing-resistant WebAuthn/passkeys or narrowly configured OIDC through TLS ingress; a private address is not sufficient. Step-up authentication is required for setup-authorization changes, resuming external actions, exception submissions, key export/recovery changes, profile deletion, and destructive restore. Grants bind actor, represented profile, authority evidence, action scope, expiry, and revocation epoch.

## Consequences

- Even single-user local mode has an onboarding/session surface.
- Cloud examples must document supported identity configuration and recovery.
- Accessibility and recovery flows need careful design.
- CLI/UI parity occurs through application services, not shared implicit trust.

## Alternatives

Anonymous localhost, IP/VPN-only trust, and reusable bearer tokens for all actions were rejected. Password-only cloud auth is not the preferred reference profile.

## Security and privacy impact

The controls reduce browser/local-user takeover and make authority auditable. They do not protect a fully compromised host.

## Review trigger

New client type, LAN binding, assistant write tool, household administration, identity provider, recovery method, or authorization incident.
