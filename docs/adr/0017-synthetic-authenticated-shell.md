# ADR-0017: Synthetic authenticated local web shell

- Status: Accepted for initial build
- Date: 2026-07-31
- Scope: `UX-001` only; this ADR does not promote production authentication

## Context

The repository already has a framework-free authentication decision spike and a
synthetic CLI, but contributors could not exercise the browser-facing session
boundary. A localhost page is not an identity boundary by itself: DNS/Host
rebinding, cross-site requests, session theft, framing, and accidental secret
logging still need explicit controls. A useful V0.x surface must teach those
controls without accepting real identity data or contacting an external site.

## Decision

Add a small server-rendered FastAPI adapter around an application-owned,
framework-free `SyntheticWebShell` state contract.

- Composition creates one volatile synthetic auth store, one installation, and
  one one-time bootstrap code. The code is disclosed only through the existing
  private foreground `/dev/tty` terminal boundary; if that boundary is absent
  or uncertain, the launcher fails closed. It is never placed in a URL, log
  field, HTML error, or cookie.
- `POST /login` consumes a bounded one-use form challenge, requires an exact
  allowed Host and same-origin `Origin`, and exchanges the opaque code through
  the existing `AuthService`.
- The browser receives only a random session handle in an `HttpOnly`,
  `SameSite=Strict` cookie. The raw session credential remains process-local and
  volatile in this precursor. A TLS composition must enable `Secure`; the
  loopback HTTP profile is the sole reason the default is false.
- Authenticated pages issue fresh tokens while retaining a bounded recent
  digest set for multi-tab forms. State-changing requests require both a
  recent token and an exact same-origin `Origin`; logout revokes the underlying
  auth session.
- Every response carries `no-store`, `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `nosniff`, a no-referrer policy, and a restrictive
  permissions policy. OpenAPI/docs routes, scripts, personal-data fields,
  broker calls, mail, browser actions, and removal submission are absent.
- The adapter accepts only `application/x-www-form-urlencoded` synthetic form
  data. Invalid/missing challenges and credentials return a generic failure and
  burn the form challenge; no auth-state detail is rendered.

## Consequences

The preview now has a real browser-shaped login/session/logout flow that can be
tested in-process without granting the repository's loopback network-test
capability. It demonstrates the intended UX and makes common security mistakes
visible to contributors.

The state is intentionally volatile and the credential custody is still a
synthetic spike. This does not prove durable sessions, native terminal custody,
TLS deployment, cloud identity, host compromise resistance, accessibility
conformance, a vault, a connector, or any removal outcome. Those remain named
M1/V1 work and review gates.

## Rejected alternatives

- Anonymous localhost access: rejected because loopback is not authentication.
- A bearer token in a query string or HTML link: rejected because URLs/history,
  referrers, and screenshots would become credential channels.
- A framework-global session or database lookup from the adapter: rejected to
  preserve application-owned contracts and keep this precursor volatile.
- A client-side SPA: rejected for this slice; server-rendered HTML keeps the
  trust surface small and preserves no-script accessibility.
