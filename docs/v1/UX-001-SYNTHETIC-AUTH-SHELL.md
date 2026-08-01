# UX-001 — synthetic authenticated web shell

Status: `IN_PROGRESS` (V0.x precursor; not an authenticated production package)

UX-001 is the first browser-shaped vertical slice after the durable synthetic
key-catalog work. It lets a contributor walk through local setup, authentication,
an honest dashboard, and sign-out while keeping every external capability
absent.

## Run it locally

From a clean checkout with the locked environment:

```console
uv run --frozen mycogni-web
```

The command binds to `127.0.0.1:8000`, discloses a one-time synthetic operator
code through the private foreground terminal, and serves `/login`. Enter that
code in the form. The process owns only volatile synthetic auth state; stopping
it invalidates the session and any unconsumed bootstrap state.

The command is safe for a developer preview only. Never paste real identity
attributes, credentials, broker URLs, or mail data into it.

## Request surface

```mermaid
sequenceDiagram
    participant T as Private terminal
    participant B as Browser
    participant A as Web adapter
    participant S as SyntheticWebShell
    participant Auth as AuthService

    T->>Auth: compose installation and one-use bootstrap
    T-->>B: operator enters code at /login
    B->>A: GET /login
    A->>S: create bounded form challenge
    S-->>A: CSRF token + opaque challenge cookie
    A-->>B: no-script form
    B->>A: POST /login (Origin + CSRF + code)
    A->>S: consume challenge
    S->>Auth: exchange opaque bootstrap
    Auth-->>S: session credential or finite denial
    S-->>A: random session handle
    A-->>B: HttpOnly SameSite=Strict cookie
    B->>A: GET /app
    A->>S: authenticate + issue fresh bounded CSRF token
    S-->>A: redacted synthetic projection
    A-->>B: dashboard; all external actions unavailable
    B->>A: POST /logout (Origin + CSRF)
    A->>Auth: revoke session
```

Routes are intentionally small:

| Route | Behavior | External effect |
| --- | --- | --- |
| `GET /` | safety boundary and links | none |
| `GET /login` | creates one form challenge | volatile in-process state only |
| `POST /login` | validates Host/Origin/CSRF and exchanges synthetic code | no network; auth spike only |
| `GET /app` | validates session and shows redacted status | none |
| `POST /logout` | validates CSRF, revokes session, clears cookie | local state only |
| `GET /healthz` | returns non-secret readiness facts | none |

## Controls exercised

- Exact allowed loopback Host; no implicit trust from a private network.
- Exact same-origin `Origin` on every state-changing request.
- One-use, five-minute login form challenges; invalid CSRF burns the challenge.
- Random opaque session handle, server-held credential, bounded session count,
  session expiry, auth-service revalidation, and logout revocation.
- Server-held bounded recent CSRF digests (multi-tab tolerant); no credential in query strings or URLs.
- `HttpOnly`, `SameSite=Strict` cookies; `Secure` is required by the TLS profile.
- `Cache-Control: no-store`, restrictive CSP with `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `nosniff`, no-referrer, and no scripts/docs route.
- Generic login failure text; denial details never reach HTML.

## Evidence

The focused lane covers successful login/logout, one-use challenge behavior,
wrong-CSRF burn, bounded multi-tab tokens, redacted representations, session
expiry, Host/Origin rejection, generic credential failure, bounded form
parsing, response headers, launcher terminal refusal/disclosure, and the
secure-cookie profile:

```console
14 passed  tests/application/test_web_shell.py tests/adapters/test_web_shell_http.py
             tests/architecture/test_web_shell_boundaries.py tests/bootstrap/test_web_shell_launcher.py
```

Ruff and strict mypy pass for the package. The HTTP tests call the ASGI app
in-process, so they do not grant or exercise live loopback authority.

## Explicit nonclaims and next gates

UX-001 does not provide a real-PII vault, durable session custody, native TTY
setup, cloud identity, TLS termination, key rotation/deletion, backup/restore,
OpenClaw access, connector code, browser automation, mail, broker observation,
submission, or removal verification. It remains `IN_PROGRESS` until the
authenticated package and M0 acceptance gates are independently reviewed.

Next work should add the durable local composition and setup/health contracts
only after the key/auth/SQLite boundaries remain intact. No connector or model
runtime should be added to this shell.
