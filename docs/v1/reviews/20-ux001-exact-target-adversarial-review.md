# UX-001 exact-target adversarial review

Date: 2026-08-01

This record preserves the three independent code-level reviews of the synthetic
authenticated web shell. It is not an authenticated package attestation,
qualified human security certification, a production authentication claim, or
evidence of a broker/removal capability.

## Exact target

| Revision | Scope | Final verdict |
| --- | --- | --- |
| `afc901841f6085e83e91a78a1a041fb9b1d36ebd` | UX-001 application state, HTTP adapter, private-terminal launcher, tests, ADR, plan, README, site and governance truth | ACCEPT; zero unresolved P0/P1/P2 across all three reviewers |
| `af473fd5ff9e143e0f481c8fa956389a378d10b6` | CI-only test-fixture follow-up: reserve the `.test` host suffix so the repository safety guard recognizes the in-process ASGI host as synthetic | ACCEPT; no production behavior changed; dual-runtime GitHub checks pass |

## Independent final verdicts

| Review hat | P0 | P1 | P2 | Verdict |
| --- | ---: | ---: | ---: | --- |
| Principal software architecture / edge / OSS | 0 | 0 | 0 | ACCEPT; boundaries, secret redaction, fail-closed launcher, bounded form/CSRF behavior, and documentation scope are consistent |
| Principal cryptography / ML-safety | 0 | 0 | 0 | ACCEPT; digest-only CSRF state, constant-time checks, bounded recent-token history, credential revocation, and no-external-action claims are sound for this synthetic precursor |
| Principal backend / infrastructure / SQLite | 0 | 0 | 0 | ACCEPT; streaming request limits, malformed-input handling, exception headers, bounded state, and revocation ordering are sound |

Reviewer labels identify role perspectives, not model identities, human
qualifications, authenticated attestations or certifications.

## Rejected findings and remediation

The first review pass rejected the pre-remediation working tree. The material
findings and exact dispositions were:

1. **Bootstrap code reached arbitrary stderr.** The launcher now uses the
   existing POSIX `/dev/tty` operator-terminal boundary, verifies foreground
   interactive readiness, discloses through `SecretField`, and fails closed
   without starting the server when private disclosure is unavailable or
   uncertain. It never substitutes stdout, logs, argv, environment or a
   browser channel.
2. **Secret-bearing DTO representations were default-renderable.** Login
   challenge, login result, authenticated view and internal session values now
   have fixed redacted representations; tests assert challenge, session and
   CSRF values do not appear in representations.
3. **Form parsing could read unbounded input before validation.** The adapter
   rejects malformed, negative and oversized declared lengths, streams the body
   with a 16 KiB hard cap even when the length is absent, limits parsed fields
   and field values, and fails closed on disconnect, invalid UTF-8 or parser
   errors.
4. **Unexpected handler errors could miss security headers.** The outer
   middleware converts an unexpected handler exception to a generic response
   and applies the complete no-store/security-header policy; the error body is
   static and does not contain the exception text.
5. **Session eviction/expiry could leave underlying auth credentials active.**
   Evicted, expired, auth-denied and explicitly logged-out sessions now revoke
   their underlying credentials outside the state lock.
6. **Single-current CSRF rotation broke concurrent tabs.** The shell retains a
   bounded tuple of recent CSRF digests, preserving multi-tab forms without
   making the token set unbounded.

## Evidence reproduced for the target

- UX-001 focused lane: **14 passed** across application, HTTP adapter,
  architecture-boundary and launcher tests.
- Broad non-loopback lane: **1,506 passed**, 8 expected `/dev/tty` precondition
  skips, and 38 established simulator-loopback tests deselected by the guard.
- The three package/lock guard tests that require the host uv runtime passed in
  the unsandboxed verification run; the sandbox-only failures were cache/system
  configuration restrictions, not project assertions.
- Full source mypy, Ruff, import-linter, governance, site, claim, safety,
  threat-catalog and network-source guards passed.
- The initial implementation target used `testserver` only as an in-process
  ASGI host. The follow-up `af473fd` changes that fixture to `shell.test`, a
  reserved synthetic suffix, so the same safety guard passes in CI as well as
  locally; it does not change the application or runtime surface.
- HTTP evidence remains in-process ASGI evidence; it does not grant live
  loopback authority or imply a deployed server certification.

## Explicit residual scope

The ACCEPT verdict is limited to the synthetic V0.x web slice. It does not
promote durable session custody, real-PII encryption, TLS termination, cloud
identity, OpenClaw integration, browser automation, mail, broker observation,
submission, removal verification, or any M1/V1 package. The one-time code is
generated before terminal readiness, but is held only in process and is neither
disclosed nor served when the private-terminal check fails. Authenticated
package acceptance and qualified human review remain separate release gates.
