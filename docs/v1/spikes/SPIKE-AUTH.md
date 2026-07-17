# SPIKE-AUTH — volatile local root-of-trust decision

Status: implementation evidence produced; independent security/recovery review pending. This document does
not promote `SPIKE-AUTH`, `AUTH-001`, `AUTH-002`, `AUTH-003`, `THR-AUTH-001` or `VFY-AUTH-001`.

## Decision and ADR disposition

The spike supports ADR-0010's local authentication direction: an explicit interactive terminal ceremony can
bootstrap a short-lived one-use exchange, an opaque server-side session, purpose-specific step-up authority
and recovery that invalidates stale authority. ADR-0010 is already the unambiguous accepted architecture
record, so this spike does not reserve or invent another ADR number.

The production decision remains conditional. The pure policy and volatile state model are suitable inputs to
`AUTH-001`, but durable crash/restart semantics, browser transport controls and recovery accessibility need
separate evidence. The spike cannot be used as production authentication.

## Implemented synthetic boundary

```text
interactive operator TTY
        |
        | one-use bootstrap code (never URL or argv)
        v
AuthService -- Clock / TokenSource / AuthDecisionStore ports
        |
        +-- exact actor + represented profile
        +-- opaque session digest + actor epoch + validity window
        +-- one-use step-up digest + session + purpose + exact scope
        +-- rotating one-use recovery digest
        v
VolatileAuthDecisionStore (RLock, process memory, digest-only records)
```

The domain is standard-library-only. Application orchestration imports no concrete adapter. Tests inject a
deterministic synthetic token source and mutable clock; the spike adapter uses `secrets.token_bytes`, which is
backed by the operating-system random source. Every issued secret has at least 256 bits. Only its SHA-256
digest is retained, and proof comparison uses `hmac.compare_digest`.

`OpaqueCredential` requires an opaque UUIDv4 handle plus typed sensitive bytes. Ordinary `str` and `repr`
render only a redaction marker. Its operator-code method is an explicit disclosure boundary for a dedicated
TTY. The entrypoint accepts no secret command argument, builds no URL and refuses a non-TTY before issuance or
recovery. A future browser exchange must accept the code in a manually submitted POST body; putting it in a
query string, fragment, referrer-bearing navigation or shell history is prohibited.

## Ceremony semantics

Default spike policy is deliberately bounded:

| Item | Default | Decision |
| --- | ---: | --- |
| bootstrap | 5 minutes, 5 attempts | one-use; replay, early use, expiry and exhaustion deny |
| server-side session | 30 minutes | opaque digest; rotation revokes its predecessor |
| step-up | 2 minutes, 5 attempts | one-use and exact actor/profile/session/epoch/purpose/scope |
| recovery | 24 hours, 5 attempts | one-use; success rotates recovery and actor epoch |
| activation delay | 0 seconds | configurable to exercise not-yet-valid behavior |

The finite step-up purposes are setup-authority change, external-action resume, exception submission,
key/recovery change, profile deletion and destructive restore. Each maps to exactly one finite scope. The
service rejects caller-selected unions, a different purpose, actor, represented profile or session, a stale
epoch, expired authority and replay. A grant binds:

- actor and represented profile;
- opaque server-side session;
- one-use challenge as authority evidence;
- exact purpose and scope;
- not-before and expiry instants; and
- actor revocation epoch.

Session rotation revokes the old session and its outstanding challenges. One-session revocation denies that
session. All-session revocation increments the actor epoch and invalidates every session and step-up. Lost
browser state is not required for recovery: the separate recovery credential creates a new session and
recovery credential, increments the epoch, and revokes all older sessions/challenges. Recovery remains a
separate operator-held authority after an all-session revoke; changing that policy requires recovery design
review.

Every policy read uses the injected aware-UTC `Clock`. A time before a credential's not-before instant denies
as `not_yet_valid`; a forward jump beyond expiry denies as `expired`; a time earlier than the actor's last
observed instant denies as `clock_rollback`. This detects rollback within one volatile process. It is not a
trusted monotonic clock across reboot or host compromise.

## Consume and crash model

The volatile adapter serializes decisions with a process-local reentrant lock. Concurrent bootstrap or
step-up consumption yields exactly one success; the loser sees replay. Attempt exhaustion burns the one-use
record. Synthetic checkpoints inject a crash after the consumed bit is set but before session, grant or
recovery replacement is issued. Within the still-running adapter, retry cannot reuse the credential and no
partial authority appears.

This evidence is intentionally narrow. The adapter has no transaction log and loses both consumed state and
all authority on restart. It does not prove database compare-and-swap, commit ordering, multi-process safety,
crash durability or restart recovery. `AUTH-001` needs a persistent adapter whose transaction makes the
consume/issue state machine explicit and whose crash matrix is verified at every commit boundary. A recovery
crash in this spike fails closed by revoking old authority and burning the recovery credential; operator
re-bootstrap is then required.

## Negative evidence

Focused tests exercise:

- bootstrap replay, expiry, not-yet-valid use, guessing/exhaustion and constant-time digest comparison;
- session fixation, opaque server-side state, rotation, individual revoke, all-session revoke and expiry;
- wrong actor, represented profile, session, purpose and scope; step-up reuse, widening, expiry and stale epoch;
- concurrent bootstrap and step-up consumption and post-consume bootstrap/step-up/recovery crashes;
- clock rollback and forward jumps, lost browser state, recovery replay and recovery-secret rotation;
- non-TTY bootstrap/recovery refusal and headless recovery over a pseudo-TTY;
- generic malformed-input errors, redacted `repr`/`str`/traceback, no ordinary stdout/stderr disclosure, no
  secret-capable typed diagnostic field, and no URL/query/argv entrypoint path; and
- domain standard-library and repository import contracts.

These are spike tests, not the canonical `VFY-AUTH-001`. That verification ID remains `PLANNED` and has no
implementation reference until governance acceptance and independent security/recovery review authorize an
exact criterion/evidence mapping.

## Redacted pseudo-TTY review transcript

The raw test channel contains a one-use code only at the explicit operator disclosure boundary. Review
artifacts apply exact credential replacement before retention:

```text
bootstrap-code (one-use, short-lived): [REDACTED:auth_secret]
bootstrap-exchange: allowed; opaque session issued; recovery issued
step-up(profile_deletion as destructive_restore): denied wrong_purpose
step-up(profile_deletion): allowed; evidence and exact scope bound
step-up(profile_deletion replay): denied replayed
recovery-code: [REDACTED:auth_secret]
new-session-code: [REDACTED:auth_secret]
new-recovery-code: [REDACTED:auth_secret]
old-session-after-recovery: denied stale_epoch
bootstrap over non-TTY: denied non_interactive
recovery over non-TTY: denied non_interactive
```

No real person, account, identifier, endpoint or credential is used. Deterministic test material is generated
at runtime rather than retained as a fixture or transcript value.

## Requirement and threat disposition

| Boundary | Spike evidence | Still required for production |
| --- | --- | --- |
| AU-01 | explicit bootstrap, authenticated opaque sessions, private location grants nothing | composed local control plane and persistent actor store |
| AU-02 | session rotation/revoke policy only | Host/Origin, CSRF, cookie, clickjacking and framework middleware evidence |
| AU-04 | six finite step-up purposes | wiring at every privileged application action and accessible reauthentication |
| AU-05 | actor/profile/evidence/scope/time/epoch-bound grant | durable audit/storage and end-to-end authorization consumers |
| THR-AUTH-001 | synthetic takeover/replay/stale-authority negative suite | exact `VFY-AUTH-001`, independent review and M1 implementation evidence |

## Accessibility and operator handoff

TTY-only display is a security experiment, not the final accessible ceremony. The production UI/CLI must
provide keyboard-only completion, non-color errors, high-contrast and zoom-safe presentation, screen-reader
labels, focus restoration, advance timeout warning and an accessible timeout-extension/restart path. It must
not echo recovery input. Recovery procedures must explain that success invalidates every prior session.

## Explicit exclusions and residual risk

This spike adds no database migration, cookie, CSRF, Host/Origin or clickjacking middleware, WebAuthn, OIDC,
password, email, SMS, network service, real user/PII, external I/O, dependency or lockfile change. It does not
claim `AUTH-001`, `AUTH-002` or `AUTH-003` completion.

Residual limits are material:

- restart destroys volatile authority and consume history, so persistence and restart behavior are unproven;
- a compromised process or host can read live credentials before hashing, capture the TTY, alter the clock or
  decision code, and bypass all same-host policy;
- UUID handles are opaque routing identifiers, not proof; only the secret comparison authenticates;
- denial timing beyond the fixed-size digest comparison and whole-flow side channels is not characterized;
- multi-process, distributed, database and backup/restore epoch behavior is unimplemented;
- browser transport and cloud identity protections remain outside this spike; and
- operator loss of both session and recovery material requires a separately designed re-bootstrap procedure.

Rollback removes `domain/auth.py`, `application/auth.py`, the volatile auth adapter, spike entrypoint and their
tests. Because the adapter is process-local, stopping the process discards every synthetic credential and
record. This convenient cleanup is also why it provides no durability assurance.
