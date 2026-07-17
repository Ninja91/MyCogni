# SPIKE-AUTH — volatile local root-of-trust decision

Status: remediation evidence produced after security/recovery review rejection; re-review pending. This
document does not promote `SPIKE-AUTH`, `AUTH-001`, `AUTH-002`, `AUTH-003`, `THR-AUTH-001` or
`VFY-AUTH-001`.

## Decision and ADR disposition

The spike resolves a narrow design question under ADR-0010: a trusted local installation can issue
installation/actor/profile/purpose-bound root capabilities, exchange an explicitly displayed one-use code for
opaque authority, require purpose-specific step-up, and recover after months of inactivity without accepting
caller-supplied identity bindings. ADR-0010 remains the architecture record; this spike does not create or
reserve another ADR.

The model is not production authentication. Its volatile adapter does not prove restart durability,
multi-process transactions, browser controls, secure root storage, or a real terminal driver. An independent
review rejected the previous evidence; this revision addresses those findings but remains pending re-review.

## Authority boundary

```text
trusted local composition (one installation, before application startup)
        |
        +-- initial-bootstrap root: installation + actor + profile + exact purpose
        +-- emergency-revoke root: same bindings, separate one-use secret
        +-- reprovision root: same bindings, separate one-use secret
        v
private interactive operator channel -- warning + confirmation + all-or-nothing display
        |
        v
AuthService -- Clock / TokenSource / AuthDecisionStore ports
        |
        +-- opaque digest-only session + actor epoch + validity window
        +-- one-use step-up + session + purpose + exact scope
        +-- immutable exact grant provenance + atomic one-use state
        +-- opaque digest-only long-lived recovery indexed by its own handle
        v
VolatileAuthDecisionStore (RLock, process memory, bounded garbage collection)
```

`TrustedLocalAuthSetup` is the only initial composition surface that mints roots. Before any store mutation,
the adapter requires exactly three distinct record objects, three distinct handles, and exactly one capability
for each `RootPurpose`, all with the same installation/actor/profile binding. It registers their digests with a
single empty volatile store. Merely knowing or choosing actor/profile UUIDs cannot bootstrap, reprovision, or
revoke authority. Root verification compares the secret digest and exact installation, actor, represented
profile, and purpose. A forged, cross-bound, wrong-purpose, stale, or replayed capability is denied.

The initial root is valid only before the actor's first successful bootstrap exchange. Later ordinary
bootstraps require a current session and an exact `setup_authority_change` step-up grant. A reprovision root is
valid only after initialization and remains one-use: every successful reprovision atomically registers a fresh,
canonically bound reprovision capability and hands it off with the new session/recovery. The old root is never
re-enabled. Root authority is consumed at successful exchange, not at bootstrap-code display. The exchange
entrypoint warns and confirms before consuming that offline route.

Every secret contains at least 256 bits from the injected token source. The spike adapter uses
`secrets.token_bytes`; state stores only fixed SHA-256 `SecretDigest` values and compares them with
`hmac.compare_digest`. Adapter ingress and return values are copied so a caller cannot mutate retained records.
A structural regression traverses nested adapter state and rejects any `OpaqueCredential`, `Sensitive`, or raw
issued secret. `OpaqueCredential` renders only a redaction marker outside its explicit operator-code boundary.

## Bounded policy and sporadic lifecycle

| Item | Default | Reviewed bounds and behavior |
| --- | ---: | --- |
| bootstrap | 5 minutes, 5 attempts | 1 second–7 days; one-use; early use, expiry, replay and exhaustion deny |
| server-side session | 30 minutes | 1 second–7 days; opaque; rotation revokes predecessor |
| step-up | 2 minutes, 5 attempts | 1 second–7 days; exact binding and one-use |
| recovery | 365 days, 5 attempts | 30–730 days; one-use; rotates all sibling recovery and actor epoch |
| activation delay | 0 seconds | 0–60 seconds, used to test not-yet-valid behavior |
| retired record GC | caller-selected | 0–24 hours; expired/burned volatile records are bounded |

Recovery is deliberately separate from short interactive authority. A device may sleep for months and use an
unexpired recovery code without a live browser session. While a session is current, an exact
`key_recovery_change` step-up rotates every existing recovery code and issues a new one with a fresh long-lived
window. Expiry is final for that code.

Recovery input supplies only the opaque code. Its handle locates the stored installation-local record; the
store canonically constructs the new session and recovery from that record's actor, profile, and current epoch.
The application cannot submit replacement actor/profile/epoch fields. On success, while holding the decision
lock, the store consumes every recovery record for that actor, increments the epoch, revokes all sessions and
step-ups, and issues exactly one new session/recovery pair. The two-bootstrap sibling regression proves that
using either sibling makes the other unusable.

If recovery expires and no current session remains, the current offline reprovision root may establish fresh
auth authority for the already-bound installation/actor/profile. The exchange rotates that root and discloses
the replacement through the confirmed all-or-nothing operator channel. A regression proves recovery expiry,
reprovision, second recovery expiry, and second reprovision with three distinct one-use roots. Reprovision does
**not** recover encrypted profile data, keys, broker history, or any other lost state. Losing every session,
recovery code, and the current reprovision root is total authority loss in this model. No recovery claim is
made for that condition.

## Step-up and incident revocation

Finite purposes map one-to-one to finite scopes: setup-authority change, external-action resume, exception
submission, key/recovery change, profile deletion, destructive restore, and all-session revoke. The service
checks exact enum types before mapping lookup, so malformed purpose/scope values produce typed denials instead
of `KeyError`. A grant binds actor, represented profile, current session, one-use evidence, purpose, exact
scope, not-before, expiry, and actor epoch.

A returned `AuthorityGrant` is not self-authenticating. Only successful step-up consumption creates an
immutable `GrantProvenanceRecord`, keyed by its evidence ID, while holding the decision lock. Every validation
or privileged consumer requires exact equality of actor, profile, session, purpose, scope, epoch, time window,
and evidence with that record; random IDs and any altered field deny. Unconsumed, expired, exhausted, revoked-
session, and crash-consumed challenges create no usable provenance. Successful validation/use atomically marks
the provenance used, so concurrent consumers yield one success and one replay. Provenance and replay state are
retained through the grant's expiry plus the bounded retention window; they are not collected merely because
the step-up record was consumed earlier.

There are two deliberately separate incident paths:

- Authenticated all-session revoke requires a current session plus an exact `all_session_revoke` step-up. It
  increments the epoch, retires every session/challenge/recovery, and returns one replacement recovery code.
- Offline emergency revoke requires the exact installation-bound `emergency_revoke` root. It is one-use,
  increments the epoch, and retires every session/challenge/recovery without issuing replacement authority.
  Recovery then requires the separate reprovision root.

Recovery itself follows the stricter all-session policy: every prior session and recovery is invalidated.

## Operator and headless ceremony

Before any secret display or offline-route consumption, the narrow `OperatorTty` port requires an interactive
channel, prints a prominent warning to disable recording, saved scrollback, copy synchronization, and session
logging, then requires an explicit confirmation. It reports finite expiry, attempt, retry, and denial guidance.
Unknown and garbage-collected codes share attempt-agnostic guidance: the code may be unknown or retired,
remaining attempts are unavailable, and the operator must verify input or use an authorized route. Attempt
counts are shown only at issuance where the configured count is known. The port contract's
`write_secret_block` must display the entire block or raise without retaining a partial block. This is a tested
contract for a synthetic channel, not a claim about a production terminal implementation.

Input uses the port's `read_secret_no_echo`; there is no command-line argument, URL, query string, or ordinary
stdout/stderr secret path. The test proves only that the injected channel does not echo. A production adapter
must separately prove OS-specific terminal mode restoration, signal handling, accessibility, and no-echo.

For a NAS, SSH host, or container, the operator attaches a private interactive terminal to the same MyCogni
installation and enters the opaque recovery code. They do not look up or type actor/profile IDs: the opaque
handle indexes the local record and all bindings come from state. Secrets must not be passed through `docker
exec` arguments, environment variables, shell history, remote logging, or a recording session. A non-TTY is
refused before issuance or recovery.

If bootstrap-code output is interrupted, the undisclosed bootstrap is burned and the same unconsumed root can
retry. Bootstrap exchange is a separate confirmed ceremony: it consumes the code/root, then hands off the new
session and recovery (and a rotated reprovision root when applicable) in one all-or-nothing block. If this
handoff fails, the in-process result may be redisplayed without replaying bootstrap. Recovery uses the same
interrupted-display pattern. These are process-memory-only behaviors; a crash after consume but before handoff
loses replacements and fails closed. Successful recovery explicitly tells the operator that old sessions and
old recovery codes were revoked.

The committed [redacted transcript](./SPIKE-AUTH-TRANSCRIPT.txt) is generated by an executable test using the
real entrypoint helpers. The harness covers warning/confirmation, bootstrap display, confirmed session/recovery
handoff, wrong/correct/replayed step-up, no-echo recovery, replacement display, old-session invalidation,
non-TTY refusal, exact credential redaction, and empty actual stdout/stderr. The later recovery input is parsed
from the completed operator handoff, not read from an in-memory `BootstrapExchange`. The artifact contains no
retained deterministic credential value.

## Consume, crash, clock, and collection model

The volatile adapter serializes decisions with a process-local `RLock`. Concurrent consumption yields exactly
one success. Attempt exhaustion and expiry retire one-use records. Synthetic crash points after bootstrap,
step-up, and recovery consumption prove retry cannot reuse burned authority within the same process.

Every policy read uses an injected aware-UTC clock. Early use, forward expiry, and time earlier than the
actor's last observed instant deny as `not_yet_valid`, `expired`, and `clock_rollback`. This is not a trusted
monotonic clock across reboot or host compromise. Garbage collection accepts only a 0–86,400 second retention
window and removes expired or explicitly retired volatile roots, bootstraps, sessions, recoveries, and step-ups.
Grant provenance uses the later live replay horizon instead: expiry plus retention.

The adapter has no transaction log and loses authority and consume history on restart. Production `AUTH-001`
needs persistent compare-and-swap/transaction evidence at every crash boundary, key protection, backup/restore
epoch rules, and multi-process tests.

## Adversarial evidence

Focused regressions cover:

- exact-three/unique initial roots and forged/wrong-installation/wrong-actor/wrong-profile/wrong-purpose/stale
  root capabilities;
- first bootstrap, authenticated rebootstrap, bounded attempts/expiry, concurrency, and crash consumption;
- exact typed step-up binding, immutable store provenance, every-field alteration, no-provenance failure modes,
  concurrent one-use, replay-horizon GC, session rotation, and malformed enum inputs;
- two sibling bootstraps followed by atomic all-recovery consumption and all-session invalidation;
- six-month recovery, authenticated renewal, two expiry/reprovision cycles, rotated reprovision handoff, and
  explicit non-recovery claims;
- authenticated versus emergency all-session revocation and their distinct replacement policies;
- canonical store-side recovery binding, immutable adapter boundaries, structural digest-only state, constant-
  time comparison, and exact mutable-state validation;
- confirmation refusal before offline consume, non-TTY refusal, interrupted bootstrap handoff/recovery
  redisplay, unknown/retired guidance, bounded GC, redacted traceback/rendering, no URL/argv path, typed
  diagnostics, and the executable transcript.

These tests are spike evidence, not canonical `VFY-AUTH-001`. That verification remains `PLANNED` until
governance acceptance and independent review authorize an exact criterion/evidence mapping.

## Accessibility, exclusions, and residual risk

TTY-only display is an experiment, not the final accessible ceremony. Production must support keyboard-only
completion, non-color errors, high contrast/zoom, screen-reader labels, focus restoration, advance timeout
warning, and accessible restart/extension paths without weakening secret handling.

This spike adds no database migration, cookie, CSRF, Host/Origin or clickjacking middleware, WebAuthn, OIDC,
password, email, SMS, network service, real person/PII, external I/O, dependency, or lockfile change. It does
not claim completion of `AUTH-001`, `AUTH-002`, or `AUTH-003`.

Residual risks remain material: restart destroys volatile state; a compromised host can capture live material,
the private channel, clock, or decision code; UUID handles route but do not prove authority; whole-flow timing
is uncharacterized; secure root storage and total-loss procedures are unresolved; durable/distributed/backup
behavior is absent; and browser/cloud protections are outside scope.

Rollback removes the auth domain/application modules, volatile adapter, trusted setup, spike entrypoint,
evidence tests, and transcript. Stopping the process discards every synthetic credential and record; that is a
limitation, not a security property.
