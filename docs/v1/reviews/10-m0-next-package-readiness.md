# M0 next-package readiness review

Review target: integration commit `f0e3535`.

Decision: `SPIKE-AUTH` is start-ready after the GOV remediation lane is integrated.
`SPIKE-RUNNER` mailbox/protocol work is start-ready after NET remediation, but its
real OCI-isolation disposition cannot be accepted until PF-002 produces real-engine
evidence. This is a Sol-labelled independent delivery review, not model attestation
or package acceptance.

## SPIKE-AUTH — core lane handoff

### Decision to earn

Prototype a local-lite root-of-trust ceremony that turns an explicit interactive
terminal action into:

1. a one-use, short-lived bootstrap exchange;
2. an opaque server-side browser session;
3. a session-, actor-, epoch- and purpose-bound one-use step-up; and
4. lost-session/headless recovery that revokes stale authority.

The result is a disposition ADR for the M1 design or a named blocker. It does not
implement or promote `AUTH-001`, `AUTH-002` or `AUTH-003`.

### Interfaces and ownership

- Reuse `OpaqueId` and the injected `Clock`; never read wall time inside policy.
- Add framework-free auth value/decision types and finite denial reasons.
- Add application ports for token generation, sessions, challenges and actor
  bootstrap/authenticate/rotate/revoke/step-up/recover operations.
- Generate high-entropy opaque material through an injected source, store only a
  digest and compare constant-time. Never place material in URLs, command arguments,
  logs, diagnostics, tracebacks, fixtures or shell history.
- Prefer a TTY-only one-use display followed by manual POST/code exchange. Recovery
  rotates the actor/session epoch and invalidates all earlier sessions by default.
- Likely ownership: `src/mycogni/domain/auth.py`, application handlers/ports, a
  clearly volatile in-memory spike adapter, a spike-only CLI entrypoint, focused
  domain/application/adversarial tests and `docs/v1/spikes/SPIKE-AUTH.md`.
- Root lockfile and machine governance records remain integration-owned.

### Required failure evidence

- replay, expiry, not-yet-valid, guessing/attempt exhaustion and timing-safe compare;
- session fixation, recovery/rotation invalidation and stale epoch;
- wrong actor/session/purpose, reuse and scope-widening step-up attempts;
- concurrent double consume and crash between consume and session issue;
- clock rollback/forward jump, lost browser state and all-session revocation;
- headless recovery, non-TTY refusal and query/referrer/history leakage;
- typed-diagnostic, stdout/stderr and traceback secret canaries;
- restart durability explicitly remains unproven until the M1 persistent adapter.

### Acceptance packet

- focused domain/application/adversarial suite on both supported Python versions;
- exact `VFY-AUTH-001`, criterion and evidence mapping after GOV is accepted;
- full `make check` and `make check-python-313` with import boundaries intact;
- redacted pseudo-TTY transcript covering success, replay, wrong purpose, recovery
  invalidation and non-TTY refusal;
- ADR fixing operator channel, timeouts, attempts, rotation/recovery, accessibility
  handoff and residual host-compromise risk;
- independent security/recovery review with no open P0/P1.

Rollback deletes volatile adapters and CLI wiring and invalidates all synthetic
session/challenge material. Decision and negative evidence remain. No migration,
real profile state or real account is permitted in the spike.

## SPIKE-RUNNER — boundary lane handoff

### Decision to earn

Prototype one statically predeclared, immutable-digest synthetic connector service
plus an action-scoped, one-time envelope/key/result/evidence mailbox. Resolve how a
dormant declared service receives one action without a Docker socket, core mount,
reusable credential or direct egress. The result refines the runner/mailbox ADR or
names a blocker.

### Interfaces and ownership

- The connector consumes only standalone `connector_protocol` types; it must not
  import `mycogni`.
- Independently bind selected image digest, connector release and capability to the
  action envelope; a manifest declaration is not verification.
- Mailbox states are `empty -> offered -> claimed_once -> result_committed`, with
  explicit expired/abandoned outcomes. Action/attempt/fence/epoch/digest/deadline/
  budget bindings are immutable; replay and cross-action access fail closed.
- Compare a tiny trusted mailbox sidecar with a core-owned push endpoint only if
  necessary, then choose one. Reject Docker socket, host paths, shared DB/vault,
  default network, reusable connector credential or direct egress.
- Reuse PF-002 hardening: non-root, read-only root, tmpfs, all capabilities dropped,
  no-new-privileges, no host network/PID/IPC, no ports/devices/privileged/host-gateway,
  exact environment allowlist and bounded PID/CPU/RAM/time.
- Likely ownership: `services/runner_mailbox/`, a synthetic connector artifact,
  spike-only Compose model, verification driver, boundary/failure/architecture
  tests and `docs/v1/spikes/SPIKE-RUNNER.md`.

### Required failure evidence

- mutable/wrong image, release/capability mismatch and stale fence/epoch/deadline;
- mailbox replay, double/concurrent claim and cross-action/connector access;
- oversized or digest-mismatched envelope/result/evidence;
- crash at every claim/upload/commit boundary, orphan cleanup and key disposal;
- environment, host/core/key/other-action mount and `/proc` disclosure attempts;
- writes outside tmpfs, privilege/capability escalation and resource exhaustion;
- default/host networking, DNS/private/loopback/metadata routes, published ports,
  devices, host PID/IPC and path traversal;
- PII/key canaries in logs/errors. Because there is no egress, a crash must never
  manufacture a transport or external outcome fact.

### Acceptance packet

- dual-runtime contract/failure and semantic Compose-mutation tests;
- one exact malicious-artifact test mapped to `VFY-RUNNER-001` after GOV acceptance;
- a real Linux Engine run recording immutable digest, effective Compose model,
  redacted image/container inspection, malicious-probe exit codes, resource kills,
  replay/cross-action denial and platform/architecture;
- artifact inspection proving connector contains the protocol package but not the
  trusted core, and core artifacts contain no connector implementation;
- full quality, safety, corrected NET and independent security/platform review.

Rollback removes the spike services, artifacts, networks, volumes and credentials,
then proves no envelope/key/evidence remained in volume, layer, log or host path.
Cleanup uncertainty is a blocker, not acceptance.

## Dependency disposition

No package beyond `CT-001` must precede the auth prototype. `DB-001` and
`SPIKE-KEY` should not be pulled into that decision.

Runner protocol/mailbox work can start after corrected NET-001. Real OCI isolation
acceptance also requires PF-002 real-engine evidence; until Docker is responsive,
the package may produce pure and semantic evidence but cannot be called complete.
SPIKE-EGRESS and SPIKE-BROWSER follow rather than precede the runner decision.
