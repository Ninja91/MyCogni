# ADR-0008: Connector artifacts and egress enforcement

- Status: Accepted for initial build
- Date: 2026-07-15
- Refines: ADR-0003

## Context

A subprocess inside the core container inherits too much authority. Domain allowlists do not prevent DNS rebinding, redirect, alternative protocols, service workers, or exfiltration to an allowed destination. Connectors handle hostile content and selected PII, so their runtime and network policy must be separate enforcement points.

## Decision

Package every connector release as a separate digest-pinned OCI or constrained WASI artifact. The core never imports connector code or includes connector runtimes in its image. An action runs rootless/non-root with a read-only root filesystem, tmpfs workspace, dropped Linux capabilities, `no-new-privileges`, syscall policy, PID/CPU/RAM/time bounds, and no core/host volumes, Docker socket, host network, reusable credentials, or unrelated session state.

Force connector/browser egress through a mandatory gateway. Before the first byte and every redirect/connection, it validates action token, monotonic fence, authorization epoch, global/profile/broker pause, connector digest/capability, method, origin, resolved public IP, protocol, disclosure plan, and byte/time budget. Private, loopback, link-local, metadata, rebinding, WebSocket, QUIC, DoH, downloads, and undeclared destinations are denied by default.

Browser automation uses a dedicated user with the Chromium sandbox enabled and ephemeral storage. Higher-assurance cloud deployment may require gVisor, Kata, or VM isolation. Local shared-kernel limits remain documented.

## Consequences

- Connector development/build/promotion becomes more complex.
- A local runtime may not provide the same isolation strength as a cloud sandbox.
- The gateway becomes security-critical and highly tested.
- An allowed broker can still misuse legitimately disclosed data; the ledger remains necessary.

## Alternatives

In-process plugins and core-image subprocesses were rejected. DNS/domain allowlists alone were rejected. A centralized remote connector service was rejected for custody and single-tenant scope.

## Security and privacy impact

Compromise is limited to one action bundle, runtime, destination policy, and bounded evidence. It does not eliminate kernel exploits or destination misuse.

## Review trigger

New runtime type, native connector code, browser image change, egress policy/proxy change, remote execution, kernel escape, or connector incident.
