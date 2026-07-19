# ADR-0008: Connector artifacts and egress enforcement

- Status: Accepted for initial build
- Date: 2026-07-15
- Refines: ADR-0003

## Context

A subprocess inside the core container inherits too much authority. Domain allowlists do not prevent DNS rebinding, redirect, alternative protocols, service workers, or exfiltration to an allowed destination. Connectors handle hostile content and selected PII, so their runtime and network policy must be separate enforcement points.

## Decision

Package every connector release as a separate digest-pinned OCI or constrained WASI artifact. The core never imports connector code or includes connector runtimes in its image. An action runs rootless/non-root with a read-only root filesystem, tmpfs workspace, dropped Linux capabilities, `no-new-privileges`, syscall policy, PID/CPU/RAM/time bounds, and no core/host volumes, Docker socket, host network, reusable credentials, or unrelated session state.

Force connector/browser egress through a mandatory fail-closed transport gateway. A gateway-owned declarative HTTP client or trusted mailer originates the exact typed request/message. For opaque browser TLS, the gateway validates the online action token, installation dispatch epoch/fence, authorization epoch, global/profile/broker pause, connector digest/capability, origin, resolved public IP, port, protocol, new redirect connections, and byte/time budget; it cannot inspect encrypted method, path, body, or response semantics. Private, loopback, link-local, metadata, rebinding, proxy bypass, WebSocket, QUIC, DoH, downloads, and undeclared destinations are denied by default.

Browser automation uses a project-owned image, dedicated non-root user, verified Chromium sandbox, private shared memory, pinned seccomp and ephemeral storage without host IPC or `SYS_ADMIN`. Local shared-kernel and allowed-origin exfiltration limits remain documented.

## Consequences

- Connector development/build/promotion becomes more complex.
- A local runtime may not provide the same isolation strength as a cloud sandbox.
- The gateway becomes security-critical and highly tested.
- An allowed broker can still misuse legitimately disclosed data, and a malicious browser connector can misuse its minimum bundle inside an allowed origin; the ledger remains necessary.

## Alternatives

In-process plugins and core-image subprocesses were rejected. DNS/domain allowlists alone were rejected. A centralized remote connector service was rejected for custody and single-tenant scope.

## Security and privacy impact

Compromise is limited to one action bundle, runtime, destination policy, and bounded evidence. It does not eliminate kernel exploits or destination misuse.

## Review trigger

New runtime type, native connector code, browser image change, egress policy/proxy change, remote execution, kernel escape, or connector incident.
