# ADR-0015: Networkless synthetic Chromium sandbox decision spike

- Status: Accepted for initial build
- Date: 2026-07-20

This decision is not acceptance for live navigation, a connector, `BROW-001`,
or production isolation.

## Context

Browser automation eventually handles hostile content, but the current project
has no accepted egress gateway, connector, scoped credential delivery, drift or
challenge policy, journal, or live-broker authority. The M0 question is narrower:
can a project-owned Playwright/Chromium artifact execute one immutable synthetic
fixture while Docker enforces a finite local boundary and Chromium's own renderer
sandbox remains active?

Playwright's upstream guidance recommends a non-root user and a seccomp profile,
but also suggests host IPC for reliability and `SYS_ADMIN` for local debugging.
Those options violate MyCogni's boundary. Its published image is explicitly a
testing/development image, so pinning that image cannot by itself establish a
production sandbox.

## Decision

The spike derives a project-owned image from the exact Playwright 1.61.1 Noble
multi-architecture index. The supported invocation is fixed: it accepts no
arguments, environment configuration, credentials, URL, mounts, or broker data.
It serves one byte-pinned checked-in HTML fixture on an invocation-owned dynamic
`127.0.0.1` port, admits only that exact request, and destroys the browser context.

The Compose boundary requires:

- UID/GID 65532, read-only root, no volumes or host paths;
- `network_mode: none`, private IPC and cgroup namespaces, no host IPC;
- all capabilities dropped, no added capability, no `SYS_ADMIN`, and
  `no-new-privileges`;
- the byte-pinned project seccomp profile with default deny;
- a private 256 MiB `/dev/shm`, a 64 MiB no-exec temporary filesystem, one CPU,
  1 GiB RAM with no extra swap, 128 PIDs, bounded file descriptors/core dumps,
  bounded local logs, no restart, and an init process; and
- a fixed 20-second in-process deadline plus a separate host verifier timeout and
  invocation-owned cleanup. Each verifier diagnostic is named and ownership-
  labelled before launch so a client timeout cannot make it unreachable; final
  cleanup stops and removes all owned Compose and diagnostic containers.

The upstream seccomp profile is extended with only one unconditional `chroot`
syscall allowance. Outer UID 65532 and zero capability sets still cannot chroot,
mount, or write the image root. Chromium can chroot only after entering the
renderer user namespace, where the capability is scoped to that namespace.

Acceptance evidence must correlate the active renderer PID through CDP and prove:
renderer user/PID/network namespaces differ from the Node/browser process; its
root device/inode differs and cannot see the outer image sentinel; it has an
additional seccomp filter; no supported launch argument disables a sandbox; the
private shared-memory mount is used; and all outer capability sets are zero.

## Consequences and residual risk

The native-arm64 Docker Desktop probe demonstrates a useful layered boundary.
It does not make the browser safe for hostile or live sites. On the evidenced host,
the renderer shares the outer mount-namespace inode even though its chroot device/
inode is distinct. This remains a P1 residual before any enabled browser profile.
Docker Desktop without Enhanced Container Isolation is a shared-kernel VM boundary,
not native Linux, user-namespace-remapped Docker, gVisor, Kata, or a dedicated VM.
Exact SIGTERM/reaping and malicious child-tree termination are not yet evidenced
and remain a P1 blocker before any enabled profile.

`network_mode: none` removes non-loopback interfaces; it does not remove loopback.
The exact invocation intentionally uses one owned loopback fixture. Source policy,
route interception, and CSP deny other supported browser requests; they are defense
in depth, not a claim that arbitrary code inside the image cannot use loopback.

No screenshot, trace, download, persistent browser profile, credential, PII,
broker URL, gateway, submission, CAPTCHA/MFA/login handling, stealth feature,
outcome inference, or AI dependency is included. `BROW-001` remains `NOT_STARTED`.
The local runtime verifier is boundary evidence, not a signature, SBOM,
provenance record, or other supply-chain attestation.

## Alternatives rejected

- `--ipc=host`, `SYS_ADMIN`, privileged/root execution, or sandbox-disabling flags;
- treating the upstream development image or `Seccomp=2` alone as sandbox proof;
- file URLs, arbitrary caller URLs, remote fixtures, or live broker traffic; and
- promoting the spike based on source inspection without effective-container and
  renderer-process evidence.

## Review trigger

Re-review is mandatory for any image/browser/seccomp digest change, runtime or
architecture claim, network/gateway addition, argument/environment input, mount,
credential, download/artifact path, browser flag, challenge behavior, or attempt
to move `SPIKE-BROWSER` beyond `IN_PROGRESS`.
