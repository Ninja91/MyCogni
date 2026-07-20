# SPIKE-BROWSER — networkless synthetic Chromium boundary

Status: `IN_PROGRESS`. A native-arm64 Docker Desktop decision probe exists. It is
not a connector, live browser workflow, remover, accepted production image, or
`BROW-001` implementation.

## Exact supported invocation

`docker/Dockerfile.browser` packages only a locked Playwright runtime, two locked
npm packages, a fixed runner, and a synthetic fixture. The entrypoint has no
command or configuration surface. `deploy/compose.browser-smoke.yml` accepts only
an exact local image ID and supplies no environment, secret, volume, socket, host
path, port, DNS, proxy, host alias, credential, or destination.

The fixture carries the reserved descriptive name
`fixture.browser.mycogni.test`, but is served only by an invocation-owned
`127.0.0.1` listener. One exact request is admitted. Fetch, image, worker,
WebSocket, and second navigation probes are denied by CSP, the exact route policy,
or the absence of a listener. Public and reserved test-address TCP attempts have
no route under `network_mode: none`.

## Layered proof

The source verifier checks exact Dockerfile, package/lock, fixture hash, vendored
seccomp bytes, and normalized Compose policy. Mutation tests safely render altered
models; they never launch weakened containers. The live verifier requires an exact
local `sha256:` image ID, exact Git revision label/source bytes, native arm64,
effective Docker inspect values, exact JSON, bounded wall time, and exact cleanup.
Its diagnostics receive invocation-derived names and ownership labels before
launch; a deliberate client-timeout test proves the surviving container is found,
stopped, removed, and absent by both name and ID. This runtime evidence is not a
supply-chain attestation.

Inside the fixed run, CDP identifies the active renderer PID. The probe compares
`/proc` namespace links, root device/inode and image-sentinel visibility, capability
sets, `NoNewPrivs`, and `Seccomp_filters`. The browser process sees the outer root
and one outer seccomp filter; the renderer must have a distinct root, nested user,
PID and network namespaces, and an additional internal seccomp filter. Chromium's
default shared-memory bypass is removed so the private 256 MiB `/dev/shm` is used.
The outer browser, no-zygote-sandbox zygote, GPU, and utility roles must have all
five capability sets zero. Nested renderer active sets are zero. Exactly one of
two nested zygotes may hold permitted/effective `CAP_SYS_ADMIN` (`0x200000`) for
Chromium's internal chroot sandbox; both nested zygotes and the renderer have the
exact recorded namespace-scoped bounding mask. This exception requires nested
user/PID/network namespaces, a distinct chroot, and explicit observation of the
known shared mount namespace. Unknown roles and nonexact capability states fail
closed; the exception is not Docker `CapAdd` or host authority.

## Nonclaims and blockers

- The evidenced renderer shares the mount-namespace inode. Its distinct chroot is
  useful evidence, not equivalent to a distinct mount namespace.
- Docker Desktop arm64 is the only evidenced host/architecture. The locked base
  advertises amd64, but no amd64 build/runtime, native Linux, rootless/userns-remap,
  ECI, gVisor, Kata, or VM result is claimed.
- The container's upstream operating system, Node, browser, and libraries remain
  broad. A minimal release artifact, SBOM, signatures, provenance, CVE policy,
  update/revocation path, and published multi-architecture digest remain open.
- No egress gateway exists here. The future live design must replace `network none`
  with a separately accepted fenced gateway without exposing arbitrary egress.
- No real content, PII, credential, CAPTCHA, MFA, login, terms drift, submission,
  receipt, removal, verification, evidence capture, or unknown-outcome recovery is
  implemented.
- Exact SIGTERM timing, zombie/reaping observation, and malicious-process-tree
  termination remain a P1 runtime blocker; `init: true`, PID limits, the internal
  deadline, and host timeout are present but are not a substitute for that test.
- `BROW-001`, connector trust, gateway, malicious-content qualification, durable
  cleanup/recovery, and qualified independent review remain blockers.

See ADR-0015 and `docs/v1/SPIKE-BROWSER-OCI-EVIDENCE.md`.
