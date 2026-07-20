# SPIKE-BROWSER OCI evidence

Status: exact native-arm64 Docker Desktop decision evidence exists. Canonical
package status remains `IN_PROGRESS`; independent review and all enabled/live
browser gates remain open.

## Evidence contract

The record names the exact Git commit, image ID/config, host/runtime,
static and mutation tests, effective Docker inspect values, exact renderer JSON,
negative outer-boundary probes, and invocation-owned cleanup.

## Exact source and image

- source commit: `d656c08a62080598f8b6676b9b9435c0d7169667`;
- local native-arm64 image ID/manifest:
  `sha256:6e443f187b621c378861813a2400571d7e2cd14e9f37c99b8b2f74a567c5c2ba`;
- build-reported config digest:
  `sha256:5c553cd7c6a4411120b844f274fc48ff80c7ed3e3ef9916bd890b737c42b2b56`;
- image size: 942,493,198 bytes;
- base index: Playwright 1.61.1 Noble
  `sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48`;
- selected arm64 base manifest:
  `sha256:824f1a789072e648c62541c2cfa4479c4061a290d5c27766d67dc1dcbc19b321`;
- image labels bind the exact source revision, Apache-2.0 project-source label,
  `0.0.0` version and fixed OCI label time `2026-07-20T00:00:00Z`.

The image's generated `Created` timestamp was not normalized. Reproducible image,
archive/index bytes and release attestations are explicit nonclaims.

The final no-cache build used Buildx with provenance/SBOM attestations disabled
for this local decision image. That does not waive `REL-001`; release artifacts
must add reviewed SBOM, provenance, signatures and notices as separate outputs.

## Host and effective container

- macOS host through Docker Desktop 4.82.0 (233772);
- Docker client/server 29.6.1;
- Linux arm64 container architecture;
- exact image ID with pull disabled;
- UID/GID 65532, immutable root, zero mounts/binds, network none, private IPC and
  cgroup namespaces, Engine-private PID namespace, all capabilities dropped,
  no-new-privileges and the exact inlined project seccomp profile;
- one CPU, 1 GiB memory and equal memory/swap ceiling, 128 PIDs, 256 MiB private
  shared memory, 64 MiB no-exec temporary filesystem, core limit zero, file
  descriptor limit 1024, no restart, and a one-file/1 MiB uncompressed local log;
- no injected command, environment, secret, port, host alias, DNS, proxy, volume,
  socket, credential or destination.

The verifier compared all four image-owned browser-spike source hashes to raw
`git --no-replace-objects cat-file` bytes from the exact commit. The application
root contains only `node_modules`, `package.json`, `package-lock.json`, `run.mjs`
and `synthetic.html`. Safe diagnostic containers under the same boundary proved
outer non-root chroot and mount fail, the image root cannot be written, and only
the bounded temporary path is writable.

## Renderer and network result

Three invocations of the exact runtime verifier passed, including an independent
root-orchestrator reproduction after the implementation-owner runs. Each required:

- one exact owned loopback fixture request and denials for fetch, image, worker,
  WebSocket and alternate navigation attempts;
- TCP denial for undeclared IPv4/IPv6 loopback, TEST-NET addresses, public DNS,
  link-local metadata and Docker Desktop host-gateway addresses;
- DNS denial for reserved synthetic names;
- CDP-correlated renderer process evidence with UID 65532, all outer capability
  sets zero, `NoNewPrivs=1`, and seccomp mode 2;
- browser outer seccomp filter count 1 and renderer count 2;
- renderer user, PID and network namespaces distinct from the Node/browser
  process; mount namespace shared;
- renderer root at a distinct device/inode and the outer
  `/opt/mycogni-browser/synthetic.html` sentinel absent from that root;
- Chromium sandbox requested, no supported sandbox-disabling launch flag, and
  Playwright's `--disable-dev-shm-usage` default removed;
- exact cgroup-v2 values, zero screenshot/trace/download artifact path, cleanup
  of the one known Chromium cache directory, exit 0, no OOM, and exact removal of
  the invocation-owned container.

The runtime verifier has a 30-second host timeout and the payload has a fixed
20-second deadline. A prior full-Chromium diagnostic hung until manually stopped;
the accepted exact target uses the bounded Chromium headless-shell path. Exact
SIGTERM timing, zombie/reaping observation and malicious child-tree termination
remain an explicit P1 blocker, not accepted evidence.

Required commands:

```console
python scripts/verify_browser_containment.py
python scripts/ci/guarded_pytest.py -q tests/architecture/test_browser_containment.py
python scripts/verify_browser_containment_runtime.py \
  --image sha256:6e443f187b621c378861813a2400571d7e2cd14e9f37c99b8b2f74a567c5c2ba \
  --revision d656c08a62080598f8b6676b9b9435c0d7169667
```

## Current fail-closed boundary

Only native arm64 Docker Desktop is recorded by this slice. amd64, native
Linux, rootless/userns-remapped Docker, ECI, gVisor, Kata, a published OCI index,
bit reproducibility, signatures, SBOM/provenance, live navigation, gateway and
connector behavior are untested or out of scope. Shared renderer mount namespace
is an explicit P1 residual before an enabled browser profile.
