# PF-002 build evidence — 2026-07-15, reproduced 2026-07-18

## Tooling

- Docker client: 29.6.1 (darwin/arm64)
- Docker Buildx: v0.35.0-desktop.2
- Builder: `desktop-linux`, Docker driver

## Immutable input resolution

Both official indexes were resolved with `docker buildx imagetools inspect`.
Their index and linux/amd64 plus linux/arm64 manifests are recorded in
`docker/images.lock.json`. This proves the selected immutable upstream inputs
exist for both target architectures; it does not prove the MyCogni image built.

## Multi-platform build attempt

Command:

```console
docker buildx bake --allow=fs.write=/private/tmp --progress=plain \
  --set core.output=type=oci,dest=/tmp/mycogni-core-pf002.oci.tar core
```

Result: **BLOCKED — no OCI archive was produced and neither architecture is
claimed built.** Buildx resolved the pinned uv image for amd64 and arm64, then
Docker Desktop's configured registry proxy timed out while fetching blobs for
the pinned official Python index on both platforms:

```text
proxyconnect tcp: dial tcp 192.168.65.1:3128: i/o timeout
failed to resolve source metadata for
docker.io/library/python@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
```

The acceptance evidence still required is a successful two-platform build log,
OCI index inspection showing linux/amd64 and linux/arm64, and a non-root,
read-only, networkless smoke run for each runnable local architecture. This
document must be updated or superseded when that evidence exists.

## Hardening recheck

After narrowing the build context to an explicit deny-all allowlist, this
daemon-side validation completed successfully for `linux/amd64`:

```console
docker buildx build --check --platform linux/amd64 --file docker/Dockerfile .
```

The static validator and full repository suite also prove that the root project
metadata, trusted-core source and connector-SDK workspace metadata/source needed
for the locked resolution remain in the context. A subsequent native
`linux/arm64 --load` build stalled while connecting to Docker Desktop's daemon
socket and was terminated; it produced no image or runtime-smoke evidence.
Therefore the status remains **IN PROGRESS**, and no architecture is claimed
built by this recheck.

After correcting the virtual-environment path so console-script shebangs are
not relocated, the static validator and mutation suite passed. A new Buildx
`--check` attempt again stalled while connecting to Docker Desktop's daemon
socket and was terminated. The Dockerfile now makes the eventual build fail
unless the generated Uvicorn and Alembic scripts name the final interpreter
path and both scripts execute successfully, but that build/runtime evidence is
still pending. No architecture is claimed built.

## Successful two-platform reproduction — 2026-07-18 PT

Docker Desktop was restarted from the installed application after a stale
backend launched from the mounted installer had stopped answering Docker API
requests. The installed CLI and credential-helper directory was supplied
explicitly because the host still had a dangling helper link into the detached
installer. This host repair is environmental evidence, not a source change.

The following pinned build then completed successfully:

```console
env PATH=/Applications/Docker.app/Contents/Resources/bin:/usr/local/bin:/usr/bin:/bin \
  docker buildx bake --allow=fs.write=/private/tmp --progress=plain \
  --set core.output=type=oci,dest=/private/tmp/mycogni-core-pf002.oci.tar core
```

Build evidence:

- Docker Desktop `4.82.0`, engine/client `29.6.1`, Buildx
  `v0.35.0-desktop.2`, BuildKit `v0.31.1`;
- both pinned Python and uv inputs resolved for `linux/amd64` and
  `linux/arm64`;
- frozen `uv sync` completed for both platforms;
- both builds executed the Uvicorn `0.51.0`, Alembic `1.18.5` and final-path
  shebang checks under CPython `3.12.12`;
- OCI index digest
  `sha256:816ace6f26acdacf1a1965c4739967b4cf535779345f6598b77cef42038e8a95`;
- ephemeral OCI archive SHA-256
  `d1699dde7486a64ff0448a4dbba871ba510805f7cb0b6c8233f8a5714f468cae`;
- linux/amd64 manifest
  `sha256:35f1263ec98a739aefead8d18ef108da4e3a0b74892c17f8db1b3e70265b6a77`;
- linux/arm64 manifest
  `sha256:0ce1a879a124510d3c0a6b024a371f39b53603782a214b65475bb4577a27e08a`.

The loaded index reported `USER 65532:65532`. Each platform then passed the
same runtime command with `--network none`, `--read-only`, `--cap-drop ALL`,
`--security-opt no-new-privileges:true` and a finite, non-executable tmpfs at
`/tmp/mycogni`. The probe asserted UID `65532`, zero effective capabilities,
`NoNewPrivs: 1`, no IPv4 route, a failed network connection probe, and no write
access to `/opt/mycogni` or `/var/lib/mycogni`. The initial smoke observed only
loopback; an independent rerun also observed inert tunnel interfaces, so
interface count is deliberately not a networkless acceptance criterion. Both
platforms emitted:

```text
Running uvicorn 0.51.0 with CPython 3.12.12 on Linux
alembic 1.18.5
PF-002 linux/<architecture> hardened smoke passed
```

The arm64 smoke was native to this Apple Silicon host. The amd64 smoke used
Docker Desktop's advertised emulation support; it is real Linux-engine runtime
evidence, not an independent physical x86 host result. PF-002's build/runtime
acceptance evidence is now present. Canonical package status remains
`IN_PROGRESS` because GOV-001 intentionally forbids `COMPLETE` without an
externally rooted authenticated semantic-review attestation.

The archive is retained only as a local `/private/tmp` reproduction artifact;
the digest makes this run self-identifying but is not durable CI storage. The
loaded image labels also used the bake default `revision=unknown`. The embedded
unsigned BuildKit provenance binds both manifests to source revision `a9f11e8`,
but has an empty builder identity and incomplete request/dependency capture.
It is corroborating local evidence, not signed provenance or a GOV-001 trust
root. A later release workflow must retain the full log/archive as a durable CI
artifact and pass the exact VCS revision into the image label.

The independent review also found that hardening the copied virtual environment
in a separate runtime `RUN` layer duplicated roughly 29 MB of compressed data
per platform. The Dockerfile now applies ownership and read-only permissions in
the build stage before `COPY`; the next reproduction must confirm the optimized
layout without weakening runtime permissions.
