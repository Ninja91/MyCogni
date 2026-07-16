# PF-002 build evidence — 2026-07-15

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
