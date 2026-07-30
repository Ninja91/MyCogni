# PF-002 container skeleton

This directory contains the first repeatable core-image build boundary. It is a
packaging skeleton, not a production release: the default command only proves
that the locked application distribution imports successfully. Role-aware
entrypoints, health contracts, signing, SBOM/provenance publication and runtime
conformance remain later work packages.

## Immutable inputs

`images.lock.json` records the OCI index and architecture manifest digests
observed through 2026-07-20 for the official Python 3.12.12 slim-bookworm,
Astral uv 0.9.26, and Playwright 1.61.1 Noble images. The Dockerfiles consume the index digests, so BuildKit selects
the matching immutable amd64 or arm64 manifest. The inventory records the exact
retrieval commands and official upstream sources.

Refreshes are reviewed changes: inspect the official tag, verify provenance,
update both the index and per-platform manifests, run the static validator, and
record build evidence. A moving tag must never replace a digest in the
Dockerfile.

## Build and validate

Static validation does not require a daemon:

```console
python3 scripts/verify_container_skeleton.py
```

The validator parses executable Dockerfile instructions (comments are not
evidence), renders Compose's canonical JSON model without contacting a daemon,
and verifies the deny-all build-context allowlist. The runtime installation
under `/opt/mycogni` is root-owned and immutable; only `/var/lib/mycogni` and
the dedicated `/tmp/mycogni` tmpfs are writable by UID/GID 65532.
The virtual environment is created at its final absolute
`/opt/mycogni/.venv` path in the build stage so generated console-script
shebangs remain valid after the same path is copied into the runtime stage.
Build and runtime smoke intent executes both `uvicorn --version` and
`alembic --version`; an import-only check cannot hide a broken shebang.

Build the two-platform OCI result with Buildx:

```console
docker buildx bake --allow=fs.write=/private/tmp \
  --set core.output=type=oci,dest=/tmp/mycogni-core.oci.tar core
```

For a local architecture smoke test, load one platform and apply the explicitly
networkless, read-only runtime profile:

```console
docker buildx build --platform linux/arm64 --load \
  --tag mycogni/core:0.0.0 --file docker/Dockerfile .
docker compose --file deploy/compose.container-smoke.yml run --rm mycogni-core-smoke
```

The smoke profile grants no connector execution authority: it has no network,
host mount, Docker socket, added capability or privileged mode. The future
supported deployment profiles will separately declare only the volumes and
network paths required by their role and must keep connectors isolated.

### One-shot synthetic preview

The separate `deploy/compose.synthetic-preview.yml` profile runs the installed
`mycogni synthetic init`, `health`, and `demo` commands as UID/GID 65532. It
uses a read-only root filesystem, bounded tmpfs, drop-all capabilities,
no-new-privileges, private cgroup namespace, `network_mode: none`, and one named
volume for synthetic state. It has no host bind mount or Docker socket, and its
`pull_policy: never` prevents an absent local image from being replaced by a
registry pull.

```console
python3 scripts/verify_synthetic_container.py
docker buildx build --load --tag mycogni/core:0.0.0 \
  --build-arg VCS_REF="$(git rev-parse HEAD)" --file docker/Dockerfile .
python3 scripts/verify_synthetic_container_runtime.py
docker compose --file deploy/compose.synthetic-preview.yml down --volumes
```

This is a synthetic developer preview only: it accepts no real PII and has no
broker, connector, submission, verification, or real-removal capability.
Source-level CLI composition does not prove containment. Static validation
proves only the checked files; Docker runtime containment evidence is limited
to the exact inspected image, Compose profile, engine, and host on which that
inspection ran.
The named volume preserves only synthetic preview state across repeated runs.
The final command above removes the profile's containers, network metadata, and
volume for a clean reset.

## Current proof boundary

PF-002 may claim a pinned two-architecture build skeleton only after static
validation. It may claim an architecture was built only when a corresponding
Buildx log and image inspection were recorded. Bit-for-bit reproducibility,
published multi-platform artifacts, signatures, SBOMs and provenance are not
claimed here. The dated [PF-002 build evidence](../docs/v1/PF-002-BUILD-EVIDENCE.md)
records the current attempt and any unresolved environmental blocker.

`Dockerfile.browser`, `seccomp.browser.json`, and
`deploy/compose.browser-smoke.yml` are a separate networkless synthetic-only
decision artifact governed by ADR-0015. They do not extend PF-002 acceptance,
package a connector, or authorize live navigation. See
`browser-spike/THIRD_PARTY.md` for upstream provenance and license boundaries.
