# SPIKE-RUNNER persistent-state and OCI evidence — 2026-07-19

## Scope and current truth

`PersistentMailboxRepository` is a POSIX local-lite adapter for the existing
finite mailbox state machine. `docker/Dockerfile.runner-mailbox` builds a real,
separate synthetic mailbox artifact: it installs the connector contract and
runner-mailbox runtime anchor, copies `services/runner_mailbox`, and build-time
asserts the trusted `mycogni` application package is absent. The executable is
only a fixed-input containment probe. It accepts no action or credential input.

This does **not** close the untrusted connector gap. There is still no accepted
connector artifact, credential-delivery channel, egress gateway topology,
signed publication, or live-broker capability.

## Executable state evidence

The adapter persists one bounded canonical JSON v1 frame under AES-GCM in a
SQLite `BEGIN IMMEDIATE` transaction. Tests cover restart across every retained
state, independent-process one-claim serialization, process loss immediately
before and after commit, ciphertext canaries, epoch substitution, fork refusal,
pre-open hardlink rejection without mutation, unchanged-denial no-write,
finite non-poisoning contention, post-commit poison/idempotent close, maximum
frame rejection and finite generation/key-rotation exhaustion.

Both locked Python 3.12.12 and 3.13.11 lanes reported:

```text
ruff: all checks passed
mypy: success, 8 source files
runner + containment + connector SDK + safety guard: 884 passed
  persistent adapter: 15 passed
  rendered/Dockerfile containment mutations: 26 passed
```

The canonical governance report was regenerated. Governance, architecture
claim and site guards passed; the focused governance/claim/site/safety suite
reported 71 passed.

## Exact local Docker evidence

Docker Desktop 4.82.0 / Engine 29.6.1 on native linux/arm64 built implementation
commit `ef379f924962a83dbee2ecd0ebd91722eb1f3368` as exact local image ID:

```text
sha256:143d871681ab395f1a658c245a0a3af5f1847f6bf6642ce7b4094f93702f4550
```

The image revision label exactly matched that implementation commit. The
machine runtime verifier reported UID 65532, schema 1, mailbox state created,
`recovery_required=false`, and denied DNS, host-gateway IPv4, metadata IPv4,
public IPv4, public IPv6 (`2606:4700:4700::1111`) and ULA IPv6
(`fd00:ec2::254`).

Container inspect matched the exact image ID and image-owned entrypoint/env,
with no Compose environment injection; non-root user; read-only root;
network-none; private IPC/cgroup and Engine-default private PID namespaces;
drop-all capabilities; no-new-privileges; active seccomp sentinel; 64 PIDs,
1 CPU and 512 MiB limits; no restart; only the runner state volume and bounded
noexec/nosuid/nodev tmpfs. The verifier removed the container and volume and
asserted that neither remained. This is local unsigned evidence, not a published
artifact digest or multi-architecture connector acceptance.

## Reproduction

```text
uv run --all-packages --frozen --python 3.12.12 ruff check .
uv run --all-packages --frozen --python 3.12.12 mypy -p services.runner_mailbox -p mycogni_runner_mailbox_runtime
uv run --all-packages --frozen --python 3.12.12 python scripts/ci/guarded_pytest.py tests/runner_mailbox tests/architecture/test_runner_containment.py
uv run --all-packages --frozen --python 3.13.11 ruff check .
uv run --all-packages --frozen --python 3.13.11 mypy -p services.runner_mailbox -p mycogni_runner_mailbox_runtime
uv run --all-packages --frozen --python 3.13.11 python scripts/ci/guarded_pytest.py tests/runner_mailbox tests/architecture/test_runner_containment.py
uv run --all-packages --frozen --python 3.13.11 python scripts/verify_runner_containment.py

docker buildx build --platform linux/arm64 --load \
  --tag mycogni/runner-mailbox:local \
  --build-arg VCS_REF=<exact-implementation-commit> \
  --build-arg BUILD_CREATED=<UTC-RFC3339> \
  --file docker/Dockerfile.runner-mailbox .
docker image inspect mycogni/runner-mailbox:local --format '{{.Id}}'
python3 scripts/verify_runner_containment_runtime.py \
  --image sha256:<exact-local-image-id> \
  --revision <exact-implementation-commit>
```

The runtime verifier refuses tags and dirty pre-existing smoke state. It checks
the image revision label, entrypoint, absence of Compose environment injection,
UID, read-only root, network/IPC/PID/cgroup isolation, capabilities, security
options, resource/restart policy, exact mounts, probe sentinel and exit status.
It then removes the container and named volume and proves both are absent.

## Nonclaims

Local Docker Desktop evidence is not multi-architecture publication, signature,
SBOM/provenance, manifest freshness, rootless/user-namespace conformance,
physical power-loss qualification, backup recovery, external rollback detection,
secure erasure, malicious connector cleanup, or connector OCI acceptance. Public
IPv6 and ULA IPv6 are separate probes; neither is described as link-local.
