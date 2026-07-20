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
SQLite `BEGIN IMMEDIATE` transaction. Tests cover restart of offered,
claimed-once, result-ready and acknowledged states; independent-process one-claim
serialization; process loss immediately before and after commit; ciphertext
canaries; epoch substitution; pre-lock fork refusal even with an inherited held lock;
pre-open hardlink rejection without mutation, unchanged-denial no-write,
finite non-poisoning contention, post-commit poison/idempotent close, maximum
frame/generation rejection; duplicate/noncanonical JSON; impossible authenticated
lifecycle/time/tombstone/quota state; and extreme-clock rollback/poison handling.

Both locked Python 3.12.12 and 3.13.11 lanes reported:

```text
ruff: all checks passed
mypy: success, 8 source files
runner + containment + connector SDK + safety guard: 901 passed
  persistent adapter: 23 passed
  rendered/Dockerfile/runtime containment mutations: 35 passed
```

The two intentional held-lock `fork()` regressions emit Python's expected
multithreaded-fork deprecation warning; both child processes refuse finitely
before the inherited lock and pass.

The canonical governance report was regenerated. Governance, architecture
claim and site guards passed; the focused governance/claim/site/safety suite
reported 71 passed.

## Exact local Docker evidence

Docker Desktop 4.82.0 / Engine 29.6.1 on native linux/arm64 built implementation
commit `4fcc4c98b1c703046c2a4d11ef1dd269fe52de5e` with
`BUILD_CREATED=2026-07-19T00:00:00Z` as exact local image ID:

```text
sha256:4b3d6f7ce8c3fa673d8a08b9bfd7d22a5e273879bf97e0553a2161e9e5e656fb
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
noexec/nosuid/nodev tmpfs. Runtime metadata reported the exact ten-distribution
allowlist and no `mycogni` core import. Exported filesystem inventory found only
runner mailbox Python sources below `services/` and byte-equal read-only
`LICENSE`/`NOTICE` files.

The invocation used random project
`mycogni-runner-39ce4e8550574be7a9a67a5c126c17b5` and captured its exact
container ID, generated volume name and Compose ownership labels. It removed
only those resources and proved both absent. A stopped trusted-core sibling
`f8ec482a08aba9bfc202682ac1e2ad791f846f46a8a86fca5ee1b11374cfa14d`
under project `deploy` retained the same ID/project/service labels through the
runner verification, and was then removed separately by its exact ID. This is
local unsigned evidence, not a published artifact digest or multi-architecture
connector acceptance.

## Reproduction

```text
uv run --all-packages --frozen --python 3.12.12 ruff check .
uv run --all-packages --frozen --python 3.12.12 mypy -p services.runner_mailbox -p mycogni_runner_mailbox_runtime
uv run --all-packages --frozen --python 3.12.12 python scripts/ci/guarded_pytest.py tests/runner_mailbox tests/architecture/test_runner_containment.py packages/mycogni-connector-sdk/tests tests/ci/test_safety_guard.py
uv run --all-packages --frozen --python 3.13.11 ruff check .
uv run --all-packages --frozen --python 3.13.11 mypy -p services.runner_mailbox -p mycogni_runner_mailbox_runtime
uv run --all-packages --frozen --python 3.13.11 python scripts/ci/guarded_pytest.py tests/runner_mailbox tests/architecture/test_runner_containment.py packages/mycogni-connector-sdk/tests tests/ci/test_safety_guard.py
uv run --all-packages --frozen --python 3.13.11 python scripts/verify_runner_containment.py
uv run --all-packages --frozen --python 3.13.11 python -m scripts.ci.governance_guard
uv run --all-packages --frozen --python 3.13.11 python scripts/ci/claim_guard.py
uv run --all-packages --frozen --python 3.13.11 python scripts/ci/site_guard.py
uv run --all-packages --frozen --python 3.13.11 python scripts/ci/guarded_pytest.py tests/ci/test_governance_traceability.py tests/ci/test_claim_guard.py tests/ci/test_site_guard.py tests/ci/test_safety_guard.py

docker buildx build --platform linux/arm64 --load \
  --tag mycogni/runner-mailbox:local \
  --build-arg VCS_REF=<exact-implementation-commit> \
  --build-arg BUILD_CREATED=2026-07-19T00:00:00Z \
  --file docker/Dockerfile.runner-mailbox .
docker image inspect mycogni/runner-mailbox:local --format '{{.Id}}'
python3 scripts/verify_runner_containment_runtime.py \
  --image sha256:<exact-local-image-id> \
  --revision <exact-implementation-commit>
```

The runtime verifier refuses tags and generates a random project name per invocation. It checks
the image revision label, entrypoint, absence of Compose environment injection,
UID, read-only root, network/IPC/PID/cgroup isolation, capabilities, security
options, resource/restart policy, exact mounts, installed-distribution inventory,
exported filesystem, Apache license/notice, probe sentinel and exit status. It
validates exact Compose ownership labels, removes only that invocation's exact
container ID and volume name, and proves both are absent without project-wide
`down` or orphan cleanup.

## Nonclaims

Local Docker Desktop evidence is not multi-architecture publication, signature,
SBOM/provenance, manifest freshness, rootless/user-namespace conformance,
physical power-loss qualification, backup recovery, external rollback detection,
secure erasure, malicious connector cleanup, or connector OCI acceptance. Public
IPv6 and ULA IPv6 are separate probes; neither is described as link-local.
