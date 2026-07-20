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
lifecycle/time/tombstone/quota state; writer-byte rejection of alternate datetime
and base64 spellings plus record/evidence/tombstone order; acknowledged
commit-after-terminal rejection; and extreme-clock rollback/poison handling.

Both locked Python 3.12.12 and 3.13.11 lanes reported:

```text
ruff: all checks passed
mypy: success, 8 source files
runner + containment + connector SDK + safety guard: 923 passed
  persistent adapter: 30 passed
  rendered/Dockerfile/context/runtime containment mutations: 50 passed
```

The two intentional held-lock `fork()` regressions emit Python's expected
multithreaded-fork deprecation warning; both child processes refuse finitely
before the inherited lock and pass.

The canonical governance report was regenerated. Governance, architecture
claim and site guards passed; the focused governance/claim/site/safety suite
reported 71 passed.

## Exact local Docker evidence

Docker Desktop 4.82.0 / Engine 29.6.1 on native linux/arm64 built implementation
commit `695ee0c29a49ad9494448fa19cda597f3ca7b318` three times from separate
`--no-cache` invocations: two independent clean contexts extracted from
`git archive` and the tracked-clean developer worktree containing 30 ignored
host `.pyc` files below `services/` and `packages/`. All builds used
`SOURCE_DATE_EPOCH=1784419200`, `BUILD_CREATED=2026-07-19T00:00:00Z`,
explicitly disabled SBOM/provenance attestations, and the Docker archive exporter
with `rewrite-timestamp=true`. All three BuildKit metadata files recorded the
same manifest/image digest:

```text
sha256:e58c2306645807605e363571a6dd76e2492c5dcceebe4442ba9f049657239343
```

All three recorded config digest
`sha256:15d6dd118a469d7f43700a3796cad9b8b24b466eb66d7d5691a0a51454529a38`.
The config records identical layer lists, config `Created` and OCI created
label `2026-07-19T00:00:00Z`, and revision label exactly matching the
implementation commit. `.dockerignore` permits exactly the six reviewed runner
Python sources and ends with global cache/bytecode exclusions after every
negation; the dirty-context parity proves host bytecode does not alter the
artifact. Dist-info identity/license metadata is retained for both
local packages; the build fails unless it finds exactly one nondeterministic
uv-cache file and matching `RECORD` row per local distribution, removes each
pair, and proves both are absent. Bytecode generation is disabled.

The OCI layers were independently reconstructed offline and passed the hardened
filesystem verifier against exact Git objects at the implementation revision.
It accepts only regular, byte-equal `LICENSE`/`NOTICE`, the six runner sources,
the five connector-contract files and the three runtime-anchor files; it rejects
every other runner/local-package subtree and every `__pycache__`, `.pyc` or
`.pyo` under `/opt/mycogni-runner`.

The last live machine runtime result remains historical evidence for superseded
implementation `60925f1`: it reported UID 65532, schema 1, mailbox state created,
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

That historical source-bound invocation used random project
`mycogni-runner-0e2732007dad4c449d771c7a44e289a8` and captured its exact
container ID, generated volume name and Compose ownership labels. It removed
only those resources and proved both absent. A separate scoped-cleanup
reproduction retained a stopped trusted-core sibling
`f8ec482a08aba9bfc202682ac1e2ad791f846f46a8a86fca5ee1b11374cfa14d`
under project `deploy` retained the same ID/project/service labels through the
runner verification, and was then removed separately by its exact ID. This is
local unsigned evidence, not a published artifact digest or multi-architecture
connector acceptance.

The exact live Compose command for `e58c2306…` remains pending solely because
the Codex Docker-socket escalation was denied after the tool approval quota was
exhausted. No new live-runtime pass is claimed for `695ee0c` in this record.

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

clean_a="$(mktemp -d /private/tmp/mycogni-runner-r4-c1.XXXXXX)"
clean_b="$(mktemp -d /private/tmp/mycogni-runner-r4-c2.XXXXXX)"
git archive 695ee0c29a49ad9494448fa19cda597f3ca7b318 | tar -x -C "$clean_a"
git archive 695ee0c29a49ad9494448fa19cda597f3ca7b318 | tar -x -C "$clean_b"
test "$(find services packages -type f \( -name '*.pyc' -o -name '*.pyo' \) | wc -l | tr -d ' ')" -gt 0

docker buildx build --no-cache --platform linux/arm64 \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=1784419200 \
  --build-arg VCS_REF=695ee0c29a49ad9494448fa19cda597f3ca7b318 \
  --build-arg BUILD_CREATED=2026-07-19T00:00:00Z \
  --metadata-file /private/tmp/mycogni-runner-r4-c1.json \
  --output type=docker,dest=/private/tmp/mycogni-runner-r4-c1.tar,name=mycogni/runner-mailbox:r4-c1,rewrite-timestamp=true \
  --file docker/Dockerfile.runner-mailbox "$clean_a"
docker buildx build --no-cache --platform linux/arm64 \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=1784419200 \
  --build-arg VCS_REF=695ee0c29a49ad9494448fa19cda597f3ca7b318 \
  --build-arg BUILD_CREATED=2026-07-19T00:00:00Z \
  --metadata-file /private/tmp/mycogni-runner-r4-c2.json \
  --output type=docker,dest=/private/tmp/mycogni-runner-r4-c2.tar,name=mycogni/runner-mailbox:r4-c2,rewrite-timestamp=true \
  --file docker/Dockerfile.runner-mailbox "$clean_b"
docker buildx build --no-cache --platform linux/arm64 \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=1784419200 \
  --build-arg VCS_REF=695ee0c29a49ad9494448fa19cda597f3ca7b318 \
  --build-arg BUILD_CREATED=2026-07-19T00:00:00Z \
  --metadata-file /private/tmp/mycogni-runner-r4-dirty.json \
  --output type=docker,dest=/private/tmp/mycogni-runner-r4-dirty.tar,name=mycogni/runner-mailbox:r4-dirty,rewrite-timestamp=true \
  --file docker/Dockerfile.runner-mailbox .
jq -e --slurp 'map(.["containerimage.config.digest"]) | unique | length == 1' \
  /private/tmp/mycogni-runner-r4-c1.json /private/tmp/mycogni-runner-r4-c2.json /private/tmp/mycogni-runner-r4-dirty.json
jq -e --slurp 'map(.["containerimage.digest"]) | unique | length == 1' \
  /private/tmp/mycogni-runner-r4-c1.json /private/tmp/mycogni-runner-r4-c2.json /private/tmp/mycogni-runner-r4-dirty.json
jq '{"containerimage.config.digest": .["containerimage.config.digest"], "containerimage.digest": .["containerimage.digest"]}' \
  /private/tmp/mycogni-runner-r4-c1.json /private/tmp/mycogni-runner-r4-c2.json /private/tmp/mycogni-runner-r4-dirty.json
docker load --input /private/tmp/mycogni-runner-r4-c1.tar
docker load --input /private/tmp/mycogni-runner-r4-c2.tar
docker image inspect mycogni/runner-mailbox:r4-c1 mycogni/runner-mailbox:r4-c2 \
  --format '{{.Id}}|{{.Created}}|{{index .Config.Labels "org.opencontainers.image.created"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{json .RootFS.Layers}}'
# Pending: requires host Docker-socket approval after loading either equal image.
uv run --all-packages --frozen --python 3.13.11 python scripts/verify_runner_containment_runtime.py \
  --image sha256:e58c2306645807605e363571a6dd76e2492c5dcceebe4442ba9f049657239343 \
  --revision 695ee0c29a49ad9494448fa19cda597f3ca7b318
```

Direct `--load` is intentionally not used for this proof because BuildKit rejects
unpack together with `rewrite-timestamp=true`. The three archives have different
tag/index metadata and are not claimed byte-equal; their manifest and config
digests are equal. Attestations are disabled explicitly so
they cannot introduce a second manifest into this local image-identity proof;
signed release SBOM/provenance remains a separate acceptance requirement.

The runtime verifier refuses tags and generates a random project name per invocation. It checks
the image revision label, entrypoint, absence of Compose environment injection,
UID, read-only root, network/IPC/PID/cgroup isolation, capabilities, security
options, resource/restart policy, exact mounts, installed-distribution inventory,
exported filesystem, Apache license/notice, probe sentinel and exit status. It
validates exact Compose ownership labels, removes only that invocation's exact
container ID and volume name, and proves both are absent without project-wide
`down` or orphan cleanup.

## Nonclaims

Local Docker Desktop evidence demonstrates a repeatable native-arm64 image
identity for this exact implementation and build contract. It is not
multi-architecture publication, signature, SBOM/provenance, manifest freshness,
rootless/user-namespace conformance,
physical power-loss qualification, backup recovery, external rollback detection,
secure erasure, malicious connector cleanup, or connector OCI acceptance. Public
IPv6 and ULA IPv6 are separate probes; neither is described as link-local.
