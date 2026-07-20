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
mypy: success, 9 source files
runner + containment + connector SDK + safety guard: 944 passed
  persistent adapter: 30 passed
  rendered/Dockerfile/context/runtime containment mutations: 71 passed
```

The two intentional held-lock `fork()` regressions emit Python's expected
multithreaded-fork deprecation warning; both child processes refuse finitely
before the inherited lock and pass.

The canonical governance report was regenerated. Governance, architecture
claim and site guards passed; the focused governance/claim/site/safety suite
reported 71 passed.

## Exact local Docker evidence

Docker Desktop 4.82.0 / Engine 29.6.1 on native linux/arm64 built implementation
commit `e4290c35ca4a9792ac5974136d5b3f6e49a7a7af` three times from separate
`--no-cache` invocations: two independent clean contexts extracted from
`git archive` and the tracked-clean developer worktree containing 34 ignored
host `.pyc` files below `services/` and `packages/`. All builds used
`SOURCE_DATE_EPOCH=1784419200`, `BUILD_CREATED=2026-07-19T00:00:00Z`,
explicitly disabled SBOM/provenance attestations, and the Docker archive exporter
with `rewrite-timestamp=true`. All three BuildKit metadata files recorded the
same manifest/image digest:

```text
sha256:1f8120be0efad46207e05f04cd938c984c3a4a192b7376d925665217e680fcbb
```

All three recorded config digest
`sha256:5f9b1a40439183b9f3e14f3cb2f0a6fa61a91b065248f91571ef9b33d0a07095`.
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
the five connector-contract files and the four runtime-anchor files; it rejects
every other runner/local-package subtree and every `__pycache__`, `.pyc` or
`.pyo` under `/opt/mycogni-runner`. The application root has exactly `.venv`,
`LICENSE`, `NOTICE` and `services`. The site-packages top level is exactly
`annotated_types`, `annotated_types-0.7.0.dist-info`, `cffi`,
`cffi-2.1.0.dist-info`, `connector_protocol`, `cryptography`,
`cryptography-46.0.7.dist-info`, `mycogni_connector_sdk-0.0.0.dist-info`,
`mycogni_runner_mailbox_runtime`,
`mycogni_runner_mailbox_runtime-0.0.0.dist-info`, `pycparser`,
`pycparser-3.0.dist-info`, `pydantic`, `pydantic-2.13.4.dist-info`,
`pydantic_core`, `pydantic_core-2.46.4.dist-info`,
`typing_extensions-4.16.0.dist-info`, `typing_extensions.py`,
`typing_inspection`, `typing_inspection-0.4.2.dist-info` and arm64-specific
`_cffi_backend.cpython-312-aarch64-linux-gnu.so`.

Both `_virtualenv.pth` and `_virtualenv.py` are asserted present during the
build and then removed; runtime inventory rejects every `.pth`,
`sitecustomize.py` and `usercustomize.py`. Both local dist-info records have
exact `Name`, version `0.0.0` and `License-Expression: Apache-2.0`, while their
package directories contain only the reviewed file allowlists. Checkout-byte
binding uses raw `git --no-replace-objects cat-file` with replacement objects,
system/global Git configuration and nonessential environment disabled. It
revalidates the exact commit object and reads each blob directly, without a
cached or worktree-mediated comparison.

The exact source-bound live verifier passed against image `sha256:1f8120be…`
and implementation `e4290c35…`. It reported UID 65532, schema 1, isolated
Python with `site` disabled, mailbox state created, `recovery_required=false`,
and denied DNS, host-gateway IPv4, metadata IPv4, public IPv4, public IPv6
(`2606:4700:4700::1111`) and ULA IPv6 (`fd00:ec2::254`).

Container inspect matched the exact image ID and image-owned entrypoint/env,
with no Compose environment injection; non-root user; read-only root;
network-none; private IPC/cgroup and Engine-default private PID namespaces;
drop-all capabilities; no-new-privileges; active seccomp sentinel; 64 PIDs,
1 CPU and 512 MiB limits; no restart; only the runner state volume and bounded
noexec/nosuid/nodev tmpfs. Runtime metadata reported the exact ten-distribution
allowlist and no `mycogni` core import. Exported filesystem inventory found only
runner mailbox Python sources below `services/` and byte-equal read-only
`LICENSE`/`NOTICE` files.

The source-bound invocation used random project
`mycogni-runner-85feaaec5c10407f9eb3a95af4ad82b2`, captured container
`b1ac9af3fbb5`, its generated volume and exact Compose ownership labels, then
removed only those resources. The verifier proved both absent; separate exact
`docker container inspect` and `docker volume inspect` commands also returned
not found. This is local unsigned evidence, not a published artifact digest or
multi-architecture connector acceptance.

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
optimizer_stdout="$(mktemp /private/tmp/mycogni-runner-opt-out.XXXXXX)"
optimizer_stderr="$(mktemp /private/tmp/mycogni-runner-opt-err.XXXXXX)"
for verifier in scripts/verify_runner_containment.py scripts/verify_runner_containment_runtime.py; do
  ! uv run --all-packages --frozen --python 3.13.11 python -O "$verifier" >"$optimizer_stdout" 2>"$optimizer_stderr"
  test ! -s "$optimizer_stdout"
  test "$(cat "$optimizer_stderr")" = "runner containment verification requires unoptimized Python"
  ! env PYTHONOPTIMIZE=1 uv run --all-packages --frozen --python 3.13.11 python "$verifier" >"$optimizer_stdout" 2>"$optimizer_stderr"
  test ! -s "$optimizer_stdout"
  test "$(cat "$optimizer_stderr")" = "runner containment verification requires unoptimized Python"
done

clean_a="$(mktemp -d /private/tmp/mycogni-runner-r5-c1.XXXXXX)"
clean_b="$(mktemp -d /private/tmp/mycogni-runner-r5-c2.XXXXXX)"
git archive e4290c35ca4a9792ac5974136d5b3f6e49a7a7af | tar -x -C "$clean_a"
git archive e4290c35ca4a9792ac5974136d5b3f6e49a7a7af | tar -x -C "$clean_b"
test "$(find services packages -type f \( -name '*.pyc' -o -name '*.pyo' \) | wc -l | tr -d ' ')" -gt 0

docker buildx build --no-cache --platform linux/arm64 \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=1784419200 \
  --build-arg VCS_REF=e4290c35ca4a9792ac5974136d5b3f6e49a7a7af \
  --build-arg BUILD_CREATED=2026-07-19T00:00:00Z \
  --metadata-file /private/tmp/mycogni-runner-r5-c1.json \
  --output type=docker,dest=/private/tmp/mycogni-runner-r5-c1.tar,name=mycogni/runner-mailbox:r5-c1,rewrite-timestamp=true \
  --file docker/Dockerfile.runner-mailbox "$clean_a"
docker buildx build --no-cache --platform linux/arm64 \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=1784419200 \
  --build-arg VCS_REF=e4290c35ca4a9792ac5974136d5b3f6e49a7a7af \
  --build-arg BUILD_CREATED=2026-07-19T00:00:00Z \
  --metadata-file /private/tmp/mycogni-runner-r5-c2.json \
  --output type=docker,dest=/private/tmp/mycogni-runner-r5-c2.tar,name=mycogni/runner-mailbox:r5-c2,rewrite-timestamp=true \
  --file docker/Dockerfile.runner-mailbox "$clean_b"
docker buildx build --no-cache --platform linux/arm64 \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH=1784419200 \
  --build-arg VCS_REF=e4290c35ca4a9792ac5974136d5b3f6e49a7a7af \
  --build-arg BUILD_CREATED=2026-07-19T00:00:00Z \
  --metadata-file /private/tmp/mycogni-runner-r5-dirty.json \
  --output type=docker,dest=/private/tmp/mycogni-runner-r5-dirty.tar,name=mycogni/runner-mailbox:r5-dirty,rewrite-timestamp=true \
  --file docker/Dockerfile.runner-mailbox .
jq -e --slurp 'map(.["containerimage.config.digest"]) | unique | length == 1' \
  /private/tmp/mycogni-runner-r5-c1.json /private/tmp/mycogni-runner-r5-c2.json /private/tmp/mycogni-runner-r5-dirty.json
jq -e --slurp 'map(.["containerimage.digest"]) | unique | length == 1' \
  /private/tmp/mycogni-runner-r5-c1.json /private/tmp/mycogni-runner-r5-c2.json /private/tmp/mycogni-runner-r5-dirty.json
jq '{"containerimage.config.digest": .["containerimage.config.digest"], "containerimage.digest": .["containerimage.digest"]}' \
  /private/tmp/mycogni-runner-r5-c1.json /private/tmp/mycogni-runner-r5-c2.json /private/tmp/mycogni-runner-r5-dirty.json
docker load --input /private/tmp/mycogni-runner-r5-c1.tar
docker load --input /private/tmp/mycogni-runner-r5-c2.tar
docker image inspect mycogni/runner-mailbox:r5-c1 mycogni/runner-mailbox:r5-c2 \
  --format '{{.Id}}|{{.Created}}|{{index .Config.Labels "org.opencontainers.image.created"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{json .RootFS.Layers}}'
uv run --all-packages --frozen --python 3.13.11 python scripts/verify_runner_containment_runtime.py \
  --image sha256:1f8120be0efad46207e05f04cd938c984c3a4a192b7376d925665217e680fcbb \
  --revision e4290c35ca4a9792ac5974136d5b3f6e49a7a7af
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
