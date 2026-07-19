# PF-002 adversarial review

Reviewed evidence commit: `fe7333e`, with follow-up documentation and layer
optimization disposition in the next integration commit.

Verdict: **ACCEPT at code/build/runtime-evidence level** — zero P0 and zero P1.
Canonical PF-002 status remains `IN_PROGRESS` because this AI review is not the
externally rooted authenticated semantic attestation required by GOV-001.

`Sol` is a role label only; it is not a model attestation or security
certification.

## Independent reproduction

The infra/edge/container-security reviewer independently established:

- every retained OCI blob matches its content digest;
- OCI index `sha256:816ace6f26ac...` contains the documented linux/amd64
  `sha256:35f1263ec98a...` and linux/arm64 `sha256:0ce1a879a124...`
  manifests;
- live upstream index/platform mappings exactly match both pinned base-image
  records in `docker/images.lock.json`;
- native arm64 and emulated amd64 hardened smokes execute as UID/GID `65532`,
  with all capability sets zero, `NoNewPrivs=1`, seccomp filtering active,
  read-only root/application/data paths and a finite writable `noexec` tmpfs;
- neither platform has an IPv4 route and an explicit network connection probe
  fails;
- Uvicorn, Alembic and the MyCogni import smoke execute on both platforms; and
- the semantic validator and seven focused mutation tests pass.

## P2 disposition

| Finding | Disposition |
| --- | --- |
| “Loopback only” was stricter than the independent observation because Docker Desktop also exposes inert tunnel devices. | Corrected the criterion to no route plus failed connection; interface count is not a security claim. |
| The program-summary matrix still said two-architecture evidence was missing. | Corrected to distinguish present build/runtime evidence from missing authenticated acceptance. |
| The temporary archive lacked a recorded checksum, durable artifact/log pointer and exact revision label. | Recorded the local tar SHA-256 and explicit limitations. Durable CI retention and exact VCS labeling remain release-workflow requirements; unsigned incomplete BuildKit provenance is only corroborating evidence. |
| Runtime `chmod` duplicated the copied virtual-environment payload in another layer. | Moved ownership/read-only hardening into the build stage before runtime `COPY`; semantic validation rejects reintroducing runtime hardening layers. Accepted-source index `sha256:7cf68edcbdc0...` passed both platform smokes and reduced the native loaded image from about 103.9 MB to 74.5 MB. |

PF-002 proves the trusted-core packaging skeleton. It does not prove the future
browser/connector runner, physical x86 hardware, hostile-code containment,
signed provenance, release reproducibility or durable CI artifact retention.
