# LOCAL-SYNTH-001 adversarial review record

Date: 2026-07-29

This record preserves agent-assisted implementation review evidence for the
synthetic local and Docker preview. It is not an authenticated package
attestation, independent qualified-human cryptographic review, release
acceptance, or production-remover evidence.

## Exact targets

| Target | Revision | Review hats | Final verdict |
| --- | --- | --- | --- |
| Installed synthetic CLI | `83ef2a7f1ddc8d97f5c98a84edbbb1eb8e0898db` | backend and local-state security | ACCEPT; zero P0/P1/P2 |
| Hardened synthetic Docker profile | `e9969bd16957fb44a955a921d608b49fe71bd1d8` | principal backend/infra and container security; senior OSS and product truthfulness | ACCEPT; zero P0/P1/P2 |

The Docker target is the single commit reviewed after rebasing onto the merged
CLI and auth foundations. PR #12 reproduced both locked Linux CI jobs before
merge.

## Material rejected findings and disposition

The first Docker review did not accept the draft. It identified:

- open-world static and runtime validation that could miss host PID/IPC,
  injected environment, device, config or secret additions;
- security assertions disabled by optimized Python;
- mutable-image and clean-host pull ambiguity;
- ambient Compose project-name coupling and undocumented named-volume
  persistence;
- predictable cleanup scope with unverified deletion;
- runtime evidence not bound to the reviewed Git revision;
- caller-directory Git provenance and daemon-dependent cgroup namespace;
- abbreviated resource IDs and Docker `null` versus empty-list device
  representation.

The accepted target closes those findings with closed-world allowlists and
mutations, optimized-Python refusal, `pull_policy: never`, build-first and reset
documentation, UUID-scoped exact resource cleanup, clean-checkout OCI revision
binding, machine-readable evidence, repository-rooted Git commands, private
cgroup namespace, non-truncated IDs, and safe cross-engine absence checks.

## Reproduced evidence

- Full local Python 3.12.12 gate: 1,939 passed with two known fork warnings.
- Full local Python 3.13.11 gate: 1,939 passed with the same warnings.
- PR #12 Linux Python 3.12 and 3.13 jobs: passed.
- Runtime proof host: macOS arm64 with Docker Desktop 4.82.0.
- Container engine: Linux/arm64 Docker Engine 29.6.2.
- Image ID:
  `sha256:a666404f204fb8742c20262b94576415a78da14f6b66ffb14beb21b6e3864d6d`.
- Runtime result: exact revision matched, Docker `none` network only, finite
  synthetic reports passed, and invocation-owned resources were removed.

## Explicit limits

- No real PII is accepted and no broker, mail, browser, connector, submission,
  verification, or real-removal capability exists.
- Docker Desktop evidence is not native Linux host, rootless Docker, Linux
  amd64, cloud, or multi-architecture release conformance.
- Source composition is not proof of host-level containment; runtime evidence
  applies only to the recorded image, revision, engine, architecture and host.
- This evidence does not promote `LOCAL-SYNTH-001`, `OPS-001`, `UX-002`,
  `AUTH-001`, `KEY-001`, PF-002 release status, or any M2/M3 product package to
  complete.
