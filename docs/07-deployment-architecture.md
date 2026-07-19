# Deployment architecture

## Build target

MyCogni will publish one minimal, non-root, multi-architecture core OCI image containing the API/UI, CLI, worker, scheduler, and migrations. It contains no connector implementation, browser, model runtime, or model weight. Each connector is a separate digest-pinned OCI or constrained WASI artifact. A separate browser-runner image contains Playwright/Chromium for approved workflows. Browser sessions remain ephemeral and stop for CAPTCHA, MFA, terms/disclosure drift, or unexpected account controls.

Images are repeatable, digest-pinned, signed, and accompanied by SBOM and provenance attestations. “Reproducible” is reserved for artifacts with demonstrated bit-for-bit rebuild evidence.

## Profile A: local-lite

Audience: one consenting adult on a laptop, NAS, or small home server for stable v1.

- one `mycogni all-in-one` container;
- encrypted SQLite metadata on a persistent volume;
- encrypted filesystem evidence store on the same volume;
- installation KEK/recovery material supplied from the host and excluded from data/evidence archives; wrapped profile-key catalog included in the managed consistent encrypted-state archive;
- loopback binding by default plus authenticated bootstrap/session, strict Host/Origin/CSRF policy, and a permissioned CLI channel;
- built-in durable scheduler and one worker;
- browser runner started only for a reviewed task;
- connector/browser artifacts have no direct egress and run through the mandatory gateway;
- one heavy-work lease permits browser or optional advisory inference, not both on the minimum tier;
- periodic rather than continuously busy operation.

The container can be stopped for months. On restart, migrations run under a lock and the scheduler computes bounded catch-up work.

## Profile B: cloud-small

Audience: one person/household using a small VM or container service.

- `serve`, `worker`, and `scheduler` roles from the same image;
- PostgreSQL with encrypted storage and private networking;
- S3-compatible encrypted evidence objects or an encrypted persistent volume;
- external secret/KMS provider;
- TLS at trusted ingress plus a phishing-resistant passkey/WebAuthn or narrowly configured OIDC reference profile; private networking alone is insufficient;
- optional browser runner on an isolated job/service with strict egress;
- mandatory egress policy gateway and separate digest-pinned connector jobs;
- one scheduler leader and horizontally scalable workers.

This is still single-tenant. Multi-tenant SaaS is explicitly out of scope because it changes threat, consent, compliance, and isolation requirements.

## Network policy

Inbound:

- the core server binds its isolated container interface and Compose publishes explicitly to host `127.0.0.1`; wildcard/LAN publication is unsupported in stable V1;
- cloud-small accepts HTTPS only through authenticated ingress;
- no connector worker accepts public inbound traffic.

Outbound:

- core: database, evidence store, configured mail provider, update sources;
- connector/browser runner: no direct path; typed HTTP/mail are gateway-originated, while browser TLS is limited to online permit/fence/authority/origin/resolved public IP/port/redirect-connection/protocol/budget enforcement with an explicit opaque-content residual risk;
- assistant gateway: no arbitrary callbacks by default;
- private, loopback, link-local, and cloud metadata destinations are denied for custom URLs.
- WebSocket, QUIC, DoH, downloads, and undeclared protocols are denied in the default connector/browser profile.

## Secret sources

Supported order:

1. cloud KMS/secret manager or Docker secret file descriptor;
2. OS keychain helper for local use;
3. root-readable file mounted read-only;
4. environment variables only as a compatibility fallback with a warning.

Example files contain names, never real values. Startup refuses default keys, world-readable secret files, missing persistent storage, or a public bind without explicit authentication configuration.

## Backup and recovery

A managed data backup contains an online-consistent encrypted database export, encrypted evidence objects, the wrapped profile-DEK catalog, schema and object manifests, policy versions, a signed checkpoint statement, submission/gateway high-water boundaries, and restore metadata. It excludes the KEK/recovery secret, checkpoint signing key, live installation dispatch epoch, unwrapped keys, and plaintext temporaries. Recovery material is protected separately. Deletion reports cover live state and known managed backups and warn that filesystem snapshots, Time Machine and operator copies are outside MyCogni's inventory.

Recovery objectives for cloud-small:

- RPO: 24 hours by default; configurable to 1 hour;
- RTO: 4 hours for a single-household operator;
- quarterly automated restore into an isolated environment;
- integrity verification of event chains and evidence hashes;
- connectors remain paused until restore validation and external-intent reconciliation complete;
- restore rotates the external dispatch epoch and every restored nonterminal external intent is `reconciliation_required` until authoritative evidence resolves it.

Local-lite provides `backup create`, integrity-only `backup verify-integrity`, and isolated decrypting `backup restore-test` flows. Integrity verification without KEK is never labeled recoverable.

## Upgrade and rollback

- the application checks migration compatibility before stopping the old version;
- backup and schema preflight are mandatory for major upgrades;
- jobs are drained or leases allowed to expire;
- connector versions referenced by active cases remain available or are explicitly migrated;
- rollback is supported only within a declared schema window;
- external submissions are never replayed merely because an application rollback occurred.

## Docker acceptance criteria

- amd64 and arm64 images build in CI;
- image runs read-only apart from declared volumes and temporary directories;
- process runs as an unprivileged UID with dropped capabilities;
- health checks distinguish liveness, readiness, migration state, key access, and scheduler leadership;
- graceful termination stops new claims and preserves/abandons leases safely;
- idle local-lite target is below 250 MiB excluding browsers;
- all example deployments pass a configuration security lint.
- connector artifacts cannot access core/data/key volumes, environment secrets, Docker socket, host metadata, private network, or direct egress;
- browser sandbox remains enabled under a dedicated user; higher-assurance cloud examples document gVisor/Kata/VM requirements;
- local-lite and cloud-small publish a conformance matrix for queue/journal, keys, evidence, auth, sandbox, egress, backup/restore, and upgrade behavior.

## Optional local intelligence

No model runtime or weight is in the core image or stable v1 dependency chain. A future opt-in process-owned `llama.cpp` adapter uses stdio or a permissioned Unix socket without network/core mounts. An explicitly configured host-local Ollama endpoint is a weaker convenience adapter and must be isolated from connectors and OpenClaw. It has no remote fallback.

Weights are an explicit digest-pinned, license-reviewed read-only cache excluded from data backup. Acquisition/update never occurs during scheduler catch-up. Active inference has separately published resource requirements; the unloaded/no-op adapter must return to the core idle target.

## Profile conformance, not parity

SQLite/filesystem/host keychain and PostgreSQL/object store/KMS have different locking, durability, recovery, and isolation behavior. “Same image/domain model” means compatible semantics, not equal assurance. Stable claims list the exact tested host/runtime/database/key/evidence/sandbox configuration and its residual risks.
