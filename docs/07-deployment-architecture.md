# Deployment architecture

## Build target

MyCogni will publish one minimal, non-root, multi-architecture core OCI image containing the API/UI, CLI, worker, scheduler, and migrations. It contains no connector implementation, browser, model runtime, or model weight. Each connector is a separate digest-pinned OCI or constrained WASI artifact. A separate browser-runner image contains Playwright/Chromium for approved workflows. Browser sessions remain ephemeral and stop for CAPTCHA, MFA, terms/disclosure drift, or unexpected account controls.

Images are reproducible where practical, pinned by digest in examples, signed, and accompanied by SBOM and provenance attestations.

## Profile A: local-lite

Audience: one consenting adult on a laptop, NAS, or small home server for stable v1.

- one `mycogni all-in-one` container;
- encrypted SQLite metadata on a persistent volume;
- encrypted filesystem evidence store on the same volume;
- installation KEK supplied from the host, never stored in data/evidence volumes; wrapped profile-key catalog protected and backed up separately;
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

- local-lite listens on `127.0.0.1` unless the user explicitly configures LAN access;
- cloud-small accepts HTTPS only through authenticated ingress;
- no connector worker accepts public inbound traffic.

Outbound:

- core: database, evidence store, configured mail provider, update sources;
- connector/browser runner: no direct path; all connections traverse the gateway, which validates fence/authority/origin/resolved public IP/redirect/protocol/method/disclosure/budget;
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

A data backup contains encrypted database export, encrypted evidence objects, manifest/policy versions, submission-journal boundary, and restore metadata. It excludes the installation/cloud KEK and normal data backup does not silently include the recoverable wrapped-profile-key catalog. Operators back up KEK and key catalog separately with clear recovery/deletion warnings.

Recovery objectives for cloud-small:

- RPO: 24 hours by default; configurable to 1 hour;
- RTO: 4 hours for a single-household operator;
- quarterly automated restore into an isolated environment;
- integrity verification of event chains and evidence hashes;
- connectors remain paused until restore validation and external-intent reconciliation complete;
- every intent newer than the trusted journal/backup boundary is `outcome_unknown` until receipts/portals/mail prove its state.

Local-lite provides a `backup create`, `backup verify`, and `backup restore --dry-run` flow. A backup that has never passed verification is shown as unverified.

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
