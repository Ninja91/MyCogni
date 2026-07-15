# Deployment architecture

## Build target

MyCogni will publish one minimal, non-root, multi-architecture OCI image containing the API/UI, CLI, worker, scheduler, migrations, and non-browser connectors. A browser-enabled variant will add Playwright and Chromium for approved workflows because bundling it into every installation would greatly increase image size and attack surface. Browser sessions remain isolated and stop for CAPTCHA, MFA, or unexpected account controls.

Images are reproducible where practical, pinned by digest in examples, signed, and accompanied by SBOM and provenance attestations.

## Profile A: local-lite

Audience: one household on a laptop, NAS, or small home server.

- one `mycogni all-in-one` container;
- encrypted SQLite metadata on a persistent volume;
- encrypted filesystem evidence store on the same volume;
- master key supplied from the host, never stored in that volume;
- loopback binding by default;
- built-in durable scheduler and one worker;
- browser runner started only for a reviewed task;
- periodic rather than continuously busy operation.

The container can be stopped for months. On restart, migrations run under a lock and the scheduler computes bounded catch-up work.

## Profile B: cloud-small

Audience: one person/household using a small VM or container service.

- `serve`, `worker`, and `scheduler` roles from the same image;
- PostgreSQL with encrypted storage and private networking;
- S3-compatible encrypted evidence objects or an encrypted persistent volume;
- external secret/KMS provider;
- TLS at a trusted ingress; application remains private or strongly authenticated;
- optional browser runner on an isolated job/service with strict egress;
- one scheduler leader and horizontally scalable workers.

This is still single-tenant. Multi-tenant SaaS is explicitly out of scope because it changes threat, consent, compliance, and isolation requirements.

## Network policy

Inbound:

- local-lite listens on `127.0.0.1` unless the user explicitly configures LAN access;
- cloud-small accepts HTTPS only through authenticated ingress;
- no connector worker accepts public inbound traffic.

Outbound:

- core: database, evidence store, configured mail provider, update sources;
- connector runner: only manifest-approved broker origins and required DNS/OCSP services;
- assistant gateway: no arbitrary callbacks by default;
- private, loopback, link-local, and cloud metadata destinations are denied for custom URLs.

## Secret sources

Supported order:

1. cloud KMS/secret manager or Docker secret file descriptor;
2. OS keychain helper for local use;
3. root-readable file mounted read-only;
4. environment variables only as a compatibility fallback with a warning.

Example files contain names, never real values. Startup refuses default keys, world-readable secret files, missing persistent storage, or a public bind without explicit authentication configuration.

## Backup and recovery

A backup contains encrypted database export, encrypted evidence objects, manifest/policy versions, and restore metadata. It excludes the master wrapping key. Users must back up the key separately with clear recovery warnings.

Recovery objectives for cloud-small:

- RPO: 24 hours by default; configurable to 1 hour;
- RTO: 4 hours for a single-household operator;
- quarterly automated restore into an isolated environment;
- integrity verification of event chains and evidence hashes;
- connectors remain paused until restore validation completes.

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
