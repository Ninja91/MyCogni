# SPIKE-RUNNER persistent-state and containment evidence — 2026-07-19

## Executable state evidence

`PersistentMailboxRepository` persists a bounded, canonical JSON state frame in
SQLite rather than serializing Python objects. The encrypted frame is committed
inside `BEGIN IMMEDIATE`; two independent spawned processes were allowed one
claim winner only. Focused tests also close/reopen offered, claimed, committed
and acknowledged state; kill a child immediately before SQLite commit (the
offer remains) and immediately after commit before reply (the claim persists);
and deny inherited parent repositories after `fork`.

Focused Python 3.12 evidence:

```text
tests/runner_mailbox/test_persistent.py: 8 passed
tests/architecture/test_runner_containment.py: 7 passed
mypy -p services.runner_mailbox: Success (6 source files)
```

The DB/WAL canary test proves the synthetic action value is absent from durable
bytes. This is a narrow ciphertext-at-rest test, not a general logs, backups,
swap or secure-erasure claim.

## Docker Desktop local reproduction

On Docker Desktop 4.82.0 / Engine 29.6.1, native linux/arm64 built local image
ID `sha256:45ff4e740f0b0e6703f1ed715bed3c2495545eee6ff9bb7f1b139ec2e49a5012`
from this worktree. The runner-only Compose profile completed its in-container
checks (UID 65532, immutable application path, writable runner volume/tmpfs,
absent Docker socket, seccomp mode 2 and failed metadata/host-gateway/public
IPv4/IPv6 connection probes).

Docker inspect reported `NetworkMode=none`, `ReadonlyRootfs=true`,
`CapDrop=[ALL]`, `SecurityOpt=[no-new-privileges:true]`, private cgroup and IPC
namespaces, no published ports, `PidsLimit=64`, `Memory=536870912`,
`NanoCpus=1000000000`, init enabled, restart policy `no`, one local named volume
at `/var/lib/mycogni-runner`, and a 32 MiB noexec/nosuid/nodev tmpfs. The Engine
default seccomp filter was active (`Seccomp: 2` inside the container).

This was a synthetic trusted-sidecar containment smoke. Its image is a local
tag, not a signed immutable published runner artifact, and it has no untrusted
connector sidecar. It must not be cited as connector OCI acceptance.
