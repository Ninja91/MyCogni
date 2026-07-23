# AUTH-001B — host-secret custody

Status: **IN_PROGRESS implementation evidence; no AUTH-001 promotion**.

AUTH-001B adds a source-level native owner-file baseline for the five composition-held
authentication credentials that AUTH-001A intentionally stores only as digests: operator
authority, service identity, and the initial-bootstrap, emergency-revoke, and reprovision roots.
It does not make MyCogni production authentication.

## Contract and composition

`AuthCustodyPort` is an application-owned read-only boundary with only `status` and `load`.
`AuthCustodyProvisioner` is a separate administration boundary with only `provision_empty`.
Neither extends the profile-key `SecretPort`. Runtime composition cannot provision, repair,
discover, export, replace, or delete a custody source.

The create-new ceremony writes custody before initializing SQLite. It uses `O_EXCL`, never
overwrites or changes permissions on an existing object, and treats a SQLite outcome-unknown
failure as reconciliation-required rather than retryable. Normal startup requires both stores to
be present, loads the expected installation/actor/profile binding, compares all five handles and
SHA-256 digests with durable state, and only then constructs `AuthService` with the persisted
service identity. Missing, malformed, unsafe, changed, fork-inherited, or mismatched state exposes
no authority.

Cross-store update is deliberately absent. A reprovision exchange can create a replacement root
inside the SQLite transaction, but AUTH-001B cannot atomically replace the host file. Durable
replacement-root handoff therefore remains disabled/fail-closed pending a reviewed reconciliation
or two-phase protocol; this slice does not simulate atomicity.

## Binary V1 source

The fixed-length binary record contains only a magic value, version, exact record count,
generation, three binding UUIDs, five fixed role tags, five credential UUID handles, and five
exact 32-byte secrets. It has no JSON, timestamps, paths, extensible fields, PII, broker data, or
recovery text. Parsing rejects wrong magic/version/count/length/order/tag, invalid UUIDs,
duplicate handles, nonpositive generations, and binding mismatches.

The reader requires a canonical absolute path structurally disjoint in both directions from every
configured database/data/evidence/archive root. It traverses descriptors with `O_NOFOLLOW` and
`O_CLOEXEC`, requires non-symlink root/effective-UID-owned non-writable ancestors, a private final
parent, a regular single-link effective-UID-owned file with exact `0400` or `0600` mode, and
revalidates named/opened/after-read file and parent identities. Content or identity change latches
that provider object into recovery-required. A fork child denies before inherited locking or I/O.

## Platform conformance and nonclaims

| Profile | AUTH-001B disposition |
| --- | --- |
| Native macOS/Linux owner-only file | source adapter and synthetic tests only; exact-host evidence remains required |
| macOS Keychain/Security.framework | deferred; no `security` CLI/stdout/env material path |
| Rootless Linux container key-only volume | deferred separate UID, mount and readonly-core conformance |
| Docker Desktop | unsupported in this slice; Linux evidence cannot be inferred |
| Compose secrets or environment | rejected |
| Cloud secret/KMS | deferred/post-V1 |

POSIX checks do not prove macOS ACL, mount alias, swap, core-dump, same-process adversary,
host-compromise, physical power-loss, container, backup, or restore behavior. There is no network,
browser, broker, mail, PII, profile encryption, Keychain, cloud, or external-action surface.

## Evidence and rollback

Focused tests cover the strict parser, create-new behavior, redaction, exact binding and digest
comparison, database/WAL/SHM raw-secret absence, mode/type/symlink/hardlink/ancestor/root-overlap
denials, rename replacement latching, fork denial, presence mismatch, and a true restart that
disposes the first composition, reopens SQLite and custody, authenticates an existing session,
and rejects bootstrap replay. Architecture tests keep runtime and administration surfaces
disjoint and deny environment, subprocess, keyring, JSON, database, browser, and network fallback.

Run:

```text
python scripts/ci/guarded_pytest.py -q tests/adapters/auth/test_owner_file_custody.py tests/architecture/test_auth_custody_boundaries.py tests/application/test_auth_spike.py tests/adapters/auth/test_sqlite.py
ruff check src tests/adapters/auth/test_owner_file_custody.py tests/architecture/test_auth_custody_boundaries.py
mypy src/mycogni
```

Exact commit, runtime counts, operating system, architecture, filesystem, effective UID, modes,
and review verdicts are recorded only after the final reviewed commit. Rollback removes the
software reader/composition support but must not automatically delete or alter the external
source. Rolling back after use requires explicit reconciliation; volatile or environment fallback
is prohibited.

### Native source-level evidence record

The implementation target is commits `e223587c8181438809b9bae72f59e9f7e37a3fbf` and
`812e0ecfc742786c2e4c9630b569df29f9e1ff9e`.
On 2026-07-22, the focused custody/auth lane passed 78 tests and the combined network-guard plus
custody lane passed 134 tests. Ruff, strict mypy for all `mycogni` source, import-linter, the
safety/claim/site guards, network source guard, and `git diff --check` passed. The executing host
reported Darwin `25.5.0`, arm64, APFS (`local, journaled`), effective UID `501`; the administration
test creates the final record as `0600` and the reader accepts only exact `0400` or `0600`.

This is reproducible source/test evidence on one developer host, not exact-host storage
conformance: it does not exercise an operator-selected long-lived path, ACL inventory, mount
aliases, power interruption, or an independently observed ceremony. Review verdicts and the final
documentation commit remain separate evidence.

Still deferred: production no-echo terminal behavior, custody mutation/rotation/delete,
replacement-root handoff, restore epochs, outcome-unknown reconciliation, exact-host conformance,
Docker/Keychain profiles, and qualified authenticated acceptance.
