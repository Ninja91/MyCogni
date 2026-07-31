# KEY-001A exact-target adversarial review record

Date: 2026-07-31

This record preserves agent-assisted code-level review evidence for the durable
synthetic wrapped-key catalog. It is not an authenticated package attestation,
qualified-human cryptographic certification, provider/host conformance, or a
production key-vault claim.

## Exact target

| Revision | Scope | Final verdict |
| --- | --- | --- |
| `3c43ba7bff17cc7c80903a749dc7296294481d1d` | KEY-001A implementation, migration, tests, ADR, roadmap, README and site truth | ACCEPT; zero unresolved P0/P1 across all three reviewers |

All reviewers confirmed their verdict against the exact commit after the clean
working tree was frozen.

## Independent final verdicts

| Review hat | P0 | P1 | P2 | Verdict and independently reproduced evidence |
| --- | ---: | ---: | ---: | --- |
| Principal cryptography and ML-safety | 0 | 0 | 1 | ACCEPT; 161 focused tests, Ruff and diff checks. Remaining P2: profile Transaction A/B crash edges use deterministic before/after-commit injection rather than real OS-level SIGKILL. Initialization has a real SIGKILL subprocess test, and the limitation is disclosed. |
| Principal backend, infrastructure and SQLite recovery | 0 | 0 | 0 | ACCEPT; 234 relevant tests, Ruff, strict source mypy and diff checks. Query-only reconciliation, actual commit ambiguity, reverse-ledger validation, source binding, restart, one-writer behavior and migration constraints accepted. |
| Principal software architecture, edge and senior OSS | 0 | 0 | 0 | ACCEPT; 41 focused tests. Exact provider/catalog sealing, admin isolation, truthful recovery/downgrade claims, roadmap/governance and public-site status accepted. |

## Rejected findings and remediation

The first review cycles rejected earlier working trees. Material blockers included:

- generating AEAD output before a nonce reservation was durably committed;
- publishing a wrapped key before durable ownership was known;
- treating a SQLite commit exception as proof of rollback;
- allowing a preparation to be forged, reused, copied across a process, or
  consumed without exact issuer identity;
- exposing a write-capable generic recovery unit of work;
- failing to resume a dirty `preparing` initialization against the exact
  originally committed source;
- failing to validate reverse-ledger orphan rows;
- allowing an interrupted `reserved` or `burned` profile/version binding to be
  reserved again after restart;
- relying on same-interpreter restart tests and contradictory read-only,
  downgrade, roadmap and completion claims.

The exact target closes those blockers with nonce-only single-use preparation,
two known-successful transactions around AEAD, commit-unknown recovery latching,
query-only reconciliation plus a narrow compare-and-swap initialization finish,
a domain-separated source commitment, strict forward and reverse ledger checks,
durable profile/version reservation uniqueness, fresh-exec and SIGKILL tests,
machine-enforced architecture boundaries, and synchronized documentation.

## Local evidence and environmental limits

- Exact-target focused integration lane: 174 passed on Python 3.12.12.
- Broad non-loopback lane: 1,940 passed, 8 expected controlling-terminal skips,
  and 38 loopback tests deselected. Three package-manager subprocess tests were
  blocked before project logic by the macOS sandbox's `uv` system-configuration
  panic.
- The same sandbox denies loopback socket binding, so the 38 established
  simulator-loopback tests require an unsandboxed host or Linux CI.
- Python 3.13.11 is installed, but the sandboxed `uv` wrapper cannot construct
  its locked environment; cross-loading 3.12 native wheels is invalid and was
  not counted as evidence. The protected Linux 3.12/3.13 CI lanes remain the
  authoritative dual-runtime reproduction for the pull request.
- All source-level quality, import-boundary, safety, claim, site, threat,
  governance and network-source guards pass locally. The namespace probe reports
  `unsupported` on this host, as designed.

## Explicit limits

- Synthetic IDs and keys only; no real PII, broker traffic or external action.
- No complete `KEY-001`, `KEY-002` or `DATA-001` claim.
- No rotation, cryptographic deletion, backup/restore, archive-horizon,
  Keychain, container-volume, Linux Secret Service, cloud-KMS, FIPS, Secure
  Enclave, hostile-host/root or power-loss conformance claim.
- No formal V0.x-to-V1 promotion. Authenticated attestations and qualified human
  review gates remain unavailable and fail closed.
