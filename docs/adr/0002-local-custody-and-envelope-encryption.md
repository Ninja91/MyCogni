# ADR-0002: Local custody and envelope encryption

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

MyCogni must assemble a complete identity profile to remove data. A database or backup compromise would otherwise expose more correlated PII than many individual brokers hold.

## Decision

Keep data in user-controlled local or single-tenant infrastructure. Field-encrypt PII and object-encrypt evidence using per-profile/per-purpose data keys. Keep the wrapping key outside the database and backups through an OS keychain, mounted secret, or KMS. Bind ciphertext to record context, redact diagnostics by construction, and support cryptographic profile deletion.

## Consequences

- Operators must manage a separate recovery key and can permanently lose data.
- Equality searches require narrowly approved blind indexes.
- Migrations, backups, exports, and support flows must operate on ciphertext safely.
- Cloud-small remains single-tenant until an entirely new tenancy/privacy design is reviewed.

## Alternatives

Disk encryption alone does not protect DB exports, object backups, or operator access. A centrally hosted vault conflicts with the local-first promise. Storing the master key beside the database defeats backup separation.

## Review trigger

Independent cryptographic review, algorithm/library change, new secret provider, shared tenancy, server-side search over encrypted fields, or recovery-model change.
