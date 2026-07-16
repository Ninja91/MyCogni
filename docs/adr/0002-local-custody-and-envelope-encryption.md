# ADR-0002: Local custody and envelope encryption

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

MyCogni must assemble a complete identity profile to remove data. A database or backup compromise would otherwise expose more correlated PII than many individual brokers hold.

## Decision

Keep stable-V1 data in user-controlled local infrastructure. Generate an independent random data-encryption key for each profile and wrap it with an installation key-encryption key held outside the data store and managed archives. Derive purpose-specific keys only below the profile key. Field-encrypt PII and object-encrypt evidence, bind ciphertext to record context, redact diagnostics by construction, and support profile deletion by destroying the profile key subject to known managed wrapped-catalog archive horizons.

## Consequences

- Operators must manage a separate recovery key and can permanently lose data.
- The wrapped-key catalog is a separately classified recovery asset included in a consistent managed archive, while KEK/recovery material stays separate. Deletion reports name known managed catalog horizons and external-backup limits.
- Equality searches require narrowly approved blind indexes.
- Migrations, backups, exports, and support flows must operate on ciphertext safely.
- Cloud-small remains single-tenant until an entirely new tenancy/privacy design is reviewed.

## Alternatives

Disk encryption alone does not protect DB exports, object backups, or operator access. A centrally hosted vault conflicts with the local-first promise. Storing the master key beside the database defeats backup separation.

## Review trigger

Independent cryptographic review, algorithm/library change, new secret provider, shared tenancy, server-side search over encrypted fields, key-catalog backup change, or recovery-model change. ADR-0007 refines deletion and catalog semantics.
