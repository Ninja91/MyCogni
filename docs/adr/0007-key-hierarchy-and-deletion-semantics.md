# ADR-0007: Key hierarchy and deletion semantics

- Status: Accepted for initial build
- Date: 2026-07-15
- Refines: ADR-0002

## Context

Deriving every profile key from one persistent installation root allows a deleted profile key to be recreated. Backups of a wrapped-key catalog may also retain the ability to decrypt data after the live key record is removed. Cryptographic deletion claims must name this boundary.

## Decision

Generate a random profile DEK for every profile. Wrap it under an install/cloud KEK held outside the application data and evidence backups. Derive separate field, evidence, blind-index, and event-authentication keys from the profile DEK with context-bound HKDF. Never derive the profile DEK from the install KEK.

Keep the wrapped-key catalog as a separately classified recovery asset. Profile deletion destroys the live wrapped DEK, cancels work, deletes blind indexes/session keys, and records a non-sensitive tombstone. The UI reports deletion as pending until every recoverable key-catalog backup containing that DEK passes its retention horizon or is sanitized. Evidence/data ciphertext may then be deleted asynchronously but is already inaccessible through live keys.

Relationship metadata and case projections receive encryption/pseudonymization proportional to sensitivity; field encryption alone is not a dossier boundary.

## Consequences

- Recovery needs both data backup and key-catalog recovery material.
- Users can permanently lose a profile.
- Backup inventory and expiry become part of deletion truth.
- Rotation rewraps profile DEKs; purpose-key changes may require data re-encryption.
- Tests must prove deletion and rotation across old backups and profiles.

## Alternatives

Root-derived profile keys were rejected because they can be recreated. One install-wide DEK was rejected because a single key compromise/deletion affects all profiles. Keeping the key catalog inside normal backups was rejected because it collapses separation.

## Security and privacy impact

The design narrows compromise and supports honest deletion, while making availability and recovery responsibility explicit. NIST cryptographic erase terminology informs the claim; implementation still requires independent review.

## Review trigger

Key provider/algorithm change, recovery redesign, shared tenancy, search over encrypted data, key-catalog retention change, or failed deletion/restore drill.
