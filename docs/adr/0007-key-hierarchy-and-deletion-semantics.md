# ADR-0007: Key hierarchy and deletion semantics

- Status: Accepted for initial build
- Date: 2026-07-15
- Refines: ADR-0002

## Context

Deriving every profile key from one persistent installation root allows a deleted profile key to be recreated. Backups of a wrapped-key catalog may also retain the ability to decrypt data after the live key record is removed. Cryptographic deletion claims must name this boundary.

## Decision

Generate a random profile DEK for every profile. Wrap it under an install/local KEK held outside application data/evidence archives. Derive separate field, evidence, blind-index, and event-authentication keys from the profile DEK with context-bound HKDF. Never derive the profile DEK from the install KEK.

Keep the wrapped-key catalog as a separately classified recovery asset included in each managed consistent encrypted-state archive; never include the KEK/recovery secret, unwrapped keys or checkpoint signing secret. Profile deletion first pauses and reconciles external actions, then destroys the live wrapped DEK, cancels work, deletes blind indexes/session keys, and records a non-sensitive tombstone. The UI reports managed-backup horizons until every known archive containing that wrapped DEK expires or is sanitized and warns that external snapshots/copies are outside MyCogni's inventory.

Relationship metadata and case projections receive encryption/pseudonymization proportional to sensitivity; field encryption alone is not a dossier boundary.

## Consequences

- Recovery needs the managed archive (including wrapped catalog) plus separately protected KEK/recovery material.
- Users can permanently lose a profile.
- Backup inventory and expiry become part of deletion truth.
- Rotation rewraps profile DEKs; purpose-key changes may require data re-encryption.
- Tests must prove deletion and rotation across old backups and profiles.

## Alternatives

Root-derived profile keys were rejected because they can be recreated. One install-wide DEK was rejected because a single key compromise/deletion affects all profiles. Keeping the KEK, recovery secret, unwrapped keys or checkpoint signing key inside managed data archives was rejected because it collapses separation; keeping the wrapped catalog outside the consistency protocol was rejected because it can make apparently valid backups unrecoverable.

## Security and privacy impact

The design narrows compromise and supports honest deletion, while making availability and recovery responsibility explicit. NIST cryptographic erase terminology informs the claim; implementation still requires independent review.

## Review trigger

Key provider/algorithm change, recovery redesign, shared tenancy, search over encrypted data, key-catalog retention change, or failed deletion/restore drill.
