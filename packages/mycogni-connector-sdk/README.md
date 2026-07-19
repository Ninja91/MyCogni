# MyCogni connector SDK boundary

This separately buildable package freezes the protocol-version-1 Pydantic wire schemas shared by
the trusted core, connector registry, and isolated runners. It depends on Pydantic for parsing and
schema generation, but never depends on or imports the trusted `mycogni` package.

The schemas validate representation only. A valid manifest is not trusted, a valid action is not
authorized, a declared runtime boundary is not enforced, and a valid result is not evidence that a
request was sent or personal data was removed. Artifact signatures, revocation, authority,
dispatch permits, sandboxing, egress, cryptography, mailbox storage, and outcome inference belong
to later work packages. This package performs none of those operations.

## Version and compatibility policy

- `schema_version` and `protocol_version` are exactly `1`. Unknown versions fail closed.
- Version 1 models are strict, frozen, and reject undeclared fields. This prevents a producer from
  silently relying on an extension an older consumer ignores.
- Additive or semantic changes require a new protocol/schema version unless every version-1
  producer and consumer can prove the old canonical JSON meaning is unchanged.
- Readers must validate before dispatch or ingestion. They must not coerce values, infer authority
  from validation, or retry an unknown action merely because a result failed validation.
- Schema snapshots are reviewed artifacts. A snapshot change requires compatibility analysis and
  a work-package/ADR reference; updating a snapshot alone is not acceptance.
- Timestamps are aware UTC instants. IDs are opaque RFC 4122 UUIDv4 values. Origins are exact
  canonical HTTPS origins and never contain userinfo, paths, queries, fragments, IP literals, or
  wildcards. A trailing slash is not canonical. Disclosure destinations are canonical hostnames
  only and must equal the hostname of an allowed origin; the origin's optional non-default port is
  enforced by the origin allowlist and is deliberately not duplicated in disclosure summaries.
- Evidence crosses this schema only as a bounded mailbox object UUID, SHA-256 ciphertext digest,
  and byte count. The aggregate evidence byte count is capped, not merely each item. Optional
  external references are small base64url-safe opaque tokens, never free-form broker content. No
  version-1 model exposes a filesystem-path field.

The typed result and reason vocabularies describe facts about one connector attempt across
observe, prepare, submit, poll, and verify capabilities. Preparation, transport receipt, broker
acknowledgement, processing, partial response, denial, and a broker assertion remain distinct.
`broker_asserted_complete` records only an external assertion. It never permits a connector to
claim MyCogni's independently evaluated removal-verification state.

After an intentional reviewed schema change, regenerate the human-readable snapshots with
`python scripts/generate_schema_snapshots.py` from this package directory. Tests fail on any
unreviewed drift.
