# MyCogni connector SDK boundary

This separately buildable package contains typed, declarative connector manifest and
message-envelope records. It has no dependency on the trusted `mycogni` core and contains no
connector runner, transport client, filesystem access, network access, cryptography, validation,
or deployment orchestration.

The runtime-boundary record documents mandatory deny-by-default properties. It is not a sandbox
implementation or security boundary. Container/runtime enforcement belongs to later egress and
runner work packages and must satisfy ADR-0003 and ADR-0008.

The record fields are intentionally minimal, unvalidated declarations until CT-001 freezes the
versioned cross-lane contracts and RUN-001 supplies enforcement. The schema offers no explicit
filesystem-path field. It declares an opaque mailbox object ID, a ciphertext digest, and a byte
count whose bounds must be enforced by the mailbox/runtime. No consumer may treat these dataclasses
as validated authority, origin, budget, digest, expiry, or path-safe values.
