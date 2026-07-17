# SPIKE-AUTH adversarial review

Initial target: integration commit `1931d20`.

Current verdict: **REJECT** — zero P0, four P1 findings plus operator/accessibility
P2s from the product/operator review. Security/recovery and backend/concurrency review
remain required after remediation. SPIKE-AUTH stays `IN_PROGRESS` and does not promote
`AUTH-001`, `AUTH-002`, `AUTH-003` or `VFY-AUTH-001`.

The security/recovery agent prompt was twice stopped by an automated content filter
before returning a code verdict. That is neither acceptance nor a finding; the review
must be rerun with an available independent lane.

## Initial findings

| Severity | Finding | Required disposition |
| --- | --- | --- |
| P1 | Two bootstrap exchanges could leave sibling recovery credentials. Recovering with one did not invalidate the other's actor-epoch authority, so the stale sibling could recover again and revoke the just-issued session. | Require exact current actor epoch and atomically burn every actor recovery record before issuing the replacement; add the sibling-recovery regression. |
| P1 | Session defaulted to 30 minutes, recovery to 24 hours and all TTLs were capped at seven days, although local-lite may sleep for months. After expiry, an uncredentialed repeat bootstrap still succeeded. | Define an offline recovery lifetime/renewal/storage decision suitable for sporadic operation; forbid ordinary rebootstrap after initialization and document total-loss/reprovision authority. |
| P1 | `begin_bootstrap` and `revoke_all` accepted actor/profile identifiers without a root/composition capability, authenticated session, recovery proof or step-up. TTY presence was not authorization. | Introduce an explicit unforgeable local root/composition authority and/or exact authenticated recovery/step-up contract. Identifier knowledge alone must never initialize/reinitialize or globally revoke authority. |
| P1 | The retained transcript described bootstrap exchange and step-up behavior the TTY entrypoint did not execute; leak tests wrapped an unrelated exception rather than the real disclosure path. | Generate a redacted retained transcript from one executable end-to-end synthetic ceremony and assert real entrypoint stdout/stderr behavior. |
| P2 | Terminal disclosure lacked scrollback/save warning, recovery did not announce old-session invalidation, denial strings lacked safe guidance, headless IDs/no-echo/SSH/container/interrupted-output procedures were unclear, and expired volatile records had no bounded cleanup. | Make the operator contract finite and testable or narrow it; add bounded retention/cleanup evidence. |

The independent backend/concurrency/OSS review also rejected the initial revision and
added these findings:

| Severity | Finding | Required disposition |
| --- | --- | --- |
| P1 | The recovery port validated scalar actor/profile inputs but stored caller-constructed session/recovery records after changing only epoch, allowing cross-bound authority through an alternate caller. | Canonically build replacement records from the consumed recovery actor/profile; reject cross-bound inputs and test the port directly. |
| P2 | Mutable record booleans/state were incompletely validated and store methods exposed mutable internal record objects. | Validate exact field types and return immutable copies/snapshots or keep mutation entirely private; test alias mutation. |
| P2 | `issue_step_up` indexed the purpose map before validating public purpose/scope types, leaking `KeyError` for malformed input. | Validate public domain types first and return a deliberate validation/typed result. |
| P2 | The digest-retention test projected only digest fields, so it would remain green if raw credentials were later retained elsewhere. | Structurally inspect the complete store graph or constrain storage representation and prove no raw credential/sensitive value is retained. |

## Positive evidence retained

The review found the redacted credential rendering, fixed-size digest comparison,
finite purpose/scope map, one-use challenge handling, UTC/rollback checks and explicit
non-production browser/durability/host exclusions to be sound directions. Focused
product-review checks passed on Python 3.12 and 3.13, but they did not make the four
semantic failures safe.

Every P1 must be fixed and independently re-reviewed by the required three hats before
the spike can receive code-level acceptance.
