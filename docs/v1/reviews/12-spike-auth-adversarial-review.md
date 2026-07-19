# SPIKE-AUTH adversarial review

Initial target: integration commit `1931d20`.
First remediation target: integration commit `ff428c1`.
Final accepted target: integration commit `030caed`.

Current verdict: **ACCEPT at source/code-review level** — zero open P0, P1 or P2
findings after independent architecture/correctness, backend/concurrency and
product/operator review of exact commit `030caed`. SPIKE-AUTH stays canonically
`IN_PROGRESS` and does not promote `AUTH-001`, `AUTH-002`, `AUTH-003` or
`VFY-AUTH-001` without authenticated acceptance and the durable production work.

Multiple independent correctness/recovery review attempts were stopped by an automated
content filter before returning a code verdict. That was neither acceptance nor a
finding. Later independent lanes completed all three required code-review hats; no
Trusted Access enrollment was used or required.

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

## First remediation disposition

Commit `ff428c1` closed the initial sibling-recovery, short recovery lifetime,
identifier-only authority, canonical recovery binding, mutable-alias, malformed-input
and structural-retention findings. Forty integrated auth/domain tests passed on the
locked Python 3.12 runtime; the implementation lane also reproduced 952 full tests and
all repository guards on both locked runtimes. Those results establish implementation
evidence, not independent acceptance.

The independent product/operator and backend/concurrency re-reviews both rejected the
remediation:

| Severity | Finding | Required disposition |
| --- | --- | --- |
| P1 | Privileged methods accepted a caller-constructed `AuthorityGrant` whose random evidence ID had never been produced by a successful step-up. A valid session plus public bindings could renew recovery, rebootstrap or globally revoke. | Persist immutable provenance only after successful step-up consumption; require exact binding equality and one-use/concurrent use; reject random, unconsumed, expired, exhausted, revoked and crash-consumed evidence. |
| P1 | Initial bootstrap exchange returned recovery only in process memory. The operator-channel transcript later recovered by reading `exchange.recovery` directly, so the demonstrated operator never received the credential needed for recovery. | Hand initial recovery through the reviewed all-or-nothing operator channel, support interrupted redisplay, and make the retained transcript feed recovery only from that completed handoff. |
| P1 | The one reprovision root was consumed by the first recovery-expiry cycle and never rotated. A second long idle/expiry period had no supported recovery route. | Rotate and hand off a fresh reprovision capability, or define an equally explicit locally authorized re-enrollment contract; prove two consecutive expiry/reprovision cycles and warn before consuming the current offline route. |
| P2 | Root setup used set equality and accepted an extra duplicate purpose/handle despite claiming exactly one root per purpose. | Require exactly three records with unique purposes and handles before mutating installation state. |
| P2 | Used-grant replay identifiers accumulated forever and were absent from garbage collection/count evidence. | Replace the append-only set with expiry-bearing provenance/tombstone state and collect it only after its replay horizon. |
| P2 | Garbage collection changed an expired recovery denial into unknown proof while operator guidance still suggested retrying. | Make unknown/retired-code guidance safe for both cases, or retain a bounded non-secret tombstone; expose remaining attempts only when genuinely known. |

The backend reviewer independently reproduced the grant-provenance bypass on Python
3.12 and 3.13. The product reviewer reproduced the missing initial handoff and repeated
reprovision dead end. No P1 is dispositioned by the green implementation suite.

## Subsequent remediation cycles and final disposition

The next integrations (`0df7343`, `5cc13e6`, `87d6042`, `f9f24af`, `69b42fa`,
`fcec6ce`) closed grant provenance, code-only reprovision, complete initial and
replacement handoff, two consecutive copied-string expiry/reprovision cycles,
malformed-grant denial, informed confirmation and bounded ceremony retention.
Independent reviewers continued to reject intermediate revisions when they found
that:

- generic service and later direct store calls could still authorize destructive
  reprovision without the operator ceremony;
- a service-local proof issuer was callable by the same alternate adapter;
- foreign service/composition rebinding over the same store bypassed the intended
  authority owner; and
- installation initialization could overwrite root handles or swap operator and
  service identities across installations.

Final commit `030caed` moves reprovision proof registration, validation, one-use
consumption, TTL/capacity/tombstone retention and garbage collection into the exact
atomic store boundary. Trusted setup binds one globally disjoint namespace across
root, operator and service identities; generic exchange categorically rejects
reprovision; confirmed exchange verifies exact store/service/installation/bootstrap
provenance and burns the proof before root transition. Collision, decline, replay,
concurrency and post-proof crash paths fail closed before unrelated authority mutates.

The operator path retains an all-or-nothing initial session/recovery handoff, recovery
from the copied displayed string, two copied-string-only reprovision rotations,
explicit destructive consequences, decline preservation, interrupted-handoff
redisplay guidance and truthful purpose/capacity messages without credential leakage.

Final exact-commit verdicts:

| Review hat | P0 | P1 | P2 | Verdict |
| --- | ---: | ---: | ---: | --- |
| Architecture/correctness | 0 | 0 | 0 | ACCEPT |
| Backend/concurrency/OSS | 0 | 0 | 0 | ACCEPT |
| Product/operator | 0 | 0 | 0 | ACCEPT |

The final focused suite passed 57 tests on both Python 3.12.12 and 3.13.11. Reviewers
also ran direct store, cross-service, cross-installation, collision, replay,
concurrency, crash and operator-output probes not represented by the original green
suite.

## Positive evidence retained

The review found the redacted credential rendering, fixed-size digest comparison,
finite purpose/scope map, one-use challenge handling, UTC/rollback checks and explicit
non-production browser/durability/host exclusions to be sound directions. Focused
product-review checks passed on Python 3.12 and 3.13, but they did not make the four
semantic failures safe.

Durable restart, browser, real terminal, host-secret storage, hostile same-process
introspection and multi-process behavior remain explicit nonclaims after this
source-level acceptance.
