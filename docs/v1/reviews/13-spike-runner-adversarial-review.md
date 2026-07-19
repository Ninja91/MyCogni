# SPIKE-RUNNER adversarial review

Reviewed implementation: integration commit `93700aa` (boundary-lane source
commit `1a40bb6`).

Current verdict: **ACCEPT at source/code-review level** for exact integration
commit `b2bfa15` — zero open P0, P1 or P2 after final product/state,
state-consistency and backend/data-consistency review. SPIKE-RUNNER remains
canonically `IN_PROGRESS`; source acceptance does not establish persistent
durability, connector OCI containment or authenticated package acceptance.

`Sol` is a role label only. These were independent-prompt AI reviews, not model
attestation, security certification or the qualified human review required at
the v0.x-to-v1 gate.

## Principal product/state review

The focused runner and safety suite passed on Python 3.12 and 3.13, but the
review rejected the contract:

| Severity | Finding | Required disposition |
| --- | --- | --- |
| P1 | The trusted core accepted connector result/retry combinations that contradict the action capability. An `observe` action could commit broker acknowledgement, and a connector could request retry after a possible effect or uncertain outcome. | Define and exhaustively test an exact capability/result/next-action matrix. Observe/prepare cannot claim send, receipt, acknowledgement or completion. Post-effect uncertainty is reconciled by the trusted core, never by connector-selected retry. Every denial must preserve state. |
| P1 | Per-mailbox evidence limits existed, but active mailbox count, installation-wide evidence, committed-result retention and terminal records were unbounded. | Add global quotas and backpressure plus finite collection/tombstone retention and concurrency-safe GC. Prove saturation, months-idle expiry, uncollected-result cleanup and replay behavior. |
| P1 | Arbitrary connector bytes were described as ciphertext although the core verified only digest and size; tests used plaintext. | Treat the connector envelope as untrusted sensitive input unless authenticity is verified. A durable adapter must immediately wrap it under a mailbox-owned storage key, authenticate on read and prove raw PII does not enter persistence, logs, exceptions, snapshots or terminal state. |
| P2 | Public snapshots exposed binding information without scoped authority. | Make inspection core-only or require an operation-scoped credential. |
| P2 | `result_committed` conflated mailbox-local collection state with externally meaningful action status. | Separate protocol/collection axes and forbid rendering it as broker or case status. |
| P2 | Wall-time bounds were metadata only. | Keep the nonclaim explicit and separate queue TTL, execution wall time and result-retention deadlines until PF-002/runtime enforcement exists. |

## Principal backend/infra review

The reviewer reproduced four additional P1 defects against unchanged code.
Mypy and 65 focused tests passed on Python 3.12.12 and 3.13.11, demonstrating
that the gaps were absent from the suite:

| Severity | Finding and reproduced evidence | Required disposition |
| --- | --- | --- |
| P1 | Time was read before acquiring the repository lock. A claim blocked behind that lock still succeeded after the real clock reached its deadline: `actual_clock_at_deadline True claim_succeeded True state claimed_once`. | Read and validate the clock inside the same transaction that mutates the record; regress every deadline transition under lock contention. |
| P1 | Collection material could equal the action key, so connector-visible material also authorized a core collection operation: `connector_received_collection_secret True connector_core_role_succeeded abandoned`. | Enforce pairwise role separation among action, claim, result and collection credentials. |
| P1 | `response_bytes` did not bound the canonical result envelope. A 232-byte result committed under a one-byte response budget. | Define and enforce aggregate result-envelope plus evidence accounting at commit. |
| P1 | Global admission, terminal retention and GC were unbounded; collected, abandoned, expired and committed records had no finite deletion path. | Add installation quotas, backpressure, bounded committed-result retention and authenticated purge/tombstone semantics with concurrent GC tests. |
| P2 | `collect()` destroyed the authoritative bundle before durable consumer acknowledgement. | Use an acknowledgement/two-phase collection contract with explicit crash edges. |
| P2 | `offer`, `snapshot` and `expire_due` shared one uncredentialed surface despite claimed core/connector separation. | Split typed faces or require exact operation-scoped core authority. |
| P2 | Queue lifetime, execution wall time and committed-result retention were not distinct or enforced. | Narrow the claim and model separate finite clocks before runtime acceptance. |

## Positive evidence and nonclaims

The initial slice does positively cover immutable binding, single-winner claim
and result commit, replay rejection, sanitized representations, fail-closed
crash transitions and explicit package/import boundaries. It does not claim
durable restart recovery, restore epochs, OS hostile-code containment,
multi-architecture behavior, artifact provenance, host-memory zeroization or a
real browser/connector runtime.

Every P1 must be fixed and returned to independent backend, product and
architecture/state-machine re-review. Real OCI runtime acceptance additionally
requires a runner-specific image and containment probes; PF-002 proves the
trusted-core packaging skeleton, not the future connector runner.

## Remediation chronology

The first remediation (`be06fac`) added an exhaustive capability/result policy,
transaction-time sampling, four-role credentials, aggregate quotas, wrapped
sensitive evidence, scoped interfaces, two-phase collection and bounded GC. It
passed 787 focused tests on each Python runtime but was independently rejected
for maintenance-role collision, an unusable default maintenance authority,
silent deletion of unacknowledged committed results, plaintext result metadata,
stale snapshot timing and incomplete active-material accounting.

The second remediation (`e789558`) made maintenance authority mandatory and
globally role-disjoint, retained unacknowledged results for reconciliation,
wrapped complete result envelopes, added time-aware snapshots and a 16 MiB
installation claim-material budget, advanced GC high-water state and preserved
tombstone replay barriers under capacity. Reviewers then found two bounded P2s:
falsey explicit storage keys were silently replaced, and a predictable plaintext
payload digest remained outside encryption.

Commit `ae31e6a` closed those findings with explicit `None`-only key generation,
AEAD-encrypted plaintext digests, randomized-ciphertext hashes and keyed semantic
MACs. Architecture review then rejected an authenticated evidence object that
could be moved under an alias dictionary key. Commit `8fa113c` bound repository
slots, authenticated object IDs, result references and complete action bindings.

Two independent consistency reviews then reproduced a final gap: evidence could
be deleted after commit, so collection returned a result referencing absent
evidence; deadline paths could also mutate time/state before discovering retained
material corruption. Final commit `b2bfa15` adds an authenticated committed
manifest over the exact sorted evidence-ID set/count, complete action binding and
wrapped-result storage digest. Every record and maintenance path now validates all
slots, result references, metadata and manifest before clock, expiry, clearing,
counter, mailbox or collection-state mutation. Missing, extra, moved, swapped,
substituted or deadline-tampered material returns `INTERNAL_UNCERTAINTY` without
mutation; acknowledgement cannot erase inconsistent committed material.

Final exact-commit verdicts:

| Review hat | P0 | P1 | P2 | Verdict |
| --- | ---: | ---: | ---: | --- |
| Product/operator/state | 0 | 0 | 0 | ACCEPT |
| State consistency | 0 | 0 | 0 | ACCEPT |
| Backend/data consistency | 0 | 0 | 0 | ACCEPT |

The final lane suite passed 843 runner/SDK/safety tests on Python 3.12.12 and
3.13.11. The merged repository subsequently passed 1,412 tests plus every guard
on both locked runtimes. The first Python 3.13 attempt was invalidated by
concurrent reviewer recreation of the shared virtual environment; after all
reviewers stopped, the isolated sequential rerun passed and is the counted
evidence.
