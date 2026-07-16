# Synthetic broker simulator (SIM-001)

This directory is a deterministic, synthetic-only fixture boundary for future connector and
network-deny tests. It is not a remover, a connector, a mock of any real company, or evidence
that a personal-data request was sent or honored.

The package intentionally lives outside `src/mycogni` and never imports the trusted core. A
later connector artifact can consume the finite types in `simulator.protocol` without acquiring
database, vault, policy, authorization, or execution authority.

## What is implemented

- a seeded corpus of clearly fictional identities using only reserved `.test` mailboxes;
- canonical JSON and SHA-256 hashes for the corpus and scenario catalog;
- a caller-controlled UTC clock with no wall-clock or random fallback;
- finite scripted scenarios for happy, not found, ambiguous, CAPTCHA, MFA, rate limit,
  timeout/unknown, schema drift, partial, denied, and resurfacing behavior;
- a pure typed web boundary and optional standard-library server fixed to numeric
  `127.0.0.1`, with a bind path that performs no hostname lookup;
- an in-memory mail capture with no SMTP/IMAP client or delivery method;
- hard caps on sessions, requests, request/response bodies, evidence, and mail; and
- source guards plus golden, property, negative, and mutation tests.

The protocol fails closed on undeclared scenarios, sessions, states, transitions, methods,
routes, path traversal, authority-form paths, invalid delays, and exceeded resource budgets.
The only way time advances is an explicit `ControllableClock.advance(seconds=...)` call.

## Developer use

Run the self-contained contract suite:

```bash
uv run --frozen pytest -q tests/simulator
```

Use the pure boundary when a socket is unnecessary:

```python
from simulator import (
    ControllableClock,
    InMemoryMailCapture,
    LocalWebSimulator,
    ScenarioEngine,
    WebRequest,
)

clock = ControllableClock()
mail = InMemoryMailCapture()
fixture = LocalWebSimulator(ScenarioEngine(clock=clock), mail)
result = fixture.handle(
    WebRequest("GET", "/v1/scenarios/happy/sessions/example-session/next/start")
)
```

Golden files are `fixtures/corpus.v1.json` and `fixtures/scenarios.v1.json`. Changing a seed,
identity, scenario, transition, response, or delay changes the canonical document/hash and must
be reviewed as an explicit fixture-contract change.

## Safety boundary and nonclaims

SIM-001 contains no real-person data, real broker name or likeness, real endpoint, copied page,
selector, trademarked workflow, removal submission behavior, credential flow, Playwright runtime,
SMTP delivery, or external network client. Scenario states describe fixture observations only;
`simulated_absent` is not `verified_removed` and must never be promoted into product evidence.

Binding to loopback is defense in depth, not network isolation. Python source guards are narrow
regression checks, not an operating-system sandbox. SIM-001 does not prove DNS, IP, redirect,
TLS, proxy, alternate-protocol, or malicious-process containment.

## NET-001 handoff

NET-001 must run the simulator in a separately denied network namespace/container or equivalent
CI boundary, allow only the exact numeric loopback listener, and demonstrate that DNS plus direct
IPv4/IPv6, private/link-local/metadata, redirect, proxy, WebSocket, QUIC, DoH, and alternate
protocol attempts fail. It should inject real socket/client mutations, prove the deny policy is
outside connector control, and emit only bounded PII-safe diagnostics. The server factory keeps
its host non-configurable so NET-001 has one explicit local exception to inspect.

## Traceability and rollback

| Concern | Evidence |
| --- | --- |
| `SIM-001`, `TEST-02` | golden/property scenario and corpus tests under `tests/simulator/` |
| `BR-03`, `RQ-07`, `RQ-11` fixture vocabulary | absent, ambiguous, challenges, and unknown outcome remain distinct states |
| PII/egress threats | reserved-domain, corpus-hash, path, cap, nondeterminism, and socket-import mutations |
| Trusted-core/connector separation | AST import assertion and standalone package boundary |

There is no migration or persistent runtime state. Rollback is a code revert: remove the
standalone `simulator/` package and `tests/simulator/`; no database, key, journal, mail, or broker
cleanup exists or is implied.
