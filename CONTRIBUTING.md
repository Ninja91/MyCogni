# Contributing

MyCogni welcomes product, legal-research, connector, security, testing, documentation, and accessibility contributions.

The repository is an architecture/specification pack entering M0 implementation. The locked Python toolchain exists, but no remover runtime, Docker image, simulator, or live connector is complete. The most valuable early work follows the dependency-gated packages in `docs/v1/WORK_PACKAGES.md`.

## Local development

Install exact `uv 0.9.26`, then use the committed environment exactly:

```bash
make bootstrap
make check
```

`make bootstrap` is frozen to `uv.lock`, the reference interpreter is pinned to CPython 3.12.12, and isolated builds are constrained by `build-constraints.txt`. Dependency changes require the explicit `make lock-update` target and review. Python 3.13 remains a separately tested compatibility target; it is not the reference lock-update environment. Do not use real PII or contact a real broker while developing or testing.

## Ground rules

1. Use synthetic data. Never paste a real person's record into an issue, test, or pull request.
2. A new connector begins in `observe` mode. Submission and verification capabilities are enabled only after contract tests and review.
3. Broker terms, privacy-law mappings, and opt-out procedures change. Every factual registry change needs a source URL, access date, reviewer, and expiry/revalidation date.
4. Do not defeat CAPTCHAs, authentication, or rate limits.
5. Keep AI optional and outside the trusted deterministic path.
6. Do not copy broker directories, product copy, fixtures, or model artifacts without an explicit license and provenance review.
7. A connector is a separate artifact. It may not be imported into the core process or inherit the core image's mounts, identity, network, or secrets.
8. No AI-generated connector, policy, legal fact, or registry change can be promoted without human review and deterministic tests.

## Proposed development workflow

- Open or select a narrowly scoped issue.
- Write an ADR for architectural changes.
- Add tests before enabling a connector capability.
- Run formatting, static analysis, unit, contract, and synthetic end-to-end tests.
- Include rollback and migration notes for stateful changes.
- Add a `Signed-off-by` trailer (`git commit -s`) certifying the [Developer Certificate of Origin](https://developercertificate.org/). The project uses DCO sign-off instead of a separate CLA during bootstrap.

## Contribution ladder

1. Documentation, synthetic fixture, or threat-case correction.
2. Sourced broker fact with access/revalidation dates.
3. Observe-only connector contract and simulator coverage.
4. Connector implementation in an isolated artifact with malicious-input tests.
5. Capability promotion record with controlled canary evidence.

The first four levels can be developed without transmitting a request. Live `submit` or `verify` promotion follows [GOVERNANCE.md](GOVERNANCE.md) and cannot receive `trusted` status from one bootstrap maintainer.

## Pull request evidence

Every material pull request should state:

- requirement IDs and threat cases affected;
- migration and rollback impact;
- exact checks run;
- source/license/provenance for facts or artifacts;
- old/new connector destinations and disclosed attribute categories;
- whether any state, external action, or user-visible claim can change.

Do not attach screenshots from real people-search records. Reproduce against the project-owned simulator and synthetic identities.

Connector-specific requirements are in [docs/06-connector-sdk.md](docs/06-connector-sdk.md).
