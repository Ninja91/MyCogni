# Contributing

MyCogni welcomes product, legal-research, connector, security, testing, documentation, and accessibility contributions.

## Ground rules

1. Use synthetic data. Never paste a real person's record into an issue, test, or pull request.
2. A new connector begins in `observe` mode. Submission and verification capabilities are enabled only after contract tests and review.
3. Broker terms, privacy-law mappings, and opt-out procedures change. Every factual registry change needs a source URL, access date, reviewer, and expiry/revalidation date.
4. Do not defeat CAPTCHAs, authentication, or rate limits.
5. Keep AI optional and outside the trusted deterministic path.

## Proposed development workflow

- Open or select a narrowly scoped issue.
- Write an ADR for architectural changes.
- Add tests before enabling a connector capability.
- Run formatting, static analysis, unit, contract, and synthetic end-to-end tests.
- Include rollback and migration notes for stateful changes.

Connector-specific requirements are in [docs/06-connector-sdk.md](docs/06-connector-sdk.md).
