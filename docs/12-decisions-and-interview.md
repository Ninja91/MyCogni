# Decisions and maintainer interview

Interview recorded: 2026-07-15.

## Confirmed product decisions

| Decision | Maintainer direction | Architectural interpretation |
| --- | --- | --- |
| Initial jurisdiction | United States only | v1 publishes no support claim for EU, UK, Canada, or other jurisdictions |
| External action | Automatic | trusted, fresh connectors automatically submit plans covered by setup authorization |
| Browser automation | Comfortable with Playwright | use an isolated Playwright/Chromium runner; stop for CAPTCHA, MFA, ambiguity, or drift |
| Interface | Any is acceptable | implement CLI first for velocity and a minimal local web UI in the same early milestone |
| License | Apache-2.0 if possible | accepted; canonical license text and NOTICE are vendored in the repository |

## Automatic execution contract

“Automatic” means the user grants a scoped setup authorization during onboarding. A submission proceeds without a per-request click only when all of these remain true:

- the profile owns the request and has active authority;
- the connector capability is trusted, fresh, and not quarantined;
- the broker, destination, jurisdiction, right, and attribute categories fit the authorization;
- the identity match meets the broker-specific threshold and is not ambiguous;
- the immutable plan stays within the connector's reviewed disclosure schema;
- the broker workflow, terms, destination, and legal-policy inputs have not materially changed;
- rate, retry, idempotency, and schedule policies allow the action.

Any failed condition produces a visible task. CAPTCHA and MFA are user-completed in the isolated browser; MyCogni does not bypass them. An unknown submission outcome is investigated and is not automatically retried.

## Decisions made by the architecture

- Deployment remains single-tenant: local-lite first, cloud-small next.
- SQLite is used for one-worker local-lite; PostgreSQL is used for cloud-small.
- Optional AI can explain or draft but receives no raw PII and has no default submit capability.
- OpenClaw starts with metadata-only status, task, and custom-case-draft tools.
- Evidence keeps encrypted raw artifacts for bounded periods and produces redacted derivatives for reports.

## Remaining discovery questions

These do not block the initial architecture, but they should be answered before their associated feature is implemented:

1. Is the first release solely for the maintainer, or should onboarding target non-technical family/friends?
2. Which measurable outcome would make the first 90 days successful?
3. Are scoped email app passwords/OAuth acceptable, or should the first mail workflow create drafts only?
4. Are family profiles required in v1, and if so, adults only?
5. Which primary host should drive packaging tests: macOS laptop, home server/NAS, or cloud VM?
6. Which notification channels matter beyond the local UI and email digest?
7. Is any remote AI acceptable with redacted inputs, or must optional AI be local-only?
8. Is “MyCogni” the final public name? Its similarity to “Incogni” requires trademark/confusion review before launch.
9. When and under which GitHub user or organization should the repository be published?

## Decision protocol

Material answers become ADRs. A decision that changes disclosure, legal authority, live external actions, encryption, tenancy, or jurisdiction support requires threat-model and test-plan updates before implementation.
