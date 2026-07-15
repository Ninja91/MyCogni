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
| Public repository | Push after adversarial review with a detailed README | intended public repository under the authenticated GitHub account; publishing status recorded in the audit |

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
- Stable v1 officially supports one consenting adult per installation; profile isolation remains in the domain for later household support.
- SQLite is used for one-worker local-lite; PostgreSQL is used for cloud-small.
- Connectors are separate digest-pinned artifacts and all egress crosses a fenced policy gateway.
- External action uses immutable intents, separate attempts, and explicit unknown outcomes rather than exactly-once claims.
- Optional AI is absent from v1; a future local adapter returns untrusted suggestions, receives no raw PII/tools/authority, and can never submit.
- OpenClaw starts with metadata-only status, task, and custom-case-draft tools.
- Evidence keeps encrypted raw artifacts for bounded periods and produces redacted derivatives for reports.

## Remaining discovery questions

These do not block the initial architecture, but they should be answered before their associated feature is implemented:

1. Should preview-alpha onboarding optimize first for the maintainer's macOS laptop, a NAS/home server, or both?
2. Are scoped email app passwords/OAuth acceptable in guided beta, or should it create drafts only?
3. Which 2–5 U.S. people-search workflows should be evaluated first, after terms/legal/source review?
4. Which notification channels matter beyond the local UI and a PII-free digest?
5. Which qualified reviewers can cover cryptography, connector isolation, and U.S. legal posture before live beta?
6. Is “MyCogni” the final public name? Its similarity to “Incogni” requires trademark/confusion review before stable launch.
7. Which cloud/VM, ingress identity provider, KMS, and evidence store should be the cloud-small reference?
8. After v1 metrics exist, is one local advisory reply-triage experiment worth its model/runtime/license/resource cost?

## Decision protocol

Material answers become ADRs. A decision that changes disclosure, legal authority, live external actions, encryption, tenancy, or jurisdiction support requires threat-model and test-plan updates before implementation.
