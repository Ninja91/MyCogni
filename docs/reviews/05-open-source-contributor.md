# Independent experienced open-source contributor adversarial review

Perspective: senior maintainer reviewing contributor safety, governance, licensing, sustainability, and fork/abuse pressure.

## Verdict

Connector breadth is an attractive nuisance. Without a contributor ladder, maturity states, second-review boundary, provenance/license rules, support expectations, and revocation process, a volunteer registry will accumulate stale scripts and eventually run untrusted code with PII. Public trust must come from visible constraints, not a promise that maintainers review things.

## Findings

### P0 — One routine pull request cannot grant live authority

Maturity is per capability: `experimental`, `observe-tested`, `submission-candidate`, `trusted`, `quarantined`, `retired`. During bootstrap, a single maintainer may accept metadata or observe work but may not label live unattended submission `trusted` without a second qualified reviewer. A local experiment is visibly pre-release and excluded from support claims.

### P1 — Contributor workflow is too abstract

Publish governance, code of conduct, support rules, DCO sign-off, CODEOWNERS, issue/PR templates, a synthetic-only quickstart target, and a contribution ladder from docs/fixtures to capability promotion. Every public form warns against PII. Security reports use private advisories.

### P1 — Coverage and freshness need generated truth

Generate `SUPPORTED_BROKERS.md` from manifests. Show capability, maturity, last validation/expiry, jurisdiction/legal basis, exact disclosure categories, human steps, verification method, and recent synthetic/canary result. Never report a metadata row as equivalent to a trusted submit connector.

### P1 — Signing without governance is theater

Connector source, built artifact, registry metadata, key roles, expiry, monotonic version, revocation, and build provenance are separate facts. Emergency disable must work without silently promoting replacements. User forks and local modifications never inherit community trust.

### P1 — Data and model licensing are separate from repository code

Do not import community directories wholesale into Apache-2.0. Preserve per-entry source, access date, observed fact, applicable terms/license, reviewer, and expiry. Model artifacts have their own licenses and acknowledgements. No product UI, text, broker data, or fixtures are copied from commercial providers.

Examples illustrate the risk: the useful community “Big Ass Data Broker Opt-Out List” carries CC BY-NC-SA 4.0; it is a research source, not an Apache-2.0 dataset. Older public lists demonstrate staleness. Bulk-email removers and CAPTCHA-solving tools conflict with MyCogni's minimum-disclosure and no-bypass rules even when their source license permits reuse.

### P2 — Maintenance capacity must be a product limit

Publish best-effort/no-SLA support. Prefer a small healthy connector set to abandoned breadth. Track reviewer availability, quarantine age, and time-to-revalidate. When capacity is insufficient, retire or demote rather than leaving trusted automation stale.

## Accepted changes

Root governance/conduct/support/roadmap files, DCO policy, CODEOWNERS, public broker matrix, structured issue/PR templates, connector maturity, signed-expiring metadata ADR, and explicit data/model provenance rules.

## Sources

- [Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List)
- [Its CC BY-NC-SA 4.0 license](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List/blob/master/LICENSE.md)
- [Data Rights Protocol repository and Apache-2.0 specification](https://github.com/consumer-reports-innovation-lab/data-rights-protocol)
- [Developer Certificate of Origin](https://developercertificate.org/)
