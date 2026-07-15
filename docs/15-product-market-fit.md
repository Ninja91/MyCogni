# Product-market-fit strategy

## Wedge

MyCogni is not positioned as an Incogni clone or a promise of more brokers. Its initial wedge is auditable, proof-first, recurring U.S. people-search removal for technically comfortable self-hosters who value local custody and minimum disclosure.

Job to be done:

> Show me where my high-risk people-search information is exposed, remove it with the least disclosure possible, prove what changed, and keep checking—without becoming another company holding my identity dossier.

## Initial customer and exclusions

Primary: U.S.-based developer, security/privacy professional, homelabber, or technically comfortable privacy user willing to run Docker periodically or a small single-tenant VM.

They distrust centralized identity aggregation; care about specific high-impact sites more than a headline count; and will trade some setup effort for evidence, custody, and inspectability.

Not the first primary segment: non-technical mass market, family administrators, minors/guardians, businesses, or people in immediate high-risk safety situations. The latter deserve rapid-response human support and a higher reliability bar than an early volunteer project can offer.

## Switching thesis

| Alternative | Why users choose it | MyCogni must prove |
| --- | --- | --- |
| DIY opt-outs | most private and effective for a small set; no subscription | recurring automation reduces burden without broadcasting PII |
| Low-cost batch service | easy and affordable | local custody plus evidence justifies Docker effort |
| High-touch commercial service | breadth, human escalation, polished reports | honest capability matrix and proof offset smaller breadth |
| Do nothing | zero setup and disclosure | accurate exposure preview creates enough benefit without fear marketing |

“Free and open source” is insufficient. Hosting, maintenance, key recovery, and connector failures are costs. The project must beat DIY on recurring time and SaaS on trust.

## Product principles derived from evidence

1. Lead with exposure preview and exact proof, not a request counter.
2. Show reason, owner, next action, and next date for every nonterminal state.
3. Preserve `not_checked`, `no_match`, `ambiguous`, `blocked`, and `inconclusive`; never hide denominators.
4. Make alias and historical-attribute handling a first-class single-person capability.
5. Publish a per-capability support matrix and connector freshness.
6. Default to observe-before-disclose for public sources; show every exception.
7. Explain offboarding: pause, export, backup, key/catalog deletion, and residual backup windows.
8. Never promise spam elimination, total internet deletion, legal enforcement, or permanent absence.

## Experiments and stop/go gates

### E1 — Exposure preview pilot

Participants: 10–15 target users. No external removal requests.

Hypotheses:

- 80% finish local setup and encrypted profile creation within 15 minutes;
- at least 95% of auto-threshold candidates are confirmed by the user;
- at least 70% see one useful accurate exposure;
- zero name-only findings become confirmed automatically.

If precision misses, do not add sites; improve matching and ambiguity UX.

### E2 — Proof comprehension

Participants see timelines for submitted, acknowledged, asserted, single absence, corroborated absence, blocked, and resurfaced cases.

Gate: nobody identifies acknowledgement/HTTP success as verified deletion; at least 80% can state the next action unaided. Failure blocks automatic-submission beta because status design is unsafe.

### E3 — Switching interviews

Interview at least five users from each relevant path: Incogni/DeleteMe/Optery/EasyOptOuts or similar commercial service, and manual DIY. Grade statements by source interest. Identify whether custody, proof, specific brokers, recurrence, custom cases, or price is the switching trigger.

Hypothesis: at least 40% of the technical target segment will install Docker for local custody/evidence. If not, packaging is a product blocker, not a marketing problem.

### E4 — Disclosure comprehension

For every automatic-action pilot, ask the participant to identify destination, purpose, and released field categories before enabling setup authorization. Gate: 100% comprehension; a miss forces onboarding redesign.

### E5 — Twelve-week recurring beta

Measure:

- day-30/day-90 active scheduler retention;
- confirmed-match precision by connector;
- `verified_removed` rate by method and 30/60/90-day cohort;
- asserted-but-unverified age;
- median manual minutes per active month and per verified outcome;
- resurfacing and time-to-next-action;
- connector quarantine/freshness;
- disclosed attribute categories per verified outcome;
- backup/restore confidence and offboarding completion.

Initial hypotheses: under ten manual minutes per active month and at least 60% day-90 scheduler retention. These are learning targets, not public effectiveness claims.

### E6 — Contributor funnel

A first-time contributor should run synthetic connector tests in under 30 minutes; a connector PR should expose provenance, disclosure diff, maturity, and expiry automatically; reviewer handling should remain under 45 minutes for a clean observe-only proposal.

If review capacity fails, reduce supported breadth.

### E7 — Optional local-assist shadow test

Post-v1 only. Compare deterministic reason-code UI with one opt-in advisory task. Gate: at least 30% review-time reduction, no change to policy/status/disclosure/false-positive behavior, no PII canary leak, all outputs validated/cited, and acceptable resource use. Otherwise retain the null adapter.

## North-star and guardrail metrics

North-star: verified exposure reduction per user-month with method/denominator visible.

Guardrails: match precision, PII categories disclosed per verified outcome, manual minutes, unexplained-state count, stale connector count, unknown external outcomes, restore success, and zero PII leakage. Broker count, requests sent, and stars are diagnostic only.

## Evidence caveats

The Consumer Reports and PETS studies have different methods and limitations; neither predicts MyCogni. Vendor pages document their features, not comparative truth. Reddit reveals language and concrete failure scenarios but includes anonymous, promotional, and synthetic-content risk. The source grading in `docs/reviews/README.md` applies to every roadmap claim.
