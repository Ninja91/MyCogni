# Independent adversarial review pack

Review date: 2026-07-15.

Five role-based reviews were run as independent critique tracks against the same repository snapshot. Reviewers were instructed to attack assumptions and return findings before seeing the principal-team synthesis. These are AI-assisted engineering reviews, not claims of independent human audit, legal advice, security certification, or user research.

| Review | Primary question | Verdict |
| --- | --- | --- |
| [ML engineering](01-ml-engineering.md) | Can optional intelligence be useful without becoming authority or leaking identity data? | do not ship a model in v1; add a typed no-authority seam and task-specific gates |
| [Backend and infrastructure](02-backend-infrastructure.md) | Can external actions survive crashes, compromise, restore, and scale-profile differences? | live automation blocked until intent journal, artifact isolation, egress, key, and auth designs are corrected |
| [Edge engineering](03-edge-engineering.md) | Can the product run intermittently on a small host without resource or local-endpoint surprises? | deterministic core fits; browser and inference require one shared heavy-work budget |
| [Product management](04-product-management.md) | What should win, what should v1 exclude, and how can product-market fit be measured? | proof-first single-adult vertical slice; do not compete on coverage count |
| [Open-source contributor](05-open-source-contributor.md) | Can strangers contribute safely without creating an abandoned or malicious connector ecosystem? | add bootstrap governance, maturity, provenance, contributor path, and public support matrix |

## Severity rubric

- **P0:** blocks any release with unattended live external actions.
- **P1:** blocks stable v1 or a public trust claim.
- **P2:** material improvement that can follow the first safety gates.
- **P3:** useful refinement or documentation debt.

## Evidence grading

- **A — empirical/primary:** peer-reviewed studies, government guidance, official technical documentation, directly inspectable repository facts.
- **B — independent field report:** transparent independent testing or neutral-community discussion; useful for hypotheses and concrete failure cases.
- **C — interested/anonymous:** vendor pages, vendor-owned communities, affiliate/SEO comparisons, anonymous reviews, or threads with promotional signals. Useful for feature discovery, never for incidence or effectiveness claims.

The user-supplied Reddit thread is Grade C: it contains valuable concrete product themes and explicit complaints, but also vendor participation, founder promotion concerns, and comments suspecting synthetic content. The architecture uses it as an interview prompt source and triangulates it with Grade A/B evidence.

## Disposition

Accepted changes are recorded in [the principal-team synthesis](../14-principal-team-synthesis.md), requirements, ADRs, diagrams, threat model, and roadmap. Residual risks are preserved rather than converted into optimistic language.
