# Interactive walkthrough adversarial review

Final source target: integration commit `c7f6bde`.

Verdict: **ACCEPT at source/offline level** — zero open P0, P1 or P2 findings.

This review does not claim browser-backed responsive, keyboard, screen-reader or
visual WCAG verification, remote-link availability, GitHub Pages publication, or
model identity. Those remain separate acceptance evidence.

## Rejected first revision

The first independent static audit rejected the site with two P1s and seven P2s:

- implementation status was stale and could drift without a Pages truth check;
- most story states existed only in JavaScript despite a complete-no-script claim;
- mobile navigation disappeared, ARIA state/atomicity was incomplete, dark focus
  contrast was weak, deployment/current status was compressed, the synthetic success
  card was insufficiently prominent, Pages validation was shallow and meta CSP could
  not provide a framing control.

The first remediation closed the UI/source defects but was rejected again because it
blurred integrated packages with not-started spikes, only checked the M0 aggregate row,
and still called an abridged no-script narrative complete. The guard's initial mutation
suite also covered less than the guard claimed.

## Accepted disposition

- Dated status now links the completion matrix and binds exact GOV-001, NET-001,
  grouped spike and SQLite-durability states to their authoritative rows.
- Deployment wording distinguishes integrated evidence, unaccepted work and the
  local-lite target; the guard reads and pins the linked deployment contract.
- No-script language now promises an essential overview, not a complete duplicate,
  and requires substantive custody, verification, authority, failure, release and
  current-status concepts.
- Mobile chapter navigation remains available; active navigation exposes
  `aria-current`; dynamic panels are atomic polite regions with correct control roles.
- Dark surfaces use a high-contrast lime focus treatment; the fictional console has
  an explicit illustrative/synthetic badge.
- The README records that a meta CSP is not a `frame-ancestors`/clickjacking control.
- Offline validation checks IDs/fragments, local assets, repository links, status and
  deployment truth, no-script substance, ARIA/focus/navigation invariants and the
  social-card provenance hash.
- Eight mutation tests attack stale text, missing assets, matrix status drift, hollow
  fallback content, synthetic-badge removal, atomic-region weakening, mobile-nav
  removal and CSP overclaim.

Final reproduced evidence: site guard passed, eight mutation tests passed,
`node --check site/app.js` passed and the worktree was clean.
