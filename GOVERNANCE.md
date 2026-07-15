# Governance

MyCogni uses maintainer-led governance during bootstrap. Governance is designed to move a personal project forward while preventing one routine connector change from silently acquiring authority over user identity data.

## Roles

- **Project maintainer:** sets roadmap priority, accepts ordinary changes, publishes releases, and handles emergencies.
- **Security owner:** approves changes to keys, authentication, connector isolation, egress, external actions, evidence semantics, and release exceptions.
- **Policy owner:** reviews jurisdiction and authorization facts; this role does not provide legal representation.
- **Connector reviewer:** reviews provenance, disclosure, destinations, fixtures, maturity, and canary evidence for a capability.
- **Contributor:** proposes code, facts, research, tests, documentation, or design changes under the contribution rules.

One person may hold several roles during bootstrap, but the repository must show which review was independent and which was a bootstrap exception.

## Decision classes

| Change | Decision record | Minimum approval |
| --- | --- | --- |
| Documentation or synthetic test with no boundary change | pull request | maintainer |
| New broker fact or observe-only connector | sourced manifest + tests | maintainer or connector reviewer |
| Architecture, privacy, security, legal-authority, tenancy, or evidence change | ADR + threat/test updates | maintainer and named owner |
| First promotion to live `submit` or `verify` | promotion record + canary evidence | two qualified reviewers |
| Emergency quarantine/revocation | signed incident/revocation record | any maintainer immediately; retrospective review |

During the single-maintainer period, a connector cannot be labeled `trusted` for unattended live submission without a second qualified reviewer. The maintainer may run an explicitly labeled local experiment, but it is `submission-candidate`, opt-in, and excluded from stable-release claims.

## Connector maturity

`experimental` → `observe-tested` → `submission-candidate` → `trusted` → `quarantined` or `retired`.

Maturity is per capability. A connector can remain trusted for `observe` while its `submit` capability is quarantined. Expired facts automatically lose unattended authority. User-modified connectors never inherit community trust.

## ADR and dissent policy

Material decisions use the ADR template in `docs/adr/`. The author records considered alternatives, security/privacy impact, operational consequences, and review triggers. Substantive dissent is preserved in the ADR or principal-team synthesis rather than erased after a decision.

## Release authority

The maintainer cuts releases only after the documented gates pass. Critical/high findings require a fix or a public, expiring risk acceptance with owner and review date. No release may weaken the safety invariants in `AGENTS.md` without a new accepted ADR.

## Conflicts and conduct

Technical disputes are resolved from requirements, threat evidence, tests, and ADR consequences. Conduct issues follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). The maintainer may remove malicious connectors, revoke signing trust, restrict participation, or privately handle a report when user safety or sensitive data is at risk.

## Project changes

Governance changes require a pull request open for at least seven days once the project has regular external contributors. During bootstrap, the maintainer may update governance directly but must explain the change in the commit or ADR.
