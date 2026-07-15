# Security policy

MyCogni is designed to process unusually sensitive identity information. Security reports should not be filed as public issues when they contain an exploit, personal information, credentials, authorization documents, connector session state, or evidence captures.

Until a private reporting address is established, contact the repository owner directly through a private GitHub security advisory. Include a minimal reproduction with synthetic data only.

The GitHub advisory URL is listed in the issue-template configuration. If it is unavailable, contact the repository owner privately and disclose only the minimum required to establish impact.

## Supported versions

There is no supported release yet. The initial repository is a specification pack.

## Security expectations for contributors

- Use synthetic identities and reserved domains in fixtures.
- Never commit secrets, broker cookies, request inbox tokens, or evidence from real people.
- Treat connector changes as security-sensitive code requiring two-person review once the project has multiple maintainers.
- During bootstrap, a connector cannot become `trusted` for live unattended submission without a second qualified reviewer; a single-maintainer experiment remains visibly pre-release.
- Do not add telemetry. A future diagnostics bundle must be explicit, locally inspectable, and PII-redacted.
- Dependency and container findings rated high or critical block a release unless a documented risk acceptance has an expiry date.
- Treat prompt/model/runtime changes as code changes. Local models receive no raw PII, tools, connector capabilities, or network access.
- Do not submit malicious connector proof-of-concepts through a public pull request when they expose a real escape or egress path.

## Coordinated disclosure target

The project will acknowledge a complete report within 3 business days, provide an initial severity assessment within 7 days, and publish a fix or status update within 30 days. These are targets, not service-level guarantees for a volunteer project.
