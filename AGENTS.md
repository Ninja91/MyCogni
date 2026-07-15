# Implementation guidance for coding agents

Read `README.md`, `docs/02-requirements.md`, `docs/03-system-architecture.md`, `docs/05-security-privacy-threat-model.md`, and relevant ADRs before changing code.

Non-negotiable rules:

- Never use real PII in tests, fixtures, logs, prompts, issues, or documentation.
- Do not add live broker traffic to CI.
- Preserve observe/prepare/approve/submit/verify capability separation.
- Do not mark a case verified removed from an HTTP success or broker assertion.
- Do not let connectors access the database, full vault, reusable core credentials, or arbitrary egress.
- Do not bypass CAPTCHAs, MFA, terms changes, or rate limits.
- Do not make remote AI a core dependency or send it raw PII.
- Add or update requirement traceability, threat cases, migrations, rollback notes, and documentation with material changes.
- Use synthetic reserved domains such as `.test`, `.example`, and `.invalid`.

If a requested change would weaken a safety invariant, stop and propose an ADR rather than implementing it silently.
