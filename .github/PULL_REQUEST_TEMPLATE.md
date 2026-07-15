## Scope

Describe the narrow outcome and linked requirement/issue/ADR.

## Safety review

- [ ] Uses synthetic data only; no PII, credentials, sessions, or live evidence
- [ ] Preserves observe/prepare/approve/submit/verify separation
- [ ] Documents disclosures, destinations, authorization, and external actions
- [ ] Updates threat cases and redaction tests where applicable
- [ ] Includes migration, backup, and rollback impact where applicable
- [ ] Does not add live broker traffic to CI

## Verification

List tests, fixtures, manual checks, and known limitations.
