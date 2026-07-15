# Product brief

## Problem

People-search sites and non-public data brokers continuously collect and redistribute identity information. Exercising deletion, suppression, access, and sale/sharing opt-out rights is repetitive, slow, inconsistent, and frequently designed around different forms, inboxes, identity checks, and deadlines. Commercial removal services reduce effort but require users to give another centralized company a high-value identity profile and often expose too little evidence about what was found, sent, or actually removed.

## Vision

MyCogni is a privacy-preserving personal operations system for data rights. It should let a person or authorized household run recurring removal work from infrastructure they control, understand every disclosure and outcome, and extend coverage through a safe community connector ecosystem.

## Initial user

A technically comfortable individual in the United States who can run Docker locally, wants automatic recurring monitoring and removal through trusted connectors, and accepts explicit intervention when a workflow becomes ambiguous or changes materially. The architecture must not prevent later non-technical packaging, but v1 intentionally supports the United States only.

## Product principles

1. **Local custody by default.** Centralizing complete identity profiles creates the very risk the product is meant to reduce.
2. **Evidence over activity.** Counts of covered brokers and sent requests are inputs, not outcomes.
3. **Progressive automation.** Observe, prepare, approve, submit, and verify are distinct capabilities.
4. **Minimum necessary disclosure.** Release only the attributes a reviewed broker workflow requires.
5. **Explain every status.** Pending work must show the blocking reason, next action, owner, and date.
6. **Continuous but sporadic.** The system should sleep cheaply and catch up safely after being offline.
7. **No automation theater.** Ambiguous matches, CAPTCHAs, identity checks, and custom disputes become explicit user tasks.
8. **Community-maintained facts expire.** Broker procedures require provenance and scheduled revalidation.
9. **Assistants are guests.** OpenClaw and AI integrations receive narrow, revocable capabilities—not the vault.
10. **Honest limits.** Public records, exemptions, copied datasets, and re-acquisition mean removal is not a guarantee of anonymity.

## User journeys

### Baseline cleanup

The user creates an encrypted identity profile, reviews aliases and historical addresses, and grants a jurisdiction- and capability-specific setup authorization. MyCogni scans, explains likely matches, and automatically submits supported requests when a trusted connector, fresh policy, match threshold, destination, and disclosure all fit that authorization. Exceptions become explicit review or guided tasks.

### Recurring maintenance

The scheduler wakes after a configured interval, rechecks high-value brokers, detects resurfaced records, and either resubmits under the active setup authorization or asks for exception review. A digest shows verified removals, asserted removals, resurfacing, deadlines, and manual actions.

### Custom removal

The user pastes a URL or domain. MyCogni safely fetches metadata without rendering active content, looks for a known organization and privacy channel, drafts a request, and shows exactly which PII would be disclosed. Unknown workflows always require review.

### Personal assistant

OpenClaw asks for a privacy digest or creates a draft custom-removal case. By default it cannot read raw identity fields, view evidence bodies, approve disclosures, or submit requests. The user approves any expansion of capability in MyCogni.

## Success measures

Primary measures are per-person and based on verifiable outcomes:

- precision of discovered records confirmed by the user;
- percentage of confirmed records independently verified absent after a request;
- median time from confirmed presence to verified removal;
- resurfacing rate and median time to re-removal;
- percentage of work requiring manual intervention and time spent by the user;
- stale/broken connector rate;
- PII fields disclosed per successful removal;
- missed legal or operational deadlines;
- restore-test success and time to recover.

“Brokers covered,” “requests sent,” and “emails received” are diagnostic metrics only.

## Scope boundaries

V0 and V1 focus on lawful individual privacy requests. They do not include dark-web monitoring, credit monitoring, insurance, VPN/antivirus features, deletion of public records at their source, reputation management, generalized web takedowns, or business/government accounts.
