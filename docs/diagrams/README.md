# Architecture diagram index

These diagrams are normative at the boundary level. Component names, trust zones, lifecycle states, and deployment roles should stay synchronized with the architecture and ADRs.

1. [System context](01-system-context.md) — people and external systems.
2. [Container and component architecture](02-container-components.md) — runtime modules and ports.
3. [Trust boundaries and PII flow](03-trust-and-pii-flow.md) — where sensitive data may travel.
4. [Observe, submit, and verify sequence](04-request-sequence.md) — automatic authorization, exception review, and evidence path.
5. [Case lifecycle](05-case-lifecycle.md) — precise outcome semantics.
6. [Core data model](06-data-model.md) — identities, brokers, cases, events, and evidence.
7. [Deployment profiles](07-deployment-profiles.md) — local-lite and cloud-small.

Mermaid source is embedded in each Markdown file so GitHub renders it and reviewers can diff it with the surrounding invariants.
