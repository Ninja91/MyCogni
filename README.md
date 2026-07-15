# MyCogni

MyCogni is a local-first, open-source personal data removal orchestrator. It is intended to discover personal information held or published by data brokers, prepare and submit lawful privacy requests, track responses, verify outcomes, and detect resurfacing without centralizing a user's identity in somebody else's SaaS.

> Project status: architecture and execution planning. This initial commit is intentionally not a runnable release and must not be represented as one.

## Product promise

MyCogni should make a difficult recurring process understandable and controllable:

- keep sensitive identity data encrypted on infrastructure the user controls;
- automatically execute deterministic work through fresh, trusted connectors covered by the user's setup authorization;
- stop for review when identity, legal authority, disclosure scope, destination, or match confidence is uncertain;
- support standard and custom removals without arbitrary quotas;
- distinguish a request being sent, a broker claiming compliance, and independent verification;
- show exactly why work is pending, what will happen next, and when it will be rechecked;
- run on a laptop periodically or as a small always-on cloud service from the same OCI image;
- expose a narrow, consent-aware integration surface for personal assistants such as OpenClaw.

## Non-goals

MyCogni is not a guarantee of invisibility, an identity-theft insurance product, a CAPTCHA bypass service, a mass-scraper, a legal representative by default, or a way to submit requests for people who have not authorized them.

## Documentation map

| Start here | Purpose |
| --- | --- |
| [Product brief](docs/00-product-brief.md) | Scope, principles, and success measures |
| [Research synthesis](docs/01-research-synthesis.md) | Product evidence and lessons from users and research |
| [Requirements](docs/02-requirements.md) | Functional and quality requirements |
| [System architecture](docs/03-system-architecture.md) | Components, boundaries, and key flows |
| [Data model and lifecycle](docs/04-data-model-and-lifecycle.md) | Records, state machines, and retention |
| [Security and privacy](docs/05-security-privacy-threat-model.md) | Threat model and controls |
| [Connector SDK](docs/06-connector-sdk.md) | Broker adapter contract and safety policy |
| [Deployment](docs/07-deployment-architecture.md) | Local and cloud profiles |
| [Operations](docs/08-observability-and-operations.md) | Metrics, runbooks, and recovery |
| [Testing](docs/09-testing-and-quality.md) | Verification strategy and release gates |
| [Execution plan](docs/10-execution-plan.md) | Phases, workstreams, and acceptance criteria |
| [Adversarial review](docs/11-adversarial-review.md) | Red-team findings and design changes |
| [Decision log](docs/12-decisions-and-interview.md) | Assumptions, open decisions, and interview prompts |
| [Inception audit](docs/13-inception-completion-audit.md) | Deliverable traceability and validation evidence |
| [Diagram index](docs/diagrams/README.md) | Architecture, trust, sequence, data, and deployment diagrams |

## Design at a glance

The proposed implementation is a Python modular monolith with a FastAPI/HTML local UI, a Typer CLI, a durable database-backed work queue, and isolated connector runners. CLI implementation leads, with the local web UI in the same early milestone. The core remains deterministic. Optional AI integrations may explain or draft, but they cannot receive raw PII or submit a request unless a user explicitly enables that capability.

One image supports three roles: `serve`, `worker`, and `scheduler`. A `local-lite` profile runs them together with encrypted SQLite on a persistent volume. A `cloud-small` profile runs the same image as separate processes with PostgreSQL. Browser automation is isolated and opt-in.

## Safety invariants

1. No request for another person without stored authorization.
2. No irreversible external action from a read-only scan.
3. No raw PII in logs, metrics, notifications, issue reports, or AI prompts.
4. No `verified_removed` status without verification evidence captured after submission.
5. No connector receives more identity attributes than its reviewed manifest declares.
6. No automatic bypass of CAPTCHAs, account controls, or broker rate limits.
7. No cloud deployment without an external secret and encrypted persistent storage.

## Intended repository shape

```text
mycogni/
  apps/                 # API/UI, CLI, worker, scheduler entrypoints
  packages/             # domain, policy, vault, evidence, orchestration
  connectors/           # reviewed broker and transport adapters
  broker-registry/      # versioned broker metadata and schemas
  tests/                 # unit, contract, integration, end-to-end, adversarial
  deploy/                # OCI, Compose, and cloud examples
  docs/                  # architecture and operations source of truth
```

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing connectors. Do not include real PII, screenshots of real people-search records, session cookies, broker credentials, or live authorization documents in issues or fixtures. Report vulnerabilities through [SECURITY.md](SECURITY.md).

## License and naming

MyCogni is licensed under Apache-2.0; see [LICENSE](LICENSE), [NOTICE](NOTICE), and [ADR-0005](docs/adr/0005-license-and-project-identity.md). “MyCogni” remains a working project name. It is not affiliated with or endorsed by Incogni, Surfshark, or Nord Security, and a trademark/name review is required before public launch.
