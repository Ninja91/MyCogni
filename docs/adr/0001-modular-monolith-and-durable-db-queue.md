# ADR-0001: Modular monolith and durable database queue

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

The product must run sporadically on a laptop or continuously on a small cloud instance. It needs durable scheduling, external-action idempotency, migrations, and isolation for volatile connectors without imposing a large operations stack.

## Decision

Build a Python modular monolith with explicit domain modules and ports. Use one OCI image exposing `serve`, `worker`, `scheduler`, and local `all-in-one` roles. Store jobs, leases, outbox events, and projections in the application database. SQLite supports a single worker/scheduler for local-lite; PostgreSQL supports separated cloud-small roles. Execute connector code out of process.

## Consequences

- Local operation needs no Redis or message broker.
- Transactional jobs/events are easier to reason about.
- SQLite concurrency is intentionally limited.
- Queue behavior must be carefully implemented and contract-tested across both databases.
- Services can be split later at existing ports if measured load or trust boundaries require it.

## Alternatives

Microservices plus Kafka/Redis/Celery were rejected for initial operational cost. A desktop-only app was rejected because cloud-small and headless operation are requirements. In-process scheduled tasks alone were rejected because crash recovery and external-action semantics would be weak.

## Review trigger

Revisit when a single PostgreSQL queue cannot meet measured workload, a connector needs a stronger remote isolation boundary, or multi-tenancy becomes an approved goal.
