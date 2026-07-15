# ADR-0011: Advisory-only local intelligence

- Status: Accepted as a boundary; runtime deferred until post-v1 evidence
- Date: 2026-07-15

## Context

Unstructured broker replies, privacy pages, and connector drift may benefit from local language models. Models also introduce prompt injection, privacy, artifact-license, resource, provenance, and nondeterminism risks. “Optional” does not prevent privilege creep.

## Decision

Define a typed `IntelligencePort` whose only result is a schema-validated `UntrustedSuggestion` with supporting spans. The default implementation is a no-op. No model/runtime/weights ship in v1.

A future opt-in local runtime receives only deterministic sanitized bounded tasks; it has no raw PII/evidence, vault/database, tools, network, connector capability, authorization, or reusable conversation. Output cannot create a command or change identity, policy, deadline, authorization, disclosure, destination, connector trust, status, verification, retry, or submission. It may appear as advisory text or a review candidate.

Artifacts are digest-pinned, license-reviewed, explicitly acquired, isolated, read-only, and separately evaluated per task. No remote fallback, per-user fine-tuning, vault/evidence RAG, mutable model tag, automatic update, or remote code execution is allowed. `ResourceBudgetManager` prioritizes deterministic work and limits advisory execution.

## Consequences

- The product remains complete without AI.
- A small trusted seam is cheaper than retrofitting authority controls later.
- Local inference is not marketed until a PMF and TEVV gate passes.
- Users bear optional model disk/RAM costs and license choices.

## Alternatives

Remote AI as a core dependency and agentic tool use were rejected. Shipping a bundled model was rejected for size/license/support. Omitting the seam entirely risks later ad hoc integration; only the null contract is accepted in v1.

## Security and privacy impact

The model remains an untrusted parser with zero authority. Local operation reduces network disclosure but does not eliminate prompt/log/swap/endpoint risks, so raw PII remains prohibited.

## Review trigger

Any runtime implementation, allowed task, remote endpoint, model/prompt/schema/redactor change, new input class, tool request, fine-tuning/RAG proposal, or safety incident.
