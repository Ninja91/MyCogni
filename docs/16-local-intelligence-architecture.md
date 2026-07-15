# Optional local intelligence architecture

## Decision

No local or remote model is required, bundled, downloaded, or advertised in v1. The deterministic product is complete without inference. V1 may establish a typed `IntelligencePort`, null adapter, redaction contract, synthetic evaluation harness, and resource budget. A runtime is post-v1, opt-in, task-specific, local-only, and advisory.

## Authority contract

```text
bounded untrusted evidence
  → deterministic parser/redactor/task builder
  → IntelligencePort
  → isolated local runtime (optional)
  → schema + supporting-span + policy validator
  → UntrustedSuggestion
  → advisory UI or human review
```

An `UntrustedSuggestion` cannot be converted into a domain command. It contains:

- task type and schema version;
- candidate label/fields;
- literal supporting spans into the sanitized input;
- model/runtime/prompt/input digests;
- confidence as display metadata only;
- validation/abstention reason;
- expiry.

The core must re-derive every domain fact deterministically from authoritative sources. The model has no tool interface.

## Allowed tasks after a passed shadow gate

1. Candidate classification of a sanitized broker reply into acknowledgement, asserted completion, challenge, denial, unrelated, or unknown.
2. Candidate date/contact extraction with supporting spans; policy calculates the actual deadline.
3. Plain-language explanation from PII-free structured events and reason codes.
4. Generic request prose with placeholders; deterministic code fills only an already authorized immutable plan and initially requires review.
5. Maintainer-only triage of sanitized form/DOM drift.
6. Review summary of a safely fetched and sanitized custom privacy page.

## Prohibited tasks

Identity matching, wrong-person resolution, legal eligibility, authorized-agent decisions, jurisdiction policy, disclosure minimization, destination allowlisting, connector trust/promotion, verification/outcome state, deadline calculation, CAPTCHA/MFA handling, retries, external submission, autonomous connector generation, per-user fine-tuning, or RAG over vault/evidence data.

## Data contract

Before inference, deterministic code:

- selects an allowlisted MIME/section and rejects attachments/images/scripts;
- normalizes Unicode and removes quoted threads/remote URLs;
- replaces known names, aliases, emails, phones, addresses, tokens, query URLs, and third-party identifiers with typed placeholders;
- caps decoded characters, input/output tokens, and repeated content;
- creates a content digest for duplicate suppression;
- seeds synthetic PII canaries in tests.

No raw vault attribute or raw evidence body is a valid port input. Prompt bodies are not persisted. Stored suggestions are encrypted as evidence-derived sensitive data. Diagnostics contain task/result codes and digests only.

## Runtime boundary

Preferred: a MyCogni-owned `llama.cpp` process over stdio or a permissioned Unix socket, running without network, vault, database, connector mounts, core credentials, or writable model files.

Optional convenience: an explicitly configured host-local Ollama endpoint on an isolated network. The UI warns that a shared HTTP server is a weaker boundary and may be reachable by other local clients. Connector runners and OpenClaw never share the runtime network or conversation. There is no remote fallback.

Weights live in a read-only reproducible cache, not evidence storage or backup. Acquisition is an explicit operator action that displays upstream revision, model card/license, size, digest, tested hardware, and evaluation status. Mutable tags and `trust_remote_code` are prohibited. Updates are never automatic or part of scheduler catch-up.

## Resource semantics

`ResourceBudgetManager` grants one heavy-work lease in local-lite. Browser/external-deadline work outranks advisory inference. Minimum tier never runs both concurrently. Inference concurrency is one, with task and batch time/RAM/CPU/tmp/token limits. OOM/timeout/unavailable becomes `assist_unavailable`; it cannot fail or delay broker work. One attempt is allowed per input/model/prompt digest. Unload immediately after the batch or within the tested idle window.

Provisional tiers are listed in the edge review and must be benchmarked before becoming support claims. The unloaded/null adapter is included in the core idle budget; active model memory is reported separately.

## Model and task registry

Record immutable upstream revision, model-card/license decision, artifact/quantizer digest, runtime digest, prompt/template digest, task/schema/redactor versions, hardware tier, evaluation card, approval date, expiry, rollback, and revocation.

Each task has its own scorecard. Changing a model, quantization, runtime, prompt, schema, redactor, or input policy requires complete re-evaluation.

## Evaluation and release gate

- 100% schema validation; invalid output is discarded.
- 100% supporting-span validation for extracted facts.
- Zero ability for adversarial output to mutate state, access PII, call tools, or create egress.
- Zero seeded PII canaries in model input/output/log/trace/support surfaces.
- Initial non-critical classification hypothesis: macro-F1 at least 0.90.
- Initial safety-category hypothesis: at least 99% recall for challenge, MFA, identity-document request, changed terms, and denial; disagreement/missing spans abstains.
- At least 30% measured manual-review time reduction with no change in deterministic outcomes, disclosure, or false positives.
- Published p50/p95 load/inference time, peak RSS, disk footprint, CPU time, abstention, and limitations for the supported tier.

Synthetic and consented irreversibly redacted examples may be used privately for evaluation. Raw user evidence is never committed, uploaded, or used for fine-tuning.

## Failure and rollback

Runtime unavailable, incompatible, revoked, timed out, or over budget produces an advisory-unavailable state. The deterministic explanation and review flow remain. Restores record required artifact digests and ask before reacquisition. Revoked/stale artifacts cannot run. Cache pruning is explicit and does not alter case truth.
