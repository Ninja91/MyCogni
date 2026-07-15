# Independent ML engineering adversarial review

Perspective: principal applied scientist / ML systems engineer.

## Verdict

The deterministic architecture is the correct product core. “Optional AI may explain or draft” is not a sufficient boundary: without a typed contract, later implementation can accidentally let a model influence match, policy, disclosure, or execution. V1 should ship with no model runtime. It should establish only a null `IntelligencePort`, deterministic redaction contract, evaluation harness, and architectural prohibition on authority.

## Findings

### P0 — Intelligence lacks an enforceable no-authority contract

Require `IntelligencePort.suggest(task) -> UntrustedSuggestion`. The model receives no vault handle, database credential, reusable conversation, tool surface, network, connector capability, authorization record, request plan, or raw evidence. Output may populate an advisory field or review queue only.

The model must never set or modify identity match/confidence, legal eligibility, policy fact, deadline, authorization, destination, disclosure bundle, connector maturity, request status, verification outcome, retry, or submission intent. Schema-constrained JSON helps validation; it is not a prompt-injection security boundary.

### P0 — Local inference can still leak PII

Local servers may log prompts, retain context, write crash dumps, use swap, share endpoints with other clients, or expose telemetry. Deterministically replace known names, aliases, addresses, emails, phones, case tokens, query URLs, and third-party identifiers before inference. Do not store prompt bodies. Encrypt accepted suggestions as evidence-derived sensitive data.

Never fine-tune or build RAG over a user's vault, inbox, evidence, or case history. “Runs locally” is not consent to create another identity corpus.

### P1 — Models, prompts, quantization, and runtime have no lifecycle

Treat any model, quantization, template, schema, redactor, or runtime change as a behavior release. A model record needs immutable upstream revision, license/model-card review, artifact and quantizer digest, runtime digest, prompt/schema version, evaluated tasks, hardware tier, approval date, rollback, and revocation state.

Do not bundle weights in the Apache-2.0 repository. Model licenses remain separate. Never execute model packages requiring remote code; prefer a reviewed digest-pinned GGUF artifact mounted read-only.

### P1 — No task-specific test, evaluation, verification, and validation gate exists

Before a task leaves shadow mode:

- 100% outputs must validate against the task schema or be discarded;
- every extracted value must cite literal spans from the sanitized input;
- adversarial output must have zero ability to mutate state, acquire PII, call tools, or create egress;
- seeded PII canaries must appear zero times in model inputs, outputs, logs, traces, or bundles;
- non-critical classification starts with a macro-F1 hypothesis of at least 0.90;
- safety categories—challenge, MFA, identity-document request, changed terms, and denial—start with at least 99% recall, with disagreement or missing spans forcing abstention;
- every artifact/runtime/prompt/redactor/schema change reruns the complete suite.

General leaderboards and anecdotes are not fitness evidence for hostile broker replies.

### P2 — The product evidence does not justify an AI headline

Users ask for automation, proof, custom-case progress, and visible rechecks. A single Reddit comment mentions ChatGPT helping locate brokers, while the same thread contains suspicion that reviews are promotional or AI-generated. AI could reduce trust. Instrument manual reasons and minutes first; prototype only if unstructured triage is a top-three burden.

## Permitted post-v1 experiments

- classify a sanitized reply into candidate reason codes;
- extract candidate dates/contact channels with supporting spans while deterministic policy calculates deadlines;
- explain a PII-free structured timeline;
- draft generic prose containing placeholders that deterministic code fills from an already approved plan;
- triage sanitized form/DOM drift for a maintainer;
- summarize a safely fetched, sanitized custom privacy page for review.

All outputs remain suggestions. Autonomous policy, identity matching, connector generation/promotion, verification, and external action remain prohibited.

## Required repository changes

Accepted: requirements `AI-*`, `IntelligencePort`, null default, ADR-0011, local-intelligence threat zone, evaluation card, model cache/license lifecycle, and an explicit post-v1 PMF gate.

## Sources

- [NIST AI RMF Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [Indirect prompt injection research](https://arxiv.org/abs/2302.12173)
- [Hugging Face repository security guidance](https://huggingface.co/docs/hub/en/security)
- [Ollama structured-output API](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [llama.cpp grammars and JSON-schema constraints](https://github.com/ggml-org/llama.cpp/blob/master/grammars/README.md)
- [Referenced Reddit discussion](https://www.reddit.com/r/CyberAdvice/comments/1l3no4j/incogni_review_my_experience_using_it_for_data/)
