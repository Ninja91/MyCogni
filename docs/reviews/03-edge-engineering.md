# Independent edge and local-first engineering adversarial review

Perspective: principal engineer for intermittent, resource-constrained, user-operated systems.

## Verdict

The deterministic core can meet a small idle footprint. Browser and optional inference workloads cannot be treated as independent: starting both can exhaust a laptop/NAS and turn advisory work into failed privacy work. Add one resource authority and keep AI absent by default.

## Findings

### P0 — No shared heavy-work budget

Add `ResourceBudgetManager` with one heavy-work lease shared by browser and inference in local-lite, memory preflight, hard CPU/RAM/tmp/time limits, queue bounds, and priority for legal deadlines and connector work. Minimum tier never runs browser and inference concurrently. OOM/timeout discards advisory output and leaves deterministic case processing intact.

### P1 — Portability does not imply acceleration parity

Keep the core image free of model runtimes and weights. Define adapters: process-owned `llama.cpp` over stdio/Unix socket as the preferred isolated path, explicitly configured host-local Ollama as a weaker convenience path, and other host runtimes only after conformance tests. CPU-only is the portability baseline. Publish p50/p95 load/inference time, peak RSS, disk, and CPU/energy for each tested tier before claiming small-cloud support.

### P1 — Shared local model endpoints cross privileges

Connector runners, OpenClaw, and the model adapter must not share a network or session. Prefer process ownership. Any HTTP adapter needs an exact loopback/Unix endpoint, dedicated network, request-size limits, runtime/version pinning, and a warning that another local client may access it. There is no remote fallback when local assist is unavailable.

### P1 — Intermittent catch-up does not include advisory semantics

Model acquisition/update never occurs during catch-up. Advisory jobs are durable but low priority, batched once under a total budget, and deduplicated by input/model/prompt digest. Unavailable/OOM/timeout becomes `assist_unavailable`, not failed broker work. Weights are a reproducible cache excluded from user backups; restore records a digest and asks before reacquisition. Unload after the bounded batch.

### P2 — Hostile content can create inference denial of service

Preprocess deterministically: allowlisted MIME types, Unicode normalization, quoted-thread/attachment removal, source-specific sections, decoded-character and token caps, output and wall limits, no images/scripts/URLs/tool followups, and content-digest duplicate suppression.

## Provisional resource tiers

These are hypotheses to benchmark, not support claims:

| Tier | Model artifact | Active RAM cap | CPU | Context | Behavior |
| --- | ---: | ---: | ---: | ---: | --- |
| Disabled/default | none | 0 | 0 | 0 | full product behavior |
| Micro advisory | at most 3 GiB quantized | at most 4 GiB | at most 2 cores | 2K | concurrency 1; unload after batch |
| Standard advisory | at most 6 GiB quantized | at most 8 GiB | at most 4 cores | 4K | concurrency 1 |

The core idle target excludes active browser/inference but must return below 250 MiB after optional runtimes unload.

## Sources

- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
- [llama.cpp hardware and quantization support](https://github.com/ggml-org/llama.cpp)
- [Ollama memory, concurrency, and queue behavior](https://docs.ollama.com/faq)
- [Ollama structured output and `keep_alive`](https://github.com/ollama/ollama/blob/main/docs/api.md)
