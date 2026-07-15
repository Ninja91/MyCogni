# ADR-0005: License and project identity

- Status: Accepted
- Date: 2026-07-15

## Context

The maintainer wants a personal open-source alternative inspired by a commercial data-removal product. The working name “MyCogni” may cause confusion with Incogni. The license should preserve user benefit without blocking a healthy contributor ecosystem.

## Decision

Use Apache-2.0, as selected by the maintainer, to maximize permissive reuse and compatibility with the wider privacy-tool ecosystem. Vendor the canonical license text and a NOTICE file. Keep “MyCogni” only as a working name until a trademark/confusion review. Include a clear non-affiliation statement and do not copy Incogni branding, proprietary connector data, UI, text, or code. Verify licenses and provenance before importing open directories or protocols.

## Consequences

- Closed commercial or hosted derivatives are permitted if they comply with Apache-2.0.
- Contributors and distributors receive Apache-2.0's explicit patent license and termination terms.
- A rename before public launch may create modest migration work.
- Apache-2.0 dependencies and protocol material can generally coexist, but every imported dataset/code source still needs review.

## Alternatives

AGPL-3.0 would keep network-deployed modifications open but can complicate adoption and integration. MPL-2.0 provides file-level reciprocity. The maintainer preferred Apache-2.0.

## Follow-up

Resolve whether “MyCogni” is the final public name before launch and update package/image/repository identifiers if renamed.
