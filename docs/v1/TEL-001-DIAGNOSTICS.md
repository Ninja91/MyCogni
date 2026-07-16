# TEL-001 typed local diagnostics contract

## Outcome

TEL-001 introduces a standard-library-only diagnostic contract and a deterministic local JSON
sink. The contract is fail closed: a caller can construct an event only from a finite event ID,
component, level, action, result, field-name catalog, bounded counters, public connector metadata,
finite exception category, and opaque UUIDv4 correlations. It has no field for a URL, path, query,
peer address, header, cookie, body, HTML, page title, selector, screenshot, mail content, browser
console/network content, proxy detail, exception message, class name, or traceback.

This is rejection by construction, not a scrubber applied after capture. Raw framework,
transport, browser, proxy, mail, and exception data must never be passed to the diagnostic API.

## Contract

- `EventId` and `EVENT_CATALOG` bind each event to exact required and optional fields.
- `FieldName` is the complete version-1 field vocabulary. String keys and event-specific extra
  fields fail.
- `ActionCode`, `DiagnosticResultCode`, `ErrorCategory`, `DiagnosticComponent`, and
  `DiagnosticLevel` are finite enums; they cannot carry caller text.
- Job, action, and trace correlations require `OpaqueId`; external identifiers, profile IDs,
  identity values, and stable cross-installation identifiers are prohibited.
- Connector ID and version are finite reviewed enums (currently synthetic-only). New public
  releases require a catalog change; page content or identity input cannot be converted into
  connector diagnostic metadata.
- Durations, retry numbers, counts, string lengths, field cardinality, and the final JSON line are
  bounded. Booleans and coercible strings do not count as integers.
- `classify_exception` uses only built-in exception type relationships and returns a finite
  category. It never calls `str`, `repr`, traceback formatting, or exception argument access.
- `LocalJsonSink` writes canonical newline-delimited JSON to an injected local text stream. It has
  no network, exporter, logging-framework, telemetry, or auto-instrumentation dependency.

The canonical timestamp is aware UTC and emitted with fixed microsecond precision. JSON object
keys are sorted and compact; serialization has no arbitrary-object or `default=str` fallback.

## Unsafe capture defaults

`UnsafeCaptureDefaults` fixes Uvicorn access/default logs, proxy access/error detail, browser
console/network/page logs, mail protocol logs, and remote exporting to `False`.
`uvicorn_safe_options()` returns `access_log=False`, `log_config=None`, and `use_colors=False`.
Future server composition must pass those options and route only explicit typed events to the
local sink. Future proxy, browser, and mail adapters must retain automatic logging as disabled;
they may add only separately reviewed typed events.

## Extension rules

A diagnostic extension requires all of the following in one reviewed change:

1. add a finite event/field/enum value and bind it to one exact catalog entry;
2. explain why the information is operationally necessary and cannot identify a person, reveal a
   credential, reproduce external content, or create a long-lived dossier;
3. define exact runtime types, bounds, cardinality, retention effect, and rollback behavior;
4. add positive tests plus negative mutation and synthetic canary tests for URL, query, headers,
   errors, HTML, mail, proxy, and browser paths;
5. preserve the no-network/no-export architecture check and update this contract;
6. require an ADR before enabling any remote export, generic instrumentation, raw framework log,
   or support-bundle inclusion.

Encoding, hashing, truncating, or renaming a prohibited value does not make it an allowed field.
PII and secrets that happen to match a safe lexical grammar remain prohibited.

## Non-claims and residual risks

- TEL-001 does not compose or start Uvicorn; the repository still contains only the PF-002
  packaging smoke entrypoint. The safe options are an executable contract for the later server
  composition package, not proof of a deployed server configuration.
- No proxy, browser, or mail runtime exists here. False defaults do not enforce another process's
  configuration; their future adapters must prove integration with tests.
- The injected stream is assumed to be operator-controlled and local. This package does not
  implement file permissions, rotation, retention, encryption, crash safety, concurrency, or
  support bundles. Those remain operations/runtime work.
- Opaque IDs reduce direct disclosure but repeated IDs still permit local correlation. Retention
  must remain short and access-controlled.
- Connector diagnostic IDs remain separate from future registry trust. Adding an enum value does
  not prove a connector artifact, capability, or registry release is trusted.
- Application code or dependencies can still bypass this API by writing directly to stdout,
  stderr, framework logs, crash reports, or container runtime logs. CI architecture checks and
  later composition tests must keep those paths disabled; TEL-001 alone is not whole-process data
  loss prevention.
