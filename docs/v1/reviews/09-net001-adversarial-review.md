# NET-001 adversarial review

Target: integration commit `e00827b` (`d325a26` implementation plus diagnostic
nonclaim correction).

Verdict: **REJECT** — unresolved P1 and P2 findings. NET-001 remains
`IN_PROGRESS`; the process-local harness must not be described as accepted network
containment.

This is an independent Sol-labelled agent review, not a claim about the underlying
model and not a hostile-code or operating-system containment assessment.

## Findings

| Severity | Finding | Required disposition |
| --- | --- | --- |
| P1 | The plugin was loaded from `tests/conftest.py`, so a package-only pytest invocation could run without registering it. Explicit plugin exclusion also allowed an ordinary test subset to pass, contradicting the every-supported-test-command/no-guard-off claim. | Load and verify the guard at repository scope, fail closed when it is excluded or disabled, and exercise supported invocations in subprocess tests. |
| P1 | A boolean `ContextVar` capability was copied into already-created async tasks. Parent teardown did not revoke that child context, so loopback authority could outlive its test lifecycle. | Use a lifecycle-revocable capability that cannot survive teardown in child tasks, threads or later tests, with deterministic regressions. |
| P1 | Runtime marker validation accepted any exact item-level marker under `tests/simulator`, while the static reviewed-set logic covered only top-level decorators in selected files. Parameter/generated marks could obtain authority without matching reviewed function provenance. | Bind runtime authorization to the exact statically reviewed module/function/node identity and reject generated or parameter-level provenance outside that set. |
| P1 | Installation patched more DNS, socket, TLS, urllib, HTTP and HTTPX entrypoints than `assert_installed` verified. A leaked mutation could therefore survive teardown while integrity still reported healthy. | Verify and restore every patched identity from a single manifest; prove mutation/leak detection for every entrypoint family. |
| P1 | Writes through inherited or preconnected descriptors were not gated, and this residual boundary was absent from the nonclaims. | Deny supported send/dup/fromfd/socketpair/Unix-descriptor paths or explicitly remove them from the claimed process-local boundary with tests and a release-blocking residual risk. |
| P2 | Documentation claimed Unix sockets were denied although an unmarked `socketpair` send succeeded. The optional namespace probe did not define failure behavior for timeout/`OSError`, and prose disagreed on the count of allowed policy functions. | Make implementation, diagnostics and documentation exact; the optional probe must return a finite honest state rather than crash or imply proof. |

## Evidence that did pass

- 53 focused policy tests;
- static network source guard;
- optional namespace probe honestly reported `unsupported` on macOS;
- dual-runtime lane checks passed at the submitted revision.

Passing evidence did not cover the rejected invocation, lifecycle, provenance,
integrity and descriptor cases. Every P1 fix must return to an independent reviewer.
