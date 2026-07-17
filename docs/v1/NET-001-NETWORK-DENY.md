# NET-001 test-network denial contract

Status: implementation complete; independent adversarial acceptance pending.

## Enforced pytest policy

The root pytest session installs `scripts.ci.network_guard_plugin` before test
collection. There is no supported guard-off flag. Setting
`MYCOGNI_DISABLE_NETWORK_GUARD`, removing the plugin, changing its registered
marker, moving a marked test, inheriting a marker, or adding marker arguments
fails either pytest configuration/collection or the static CI guard.

Every test receives an input-free opaque test ID. The default capability denies
DNS and address-bearing socket operations. Only an exact, argument-free
`simulator_loopback` marker on the reviewed tests below enables TCP/IPv4 to the
literal address `127.0.0.1`:

- the four raw-HTTP simulator tests in
  `tests/simulator/test_web_mail_safety.py`;
- the four local HTTP policy mutation tests in
  `tests/simulator/test_network_guard_simulator.py`.

The capability is a `ContextVar` installed for one pytest setup/call/teardown
lifecycle and reset after fixture cleanup. A new thread receives no capability.
Async work inside that test remains restricted to the same numeric-loopback
policy. A later test receives a distinct context and cannot reuse the prior
capability.

The runtime guard denies all resolver APIs, non-IPv4 families, IPv6 (including
IPv4-mapped IPv6), wildcard/broadcast/non-loopback addresses, hostnames,
integer/hex/encoded IP aliases, Unix sockets, invalid ports, TLS wrapping/SNI,
non-HTTP URL schemes, userinfo, fragments, default/zero ports, proxy environment
variables and explicit HTTPX/urllib proxies. It checks each HTTPX send and each
urllib opener invocation, so a redirect is validated again. Denial tests spy on
the underlying DNS/socket/async/client primitive and prove it is not invoked.

The emitted `NetworkDenied` diagnostic payload and its `str`/`repr` rendering
contain only a finite category, finite reason, and SHA-256-derived opaque test
ID. They never retain or render the attempted host, URL, query, header, body,
proxy, SNI, or lower-level exception. Like every raised Python exception, a
caught instance can carry an interpreter-managed in-memory traceback; the guard
does not serialize, log, or export it. NET-001 therefore claims input-free guard
diagnostics, not elimination of Python traceback objects from process memory.

`scripts/ci/network_source_guard.py` pins the plugin and marker provenance,
rejects unreviewed runtime network/process imports, and preserves the simulator's
recursive subprocess/dynamic-import/network source guard. `make check` and both
CI Python lanes execute it; the pytest plugin protects every test command, not
only the full CI target.

## Optional OS layer and nonclaims

`make network-namespace-probe` reports one of these exact states without making
the suite fail:

- `network_namespace=supported_optional`; or
- `network_namespace=unsupported`.

On Linux hosts where unprivileged user/network namespaces are supported,
`python scripts/ci/network_namespace.py --run <command>` runs the command under
`unshare --user --map-root-user --net`. A return code of 2 means containment was
not available and no command ran. CI records the probe; it does not silently
claim enforcement.

The Python guard is not an operating-system sandbox and does not defend against
hostile test code retaining original primitives before installation, native
code, `ctypes`, a compromised interpreter, or a subprocess deliberately added
outside the source guard. macOS/Docker Desktop normally reports the namespace
layer unsupported. NET-001 therefore proves the reviewed Python CI/test harness
does not initiate real network access; it does not prove host-wide packet
containment.

## Handoff

`SPIKE-EGRESS` must add an OS/container egress boundary, resolver/rebinding and
TLS policy at the outbound service itself. `BROW-001` must place Playwright in a
separate deny-by-default runner and first execute only against the numeric
loopback simulator. Neither package may treat this pytest safety belt as its
production isolation mechanism.
