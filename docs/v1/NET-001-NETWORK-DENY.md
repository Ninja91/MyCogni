# NET-001 test-network denial contract

Status: implementation complete; independent adversarial acceptance pending.

## Enforced pytest policy

`scripts/ci/guarded_pytest.py` is the only supported repository or package-suite
pytest launcher. Make, CI, governance evidence and threat evidence all use it.
Root and connector-package conftests are sentinels: direct pytest fails instead
of silently running without the plugin. The launcher rejects plugin-autoload
disablement, guard-off environment state, `-p no:...`, `--noconftest` and
`--confcutdir`. `PYTEST_ADDOPTS` is parsed with POSIX shell quoting before the
environment options and command-line options are evaluated together. Malformed
quoting and split, combined, equals, quoted, or environment-plus-command-line
exclusion forms fail closed before pytest starts. Removing the
launcher/plugin/sentinel wiring fails the static CI guard.

Every test receives an input-free opaque test ID. The default capability denies
DNS and address-bearing socket operations. Only an exact, argument-free
`simulator_loopback` marker on the reviewed tests below enables TCP/IPv4 to the
literal address `127.0.0.1`:

- the four raw-HTTP simulator tests in
  `tests/simulator/test_web_mail_safety.py`;
- all parameter cases from the five local HTTP policy mutation functions in
  `tests/simulator/test_network_guard_simulator.py`.

`ci/network-loopback-authority.json` enumerates all 38 authorized pytest nodes,
including explicit parameter IDs, and pins SHA-256 digests for both source
files. It also pins the normalized AST digest and line plus runtime code line
and qualified name of each of the nine reviewed top-level test callables.
Runtime collection requires the exact normalized `item.nodeid`, preserving all
collector, class and parameter hierarchy; an exact top-level function and
function-level source decorator; matching AST and code identity; the module's
original callable object; and one argument-free own marker. Inherited,
parameter-, class- or module-level, generated, dynamically attached, duplicate
name, collector-collision and unregistered parameter cases cannot acquire
authority.

The capability is a mutable revocation lease referenced by a `ContextVar` only
during the reviewed Python test-function call, never fixture setup or teardown.
The plugin snapshots provenance at collection and revalidates the exact node,
callable, code object, module binding, AST identity and marker immediately
before granting the lease. It revokes the lease immediately after the call. A
new thread receives no capability; an already created async task may copy the
lease reference but cannot use it after revocation. A later test receives a
distinct lease.

The runtime guard denies all resolver APIs, non-IPv4 families, IPv6 (including
IPv4-mapped IPv6), wildcard/broadcast/non-loopback addresses, hostnames,
integer/hex/encoded IP aliases, filesystem-path Unix sockets, invalid ports, TLS wrapping/SNI,
non-HTTP URL schemes, userinfo, fragments, default/zero ports, proxy environment
variables and explicit HTTPX/urllib proxies. It checks each HTTPX send and each
urllib opener invocation, so a redirect is validated again. Denial tests spy on
the underlying DNS/socket/async/client primitive and prove it is not invoked.
Inherited/preconnected descriptors, `fromfd`, descriptor duplication/detach and
post-revocation send/receive fail closed. Accepted loopback sockets receive the
same revocable object capability as their listener. Anonymous `socketpair()` is
permitted only for in-process interpreter/event-loop control; its endpoints
cannot connect to a filesystem path, detach or duplicate.

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
CI Python lanes execute it. The guarantee applies to guarded-launcher commands;
unsupported direct pytest invocations fail via repository/package sentinels.

## Optional OS layer and nonclaims

`make network-namespace-probe` reports one of these exact states without making
the suite fail:

- `network_namespace=supported`;
- `network_namespace=unsupported`;
- `network_namespace=denied`; or
- `network_namespace=failure`.

On Linux hosts where unprivileged user/network namespaces are supported,
`python scripts/ci/network_namespace.py --run <command>` runs the command under
`unshare --user --map-root-user --net`. For `--run`, unsupported, denied and
probe/exec failure return 2, 3 and 4 respectively without running the requested
command. Probe and execution timeouts/OSErrors classify as `failure` instead of
crashing. CI records the probe; it does not silently claim enforcement.

The Python guard is not an operating-system sandbox and does not defend against
hostile test code retaining original primitives before installation, native
code, `ctypes`, a compromised interpreter, or a subprocess deliberately added
outside the source guard. A deliberately hostile test could also retain the
original C socket class, obtain/duplicate descriptors through unpatched native
or `os` primitives, or disable all Python startup/configuration outside the
supported launcher. macOS/Docker Desktop normally reports the namespace
layer unsupported. NET-001 therefore proves the reviewed Python CI/test harness
does not initiate real network access; it does not prove host-wide packet
containment.

## Handoff

`SPIKE-EGRESS` must add an OS/container egress boundary, resolver/rebinding and
TLS policy at the outbound service itself. `BROW-001` must place Playwright in a
separate deny-by-default runner and first execute only against the numeric
loopback simulator. Neither package may treat this pytest safety belt as its
production isolation mechanism.
