# AUTH-001C — native operator terminal boundary

Status: **IN_PROGRESS implementation evidence; no AUTH-001 promotion**.

AUTH-001C replaces SPIKE-AUTH's impossible “all-or-nothing terminal write” assumption with an
application-owned, finite contract and a native POSIX `/dev/tty` adapter. A secret write is
`NOT_STARTED`, `MAY_HAVE_DISCLOSED`, or `COMPLETE`. Once any secret byte may have reached the
terminal, MyCogni never describes the secret as undisclosed and never retries a consumed proof.

## Implemented boundary

- The application contract owns bounded `SecretField`, `OperatorTerminal`, redacted finite failure
  codes, and typed delivery state.
- The adapter opens `/dev/tty` itself with read/write, no-controlling-terminal and close-on-exec
  flags. Linux uses no-follow directly. Darwin rejects no-follow on this special device, so the
  adapter permits only a root-owned `/dev/tty` character-device fallback and validates the opened
  descriptor as a TTY character device. The magic `/dev/tty` device resolves to the caller's
  controlling terminal, so its path `st_rdev` is intentionally not claimed to equal the resolved
  descriptor's device identity. There is no stdio, environment, argv, browser, network, subprocess,
  logging, keyring, or `getpass` fallback.
- A process-lifetime ownership lock and a separate nonblocking operation lock reject a second
  session, concurrent method call, same-thread reentry, or close during an operation before
  terminal I/O. Close never releases session ownership or closes a descriptor while a read or
  disclosure is active. PID and at-fork poison reject inherited use and close without touching
  inherited locks or descriptors.
- Every public operation revalidates the descriptor as a character device, TTY, and foreground
  process-group terminal. Secret reads and all publications revalidate again immediately before
  their byte I/O. Losing the foreground fails closed before that I/O or a new termios transition.
- Reads require the main thread and a foreground controlling terminal. They retain canonical input
  and `ISIG`, disable `ECHO`/`ECHONL` with a flush before making the prompt visible, bound and
  validate UTF-8 input, reject C0, DEL, and Unicode C1 controls, drain an oversize line while
  hidden, restore the exact saved attributes, and then emit a newline. The mutable input bytearray
  is overwritten in `finally` as best-effort hygiene; Python string/allocator erasure is not
  claimed. This ordering prevents a prompt-triggered response from racing ahead of the flush and
  being echoed or discarded.
- Temporary `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` handlers unwind through restoration and are
  restored afterward. The POSIX adapter requires `pthread_sigmask`: begin blocks those signals,
  installs every handler, and returns while they remain blocked. Only after the caller has entered
  its protecting `try` does activation restore the old mask. Cleanup restores terminal attributes
  first, blocks the handled signals, restores every old handler, and restores the exact old mask
  last. Partial install, activation, mask-transition, and handler-restore failures become finite
  redacted failures. The private unwind sentinel is contained; an unrecoverable operating-system
  mask failure latches the adapter and is not claimed to preserve future process-wide signal
  behavior. A platform without `pthread_sigmask` is unsupported rather than using a racy fallback.
  `SIGKILL` restoration is neither possible nor claimed.
- Disclosure prebuilds at most eight fields (96 printable ASCII label characters, 512 UTF-8 value
  bytes each, 8192 total bytes), loops over short writes, revalidates foreground/device identity
  before every chunk, and drains the TTY. Delivery becomes `MAY_HAVE_DISCLOSED` immediately before
  the first secret `write(2)` attempt because the kernel may accept bytes before Python receives a
  return count. Only failure before any secret syscall attempt is `NOT_STARTED`; any attempted
  write, later foreground loss, drain, cancellation, or I/O uncertainty remains
  `MAY_HAVE_DISCLOSED`.

## Ceremony correction

SPIKE-AUTH result objects now retain the typed delivery state. Initial/reprovision bootstrap output
is burned on interruption. `NOT_STARTED` permits truthful reissue from the still-unconsumed root;
`MAY_HAVE_DISCLOSED` warns that output may have escaped and the exposed bootstrap is unusable.
Post-consume bootstrap, reprovision, and recovery handoffs retain the in-process exchange for an
explicit redisplay without re-consuming the submitted credential.
Public guidance written after a `COMPLETE` disclosure is best effort: its failure cannot erase the
issued handle, downgrade `COMPLETE`, or hide a successfully consumed in-process exchange. Terminal
input failures have a finite truthful projection: cancellation is operator decline, EOF/oversize
is malformed input, and noninteractive, foreground, busy, fork, I/O, and restoration failures keep
distinct public denial codes and bounded guidance.
Those terminal transport denials are response-only entrypoint results. They are not written into
the durable auth decision snapshot, do not consume proof-attempt counters, and are deliberately
excluded from the frozen V1 `ReprovisionCeremonyRecord.terminal_denial` grammar; durable ceremony
denials remain decision-engine outcomes such as `replayed` and `expired`.

## Evidence and limits

Deterministic tests cover zero/partial/short writes, drain failure, redacted errors, close/read/write
serialization, child-after-fork close, repeated foreground validation, signal install/restore/mask
faults and cleanup ordering, per-attempt delivery accounting, control rejection, non-main-thread
input refusal, all-ceremony readiness/warning/confirmation failure, post-disclosure public-write
failure, finite input guidance, and corrected application semantics. The fresh-exec PTY matrix
uses a new interpreter which establishes its own controlling terminal with
`setsid`/`TIOCSCTTY`; it has no threaded-runner `preexec_fn`, applies deadlines to all reads, and
escalates terminate to kill during cleanup. It verifies exact restoration and no echo after success,
EOF, oversize, invalid UTF-8, `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT`. Only an independent direct
`/dev/tty` precondition may produce exit 77/skip in a host application sandbox; generic adapter
`IO_FAILED` remains a failure.
An unsandboxed Darwin arm64 run exercised the controlling PTY successfully; Linux CI and broader
exact-host terminal-emulator conformance remain required evidence rather than claims.

Source commits through `7656fb1` passed the earlier unsandboxed native terminal lane with 16 tests
and no skip. Final production target `cac6800b6dd7322af620b1e29ffc2dbe2c2569a0` plus test-isolation
target `ca3de6c2bb5057cdce278b728dd581dcc2714b76` passed the local guarded AUTH-focused lane with
273 tests and eight skips, all eight caused only by the independent direct `/dev/tty` host
precondition in the Codex application sandbox. The complete adapter file then passed twice on
unsandboxed Darwin arm64 in independent runs: 56 tests, no skips, including the full PTY exit-path
matrix in suite order. A per-test invariant also proves that the pytest process retains its exact
initial signal mask and all four initial handlers. Ruff, mypy, all four import contracts, the
network-source guard, claim guard, and governance guard passed on the same source tree. Linux PTY
evidence remains open. After final review, the complete locked Python 3.12.12 and Python 3.13.11
lanes each passed 1,900 tests with the same two known macOS multi-threaded-fork deprecation
warnings. Both lanes also passed formatting/lint where applicable, import contracts, and every
safety, site, claim, threat-catalog, governance, and network-source guard; the optional local
network-namespace probe reported `unsupported` on this Darwin host.

This slice does not provide a production CLI command, Docker/container terminal support,
accessibility acceptance, cross-process locking, custody mutation/reconciliation, backup/restore,
browser authentication, PII, or broker behavior. AUTH-001, AUTH-002, and AUTH-003 remain
`IN_PROGRESS`/`NOT_STARTED` according to the canonical matrix.
