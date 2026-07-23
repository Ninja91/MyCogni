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
  descriptor as a TTY character device. There is no stdio, environment, argv, browser, network,
  subprocess, logging, keyring, or `getpass` fallback.
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
  restored afterward. Where `pthread_sigmask` exists, handler installation and restoration occur
  with those signals blocked: terminal attributes are restored first, old handlers second, and
  pending signals unblocked last. Partial install, mask-transition, and handler-restore failures
  become finite redacted failures; the private unwind sentinel never crosses the adapter. Platforms
  without `pthread_sigmask` retain best-effort handler transitions and require exact-host evidence.
  Restore failure latches the object closed. `SIGKILL` restoration is neither possible nor claimed.
- Disclosure prebuilds at most eight fields (96 printable ASCII label characters, 512 UTF-8 value
  bytes each, 8192 total bytes), loops over short writes, and drains the TTY. A failure before the
  first nonzero secret write is `NOT_STARTED`; any later write, newline, drain, cancellation, or I/O
  uncertainty is `MAY_HAVE_DISCLOSED`.

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

## Evidence and limits

Deterministic tests cover zero/partial/short writes, drain failure, redacted errors, close/read/write
serialization, child-after-fork close, repeated foreground validation, signal install/restore/mask
faults and cleanup ordering, control rejection, non-main-thread input refusal, post-disclosure
public-write failure, finite input guidance, and corrected application semantics. The fresh-exec PTY
test uses a new interpreter which establishes its own controlling terminal with
`setsid`/`TIOCSCTTY`; it has no threaded-runner `preexec_fn`, applies deadlines to all reads, and
escalates terminate to kill during cleanup. Only an independent direct `/dev/tty` precondition may
produce exit 77/skip in a host application sandbox; generic adapter `IO_FAILED` remains a failure.
An unsandboxed Darwin arm64 run exercised the controlling PTY successfully; Linux CI and broader
exact-host terminal-emulator conformance remain required evidence rather than claims.

Source commits through `7656fb1` passed the earlier unsandboxed native terminal lane with 16 tests
and no skip. The remediation target's exact commit and full locked-runtime/distribution results are
recorded only after final review. Linux PTY evidence remains open.

This slice does not provide a production CLI command, Docker/container terminal support,
accessibility acceptance, cross-process locking, custody mutation/reconciliation, backup/restore,
browser authentication, PII, or broker behavior. AUTH-001, AUTH-002, and AUTH-003 remain
`IN_PROGRESS`/`NOT_STARTED` according to the canonical matrix.
