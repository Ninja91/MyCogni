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
  session, concurrent method call, or same-thread reentry before terminal I/O. PID and at-fork
  poison reject inherited objects and locks.
- Reads require the main thread and a foreground controlling terminal. They retain canonical input
  and `ISIG`, disable `ECHO`/`ECHONL`, bound and validate UTF-8 input, drain an oversize line while
  hidden, restore the exact saved attributes, and then emit a newline.
- Temporary `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` handlers unwind through restoration and are
  restored afterward. Restore failure latches the object closed. `SIGKILL` restoration is neither
  possible nor claimed.
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

## Evidence and limits

Deterministic tests cover zero/partial/short writes, drain failure, redacted errors, same-thread
reentry, concurrent calls, non-main-thread input refusal, and corrected application semantics. A
fresh-exec PTY test uses `setsid`/`TIOCSCTTY` and proves no echo plus exact successful restoration
where the host permits child `/dev/tty` access. The Codex macOS sandbox currently denies that open,
so an exact-host unsandboxed Darwin run and Linux CI remain required evidence rather than claims.

Source commit `f54fddf` passed Ruff, strict mypy for the changed runtime surface, import-linter,
safety/site/claim/threat/governance/network guards, and 170 focused guarded tests; the terminal lane
reported one explicit sandbox PTY skip. The distribution build lane could not initialize `uv` under
the sandbox (cache permission/system-configuration panic) and remains for the orchestrator's
unsandboxed full-suite verification.

This slice does not provide a production CLI command, Docker/container terminal support,
accessibility acceptance, cross-process locking, custody mutation/reconciliation, backup/restore,
browser authentication, PII, or broker behavior. AUTH-001, AUTH-002, and AUTH-003 remain
`IN_PROGRESS`/`NOT_STARTED` according to the canonical matrix.
