<!-- SPDX-License-Identifier: Apache-2.0 -->

# Crash & Resource Diagnostics

GovFuzz writes a durable diagnostics trail so a run that dies without a normal
error — most importantly one the terminal reports only as `Killed` — can still
be explained after the fact.

There are three ways a run ends, and each leaves evidence:

| Death mode | How it is captured |
| --- | --- |
| Internal Rust panic | `bug_report.{json,md}` under `<work>/auto` (unchanged) |
| Process SIGKILLed (usually the OOM killer / a cgroup memory limit) | `session_start` with **no** `session_end` in the diagnostics log, a memory-watermark trail, and kernel-log correlation |
| A fuzz worker killed by a signal | the worker's decoded signal + captured stderr in the campaign summary, plus a live message |

## The diagnostics log

Every invocation is bracketed by two records:

```text
2026-07-17T15:56:52.109Z INFO  pid=2054433 session_start: ... label=auto version=0.2.15 argv="govfuzz auto src" mem_limit_kib=4194304
2026-07-17T15:56:52.940Z INFO  pid=2054433 memory: memory watermark advanced label=auto rss_kib=36432 peak_kib=36428 limit_kib=4194304
2026-07-17T15:56:53.941Z INFO  pid=2054433 session_end: ... exit_code=0 elapsed_ms=200 peak_kib=36560
```

**A `session_start` with no matching `session_end` for that pid is the
fingerprint of a killed process** — SIGKILL cannot be caught, so nothing can be
logged at the moment of death, but the missing end record (plus the last
`memory` watermark line) tells you the run was terminated externally and how
much memory it was holding.

### Location

- Default: `<tmpdir>/govfuzz/govfuzz.log` (a single append-only, greppable file;
  every line carries a pid so concurrent runs stay separable).
- `GOVFUZZ_LOG=/path/to/file` — write there instead.
- `GOVFUZZ_LOG=off` (also `0`, `none`, `false`) — disable file logging.

Memory-heavy commands (`auto`, `fuzz`, `ci`, `differential`, `binary fuzz`)
print the log path to stderr on start and run a background memory-watermark
heartbeat. A `WARN` record fires the first time resident memory crosses 90% of a
detected cgroup limit, so an impending OOM is visible *before* the kill.

## Diagnosing an OOM kill

If a run just says `Killed`:

1. `echo $?` — an exit status of `137` is `128 + 9`, i.e. SIGKILL.
2. Look at the diagnostics log: a `session_start` with no `session_end`, and the
   final `memory` line showing `peak_kib` near `limit_kib`, points squarely at
   memory exhaustion.
3. Confirm with the kernel log: `dmesg -T | grep -i -E 'killed process|out of memory'`
   or `journalctl -k`. GovFuzz performs this correlation automatically when a
   fuzz **worker** is SIGKILLed (see below).
4. Mitigate: lower `--workers`, reduce the per-input size, or raise the
   container/cgroup memory limit.

## Fuzz worker deaths

The multi-core orchestrator now captures each worker's stderr to
`<worker_dir>/worker-stderr.log` (previously it was piped and discarded) and
decodes the worker's terminating signal instead of collapsing every signal death
into an opaque "no exit code". When a worker exits abnormally the orchestrator
prints a live diagnostic naming the signal, tails the captured stderr, and — for
a SIGKILL — correlates against the kernel OOM log:

```text
govfuzz: fuzz worker 3 killed by signal 9 (SIGKILL) — likely out-of-memory (OOM killer or cgroup/container memory limit) (stderr: .../worker-stderr.log)
govfuzz: kernel OOM log for worker 3: ... Out of memory: Killed process 12345 (govfuzz) ...
```

The same `term_signal` and `stderr_log` fields are persisted in the campaign
summary JSON for offline triage.
