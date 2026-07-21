<!-- SPDX-License-Identifier: Apache-2.0 -->

# Runtime Virtualisation

`libgovfuzz_runtrace.so` is the LD_PRELOAD shim that `govfuzz auto` loads
into each fuzz target. It turns "this binary cannot run because the
environment is wrong" into "this binary runs against a synthesised
environment that the fuzzer drives."

The shim lives in `crates/govfuzz_runtrace_shim` and is Linux-only. On other
hosts the cdylib is built empty; `govfuzz auto` falls through to build-time
sweeping with no runtime audit.

The shim is armed for native C/C++/Ada/Rust/Go/COBOL/Fortran harnesses and for
the interpreted Python/Perl/Ruby/Lua/PHP lanes by interposing their interpreter
processes. It is **not** armed for Java/JVM, C#/.NET, or
JavaScript/TypeScript/Node—each uses managed-runtime-specific coverage and crash
signals—and not under cross-compiled or emulated runs (qemu-user, wine). In
those cases the runtime audit, resource virtualisations, and shim-fed executable
oracles described below are unavailable.

## Intercept List

| Symbol | Behaviour |
|---|---|
| `getenv`, `secure_getenv` | Audit only. Logs the variable name, API, and whether a value was present; never logs the value. The auto loop injects fakes only for NULL results via the real `setenv` so secure-execution and threading semantics stay correct. |
| `open`, `openat` | Logs audited successful opens with fd/path evidence. On ENOENT for a path outside `/proc`, `/sys`, real `/dev`, or the work directory, substitute a `memfd_create` fd. On a path derived from the current fuzz input (a run of at least four input bytes), also appends byte-origin taint fields (`u`=1 controlled, `o`=input offset) to the path event so the CLI can confirm the GF-405 path-controlled-open oracle. Also logs an `insecure_tempfile` event when a file is created (O_CREAT) without O_EXCL in a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`) so executable oracles can flag predictable-temp-file/symlink races. |
| `close` | Logs successful descriptor closes so per-input executable oracles can detect opened descriptors that were not released. |
| `unlink`, `unlinkat`, `remove`, `rmdir`, `rename`, `renameat`, `symlink`, `symlinkat`, `link`, `linkat`, `truncate` | Audit only. Logs destructive filesystem operations (delete, rename, link, truncate) so the GF-440 destructive-fs oracle can flag a parent-directory or otherwise dangerous mutation. |
| `stat` (via `__xstat`), `access`, `faccessat` | Audit only. The stat hook calls the real syscall and logs a `path_miss` on ENOENT (no synthesised stat is returned); `fstat`/`lstat` are not hooked. `access`/`faccessat` return the real result and log a `path_check` event on success (the TOCTOU time-of-check) so executable oracles can flag a path checked then opened. |
| `readlink`, `readlinkat` | Audit only. Calls the real syscall and logs a `path_miss` event on ENOENT; the real result is returned unchanged (no synthesised link target). |
| `connect` (AF_UNIX, AF_INET) | On ECONNREFUSED, replace the fd with one end of a `socketpair()` so a connection to an unreachable peer succeeds against a shim-controlled socket. |
| `dlopen`, `dlclose`, `dlmopen` | On NULL return, allocate a synthetic handle. `dlsym(handle, name)` returns a per-name weak stub that returns `NULL`; `dlclose(handle)` accepts synthetic handles. Disabled by setting `GOVFUZZ_DISABLE_DLOPEN_FAKE=1`. |
| `getaddrinfo` | Audit only. Logs a `net_egress` / `getaddrinfo` event and returns the real result; no address is synthesised (name resolution is not faked). `gethostbyname` is not hooked. |
| `chmod`, `fchmod` | Audit only. Logs an `insecure_chmod` event when a setuid/setgid/world-writable mode is requested so executable oracles can flag incorrect-permission assignment (GF-416, CWE-732). |
| `mkdir`, `mkdirat` | Audit only. Logs an `insecure_mkdir` event when a directory is created world-writable without the sticky bit (or setuid/setgid), promoted to the same GF-416 incorrect-permission oracle (CWE-732). |
| `system`, `popen`, `execv`, `execvp`, `execvpe`, `execve`, `fexecve`, `posix_spawn`, `posix_spawnp` | Audit only. Logs shell command strings and process-execution argv so executable oracles can flag metacharacter-driven command injection (GF-304). |
| `printf`, `fprintf`, `dprintf`, `sprintf`, `snprintf` | Audit only. Logs printf-style format strings and whether the observed bytes match the current fuzz input so executable oracles can flag controlled conversion formats. |
| `__assert_fail`, `__assert_perror_fail` | Audit then forward. Logs native assertion/contract failures before preserving libc's aborting assertion behavior. |
| `sqlite3_exec`, `sqlite3_prepare[_v2/_v3]`, `PQexec`, `PQexecParams`, `mysql_query`, `mysql_real_query` | Audit only. Logs SQL query strings passed to SQLite / libpq / MySQL so the GF-441 SQL-injection oracle (CWE-89) can flag a fuzz-controlled query. |
| `getpid`, `getuid`, `getgid`, `getppid` | Env-gated on `GOVFUZZ_FAKE_IDENTITY`. Returns deterministic identity constants so environment-driven crashes reproduce identically across runs. |
| `strcmp`, `strncmp`, `memcmp` | Env-gated on `GOVFUZZ_CMPLOG`. Records comparison operands (cmplog / RedQueen) so the engine can splice them into inputs to defeat magic-byte and string gates. Off unless the fuzz loop enables it. |
| `mq_open`, `mq_receive`, `mq_timedreceive`, `mq_send`, `mq_getattr`, `mq_close`, `mq_unlink` | Message-queue virtualization (#440). Partitioned / message-driven systems on POSIX (cFS Software Bus, DDS, RTOS-on-Linux IPC) move data over POSIX message queues; a message loop normally blocks in `mq_receive` waiting for a peer that doesn't exist under fuzzing. During a faking pass `mq_open` returns a private fake descriptor and `mq_receive`/`mq_timedreceive` DELIVER the current fuzz input as a message (mode-driven: Empty → none, Rng → pseudo-random, FuzzDriven → the live input), feeding a partition's handler its input through the real IPC API. Delivery is bounded so a `while (1) mq_receive(...)` loop terminates instead of spinning. `mq_send` is swallowed; `mq_getattr` reports a sane message size. (Vendor message-bus structs — cFE `CFE_SB_*`, ARINC 653 APEX — sit above this and are generated against the target's own headers by stub-gen.) |
| `open`/`openat` of `/dev/mem`, `/dev/kmem`, `/dev/gpiomem`, `/dev/uio*`, `/dev/mtd*`, `/dev/i2c-*`, `/dev/spidev*`, `/dev/watchdog*` | MMIO / device-register virtualization (#441). A Linux MMIO driver `open`s one of these and `mmap`s it to reach device registers. During a faking pass the open is redirected to a private, mode-filled memfd (logged as an `mmio` event), so the unprivileged open that would fail with EACCES succeeds, the driver's `mmap` + register reads hit fuzz-controlled memory, and no real device memory is touched. Intercepting at `open` (not `mmap`) keeps this off the allocator/loader hot path. |
| `shm_open`, `shm_unlink`, `shmget`, `shmat`, `shmdt`, `shmctl` | Shared-memory virtualization (#438), POSIX and System V. During a faking pass, `shm_open` returns a harness-PRIVATE `memfd` and `shmget` returns a synthetic id backed by a private anonymous `mmap`; `shmat` returns that private pointer. Two unrelated processes opening the same name / key therefore get distinct memory — there is no foreign writer, runs are deterministic, and the cross-partition MSan-uninitialized / TSan-race false-positive classes disappear. The region is pre-filled with mode-driven bytes (Empty → zero, Rng → pseudo-random, FuzzDriven → the live input) so a target that READS shared memory (expecting a peer partition to have written it) is driven by the fuzz input and the fuzzer reaches content-dependent handlers — still private, and "initialized" to MSan since the shim wrote it. System V segments are keyed and reused so a persistent-mode harness re-`shmget`-ing each input doesn't leak (bounded table); `shmctl(IPC_RMID)` frees, `shmdt`/`shm_unlink` are no-op successes. Audit mode passes all through. |
| `mmap`, `mmap64` | Anonymous-shared-mapping virtualization (#443) — the last shared-memory path. A target that creates inter-process shared memory directly with `mmap(MAP_SHARED \| MAP_ANONYMOUS)` (no shm_open/shmget) would otherwise keep a genuinely-shared region. During a faking pass that one case is rewritten to `MAP_PRIVATE` so it is harness-private (logged as `mmap_private`). Every other `mmap` — file maps, `MAP_PRIVATE`, and all allocator/loader maps — takes a fast path that issues the raw `SYS_mmap` syscall with no reentrancy guard, mode lookup, or allocation, so the interposer can never recurse through the allocator. The real mapping is always the raw syscall (never the `mmap` libc symbol), so there is no self-recursion. |

Each event is appended as one JSONL line to the path in
`GOVFUZZ_RUNTRACE_LOG`. The auto loop parses this between passes to populate
`needed_for_build` Layer C and, during built-in fuzzing, to evaluate
executable oracles against only the events appended by the current input.

## Allocation Discipline

Every hook formats its event into a stack buffer and writes through `libc::write`.
Hooks never call `malloc` / `free` / `Box::new` / `String` / `Vec`. The hooked
process may be inside its own allocator on the call path that reached us.

## Pass Modes

The shim caches `GOVFUZZ_RUNTRACE_MODE` on first use:

| Mode | Behaviour |
|---|---|
| `audit` (default) | Log on failure; do not substitute fakes. |
| `empty` | Create the fake but every `read()` returns EOF on the first call. |
| `rng` | Each fake resource gets a xorshift RNG seeded by `(harness_id, resource_name, fuzz_seed)`. |
| `fuzz_driven` | Reads pull from a shared memfd populated by the harness with the current fuzz input. The engine's coverage feedback learns to steer bytes to whichever fake gates a code path. |

`Mode::is_faking()` returns true for the last three.

## Environment Variables

The shim consumes these env vars. The auto loop sets them via
`Command::env` when spawning each harness, so they do not need to be exported
in the parent shell.

| Variable | Set by | Consumed by | Purpose |
|---|---|---|---|
| `GOVFUZZ_RUNTRACE_LOG` | auto | shim | Path to the per-harness JSONL audit log |
| `GOVFUZZ_RUNTRACE_MODE` | auto | shim | One of `audit` / `empty` / `rng` / `fuzz_driven` |
| `GOVFUZZ_RUNTRACE_SEED` | auto (replay) | shim | Fuzz seed for the per-resource RNG; lets `govfuzz replay` reproduce a finding |
| `GOVFUZZ_FUZZ_INPUT_FD` | harness | shim | File descriptor of the shared memfd carrying the current fuzz input (pass `fuzz_driven`) |
| `GOVFUZZ_FUZZ_INPUT_LEN` | harness | shim | Length of the fuzz input in the shared memfd |
| `GOVFUZZ_DISABLE_DLOPEN_FAKE` | user | shim | Opt out of synthetic `dlopen` / `dlsym` handles when a target uses struct-return-by-value through `dlsym` |
| `GOVFUZZ_FAKE_IDENTITY` | auto (replay) | shim | Enable deterministic `getpid`/`getuid`/`getgid`/`getppid` constants |
| `GOVFUZZ_CMPLOG` | auto | shim | Enable `strcmp`/`strncmp`/`memcmp` comparison-operand recording (cmplog / RedQueen) |
| `LD_PRELOAD` | auto | dynamic linker | Always includes the absolute path to `libgovfuzz_runtrace.so`. Pre-existing values are preserved. |

`govfuzz auto` locates the shim by searching alongside the `govfuzz` binary.
Release-style source builds use `libgovfuzz_runtrace.so`; direct Cargo builds
also accept Cargo's native `libgovfuzz_runtrace_shim.so` artifact. Dist
releases ship the shim as a separate `govfuzz_runtrace_shim-*` archive, and
`govfuzz auto` also searches sibling extracted shim archive directories. When
the shim is not found the auto loop prints a single warning and runs without
the runtime audit.

## Setenv Injection

After the audit pass, the auto loop reads every NULL-result `getenv("X")` or
`secure_getenv("X")` event and calls the real
`setenv("X", "/tmp/govfuzz/fake_env/X", 1)` in the spawned child for the next
pass. The shim does not synthesize values in the env lookup path; the fake
value comes from the actual process environment. This keeps secure-execution,
threading, and glibc internals correct and makes findings reproducible:
`export X=/tmp/govfuzz/fake_env/X` and re-run.

## Replay Envelope

Each finding carries enough state to reproduce the runtime conditions:

```json
"runtime_mode": {
  "pass": "rng",
  "fuzz_seed": "0x47564655_5a5a",
  "env_injected": { "ACME_CONFIG_DIR": "/tmp/govfuzz/fake_env/ACME_CONFIG_DIR" },
  "fakes_active": ["/etc/foo.conf", "unix:///var/run/acme.sock"]
}
```

`govfuzz replay --finding <F> --harness <bin>` rebuilds the same env and
re-loads the shim with the same mode. Reproduction is bit-stable for `rng`
and `empty`; `fuzz_driven` requires the same fuzz input bytes.

## Executable Oracles

Most of these oracles consume the shim's audit stream, so they fire wherever the
shim is armed (native C/C++/Ada/Rust/Go/COBOL/Fortran and the interposed
Python/Perl/Ruby/Lua/PHP interpreters). They do not fire for Java, C#,
JavaScript/TypeScript, or cross-compiled/emulated targets. The Ada
constraint-check oracles (GF-102/103/104/105)
below are the exception — they are fed by Ada source instrumentation compiled
into the binary, not the LD_PRELOAD shim, so they remain available on
cross-compiled Ada targets.

The shim's JSONL audit stream feeds executable oracles in the built-in fuzz
engine. GovFuzz reads only the runtrace lines appended by the current harness
execution, evaluates registered oracles, and emits each unique oracle hit as a
normal finding with the exact input bytes for that execution. The current
executable oracles turn file path events containing a `..` segment, network
egress destinations observed through connect or resolver audit events, and
secret-like environment variable names observed through redacted `getenv` or
`secure_getenv` audit events into `oracle_hit` findings with the matched API
and runtime evidence, even when the value was already present in the
environment. Command
strings observed through `system` or `popen` become command-injection oracle
hits when they contain shell metacharacters. The resource leak oracle also
reports audited file descriptors opened without a matching `close` event before
the current harness execution ends. Successful `unlink`, `unlinkat`, or
`remove` events whose path contains a parent-directory segment become
`file-deletion-runtime` GF-414 oracle hits. Printf-style format strings observed
through `printf`, `fprintf`, `dprintf`, `sprintf`, or `snprintf` become
format-string oracle hits when the format bytes match the current fuzz input
and contain a conversion marker such as `%x`, `%p`, `%s`, or `%n`. `dlopen`
events for bare names, relative paths, parent-directory paths, temporary
writable directories, or otherwise non-system absolute library paths become
`dynamic-library-load-runtime` GF-413 oracle hits. Native C/C++ assertion
failures observed through `__assert_fail` or `__assert_perror_fail` become
`native-assertion-contract` GF-415 oracle hits with expression and source
evidence. `chmod`/`fchmod` calls requesting setuid, setgid, or world-writable
modes (and `mkdir`/`mkdirat` creating world-writable non-sticky or setuid/setgid
directories) become `insecure-permissions-runtime` GF-416 oracle hits (CWE-732), and
files created without `O_EXCL` in a world-writable directory become
`insecure-temp-file-runtime` GF-417 oracle hits (CWE-377). A `path_check`
(access/stat) followed by an `open` of the same path within one execution
becomes a `toctou-runtime` GF-418 oracle hit (CWE-367, time-of-check/time-of-use
race). `open`, `openat`, or `fopen` calls whose path argument carries byte-origin
taint from the current fuzz input (the shim stamps the controlled flag and the
originating input offset on the path event) become `path-controlled-open-runtime`
GF-405 oracle hits (CWE-22). Unlike the per-input oracles above, GF-405 is
confirmed by cross-execution correlation: a path is reported only if it was
tainted on at least one execution and never opened untainted during the run,
which suppresses program-constant paths the auto-dictionary (cmplog tokens
harvested from the target's own string constants) echoes back into inputs.
Ada source instrumentation (the breadcrumb/handler/raise probes, not the
LD_PRELOAD shim) can also
append `runtime_check` events for handled `Constraint_Error` range/index checks,
`Storage_Error`, `Tasking_Error`, or user-defined exceptions; the same
executable-oracle path promotes them to `ada-runtime-constraint-check` GF-102,
`ada-runtime-storage-error` GF-103, `ada-runtime-tasking-error` GF-104, or
`ada-runtime-user-exception` GF-105 findings with handler/source evidence.

### Runtime confirmation

Static source scans emit candidate findings (for example GF-405
path-controlled-file-open and GF-408 format-string) with no confirmation marker.
When the runtrace shim observes the same data flow dynamically — fuzz-input
bytes reaching the sink unsanitized, tracked by byte-origin taint — the
resulting oracle-hit finding is stamped `"confirmation": "runtime"` and carries
a `taint_path` evidence value describing the source→sink flow:
`fuzz_input[offset..] → open(path)` for GF-405, `fuzz_input → printf(format)`
for GF-408. Static-scan findings carry no `confirmation` marker, so consumers
use the field to separate runtime-confirmed hits from static candidates.

## Audit-Only Fallback

If the shim cannot be loaded (host without `LD_PRELOAD` support, statically
linked harness, or `--no-stubs`-style diagnostics modes), the auto loop
falls back to running the harness without the shim. Layer C of
`needed_for_build` stays empty for that target; build-time layers A / B are
unaffected.

## Stderr Pattern Source

Auto also matches a small set of stderr patterns for messages the shim
cannot catch (a target that wrote a custom `No such file: /etc/myconf`
instead of relying on glibc's error string). Hits fold into Layer C with
`source: "stderr_pattern"`.

## Diagnostics

- Inspect `<work>/auto/<harness-id>/runtrace.jsonl` for the raw event log.
- Inspect `<work>/auto/<harness-id>/repairs/` for synthesised stubs, types,
  placeholder headers, and Ada package bodies the attempt loop applied.
- Inspect `<work>/auto/run.json` for the aggregate `needed_for_build`
  ledger and per-target build error classifications.

For the broader auto workflow that drives this shim, see [Auto](../auto/).
