<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fake-resource SDK

GovFuzz's `runtrace_shim` virtualises the libc boundary so a target
that depends on missing files, unreachable sockets, or unset
environment variables keeps executing against a synthesised
substitute. The fake-resource SDK is the contract for adding a new
fake without forking the shim.

## Architecture

The shim is an `LD_PRELOAD` `cdylib` with strict allocation
discipline: no `malloc` / `Box` / `Vec` / `String` inside hooks,
because the target process may already be inside its own allocator
on the call path being interposed. Plugins are **compile-time**
unit structs that implement `FakeResource`. The trait carries
metadata only — actual interception is done by
`#[no_mangle] extern "C" fn` declarations the dynamic linker
resolves by symbol name.

A plain-data `ManifestEntry` slice (`MANIFEST`, defined in the
cli-safe `runtrace_manifest` crate and re-exported as
`manifest::MANIFEST`) mirrors the trait registry so the cli can list
the inventory without linking interceptors. A unit test in
`registry.rs` enforces the two stay in sync.

## Adding a plugin

For a hypothetical `clock` plugin that fakes `clock_gettime`:

1. Create `crates/govfuzz_runtrace_shim/src/hooks/clock.rs` with:
   - A unit struct (`pub struct Clock;`).
   - An `impl crate::sdk::FakeResource for Clock` returning
     `name = "clock"`, the intercept list, `is_enabled` reading a
     `GOVFUZZ_FAKE_CLOCK` env var, and a one-line description.
   - `#[no_mangle] extern "C" fn clock_gettime(...)` that returns
     a deterministic timespec when enabled and forwards to the real
     symbol otherwise.
2. Register the new module in `hooks/mod.rs`.
3. Append a matching `ManifestEntry::gated(...)` to `MANIFEST` in the
   `runtrace_manifest` crate and a `&Clock` entry to
   `registry::REGISTRY`.
4. The cross-check unit test in `registry.rs` verifies the two
   slices agree.

## Allocation discipline

Every line of hook code runs inside an arbitrary target process on
an arbitrary call path. Do not:

- Allocate (`malloc`, `Box::new`, `String`, `Vec::new`, `format!`).
- Acquire locks unrelated to the shim's own `HookGuard`.
- Recurse into the symbol being intercepted (use `HookGuard` to
  detect re-entry).
- Read configuration from disk.

Do:

- Read configuration from env vars cached in an `AtomicU8` on first
  access.
- Emit audit events via `jsonl::Builder`, which writes to a
  fixed-size stack buffer and calls `libc::write` directly.
- Forward to the real libc symbol via the `dlsym::ResolvedFn`
  helper.

## Diagnostics

`govfuzz auto --list-fakes` prints the inventory:

```
NAME                STATE        ENV_VAR                     INTERCEPTS
env                 always-on    (always-on)                 getenv secure_getenv
net                 always-on    (always-on)                 connect getaddrinfo
fs                  always-on    (always-on)                 open openat close stat fopen unlink unlinkat remove mkdir mkdirat rmdir rename renameat symlink symlinkat link linkat truncate
dl                  always-on    (always-on)                 dlopen dlmopen dlclose
dlsym               always-on    (always-on)                 dlsym
proc                always-on    (always-on)                 system popen execv execvp execvpe execve fexecve posix_spawn posix_spawnp
format              always-on    (always-on)                 printf fprintf sprintf snprintf dprintf
assertion           always-on    (always-on)                 __assert_fail __assert_perror_fail
identity            env-gated    GOVFUZZ_FAKE_IDENTITY       getpid getuid getgid getppid
cmplog              env-gated    GOVFUZZ_CMPLOG              strcmp strncmp memcmp
mem                 always-on    (always-on)                 shm_open shm_unlink shmget shmat shmdt shmctl mmap mmap64
mqueue              always-on    (always-on)                 mq_open mq_receive mq_timedreceive mq_send mq_getattr mq_close mq_unlink
sql                 always-on    (always-on)                 sqlite3_exec sqlite3_prepare sqlite3_prepare_v2 sqlite3_prepare_v3 PQexec PQexecParams mysql_query mysql_real_query
```

## Reference plugin: Identity

`hooks/identity.rs` is the v0.1 reference. When
`GOVFUZZ_FAKE_IDENTITY=1` is set the four POSIX identity calls
return deterministic constants:

| Symbol    | Faked value |
| --------- | ----------- |
| `getpid`  | 4242        |
| `getuid`  | 1000        |
| `getgid`  | 1000        |
| `getppid` | 1           |

Use case: differential fuzzing (issue #306) and reproducible replay
both need identical-looking processes across consecutive runs.

## See also

- [Runtime virtualisation overview](runtime-virtualisation.md).
- [Architecture](architecture.md).
