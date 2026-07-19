<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cross-Compilation

GovFuzz supports cross-compilation through explicit target, runtime, toolchain,
probe-backend, and qemu-user runner flags.

## Build Flags

```sh
govfuzz build govfuzz_work \
  --harness H-TEST \
  --target aarch64-linux-gnu \
  --runtime ravenscar-full \
  --toolchain aarch64-linux-gnu
```

When `--toolchain` is present, GovFuzz looks for prefixed tools such as
`<prefix>-gprbuild` and `<prefix>-gnat`. If `--toolchain` is omitted but
`--target` is provided, the target triple is used as the prefix.

## Foreign-Platform Targets in `govfuzz auto`

`govfuzz auto` does NOT host-filter foreign-platform code. A function whose
definition is guarded by a non-host platform/arch conditional — a C/C++
`#ifdef _WIN32` / `_MSC_VER`, an Ada `__win32` unit, or a SIMD-arch backend dir
(`arm64`, `neon`) — is discovered, ranked, and tagged with a `foreign_guard`
instead of being dropped. The attempt loop then picks a build+fuzz strategy:

- **Windows (`_WIN32`) C/C++ → mingw + wine (real Windows execution).** When the
  `x86_64-w64-mingw32` cross toolchain and `wine` are on `PATH`, the harness is
  cross-compiled to a real Windows PE and fuzzed under wine, exercising the
  target's actual Win32 behavior. Coverage and cmplog are real: mingw-w64 gcc
  supports `-fsanitize-coverage=trace-pc,trace-cmp` (the driver implements the
  guard-less `__sanitizer_cov_trace_pc` hook), so the engine gets edge coverage +
  input-to-state feedback. There is no ASan runtime for mingw, so memory-safety
  faults are detected by a vectored exception handler the driver installs: a
  hardware fault (access violation, stack overflow, …) becomes an immediate,
  distinctive process exit the engine classifies as a crash.
- **Arch/SIMD (aarch64, armhf, neon) → cross toolchain + qemu-user.** A 64-bit
  ARM / NEON guard builds with `aarch64-linux-gnu-gcc` under `qemu-aarch64`; a
  32-bit ARM (armv7/armhf) guard builds with `arm-linux-gnueabihf-gcc` under
  `qemu-arm`. This
  path is coverage-blind today (the cross GCCs reject `trace-pc-guard` and ASan
  does not survive qemu-user); hard crashes still surface via SIGSEGV/SIGABRT.
- **Windows fallback → native stub-isolated build.** When mingw/wine is absent,
  a `_WIN32` C/C++ target (not Ada or Rust) is built NATIVELY with `_WIN32` defined and a synthesized
  fake `<windows.h>` so its portable logic type-checks and fuzzes with real host
  ASan + coverage. Findings are flagged REDUCED-FIDELITY (the platform surface is
  faked: handles are inert, Win32 behavior is not modeled).
- **No strategy → actionable skip.** A guard with neither a platform stub nor an
  installed cross toolchain is skipped with a reason naming exactly what to install.

### Cross-compilation scope and oracle limitations

These `auto` build+fuzz strategies cover C and C++ targets; foreign-platform Ada
targets are skipped with an actionable reason (`auto` cross-compiles only C/C++ —
Ada cross-compilation is available via the explicit `govfuzz build
--target/--toolchain` path with a matching GNAT cross toolchain). Rust
cross-compilation is partial (it shares the qemu-user path), and Java targets
cannot be cross-compiled — they run only on the host JVM.

Emulated targets (qemu-user / wine) run WITHOUT the LD_PRELOAD runtrace shim, so
the behavioral and taint-tracking oracles (GF-405 path-controlled file access,
GF-304 command injection, GF-417 insecure temp files, GF-305 sensitive-environment
exposure) are unavailable — only crashes and, where the toolchain supports it,
edge coverage surface. To catch those vulnerability classes, fuzz the target
natively.

The AFL++ secondary engine is native C/C++ only, so cross-compiled or emulated
C/C++ targets — along with all Ada, Rust, and Java targets — fall back to the
built-in engine.

### Prerequisites for the Windows path

```sh
# Debian/Ubuntu
sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64
# Initialize the wine prefix once and disable the crash dialog so an unhandled
# guest fault exits fast instead of blocking on a debugger popup (the driver's
# own exception handler already terminates on a fault, but this is belt-and-suspenders):
wineboot -i
wine reg add 'HKCU\Software\Wine\WineDbg' /v ShowCrashDialog /t REG_DWORD /d 0 /f
```

The coverage / cmplog shared-memory maps are backed by real files, so the engine
(running on the Linux host) and the wine'd harness see the same bytes; wine maps
the host root at drive `Z:` so the absolute paths the engine passes resolve.

## Building govfuzz Natively for Windows

govfuzz also cross-compiles to a native Windows binary (in addition to Linux):

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p govfuzz
# -> target/x86_64-pc-windows-gnu/release/govfuzz.exe
```

`govfuzz.exe` runs the full CLI on Windows and fuzzes Windows harnesses. With no
POSIX signals on Windows, a harness fault is classified as a crash via the
driver's vectored-exception-handler exit sentinel (`0x39`). Validated under wine;
on a real Windows host, use clang/mingw for the harness build step.

Current native-Windows scope:

- ✅ Builds clean for `x86_64-pc-windows-gnu`; the CLI + reporting run natively.
- ✅ Fuzzes a built harness and detects crashes.
- ✅ Coverage-guided feedback + the persistent fork-server run on Windows the same
  as on Linux: the shared-memory coverage/cmplog readers are implemented on Win32
  file mapping (`CreateFileMappingW`/`MapViewOfFile`) on both the engine and
  harness sides.

The one native-Windows gap is the LD_PRELOAD runtrace shim, which is Linux-only
(an empty stub on Windows), so the behavioral/taint oracles are unavailable
natively. To get those oracles on a Windows target, run govfuzz on Linux and let
it cross-compile + emulate the target under wine (the section above). See
[Windows](./windows.md) for the native-host guide.

## Probe Backends

- `host_file` writes the event stream through host file I/O.
- `memory_buffer` keeps events in an exported target memory ring buffer.
- `semihosting` writes through an imported semihosting support hook.
- `stub` preserves testcase result status without emitting an event stream.

## qemu-user Replay

```sh
govfuzz replay --finding F-0001 \
  --harness build/H-TEST/main \
  --qemu-user qemu-aarch64 \
  --qemu-arg=-L \
  --qemu-arg=/usr/aarch64-linux-gnu
```

The runner still passes testcase bytes on stdin and preserves GovFuzz finding
normalization, so host and emulated replay results can be compared.

## Sandbox Execution

Harness execution can be wrapped with a user-installed Linux sandbox:

```sh
govfuzz replay --finding F-0001 \
  --harness build/H-TEST/main \
  --sandbox firejail \
  --sandbox-tool /usr/bin/firejail \
  --sandbox-strict
```

`--sandbox auto` tries `bwrap` and then `firejail`. Without `--sandbox-strict`,
missing sandbox tooling falls back to direct execution and records
`sandbox.mode = "none"` in fuzz summaries and findings. With strict mode,
GovFuzz reports a clear missing-sandbox error.
