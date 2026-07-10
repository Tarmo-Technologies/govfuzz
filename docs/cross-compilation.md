<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cross-Compilation

> **Scope.** This guide covers **Ada** cross-compilation with GNAT/GPRbuild and the
> embedded probe backends. **C and C++** also cross-compile and emulate — qemu-user
> for foreign-architecture ELF Linux and wine for Windows-native targets — and
> support RTOS platform-stub packs (VxWorks/INTEGRITY/QNX). **Rust** cross-compilation
> is partial; **Java** does not cross-compile. The LD_PRELOAD runtrace shim
> (behavioral and taint oracles) and the AFL++ secondary engine are **native-only**:
> neither is active under cross-compiled or emulated (qemu/wine) runs.

`govfuzz build` accepts cross-toolchain flags:

```sh
govfuzz build govfuzz_work \
  --harness H-TEST \
  --target aarch64-linux-gnu \
  --runtime ravenscar-full \
  --toolchain aarch64-linux-gnu
```

The generated `govfuzz_build.gpr` includes:

```gpr
for Target use "aarch64-linux-gnu";
for Runtime ("Ada") use "ravenscar-full";
for Toolchain_Name ("Ada") use "aarch64-linux-gnu";
```

`--toolchain` is the executable prefix used on `PATH`. With the example above,
govfuzz looks for `aarch64-linux-gnu-gprbuild` for project builds and
`aarch64-linux-gnu-gnat` for the capability canary. If `--toolchain` is omitted
but `--target` is present, the target triple is used as the prefix.

Before building, the capability probe compiles a tiny canary with:

```sh
<prefix>-gnat -c -gnatc <dialect> canary.adb
```

If a required prefixed tool is missing, the command exits with code `2` and a
message of the form:

```text
host toolchain <prefix> for target <target> not found: missing <tool> on PATH
```

`govfuzz stub` accepts the same flags so diagnostic-driven stub generation can
use the same generated project attributes and compiler adapter selection.

## Probe Backend

`govfuzz build` and `govfuzz stub` also accept `--probe-backend`:

```sh
govfuzz build govfuzz_work \
  --harness H-TEST \
  --target arm-eabi \
  --runtime light-cortex-m3 \
  --toolchain arm-eabi \
  --probe-backend memory_buffer
```

The default backend is `host_file`, which preserves the existing
`AdaFuzz.Probe` behavior of writing events through host file I/O. The
`memory_buffer` backend compiles the same probe API against a fixed-size in-RAM
ring buffer and avoids `Ada.Streams.Stream_IO` and environment-variable access.

The memory-buffer backend exports these C symbols for a runner, emulator, JTAG,
or serial drain to inspect:

- `adafuzz_probe_memory_buffer`
- `adafuzz_probe_memory_buffer_capacity`
- `adafuzz_probe_memory_buffer_write`
- `adafuzz_probe_memory_buffer_wrapped`

The selected backend is materialized into the build-local runtime source
directory as `adafuzz-probe.adb`, so generated GPR projects compile exactly one
probe body per build.

`--probe-backend semihosting` selects a target runtime body for ARM/RISC-V
semihosting-style runs. It writes the same binary event stream to host file
descriptor `2` by calling an imported runtime support hook:

```c
void adafuzz_semihosting_write(uint32_t fd, const void *buf, uint32_t len);
```

That symbol must be provided by the selected target runtime, BSP, or user linker
inputs. If it is absent, the target link should fail rather than silently
falling back to host file I/O.

`--probe-backend stub` selects a no-output runtime body for ROM-only smoke
runs. It preserves the `AdaFuzz.Probe` API and breadcrumb/current-testcase state
for instrumented code, but it does not write an event stream, expose a drain
buffer, or import semihosting support. A top-level harness catch records failure
status, and explicit nonzero `End_Testcase` result classes are reflected through
`Ada.Command_Line.Set_Exit_Status`, so runners that only observe the target
process return code still get a coarse signature class.

## qemu-user Runner

`govfuzz replay` and `govfuzz minimize` can wrap harness execution with a
user-installed qemu-user binary for ELF-Linux cross targets:

```sh
govfuzz replay --finding F-0001 \
  --harness build/H-TEST/main \
  --qemu-user qemu-aarch64 \
  --qemu-arg=-L \
  --qemu-arg=/usr/aarch64-linux-gnu
```

The runner invokes:

```text
<qemu-user> <qemu-args...> <harness>
```

GovFuzz still pipes testcase bytes to the harness stdin and sets
`GOVFUZZ_EVENTS_PATH` for the selected `host_file`-compatible event stream. The
qemu executable is not bundled or auto-detected in this phase; pass the
appropriate `qemu-*-static` or `qemu-*` command and any sysroot/library path
arguments required by the target environment.

## aarch64 Acceptance Fixture

`examples/swallowed_constraint_error/` is the M17 acceptance fixture for
ELF-Linux cross replay. Its generated direct harness reaches a swallowed
`Constraint_Error` in `Pkg.Parse`. The acceptance test builds and runs that
harness on the host, then builds it again for `aarch64-linux-gnu` and checks
that qemu-user replay matches the host finding.

Run the focused acceptance test with:

```sh
cargo test -p govfuzz --test m17_aarch64_cross_fixture swallowed_constraint_error_ -- --nocapture
```

The full aarch64 path runs only when these user-installed tools are available:

- `gprbuild`
- `aarch64-linux-gnu-gprbuild`
- `aarch64-linux-gnu-gnat`
- `qemu-aarch64` or `qemu-aarch64-static`

Set `GOVFUZZ_AARCH64_QEMU_USER` to override qemu discovery. Set
`GOVFUZZ_AARCH64_SYSROOT` when qemu-user needs an explicit target sysroot; the
test passes it as `-L <sysroot>`. If the override is absent and
`/usr/aarch64-linux-gnu` exists, the test uses that path as the qemu sysroot.
