<!-- SPDX-License-Identifier: Apache-2.0 -->

# Running govfuzz on Windows

govfuzz builds and runs natively on Windows in addition to Linux. This page is
the full install + run guide for native Windows. (To fuzz Windows targets *from
Linux* without a Windows host, see the wine cross-fuzzing path in
[cross-compilation.md](./cross-compilation.md).)

## Prerequisites

Install these (e.g. with [Chocolatey](https://chocolatey.org), `winget`, or the
direct installers linked below) and make sure the listed `bin` directories are on
`PATH`:

| Tool | Why | Install |
|------|-----|---------|
| **LLVM/clang** | Harness coverage instrumentation (`-fsanitize-coverage=trace-pc-guard,trace-cmp`) + ASan. The system C/C++ compiler used to build harnesses. | `choco install llvm` or the [LLVM release](https://github.com/llvm/llvm-project/releases) (`LLVM-*-win64.exe`). Adds `C:\Program Files\LLVM\bin`. |
| **VS Build Tools (MSVC + Windows SDK)** | The CRT + linker clang links against, and `msbuild` for Visual Studio solutions. | [`vs_buildtools.exe`](https://aka.ms/vs/17/release/vs_buildtools.exe) `--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended` |
| **GNU make** | govfuzz builds each C/C++ harness through a generated Makefile (same as Linux). | [w64devkit](https://github.com/skeeto/w64devkit/releases) (ships `make` + unix tools); add `C:\w64devkit\bin`. |
| **git** | Cloning target projects (optional). | `choco install git` or [Git for Windows](https://gitforwindows.org). |
| **Rust** (optional) | Only to build govfuzz from source; you can also use a prebuilt `govfuzz.exe`. | [rustup](https://rustup.rs). |

clang on Windows links against the MSVC CRT, so **VS Build Tools must be
installed even when clang is your compiler**.

### One-shot setup on a stock Windows 11 VM

Windows 11 ships [`winget`](https://learn.microsoft.com/windows/package-manager/),
so from a fresh VM (an elevated PowerShell):

```powershell
winget install --id LLVM.LLVM -e                       # clang + ASan + sancov
winget install --id Microsoft.VisualStudio.2022.BuildTools -e `
  --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Git.Git -e                          # optional: clone targets
winget install --id Rustlang.Rustup -e                  # build govfuzz from source
# GNU make: w64devkit is not in winget — download the release zip and add its bin\ to PATH:
#   https://github.com/skeeto/w64devkit/releases
```

Then add the tool `bin` dirs to `PATH` (LLVM, w64devkit) for the shell you build/run in.
Optional per-lane toolchains are needed only for a lane you actually run. See
the limitations below before installing them: several managed/interpreted lanes
currently emit POSIX launchers and should be run under WSL/Linux rather than
native Windows.

## Getting `govfuzz.exe`

Either build it natively:

```powershell
rustup target add x86_64-pc-windows-msvc   # or -gnu
cargo build --release -p govfuzz
# -> target\release\govfuzz.exe
```

…or cross-build it on Linux and copy it over (see cross-compilation.md):

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p govfuzz
```

## Running

`govfuzz` works the same as on Linux. Make sure clang + make are on `PATH` for
the current shell, then point `auto` at a source tree:

```powershell
$env:Path = "C:\Program Files\LLVM\bin;C:\w64devkit\bin;$env:Path"
govfuzz.exe auto C:\path\to\source --per-target-time 30
```

`auto` discovers fuzzable functions, generates typed harnesses, builds them with
clang (edge coverage + cmplog + ASan), fuzzes with the built-in engine, and
writes JSON/Markdown findings — the same core fuzzing pipeline as on Linux. A harness fault is
detected as a crash via the driver's structured-exception handler (Windows has no
POSIX signals).

### Verify the install

Clone the repo and run `auto` against a bundled C library (needs only clang + make
on `PATH`):

```powershell
git clone https://github.com/Tarmo-Technologies/govfuzz.git
cd govfuzz
$env:Path = "C:\Program Files\LLVM\bin;C:\w64devkit\bin;$env:Path"
cargo build --release -p govfuzz
.\target\release\govfuzz.exe auto tests\fixtures\build_recovery\fixtures\miniz `
  --work-dir C:\Temp\gf-miniz --per-target-time 10
```

A summary line reporting discovered + built+fuzzed targets confirms the toolchain
is wired up.

## Visual Studio solutions (.sln / .vcxproj)

`govfuzz auto` understands MSBuild projects. Point it at a tree that contains a
`.sln` or `.vcxproj` and pass `--probe-build`:

```powershell
govfuzz.exe auto C:\path\to\solution-tree --probe-build --per-target-time 30
```

`--probe-build` activates the MSBuild build-probe. govfuzz finds the solution
(scanning a few directory levels — VS solutions often live in `build\VS2022\`,
`msvc\`, …), parses each referenced `.vcxproj` for its include directories
(`AdditionalIncludeDirectories`), preprocessor defines (`PreprocessorDefinitions`),
and source files (`ClCompile`), resolving `$(ProjectDir)` / `$(SolutionDir)`
macros, and writes a `compile_commands.json` under `<tree>\.govfuzz-build\`. It
then builds each harness with the project's real `-I`/`-D` flags via clang (with
edge coverage + cmplog + ASan), so a target that only compiles with a project
define builds correctly.

Example (lz4's bundled solution): `govfuzz.exe auto C:\src\lz4 --probe-build`
recovers the compile database from `build\VS2022\lz4.sln`, then builds and fuzzes
the `LZ4_decompress_*` parsers.

Notes:
- The probe reads the project XML; it does not execute msbuild, so headers
  produced by a custom pre-build/codegen step are not materialized — run that step
  first, or use the CMake probe if the project also ships CMake.
- Coverage is instrumented by compiling the target's sources with clang (not the
  cl-built objects), so findings carry real edge coverage.
- A target whose signature govfuzz cannot yet auto-harness is skipped/reported as
  a failed build; the rest of the solution still fuzzes.

## Software that only builds on Windows (MSVC / Win32)

This is the reason to run govfuzz on a Windows host rather than cross-fuzzing from
Linux: a target that calls Win32 APIs (`<windows.h>`, `CreateFileW`, sockets via
`ws2_32`), uses MSVC-only language constructs (`__declspec`, `__try/__except` SEH,
MSVC intrinsics), or only ships a Visual Studio build cannot be built anywhere but
Windows. govfuzz harnesses it natively there.

**MSVC-only source compiles.** On Windows clang defaults to the
`x86_64-pc-windows-msvc` target, so it accepts the MSVC dialect: `__declspec`,
`__try/__except`, calling-convention attributes, and MSVC intrinsics all compile,
and the harness links against the same MSVC CRT + Windows SDK that `cl` uses (this
is why VS Build Tools is a hard prerequisite even though clang is the compiler).
You do not need `cl.exe` to build the harness, only the SDK + CRT it installs.

**Link libraries.** clang honours in-source `#pragma comment(lib, "ws2_32")`
directives — it emits the linker directive and `lld-link`/`link.exe` pulls the
import library in automatically — and the default Win32 import libs are linked
without any flags. The `.vcxproj` probe does **not** read a project's
`<AdditionalDependencies>`, so a library declared only in the project (not in a
source `#pragma comment(lib)`) is not auto-linked and the harness link fails with
unresolved externals. Two ways to supply them:

```powershell
# Add link inputs (import libs, or the project's own prebuilt .lib) for the
# harness link. Space-separated; honoured by the generated Makefile recipe.
$env:AUTO_EXTRA_LDFLAGS = "ws2_32.lib advapi32.lib C:\src\proj\x64\Release\proj.lib"
govfuzz.exe auto C:\path\to\solution-tree --probe-build --per-target-time 30
```

…or recover the full compile + link context from the real build (below).

**Recovering the real MSVC build (`--build-command`).** When the project's compile
flags or link inputs are too complex to capture from the `.vcxproj` alone, run its
actual build under govfuzz's compiler-interception shim so the exact `cl`/`clang`
invocations are logged into a `compile_commands.json`:

```powershell
# From a "x64 Native Tools" prompt (so msbuild + cl are on PATH):
govfuzz.exe auto C:\src\proj --build-command "msbuild proj.sln /p:Configuration=Release" --per-target-time 30
```

On Windows the interception is a **PATH shim**: it catches compilers invoked by
name (`cl`, `clang`) — the common case once `vcvars` is on `PATH`. The Linux-only
`LD_PRELOAD` exec-shim has no Windows equivalent, so a build step that invokes a
compiler by absolute path may be missed; fall back to `--probe-build` +
`AUTO_EXTRA_LDFLAGS` for those. `--build-command` executes the project's own
(untrusted) build — only run trees you trust.

**Generated headers.** If the build generates headers via a codegen/pre-build step
(`midl`, a `.tt` template, a custom tool), run that step (or a full `msbuild`) once
first so the headers exist on disk; `--probe-build` reads the project XML but does
not execute msbuild. `--build-command` runs the real build and so materializes them.

**Out-of-tree headers / sibling sources.** `--extra-include C:\sdk\include` adds
`-I` paths for dependency headers outside the swept tree; `--extra-source
C:\src\proj\helpers.c` compiles+links a sibling translation unit whose symbols the
target needs (instead of blind-stubbing them). Both are repeatable.

**What you give up vs. Linux.** Only the LD_PRELOAD behavioral/taint oracles (see
the limitations below) — they are Linux-only. Crash detection (a fault becomes a
distinctive exit via the driver's structured-exception handler), edge coverage,
cmplog, and ASan all work natively on Windows.

## Notes / current limitations

- govfuzz itself runs on Linux and Windows; macOS is not yet a target.
- The **C/C++ lane** (including Visual Studio solutions) is the primary,
  most-exercised native-Windows path. Go emits a native binary and works with
  `go` installed. Rust, Ada, COBOL, and Fortran also produce native binaries but
  their Windows toolchain combinations are less exercised; validate them on a
  representative target before relying on a campaign.
- Java, Python, Perl, C#, JavaScript/TypeScript, Ruby, Lua, and PHP currently
  emit POSIX `main` launchers even though discovery is portable. Run those lanes
  under WSL/Linux for now; installing only the interpreter/JDK on native Windows
  is not sufficient. A missing toolchain still skips cleanly.
- The persistent fork-server + coverage-guided engine run on Windows the same as
  on Linux (shared-memory coverage via Win32 file mapping).
- The LD_PRELOAD runtrace shim is Linux-only (an empty stub on Windows), so the
  behavioral and taint oracles (GF-405 path control, GF-304 command injection,
  GF-417 insecure temp, GF-305 sensitive env) do not fire on native Windows.
  Crash detection and coverage-guided fuzzing are unaffected; fuzz the target on
  Linux to exercise those oracle classes.
- The native-Windows harness build uses GNU `make` + clang (same as Linux); the
  drive-letter colon + backslash quirks are handled by emitting forward-slash
  paths into the recipe.
