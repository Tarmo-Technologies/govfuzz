<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing C# / .NET with govfuzz

govfuzz fuzzes C# with **no harness to write** — point it at a .NET source tree and
it discovers fuzzable methods, generates the harness, builds the target with
`dotnet`, instruments it, and fuzzes, coverage-guided, at native fork-server rates.

```sh
govfuzz auto path/to/dotnet-src --languages csharp
```

## How it works

A `public` method taking a byte buffer (`byte[]`, `ReadOnlySpan<byte>`,
`Memory<byte>`), a `string`, or a `System.IO.Stream` is the fuzzable unit. govfuzz:

1. **Discovers** each such method, tracking the namespace and enclosing type by
   brace depth, and typing every parameter. Constructors, properties, local
   functions, generic methods, and interface/enum members are excluded. A method
   is fuzzed when it has exactly one input parameter plus only synthesizable
   scalar siblings (an `int` length operand), so govfuzz never invents a
   reference-type argument and reports the resulting `NullReferenceException` as a
   phantom bug.
2. **Builds** the target with `dotnet build -c Release` through a
   `ProjectReference` to the owning `.csproj`, alongside a generated
   `GovfuzzEntry.Run(byte[])` shim that decodes the fuzz bytes to the parameter's
   exact static type (`byte[]` straight through, `string` via UTF-8, `Stream` via
   a `MemoryStream`, spans via the matching wrapper).
3. **Instruments** the target assembly's IL with
   [SharpFuzz](https://github.com/Metalnem/sharpfuzz) (`sharpfuzz <dll>`, Apache-2.0),
   which rewrites every basic block to record edge coverage.
4. **Fuzzes** it over govfuzz's own coverage-guided fork-server engine. The driver
   `mmap`s govfuzz's file-backed `GOVFUZZ_COV_SHM` edge bitmap (64 KB — exactly the
   AFL map size SharpFuzz targets) into `SharpFuzz.Common.Trace.SharedMem`, so the
   instrumented target writes coverage straight into govfuzz's cumulative bitmap.
   The driver speaks the framed fork-server protocol, keeping **one warm CLR**
   alive across all inputs (amortizing JIT + assembly-load startup) — no AFL
   fork-server, no libFuzzer, no `afl-fuzz` process.

### Oracle

An **uncaught exception** that is not input rejection is the finding signal (the
driver hard-halts with exit 86 and a `== govfuzz csharp finding:` marker). The
.NET exception type maps to a GF rule + CWE:

| Exception | Rule | CWE |
|---|---|---|
| `IndexOutOfRangeException` | GF-201 | CWE-125/787 (out-of-bounds) |
| `NullReferenceException` | GF-206 | CWE-476 (null dereference) |
| `DivideByZeroException` / `OverflowException` | GF-205 | CWE-369/190 |
| `StackOverflowException` | GF-207 | CWE-674 (uncontrolled recursion) |
| `OutOfMemoryException` | GF-209 | CWE-789 |
| any other / custom throwable | GF-210 | reachable crash |

Input-rejection exceptions (`ArgumentException` and its subclasses,
`FormatException`, `NotSupportedException`, `IOException`, `KeyNotFoundException`)
and exceptions declared in the **target's own namespace** are treated as the
library's intended way of rejecting bad input — swallowed, not reported — which is
the key to a low false-positive rate on a dynamically-fed API.

Unlike the native C/C++/Ada/Rust/Go/COBOL/Fortran and
Python/Perl/Ruby/Lua/PHP lanes, the C# lane does **not**
run under the runtime-virtualisation shim: the .NET host's own startup file I/O
(resolving `libhostfxr.so` via `access()`→`open()`, loading assemblies) would
otherwise trip the shim's TOCTOU/open oracles as false positives. Coverage comes
from SharpFuzz's IL instrumentation and crash detection from the exception
hard-halt, so no shim is needed.

## Where govfuzz stands vs the field

C# has essentially **one** open-source fuzzer:
[SharpFuzz](https://github.com/Metalnem/sharpfuzz), the same IL-instrumentation
library govfuzz builds on. SharpFuzz is excellent, but it is a *library*: to use it
you hand-write a fuzzing program (`Fuzzer.LibFuzzer.Run(bytes => Target.Parse(bytes))`
or `Fuzzer.OutOfProcess.Run`), instrument the target dll yourself, install and run
`afl-fuzz` (or a libFuzzer host) with the right shared-memory plumbing, and repeat
per target. Microsoft's OneFuzz (archived 2023) orchestrated fuzzing at scale but
never fuzzed C# *source methods* directly. On the static side, Roslyn analyzers,
SonarQube, and Coverity flag candidate issues but do not confirm them with real
input.

govfuzz automates the entire SharpFuzz workflow end to end:

| | SharpFuzz (raw) | **govfuzz `auto --languages csharp`** |
|---|---|---|
| Fuzzing function to write | one per target | **none — auto-discovered** |
| Instrument the dll | manual `sharpfuzz` call | automatic |
| Fuzzer to install & wire | AFL / libFuzzer host | **built-in engine** |
| Coverage plumbing | `__AFL_SHM_ID` / shmat | **automatic (`GOVFUZZ_COV_SHM` bridge)** |
| Multi-target sweep | scripted by hand | **one command over the whole tree** |
| Findings → CWE / SARIF / CSV | — | built-in |

It is the first tool to fuzz C# from source with **zero harness** and **zero AFL
setup**, reusing SharpFuzz's proven IL instrumentation as the coverage source (the
honest analog of how the Fortran lane reuses gfortran + ASan).

## Validation (campaign)

A 25-project campaign over the most-starred .NET libraries — dotnet/runtime,
roslyn, EF Core, Newtonsoft.Json, MessagePack-CSharp, YamlDotNet, ImageSharp,
protobuf-net, SharpZipLib, ML.NET, and more:

- **69,608 C# files scanned, 3,113 fuzzable methods discovered, 0 govfuzz panics** —
  discovery is robust across enormous, idiomatic C# (roslyn alone: 17,094 files →
  973 targets). 24 of 25 repos completed cleanly; only dotnet/runtime (32,403
  files, the single largest .NET repo) needs a longer discovery budget.
- **End-to-end on YamlDotNet**: 14 of 21 methods were built, IL-instrumented, and
  fuzzed at **~15,000 executions/second** on one warm CLR with **2,304 edges** of
  real coverage — and govfuzz **fuzz-confirmed 8 real bugs**: a
  `System.IndexOutOfRangeException` (CWE-125) reachable from every naming-convention
  entry point, root-caused to an unguarded `text[0]` on an empty string in
  `StringExtensions.ToCamelOrPascalCase`. Zero hand-written harness, **0 shim false
  positives**.

## Requirements & licensing

- **.NET SDK** on the host — [install](https://dotnet.microsoft.com/download).
- **SharpFuzz.CommandLine**: `dotnet tool install --global SharpFuzz.CommandLine`.
- SharpFuzz and SharpFuzz.Common are **Apache-2.0** and link into the *user's*
  harness assembly, never into govfuzz. The .NET runtime is MIT. No GPL is
  involved; the lane keeps govfuzz's permissive-core policy intact.

## Limits (honest)

- The fuzzable surface is a single `byte[]`/`string`/`Stream` input parameter (plus
  an optional `int` length). Methods that need a constructed options/context object,
  a generic type argument, or multiple structured inputs are skipped cleanly rather
  than driven with synthesized `null`s — widening this is a planned enhancement.
- An instance method's declaring type must be no-argument-constructible (the shim
  `new`s it); a type with only a parameterized constructor is skipped.
- The target must build with the .NET SDK through a project reference; a project
  that only targets .NET Framework (`net48`) on a non-Windows host degrades to a
  clean skip.
- One method is instrumented + fuzzed at a time; the target's own dependencies are
  loaded but not instrumented (coverage is scoped to the code under test).
