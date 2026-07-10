<!-- SPDX-License-Identifier: Apache-2.0 -->

# Instrumentation

GovFuzz instruments eight fuzzing lanes with different mechanisms. The Ada lane
**rewrites source** to emit probe events; the C, C++, and Rust lanes rely on
**compiler-inserted** SanitizerCoverage and add no source rewriting; the Java
lane uses GovFuzz's own **ASM bytecode** coverage agent (not Jazzer); the Python
and Perl lanes instrument the **interpreter** with runtime tracers
(`sys.monitoring`/`sys.settrace`, `DB::DB`) that feed edge counters into the
shared map; and the Go lane is **compiled** to a native fork-server binary that
fuzzes **black-box** for now. Every coverage lane feeds the built-in engine's
coverage-guided corpus.

## Ada source instrumentation

GovFuzz instrumentation rewrites Ada source so fuzz harnesses can report
testcase boundaries, breadcrumbs, exception-handler transitions, and result
classes.

### Event Model

The generated harness starts each testcase, feeds decoded inputs into the target
subprogram, and records the path through selected source spans. A top-level
harness catch records unhandled exceptions, while explicit swallowed-exception
signals are preserved as findings when a target handles an error without
surfacing it to the runner.

### Ada probe backends

The instrumented API is stable across probe backends:

- `host_file` writes events to a host-visible event stream.
- `memory_buffer` stores events in an exported ring buffer.
- `semihosting` calls a target-provided write hook.
- `stub` keeps result status without trace output.

This keeps generated instrumentation independent from the runner selected for a
specific target.

### Edge coverage

Beyond the probe events, an Ada harness is additionally compiled with
`-fsanitize-coverage=trace-pc` against the AdaFuzz `__sanitizer_cov_trace_pc`
runtime (`ada_runtime/adafuzz_cov.c`). GNAT/GCC rejects the C/C++ lane's
`trace-pc-guard`, so the Ada lane uses the parameterless `trace-pc` variant.
This feeds the same edge bitmap the engine uses for corpus guidance, plus a
bounded persisted corpus (#412). The Ada lane is **presence-only**: the
hit-count-bucket and comparison-progress channels described below are available
in the C/C++/Rust lanes only.
A target whose toolchain rejects `trace-pc`, or that is built uninstrumented,
falls back to event-log / signature feedback.

## C/C++ coverage instrumentation

C/C++ direct harnesses are instrumented at compile time, not by source
rewriting. The generated Makefile compiles each driver with
`-fsanitize-coverage=trace-pc-guard,trace-cmp`, and the harness ships a built-in
SanitizerCoverage runtime — no LLVM, libFuzzer, or sanitizer-fuzzer runtime is
linked. The runtime exposes three coverage-feedback channels, each a separate
`MAP_SHARED` region read by the engine once per execution:

- **Edge presence** — `trace-pc-guard` sets one bit per instrumented edge in a
  cumulative bitmap (`GOVFUZZ_COV_SHM`); the engine reads the popcount to detect
  new edges.
- **Hit-count buckets** (#420) — a parallel byte-map (`GOVFUZZ_COV_CNT_SHM`)
  saturating-increments each edge's per-exec hit count, bucketed AFL-style
  (`1, 2, 3, 4-7, 8-15, …`), so a deeper loop or recursion registers as new
  coverage that edge presence alone cannot see.
- **Comparison progress** (#421, opt-in) — a per-site byte-map
  (`GOVFUZZ_CMP_PROGRESS_SHM`) records the longest leading-byte prefix an input
  matched at each compare site, a laf-intel-style gradient that rewards getting
  one more byte of a multi-byte gate correct. Enabled with
  `--comparison-progress`; inert when the env var is unset.

The same `trace-cmp` callbacks also feed RedQueen/cmplog input-to-state operand
capture (#400) and value-profile dictionary mining (#398). See
[libFuzzer feature parity](libfuzzer-parity.md) for how these map to libFuzzer
knobs.

## Rust coverage instrumentation

Rust direct harnesses are instrumented by the compiler, not by source rewriting.
The target crate and harness are built as a `staticlib` with `cargo +nightly`,
under `RUSTFLAGS` that arm SanitizerCoverage (`-Cpasses=sancov-module`,
`-Cllvm-args=-sanitizer-coverage-trace-pc-guard`,
`-Cllvm-args=-sanitizer-coverage-trace-compares`) plus ASan
(`-Zsanitizer=address`). The resulting `.a` is then `clang`-linked against the
shared C fork-server driver, which is compiled with the matching
`-fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp` and ships the
same built-in SanitizerCoverage runtime as the C/C++ lane. The Rust binary
therefore exposes the same three coverage-feedback channels — edge presence,
hit-count buckets, and (opt-in) comparison progress — and feeds the same
RedQueen/cmplog operand capture and value-profile mining.

## Java instrumentation (ASM bytecode agent)

Java harnesses are instrumented by GovFuzz's own JVM bytecode coverage agent —
the native, Jazzer-free equivalent of SanitizerCoverage for the JVM, not a
third-party fuzzer. The harness runs under
`java -javaagent:govfuzz-jvm-agent.jar ...`, and the agent instruments the
target's classes at load time, inserting a stack-neutral probe
(`LDC <blockId>; INVOKESTATIC Coverage.recordEdge(I)V`) at method entry and at
the start of each basic block. The probe records AFL-style **edges** (block
transitions, `idx = prev ^ block`) into the file-backed `GOVFUZZ_COV_SHM` map,
with a per-edge byte counter that saturates at 255. The built-in engine reads
that map exactly as it reads a C/Rust sancov binary's, so Java targets join the
same coverage-guided cascade. Java uses this single edge map only; the separate
hit-count-bucket and comparison-progress channels are not part of the lane.

## Python instrumentation (interpreter tracer)

Python harnesses are not instrumented by source rewriting or by a compiler — the
lane instruments the **CPython interpreter** at runtime. The generated driver
runs under a persistent CPython held open by the framed fork-server protocol, and
coverage is collected by `sys.monitoring` (3.12+) or a `sys.settrace` fallback,
whose edge counters are written into the same file-backed `GOVFUZZ_COV_SHM` map
the engine reads for every other lane. So unlike the Go lane this is
**real coverage feedback**, not black-box. The LD_PRELOAD runtrace shim is armed
for this lane (it interposes the interpreter process), so the behavioral/taint
oracles run alongside coverage — unlike the Java lane, where the shim is not
armed. Python uses this single edge map only; the hit-count-bucket and
comparison-progress channels are not part of the lane.

## Perl instrumentation (interpreter tracer)

Perl harnesses are likewise instrumented at the **interpreter** level rather than
by source rewriting. The harness runs under `perl -d:GovfuzzCov`, whose `DB::DB`
hook records per-statement edge coverage into the shared `GOVFUZZ_COV_SHM` map;
the `perl -d` debugger path is what makes this the slowest of the tracer lanes,
but the coverage feedback is real, not black-box. The LD_PRELOAD runtrace shim is
armed here too (it interposes the `perl` process). Perl uses this single edge map
only.

## Go (compiled, black-box for now)

Go harnesses are **compiled**: the generated `main` imports the target package
through a module `replace`, decodes by Go type, and is built with `go build` to a
native framed fork-server binary that recovers panics into findings. The runtrace
shim is native for this lane. Unlike the other compiled lanes, Go coverage is
currently **black-box** — Go's libFuzzer SanitizerCoverage needs the Go fuzzing
runtime, so the edge map is not populated and the lane is **not coverage-guided
yet** (coverage-guided Go is a documented follow-up). Because Go panics readily,
shallow bugs still surface fast, and it is among the fastest lanes (compiled;
thousands of exec/s).
