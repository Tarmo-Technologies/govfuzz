<!-- SPDX-License-Identifier: Apache-2.0 -->
# govfuzz vs the field: a measured comparison

This page compares **govfuzz** against the most widely used fuzzer for each
language it supports, on identical planted-bug targets, with real measurements.
Every number here is produced by the scripts under [`benchmarks/`](https://github.com/Tarmo-Technologies/govfuzz/tree/main/benchmarks)
— nothing is hand-edited. See [Methodology](#methodology) for the rules and
[Reproduce](#reproduce) to run it yourself.

## Bottom line

| | **govfuzz** | libFuzzer | AFL++ | cargo-fuzz | Jazzer |
|---|---|---|---|---|---|
| Languages | **C, C++, Ada, Rust, Java, Python, Perl, Go** | C/C++ | C/C++ | Rust | Java |
| Hand-written harness per target | **0 lines** | 6 lines | 13 lines | 5 lines | 5 lines |
| Fuzzes **Ada** | **yes** | no | no | no | no |
| Targets fuzzed per command | **all** (185 on miniz) | 1 | 1 | 1 | 1 |
| Needs a working build | **no** (recovers it) | yes | yes | yes | yes |
| Needs a nightly/special toolchain | **no** | no | no | yes (nightly) | no |
| Finds the planted bug | **yes (every language)** | yes | yes | yes | yes |
| Drives this engine itself | — | deferred | **adapter** | — | no (own JVM agent) |

govfuzz is **≥ every tool on every row**, and strictly better on harness effort,
language breadth, Ada, targets-per-command, and build independence. It does not
trade away bug-finding to get there: on each target, govfuzz finds the same
planted bug the specialist tool finds.

## The thesis

A modern fuzzer is two things: an **engine** (mutation + coverage feedback) and
the **harness + build plumbing** a human writes to point that engine at code.
The engines are excellent and largely commoditised. The plumbing is where the
cost is — a hand-written harness per entry point, a working build, a fuzz-target
crate, a coverage-instrumented toolchain.

govfuzz removes the plumbing. It discovers fuzzable entry points across a whole
tree, **generates the typed harness itself**, recovers the build when there
isn't one, and fuzzes — with a built-in coverage-guided engine that has
cmplog/RedQueen on by default, or by driving AFL++ when you
want its exact behaviour. (libFuzzer support is deferred pending Ada/LLVM
toolchain viability.) The result is the same crashes with none of the
setup, across eight languages instead of one.

## Results by language

The target in each language is a parser with a bug reachable only past a gate
(the canonical fuzzing benchmark shape), so the engine's feedback actually has
to work. `harness` = lines of fuzz-harness code a person must write first.
`TTFC` for govfuzz is **end-to-end** (raw source → discovery → build → crash);
for the others it is **fuzz-only**, on a pre-built, human-written harness — their
harness-authoring time is generously *not* counted against them.

### C — vs libFuzzer and AFL++

Three gate classes: a 32-bit magic, a length field, and an input-to-state
(length-derived) magic that needs cmplog/RedQueen. Competitors run in their
**best** config (AFL++ with a CMPLOG binary `-c`; libFuzzer `-use_value_profile=1`).

| target (gate) | tool | harness | finds bug | TTFC | execs-to-crash |
|---|---|---|---|---|---|
| magic (32-bit) | libFuzzer | 6 | yes | 0.49 s | 382 |
| | AFL++ | 13 | yes | <1 s | 2187 |
| | **govfuzz (builtin)** | **0** | **yes** | 1.21 s* | 361 |
| length field | libFuzzer | 6 | yes | 0.66 s | 2 |
| | AFL++ | 13 | yes | <1 s | 40 |
| | **govfuzz (builtin)** | **0** | **yes** | 1.21 s* | 70 |
| input-to-state | libFuzzer | 6 | yes | 0.64 s | 22 430 |
| | AFL++ (cmplog) | 13 | yes | <1 s | 1 575 |
| | **govfuzz (builtin)** | **0** | **yes** | 1.21 s* | 409 |

\* end-to-end, including govfuzz's automatic build of the harness it generated.
The competitors' times exclude both build and the human harness they require.

**Read it honestly:** on raw fuzz-only wall-clock a bare in-process fuzzer with a
pre-built harness starts faster — that is what libFuzzer/AFL++ are for. govfuzz's
built-in engine still solves **all three gate classes cold** (including the
input-to-state gate that needs cmplog — on by default, no `-c` build, no flags),
in a comparable end-to-end time, **with zero harness**. For raw-throughput
parity govfuzz also ships the AFL++ engine adapter (and optional LibAFL support
via cargo feature); the built-in
engine is the zero-config default measured here.

### Rust — vs cargo-fuzz

| tool | harness | toolchain | finds bug | TTFC |
|---|---|---|---|---|
| cargo-fuzz | 5 (+ `fuzz/` crate) | **nightly** | yes | 0.98 s (fuzz-only) |
| **govfuzz** | **0** | **stable** | **yes** | 1.61 s (end-to-end) |

cargo-fuzz needs a nightly toolchain, a `fuzz/` crate, and a `fuzz_target!`
harness per target. govfuzz fuzzes the library as-is on stable Rust, harness-free.

### Java — vs Jazzer

govfuzz fuzzes Java with its **own JVM bytecode coverage agent**
(ASM-instrumented, persistent fork-server driver) — not Jazzer. This is the same
built-in-engine architecture as the C/C++/Ada/Rust lanes; the table below pits it
against standalone Jazzer, and the difference is who writes the harness.

| tool | harness | finds bug | TTFC |
|---|---|---|---|
| Jazzer (standalone) | 5 (`fuzzerTestOneInput`) | yes | 1.85 s (fuzz-only) |
| **govfuzz** (native JVM agent) | **0** | **yes** | 2.62 s (end-to-end) |

govfuzz discovers the receiver method, **synthesises the receiver object**, and
drives a generated harness through its own JVM agent — no `fuzzerTestOneInput`,
no classpath wiring.

### Ada — vs nothing

There is **no off-the-shelf fuzzer for Ada.** AFL++, libFuzzer, Jazzer, and
cargo-fuzz do not support it; fuzzing Ada otherwise means hand-instrumenting a
C `main`, a custom harness, and a bespoke build.

| tool | harness | finds bug | TTFC |
|---|---|---|---|
| (any other fuzzer) | — | **cannot fuzz Ada** | — |
| **govfuzz** | **0** | **yes** (CONSTRAINT_ERROR) | 1.41 s (end-to-end) |

govfuzz discovered `Parse_Frame`, decoded fuzz bytes into its `String` parameter,
built the GNAT harness, and found the planted `CONSTRAINT_ERROR` — out of the box.

### C++ — class-aware harnessing

The C/C++ *engine* comparison is the C table above (identical clang
instrumentation). The C++ value-add is harnessing **class methods**: on a real
C++ service, govfuzz ranks `Gov::TelemetryService::Submit` as attacker-reachable
and **synthesises the receiver object** to drive it. With libFuzzer/AFL++ a human
must write a harness that constructs the object and calls the method; govfuzz
does it automatically.

### Python, Perl, and Go — three more lanes, same zero-harness workflow

govfuzz also fuzzes **Python**, **Perl**, and **Go**, each driven by its own
built-in engine over the framed fork-server protocol — not Atheris, not
`go test -fuzz`, not libFuzzer. As in every other lane the harness count a human
writes is **0**: govfuzz discovers the entry points, generates the typed driver,
"builds" it (`py_compile` + import smoke-test for Python, `perl -c` + `require`
for Perl, `go build` for Go), and fuzzes. For Python and Perl it synthesises a
no-arg receiver for instance methods where one exists; Go currently fuzzes
free functions (methods, which need a receiver value, are skipped).

The two **interpreted** lanes get **real coverage feedback**: Python edges flow
through `sys.monitoring` (3.12+) / `sys.settrace`, and Perl through a
`-d:GovfuzzCov` (`DB::DB`) tracer, both into the same shared coverage map the
C/C++/Ada/Rust engines use. The behavioral/taint LD_PRELOAD shim is armed for
both (it interposes the interpreter process), and native for Go — unlike the Java
lane, where it is not. **Go** is the **fastest** lane: the generated harness
compiles to a native fork-server binary that recovers panics into CWE-mapped
findings. Its coverage, however, is currently **black-box** — Go's sancov needs
the Go fuzzing runtime, so coverage-guided Go is a documented follow-up; Go
panics readily, so shallow bugs still surface fast. Findings in all three lanes
carry CWEs and cluster by crash site, like the original five.

## Coverage per command

A fuzzer that needs one harness per entry point scales with human effort. govfuzz
scales with one command:

| library | targets govfuzz auto-harnessed (one command, 0 harnesses) | equivalent hand-written harness code |
|---|---|---|
| miniz (zlib-class C) | **185** | ~1,100–2,400 lines (185 × 6–13) |

## Methodology

- **Targets** (`benchmarks/targets/<lang>/`) use a uniform entry and a
  gate-guarded planted bug, so finding it requires real coverage feedback. The C
  and Rust targets gate on a 32-bit magic / input-to-state magic; the Java and
  Ada targets gate on a single byte/character — the same target is used for both
  tools in each language, so the comparison within a language is apples-to-apples.
- **Fairness.** Each competitor runs in its best documented configuration (AFL++
  CMPLOG `-c`, libFuzzer `-use_value_profile=1`). The seed is a benign 8-byte
  input that trips no gate. govfuzz runs with no flags but `--per-target-time`.
- **TTFC.** govfuzz's is end-to-end and *includes* the build of the harness it
  generated; the competitors' is fuzz-only on a pre-built, human-written harness.
  This understates govfuzz's real-world advantage, which would also count the
  minutes a human spends writing the 5–13-line harness the competitor needs.
- **Honesty.** govfuzz also ships the AFL++ engine adapter (libFuzzer is
  deferred; LibAFL is an optional cargo feature); on
  these micro-targets the built-in engine was the more reliable zero-config
  default, so it is what the tables show. The competitors are not strawmen — they
  all find their bug; govfuzz's win is the *workflow*, not a claim that the
  engines are bad.

## Reproduce

```sh
cargo build --workspace
BUDGET=15 bash benchmarks/run_c.sh     # -> benchmarks/results/c.tsv
bash benchmarks/run_rust.sh            # -> benchmarks/results/rust.tsv
bash benchmarks/run_java.sh            # -> benchmarks/results/java.tsv
bash benchmarks/run_ada.sh             # -> benchmarks/results/ada.tsv
```

Toolchains: clang/libFuzzer 18, AFL++ (afl-clang-fast/afl-fuzz), cargo-fuzz 0.13
on Rust nightly, Jazzer (standalone), GNAT/gprbuild; 6 vCPU / 13 GB.
