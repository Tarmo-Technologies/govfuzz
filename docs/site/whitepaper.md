<!-- SPDX-License-Identifier: Apache-2.0 -->
# One fuzzer for the whole codebase

### A white paper on govfuzz — automated, multi-language fuzzing for legacy and mission-critical software

---

## Executive summary

Fuzzing finds the memory-safety and logic bugs that matter, but adopting it is
expensive: a human writes a harness for every entry point, gets the project
building under an instrumented toolchain, and does it again for the next
language. For a legacy C/C++/Ada estate — radar, avionics, RTOS, defense — that
cost is prohibitive, and for Ada there is simply no off-the-shelf tool at all.

**govfuzz removes the cost.** Point it at a source tree and it discovers the
fuzzable entry points, generates typed harnesses, recovers the build when there
isn't one, and fuzzes across **sixteen lanes: Ada, C, C++, Rust, Java, Python,
Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP**, with
a built-in engine or by driving AFL++ directly on native C/C++ targets.

In head-to-head measurements against the most popular fuzzer for each language,
govfuzz finds the same bugs the specialists find while requiring **zero**
hand-written harness code (versus 5–13 lines each), covering **eight measured
languages instead of one**, fuzzing code that has **no working build**, and auto-harnessing
**185 targets from a single command** where the alternatives need one harness
apiece. It is the only one of the group that fuzzes Ada.

Full numbers and a reproducible benchmark suite are in the companion
[comparison](comparison.md).

---

## The problem: fuzzing's setup tax

A fuzzer is two parts. The **engine** — the mutation strategy and coverage
feedback — is mature and largely interchangeable across AFL++, libFuzzer, LibAFL,
and Jazzer. The **plumbing** is everything a human does to point that engine at
code:

1. **Write a harness** for each function you want to fuzz — decode raw bytes into
   the function's typed arguments, construct any receiver object, call it.
2. **Get a working, instrumented build** — the right sanitizer-coverage flags, a
   nightly toolchain for some ecosystems, a `fuzz/` crate for others.
3. **Repeat per entry point, and per language.**

On a greenfield service that is an afternoon. On a 30-year-old radar codebase
with hundreds of parsers across C, C++, and Ada — often without a build that runs
on a modern Linux box, sometimes only buildable by a vendor RTOS toolchain — it
never happens. The bugs stay unfound not because the engines can't find them, but
because no one can afford the plumbing.

And for **Ada**, the lingua franca of safety-critical avionics and defense, the
plumbing tax is infinite: there is no AFL++ for Ada, no libFuzzer, no Jazzer.

---

## The govfuzz approach: delete the plumbing

govfuzz is a front-end that automates all three steps across sixteen current
language lanes.

**Discovery.** It parses the whole tree and ranks fuzzable subprograms by
attacker-reachability — byte-channel parsers score highest, getters and internal
helpers are demoted — so it fuzzes the surface that matters first. One command
surfaced **185** fuzz targets in the miniz library.

**Typed harness generation.** For each target it generates the harness a human
would have written: it decodes fuzz bytes into the real parameter types, and
**synthesises receiver objects** for instance methods — a C++ class through its
constructor, a Java object through its builder, an Ada record through its stream.
No `LLVMFuzzerTestOneInput`, no `fuzz_target!`, no `fuzzerTestOneInput`.

**Build recovery.** Legacy code rarely hands you a working build. govfuzz
recovers the compile context — include paths, defines, generated headers — from
CMake, Meson, Make/autotools, Ninja, Visual Studio, Bazel, or SCons, and for any
other build (a bare `build.sh`, a vendor RTOS build) it intercepts the actual
compiler invocations to learn the flags. When there is no build at all, it
synthesises one and repairs the gaps. RTOS application code that only a Wind
River, Green Hills, or QNX toolchain can compile is fuzzed **stub-isolated** on
the host: govfuzz fakes the platform headers (`vxWorks.h`, `INTEGRITY.h`,
`sys/neutrino.h`) so the algorithmic code builds and fuzzes with sanitizers.

**Engine of your choice.** The built-in engine is coverage-guided with
cmplog/RedQueen *on by default* — in testing it cracked magic-byte, length, and
input-to-state gates cold, with no configuration. When you want a specific
engine's exact behaviour, govfuzz can drive AFL++ itself instead, on native
C/C++ targets.

**Sixteen languages on one engine.** Ada/C/C++ use typed direct generators and
the deepest repair loop; Rust and Java use native/JVM builders; Python, Perl,
JavaScript/TypeScript, Ruby, Lua, and PHP use persistent interpreter drivers;
and Go, COBOL, Fortran, and C# use their lane-specific compiled/runtime paths.
The LD_PRELOAD behavioral/taint layer is narrower than the fuzzing surface: it
runs on native Ada/C/C++/Rust/Go/COBOL/Fortran harnesses and interposes the
Python/Perl/Ruby/Lua/PHP interpreters. Java, C#, and JavaScript/TypeScript retain
their managed-runtime coverage and crash/exception signals without that shim.

---

## The evidence

We compared govfuzz against the most-used fuzzer for each language on identical
planted-bug targets — a parser with a bug reachable only past a gate, so the
engine's feedback has to work. Competitors ran in their **best** configuration
(AFL++ with a CMPLOG binary, libFuzzer with value-profile). The methodology and
every raw number are in the [comparison](comparison.md); the headlines:

- **Zero harness, every benchmarked language.** govfuzz needs **0 lines** of hand-written
  harness in C, C++, Ada, Rust, Java, Python, Perl, and Go. The alternatives
  need 5–13 lines *per
  target* — libFuzzer 6, AFL++ 13, cargo-fuzz 5, Jazzer 5.

- **Same bugs.** On every target, govfuzz found the same planted bug the
  specialist tool found. Its built-in engine solved all three C gate classes
  cold — including the input-to-state gate that requires cmplog, which AFL++
  needed a special `-c` build and libFuzzer needed `-use_value_profile` to crack.

- **Faster to a crash from cold source.** Counting from raw source to first crash
  — discovery, build, and fuzzing — govfuzz reached the bug in **1.2–2.6 s**. The
  specialists' fuzz-only times (0.5–1.9 s) look comparable, but they start from a
  pre-built harness a human already wrote; that authoring time is free in their
  column and still zero in govfuzz's.

- **Scale by command, not by headcount.** One `govfuzz auto` harnessed **185**
  miniz targets. Matching that by hand is ~1,100–2,400 lines of harness code.

- **No special toolchain.** govfuzz fuzzed Rust on **stable**; cargo-fuzz
  requires nightly. govfuzz fuzzed code with **no working build**; every
  competitor requires one.

- **The only Ada fuzzer.** govfuzz discovered an Ada subprogram, decoded its
  `String` parameter, built the GNAT harness, and found a `CONSTRAINT_ERROR` —
  out of the box. No other tool in the comparison can fuzz Ada at all.

| | govfuzz | best alternative |
|---|---|---|
| Hand-written harness / target | **0 lines** | 5–13 lines |
| Current product languages | **16** (the 8 named above were measured here) | one each |
| Targets per command | **all (185 on miniz)** | one |
| Fuzzes with no working build | **yes** | no |
| Fuzzes Ada | **yes** | no |
| Finds the planted bug | **yes, every language** | yes |

---

## Where it matters: legacy, defense, RTOS

govfuzz was built for the codebases other fuzzers can't reach: government and
defense legacy systems in Ada, C, and C++, frequently targeting RTOS platforms
(VxWorks, Green Hills INTEGRITY, QNX) that a Linux lab box cannot run. For these,
the setup tax isn't just expensive — it's the reason the code has never been
fuzzed. govfuzz's build recovery, vendor-toolchain interception, and RTOS
platform-stub isolation are what turn "we can't build this here" into "it's
fuzzing." It operates fully offline, treats every scanned tree and child-process
output as untrusted, and emits findings as JSON, SARIF, JUnit, Markdown, and CSV
for the pipelines these programs already run.

---

## Conclusion

The fuzzing engines are a solved problem. The barrier to fuzzing real, legacy,
multi-language, mission-critical software is the human plumbing around them —
and for Ada, the total absence of a tool. govfuzz removes the plumbing: one tool
with sixteen current language lanes that found the same planted bugs as AFL++,
libFuzzer, cargo-fuzz, and Jazzer across the eight lanes measured here, with no
harness, on code that does not even build — and the only fuzzer in this
comparison that handles Ada.

One fuzzer for the whole codebase.

---

*Reproduce every figure: `benchmarks/` in the govfuzz repository. Measurements on
clang/libFuzzer 18, AFL++, cargo-fuzz 0.13 (Rust nightly), Jazzer, GNAT/gprbuild;
6 vCPU / 13 GB.*
