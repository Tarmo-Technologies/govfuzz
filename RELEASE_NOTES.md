<!-- SPDX-License-Identifier: Apache-2.0 -->

# GovFuzz v0.2.22 release notes

Released 2026-07-28.

A correctness release. GovFuzz v0.2.21 went after the targets `--force` could not
rescue; this one goes after the targets GovFuzz was failing for reasons of its
own. Nineteen defects, every one found by measurement rather than inspection: a
full re-run of the 500-project sweep, then reading what the sweep could not
explain, then profiling what was slow.

Two of them had been true for a long time and never surfaced as an error anyone
read.

## No Ada target could be built on GNAT 11

The harness build passed `-gnat2022` unconditionally, documented as "the latest
supported standard, which accepts older code too". That switch arrived in GNAT
12. On GNAT 11 — the default on Ubuntu 22.04 and on still-supported RHEL 9
derivatives — `gnat1` answers `invalid switch: -gnat2022` and the build dies
before reading a line of Ada. Not one Ada target could be harnessed there.

The standard is probed now, once, by compiling a trivial unit, and lowered to
`-gnat2012` where the compiler lacks the switch. Probed rather than parsed from a
version string because vendor GNATs spell their versions freely, and any probe
failure answers "supported" so this can never downgrade a working build.

## `list targets` was blind to 11 of 16 languages

`govfuzz list targets` had its own five-variant language enum — Ada, C, C++,
Java, Rust — written when there were five lanes and never revisited. On a Go,
Python, JS/TS, C#, Ruby, PHP, Perl, Lua, Fortran or COBOL tree it printed nothing
at all, from the one command whose job is to answer "what can this tool see
here?". Across the sweep it listed 2.0 million targets and every one of them was
in those five, while `auto` discovered targets in all sixteen.

The eleven are deferred to `auto`'s own discovery rather than given a second
parser — two surfaces disagreeing about the same tree is the failure mode worth
designing out — gated on a cheap extension scan so a C/C++/Ada/Java/Rust-only
tree pays exactly what it paid before.

## 12.4 GiB during discovery, and a preflight that never finished

The sweep lost 22 projects to `exit=-9`: SIGKILL, no timeout, before a single
target was attempted. Not the harness oversubscribing — one `govfuzz auto` on
simdjson, alone on an idle box, peaks at **12.4 GiB and is OOM-killed**, where
`list targets` over the same 39 MB tree uses 225 MiB.

The C++ parameter decoder's recipe block carried an invariant in a comment:
recipes exist only for a target's DIRECT parameters, so a constructor's arguments
are always directly decodable. The producer graph had since made that false — it
exists to resolve what a chosen constructor's arguments need, to a fixed point,
and is explicitly cyclic. The consumer following those recipes had no bound. It
now carries the chain of keys it is expanding; a repeat is "not decodable", the
same clean skip the parameter got before recipes existed.

With the memory fixed, simdjson still could not be swept: discovery ran past 1500
seconds. Profiling — not inspection — named the cost, and the obvious-looking
quadratic was not it. `recipe_mining::for_source` handed back a CLONE of the whole
recipe map on every cache HIT: 133 of the preflight's 137 seconds on one
2,863-function file. The preflight on simdjson.h (10,894 functions) went from
never finishing to 9.5 seconds, and the whole directory from >1500 s to 218 s.

## Whole lanes that were failing for one small reason

- **Go `/vN` modules** — the harness `go.mod` hardcoded `v0.0.0-incompatible`,
  which semantic import versioning makes illegal for a `/vN` path. Go rejects the
  file before any build, so every target in the project failed: 51 targets across
  9 of 40 Go repos.
- **Go `internal/` packages** — Go decides "outside the internal tree" from the
  import path, so a harness module named `govfuzzharness` was outside every
  project.
- **Java language previews** — javac names the flag it wants; it is asked for once
  now and carried through to the harness compile and the JVM, which both refuse
  preview class files without it.
- **C# classic projects** — the SDK synthesizes `[assembly: AssemblyTitle]` and a
  classic project declares its own, giving `error CS0579` on every target.
- **Ada staged stubs** — a quoted `#include` resolves against the including file's
  own directory, and only the `.c` was being staged. eepers: 0 built+fuzzed → 4.
- **Rust binary-only crates** — a `path =` in `[[bin]]` answered for `[lib]`.

## Honest reporting

- A JS/TS harness that builds and then cannot construct its receiver used to
  report `built, no fuzz pass ran` and name nothing — 58 targets. A load-only
  build gate now takes the driver's own error as the skip reason. Load-only
  rather than "run one input", because a finding halts the driver with a nonzero
  exit and gating on that would skip exactly the targets that crash.
- The blocker histogram was destroying its own grouping key two ways: a path in
  the middle of a diagnostic (176 of 1109 rows were one-offs for that alone) and
  an apostrophe inside a word, which mangled Perl's most common failure.
- A line the interpreter merely ECHOED is not the diagnosis. Node prints
  `throw error;` before the real error; 77 targets reported that line, and
  nothing else, as their whole reason.

## CI

Three workflows had been failing unattended. The GNAT matrix had been red on
every nightly run for at least a week: the pinned gprconfig config declared Ada
only, so all 32 cells died compiling the Ada runtime's one C file. Two C# tests
asserted a fact about the machine rather than the code. The SPDX manifest was
stale.

## What is still missing

`docs/expected-gaps.md` is an honest inventory of every class of target GovFuzz
does not fuzz, sized from the sweep, with a verdict on each: a GovFuzz gap, a
genuinely absent dependency, a toolchain fact, or a deliberate refusal. Read it
before assuming a skip is a bug.
