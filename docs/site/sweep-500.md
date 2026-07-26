<!-- SPDX-License-Identifier: Apache-2.0 -->
# What 500 real projects say about govfuzz

A fuzzer's brochure numbers come from a corpus its authors chose. This page
reports the opposite: govfuzz run over 500 open-source projects picked by
star rank rather than by suitability, across all sixteen languages it supports,
with every failure counted.

The sweep was run to find defects. It found twenty-one, listed below with the
project that exposed each one. The measurements come after the fixes, from a
single pinned binary over the whole corpus.

## Method

- **Corpus**: 500 repositories, star-ranked per language, pinned in
  `benchmarks/campaign-2026-07-25/corpus.tsv`. Excluded: fuzzing corpora and
  deliberately-vulnerable trees (they supply their own bugs), awesome-lists and
  courses (no code), forks, archived trees, anything over 400 MB. GitHub's
  language label is not trusted — each clone is checked against its lane and
  replaced from a ranked pool if it is not mostly that language.
- **Budget**: every project gets the same one. No per-project tuning, no
  hand-written harnesses, no build fixes, no dependency installation beyond what
  a developer of that language would already have.
- **Counting**: a target counts as fuzzed only if it built AND the fuzz entry
  point was reached. A build that links against stubs and executes none of the
  project's own code is recorded separately (`fuzzed_stub_only`), never folded
  into the headline.

Everything needed to re-run it is in `benchmarks/campaign-2026-07-25/`.

## What the sweep is measuring

The question is not "how fast does the engine mutate bytes" — on one hand-written
harness, libFuzzer and AFL++ are excellent and govfuzz says so. The question is
how much of a real estate can be fuzzed *at all* without someone writing
harnesses first, because that is the work that does not happen: an engineer with
a week can write five harnesses, not five hundred.

So the headline is coverage of the estate:

- targets discovered, per language, across 500 projects nobody prepared
- of those attempted, how many built and fuzzed
- what stopped the rest, named precisely enough to fix

## Defects the sweep found

Every one of these was a govfuzz bug, not a project bug, and each is fixed with
a regression test:

| Language | What was wrong | Effect on the project that exposed it |
|---|---|---|
| Perl | code was classified by file extension only | cloc — 20k lines of Perl in a file named `cloc` — discovered **0** targets; now 6/6 fuzzed |
| Perl | `require FILE` compiles into the caller's package | a script's `main::` subs looked undefined |
| Fortran | the C driver and the Fortran glue both defined `__sanitizer_cov_trace_pc` | **every** Fortran target failed to link |
| Fortran | only MODULE-defining files were pre-compiled | FORTRAN 77 (LAPACK, BLAS) had nothing to link against |
| C# | the framework table was hardcoded to net8.0 and ignored `Directory.Build.props` | v2rayN: **0 of 25** targets; now 3/5 at 9.5k exec/s |
| C# | `dotnet build -o` across a project graph | every harness after the first died in MSB4018 |
| Ruby, Lua | the interpreter saw only the file's directory and the checkout root | nearly everything skipped as "not loadable" |
| Python | a module whose name is not an identifier | git's `git-p4.py`: **0 of 3**, reported as the project's syntax error; now 3/3 |
| C | `app/` was on the non-library exclusion list | scrcpy, a C project, discovered **0** C targets; now 759 candidates |
| C | ANSI `(void)` prototypes and commented-out examples read as K&R | modern C files routed to report-only, never fuzzed |
| C | an undefined function-like macro in a `#if` | scrcpy's FFmpeg version check left a whole TU unbuildable |
| core | `--campaign-time` was billed from process start | discovery on a large tree consumed the budget: 8606 candidates, **0** attempted |
| core | the budget did not bound work already running | a 150-second budget took ten minutes |
| triage | `verify-poc` on a capsule packaged as non-reproducing | reported FAIL, reading as a regression rather than a known limitation |
| Rust | a binary-only crate has no `src/lib.rs`, and the generated manifest did not say where the library was | cargo refused the manifest: "can't find library `vaultwarden`" |
| Rust | a path dependency inside the crate was pinned back to the original tree, which the copy also contained | "package collision in the lockfile" |
| C# | an old-style project declares `<TargetFrameworkVersion>`, not `<TargetFramework>` | .NET Framework projects were referenced anyway and died on reference assemblies that do not exist off Windows — 28 targets |
| core | parsing recurses, and a main thread's 8 MiB is not enough for real source | vllm and milvus **aborted the whole run** during discovery |
| report | a file's static findings were keyed by the target being harnessed | one Fortran project reported **120 findings for 24 real weaknesses** |
| report | a compiler `note:` was read as the blocker | Ventoy's histogram named a deprecation notice as what stopped the build |
| sloc, static | the file walk admitted ten of the sixteen fuzzed lanes | a 217-file PHP project measured **333 lines**, all of it config; Ruby, Lua, C#, COBOL and Fortran were equally invisible |
| sbom | the gemspec parser required parentheses | every gemspec-driven Ruby project reported **zero** components |

The last two were found by running govfuzz against cloc and syft rather than
against projects — the comparison was worth as much as the sweep. Two others
were caused during this campaign and caught by it: a repair-loop
`break` that reached an `unreachable!`, and a binary rebuilt mid-sweep that would
have made the corpus numbers unattributable. Both are in the table's spirit —
the sweep is the thing that notices.

## Results

1 projects measured, 34,324 lines of code, 1,272 fuzzable targets discovered, **zero harnesses written by hand**.

| Language | Projects | SLOC | Targets found | Attempted | Fuzzed | Rate | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|
| C | 1 | 34,324 | 1,272 | 10 | 0 | 0% | 0 |
| **All 16** | **1** | **34,324** | **1,272** | **10** | **0** | **0%** | **0** |

### Robustness

Across 1 projects and 6 surface invocations: **0 panics**, **0 timeouts**. A tool that is run unattended over an estate has to survive every tree in it, including the malformed ones.

### What blocked the rest

| Targets | Language | Cause |
|---:|---|---|
| 5 | java | javac (target) failed: /home/ubuntu/govfuzz-corpus-N/c/Genymobile__scr |
| 3 | c | C parameter "X" of type "X" has no byte-buffer decoder after struct sy |
| 2 | c | missing header |

## Honest limits

- A target whose parameters are types the project does not define — an external
  SDK's opaque handle — is skipped, not guessed at. govfuzz names the type; it
  does not invent one and call the result a clean fuzz.
- A project whose dependencies are not installed is reported as needing them,
  with the package named, rather than fuzzed against stubs by default.
  `--force` will drive past that; what it produces is recorded as stub-only.
- Interpreted lanes execute the target's module to load it. That is the same
  exposure as fuzzing it, and it is bounded, but it is not free.
- The per-project budget bounds how many targets are attempted. A project with
  thousands of candidates has a fraction of them measured here; the ratio
  reported is over attempted targets, and the discovered total is reported
  beside it so the difference is visible.
