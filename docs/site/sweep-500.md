<!-- SPDX-License-Identifier: Apache-2.0 -->
# What 500 real projects say about govfuzz

A fuzzer's brochure numbers come from a corpus its authors chose. This page
reports the opposite: govfuzz run over 500 open-source projects picked by
star rank rather than by suitability, across all sixteen languages it supports,
with every failure counted.

The sweep was run to find defects. It found thirty-four, listed below with the
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
| afl++ | the armed `ASAN_OPTIONS` reached afl-fuzz without `symbolize=0`, which AFL++ v4 refuses to start without | the **entire `--engine afl++` path was dead**: harnesses built, AFL aborted in pre-flight, no target ever counted as fuzzed |
| Python, JavaScript, PHP | a target that could not LOAD because a package is not installed was reported as "a parameter couldn't be driven", and named no package | the **largest single blocker class in the corpus** told the operator to run `--force`, which cannot install a package, while `missing-deps.txt` said no dependency was missing |
| Python | the extractor for CPython's `No module named 'x'` stopped at the opening quote | the needle was in the table but never once fired |
| PHP | a Composer project with no `vendor/` produced no requirement at all | the shape of nearly every real PHP tree; now recorded as `vendor/autoload.php` with `composer install` as the remedy |
| report | a backtick span was assumed to close with an apostrophe (the GNAT `` `foo' `` form) | rustc- and interpreter-style `` `foo` `` messages leaked the identifier into the grouping key, so each distinct name became its own histogram row — the opposite of what the histogram is for |
| C++ | the check that degrades an unsuppliable external class to a report-only scan matched on the compiler's *wording*, and the substitution it was written for is no longer the one govfuzz emits | an out-of-tree MFC class stayed a bare `failed_build`; the check now decides on provenance — a diagnostic in the project's own source cannot be a govfuzz codegen bug — so it survives the next change of substitution shape |
| tests | a fuzz assertion's budget is wall-clock, and seven of them shared six cores | a planted OOB went unfound at ~6 executions where one test alone gets ~32; the assertion was sound, the contention was not |
| fuzz | the AFL++ fix above armed `symbolize=0` on **every** fuzz child, and file:line in a sanitizer report is what joins a crash to the static finding at the same line | **every `fuzz_confirmed` static finding silently became `fuzz_exercised`** — the one result govfuzz exists to produce, traded away to make another engine start. The two engines want opposite settings and now get them |
| C, C++ | UBSan's `nonnull` check — how `memcpy(NULL, …)` is actually reported — was not one of the four the parser named, and it returned nothing for the rest | the abort read as the target rejecting the input and the crash was **discarded**, so `govfuzz capsule` had nothing to package and the provenance pass had nothing to demote to `lab_only`. An unrecognised check is now reported generically rather than dropped |
| core | `--max-targets` is exact only when attempts are serial | an exact-count assertion against a parallel sweep read 4 where it wanted 2; the in-flight attempts finishing past the cap is deliberate |
| docs | the site generator refuses to build when a page in `docs/site/` is absent from its manifest | this very page was never registered, so `govfuzz`'s own documentation build failed |
| Ada | a snapshot asserted the probe body is Ada 95 | the body's own header explains why it is Ada 2005 — a `Stream_IO.File_Type` in a `Preelaborate` unit, which `-gnatc` rejects. The parser was right and the expectation was stale |

Two were found by running govfuzz against cloc and syft rather than against
projects — the comparison was worth as much as the sweep. Two more were caused
during this campaign and caught by it: a repair-loop `break` that reached an
`unreachable!`, and a binary rebuilt mid-sweep that would have made the corpus
numbers unattributable. And the `symbolize=0` regression above was introduced by
the fix immediately preceding it, then caught by the suite two commits later.
All of that is the table's spirit: the sweep, and the gate it runs behind, are
the things that notice.

Six of these surfaced only after switching the verification run to
`--no-fail-fast`. The suite had been aborting at one C++ test — binary 92 of 315
— so five later failures were invisible; fail-fast had been reporting one problem
where there were six.

## Results

534 projects measured, 156,861,059 lines of code, 1,048,530 fuzzable targets discovered, **zero harnesses written by hand**.

| Language | Projects | SLOC | Targets found | Attempted | Fuzzed | Rate | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|
| Java | 39 | 8,585,082 | 258,463 | 240 | 45 | 19% | 3 |
| C | 62 | 58,369,970 | 211,934 | 414 | 95 | 23% | 56 |
| Rust | 40 | 10,958,714 | 139,262 | 236 | 56 | 24% | 10 |
| Go | 40 | 13,252,595 | 117,922 | 366 | 63 | 17% | 17 |
| C++ | 59 | 15,274,203 | 64,876 | 187 | 43 | 23% | 13 |
| Ada | 26 | 3,109,189 | 42,043 | 212 | 39 | 18% | 6 |
| Ruby | 23 | 4,464,292 | 41,825 | 211 | 55 | 26% | 0 |
| Perl | 30 | 3,435,644 | 40,959 | 144 | 86 | 60% | 4 |
| Python | 43 | 3,893,826 | 37,190 | 384 | 135 | 35% | 12 |
| Fortran | 20 | 12,808,458 | 24,996 | 124 | 37 | 30% | 159 |
| PHP | 24 | 4,685,622 | 24,842 | 206 | 109 | 53% | 0 |
| TypeScript | 25 | 5,159,766 | 12,624 | 210 | 55 | 26% | 2 |
| Lua | 21 | 3,024,694 | 10,843 | 183 | 54 | 30% | 1 |
| COBOL | 24 | 2,243,149 | 10,082 | 83 | 27 | 33% | 7 |
| C# | 25 | 6,002,013 | 5,887 | 180 | 22 | 12% | 4 |
| JavaScript | 33 | 1,593,842 | 4,782 | 228 | 107 | 47% | 10 |
| **All 16** | **534** | **156,861,059** | **1,048,530** | **3608** | **1028** | **28%** | **304** |

One repository, `DeusData/codebase-memory-mcp`, contributes 37,987,460 of those lines (24% of the corpus) at roughly 46,000 lines per file — generated or amalgamated content rather than written code. Without it the corpus is 118,873,599 lines, which is the figure to reason about; it is left in because the corpus is star-ranked, not curated.

### Robustness

Across 534 projects and 3204 surface invocations: **0 panics**, **17 timeouts**. A tool that is run unattended over an estate has to survive every tree in it, including the malformed ones.

### What blocked the rest

| Targets | Language | Cause |
|---:|---|---|
| 179 | typescript | Cannot find module "X"); run "X" |
| 171 | python | ModuleNotFoundError: No module named "X" |
| 80 | c | C parameter "X" of type "X" has no byte-buffer decoder after struct sy |
| 76 | php | target "X" |
| 71 | java | Java target "X" parameter #N has an unsupported type "X" |
| 58 | go | unsupported Go parameter type "X" |
| 56 | javascript | Error [ERR_MODULE_NOT_FOUND]: Cannot find package "X" imported from /h |
| 53 | cpp | [cpp20] blocked_by_non_self_contained_header: "X" cannot be included b |
| 47 | rust | Rust parameter type "X" has no govfuzz-native byte decoder |
| 44 | javascript | Cannot find module "X"); run "X" |
| 38 | cpp | C++ parameter "X" of type "X" has no byte-buffer decoder (auto-harness |
| 34 | csharp | instance method "X" |

## Reading the blocker table

The largest single class is not a govfuzz limitation: it is uninstalled
dependencies. TypeScript's 179 and Python's 171 top entries are "cannot find
module" — the corpus was cloned and measured without running `npm install` or
`pip install` for 500 projects, so a target whose module graph reaches a package
that is not on the machine cannot be loaded. Install the dependencies and those
targets move.

Finding that out took reading per-target reasons by hand, because the tool did
not say it: three of the six interpreted lanes (Python, JavaScript, PHP) filed
these under "a parameter couldn't be driven", recorded no requirement, and
advised `--force` — the one lever that cannot install a package. All six now name
the package, record it as an acquirable requirement (`missing-deps.json`,
actionable with `--install-deps`), and separate it in the triage from the skips
`--force` is actually for.

What IS a govfuzz limit is the next tier: parameters whose types the project
never defines (80 in C, 38 in C++, 47 in Rust, 58 in Go), C++ headers that
cannot be included outside their owning translation unit (53), and instance
methods whose receiver cannot be constructed (34 in C#). Those are the levers
worth building next, in that order.

## Honest limits

- A target whose parameters are types the project does not define — an external
  SDK's opaque handle — is skipped, not guessed at. govfuzz names the type; it
  does not invent one and call the result a clean fuzz.
- A project whose dependencies are not installed is reported as needing them,
  with the package named, rather than fuzzed against stubs by default. For a
  compiled lane `--force` will drive past a missing type or symbol, and what it
  produces is recorded as stub-only; for an interpreted lane a missing package
  cannot be forced past at all, and govfuzz says so instead of implying it can.
- `--force` is worth less than it sounds. Measured over the 126 corpus projects
  that had at least one undrivable target, applying it from the start of the
  sweep reached **13 fewer** targets than not passing it (214 → 201) for **one**
  extra fuzz finding, because a forced attempt costs ~36% more and the campaign
  budget ran out before the viable targets were reached. It is now a second pass
  that runs after the normal one and only ever adds reach — but the honest
  summary of the lever is that it converts unbuildable targets into static
  analysis, not into fuzzing.
- Interpreted lanes execute the target's module to load it. That is the same
  exposure as fuzzing it, and it is bounded, but it is not free.
- The per-project budget bounds how many targets are attempted. A project with
  thousands of candidates has a fraction of them measured here; the ratio
  reported is over attempted targets, and the discovered total is reported
  beside it so the difference is visible.
