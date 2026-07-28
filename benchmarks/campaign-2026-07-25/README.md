<!-- SPDX-License-Identifier: Apache-2.0 -->
# 500-project sweep (2026-07)

A single sweep of govfuzz over 500 pinned open-source projects spanning all
sixteen supported languages, run to find bugs and feature gaps rather than to
produce a number. The numbers came second; every one of them is reproducible
from what is in this directory.

## How to reproduce

```sh
python3 build_corpus.py select      # re-select the corpus (writes corpus.tsv + pool.tsv)
sh launch_full.sh                   # run the sweep with the pinned binary
python3 aggregate.py --blockers 25  # the tables below
python3 charts.py                   # the figures
python3 surfaces.py --project <dir> # the 22 non-fuzz surfaces
python3 compare.py sloc|static|sbom # against cloc/tokei, cppcheck/…, syft
```

The corpus is pinned in `corpus.tsv` (lane, repo, clone URL, stars, size), with
`pool.tsv` holding ranked replacements. Clones are streamed — cloned, measured,
deleted — so the whole 500-project sweep never holds more than a handful of
working trees on disk. `results/` has one distilled JSON row per project:
target-status histogram, residual blockers, findings, per-surface exit codes and
wall times, and any panic.

The binary is pinned to a copy (`/home/ubuntu/govfuzz-sweep-bin/govfuzz`) for
the duration: rebuilding mid-sweep would mix tool versions across the corpus and
make the aggregate unattributable.

## Corpus selection

Star-ranked GitHub search per language, minus repositories that would distort
the measurement: fuzzing corpora and deliberately-vulnerable trees (they supply
their own bugs), awesome-lists and courses (no code), forks, archived trees, and
anything over 400 MB.

GitHub's primary-language attribution is unreliable — JavaScript wrappers get
tagged COBOL, C projects tagged Perl, editor-config trees tagged Lua — so each
clone is checked against its lane before it counts, and a clone that is not
mostly that lane's source is replaced from the pool.

## What the sweep exercises

Every project: `sloc`, `list targets`, `static-scan` (report + SARIF), `sbom`,
`auto` (discover → harness → repair → build → fuzz → report), and `report` in
all four formats. Separately, `surfaces.py` exercises the 22 commands the
per-project sweep does not: the triage chain (`minimize`, `replay`, `explain`,
`capsule`, `verify-poc`, `cartography`), supply chain (`license-audit`),
governance (`policy`, `audit`, `export`), `binary scan`, `snippet`, and `ci`.

## What it found

The sweep's purpose was to find defects, and it did. Each of these was a real
bug with a real fix, verified against the project that exposed it:

| Defect | Effect | Verified fix |
|---|---|---|
| Extension-only language detection | cloc — 20k lines of Perl — discovered **0** targets, because its code lives in a file named `cloc` | shebang detection; 0 → 6/6 fuzzed |
| `require` compiles into the caller's package | a script's `main::` subs looked undefined to the harness | load as `main`; part of the same 0 → 6/6 |
| Driver and Fortran glue both defined `__sanitizer_cov_trace_pc` | **every** Fortran target failed to link | weak symbol; LAPACK failed_build → built+fuzzed |
| Only MODULE-defining Fortran files were pre-compiled | FORTRAN 77 projects had nothing to link against | symbol-directed link closure |
| C# TFM table hardcoded net8.0, ignored platform suffixes and `Directory.Build.props` | v2rayN: **0/25** targets | dynamic SDK ceiling; 0 → 3/5 at 9.5k exec/s |
| `dotnet build -o` across a project graph | every C# harness after the first died in MSB4018 | build in place, copy output |
| Interpreted lanes searched only the file's directory and the checkout root | Ruby and Lua skipped nearly everything as "not loadable" | package-root recovery |
| `app/` on the non-library exclusion list | scrcpy, a C project, discovered **0** C targets | recover a language that would otherwise be empty; 0 → 759 candidates |
| ANSI `(void)` prototypes and commented-out example calls read as K&R | modern C files routed to report-only, never fuzzed | comment-aware scan, keywords are not parameter names |
| `--campaign-time` billed from process start | discovery on a large tree ate the whole budget; 8606 candidates, **0** attempted | bill from the sweep |
| `--campaign-time` did not bound work in flight | a 150s budget ran ten minutes | clamp subprocesses, stop repairing past the budget |
| Undefined function-like macro in a `#if` | scrcpy's FFmpeg version check left every target in the TU unbuildable | numeric function-like expansion |
| `verify-poc` on a known-non-reproducing capsule | reported FAIL, reading as a regression | report the packaged verdict |
| Blocker histogram keyed on the first line | MSBuild's "Build FAILED." banner merged every C# failure into one row naming nothing | prefer the line that names an error; keep diagnostic codes intact |
| A package that isn't installed reported as "a parameter couldn't be driven" | 661 corpus targets advised to run `--force`, which cannot install a package, while `missing-deps.txt` reported nothing missing | one shared reason builder for all six interpreted lanes; the triage counts the two causes apart |
| CPython quotes the module name, and the extractor stopped at the quote | the Python needle never fired, so no Python package was ever named | skip the opening quote |
| A Composer tree with no `vendor/` matched nothing | the shape of nearly every real PHP project produced no requirement at all | `Failed opening required` needle → `vendor/autoload.php`, with `composer install` as the hint |
| A backtick assumed to close with an apostrophe | rustc- and interpreter-style `` `foo` `` leaked the name into the grouping key; the published table carried a mangled `target module "X"torch"X"` row | close a backtick on either delimiter |
| The external-class degradation matched compiler wording | the substitution it was written for (an opaque scalar) is no longer what govfuzz emits, so an unsuppliable MFC class stayed a bare failed_build | decide on provenance: a diagnostic in the project's own source is not a govfuzz codegen bug |
| Seven wall-clock-budgeted fuzz assertions on six cores | a planted OOB went unfound at ~6 executions where one test alone gets ~32 | serialize the fuzz-bearing tests |

### Re-measuring one surface, or an A/B

`--merge` updates only the surfaces named by `--surfaces`, keeping the rest of an
existing row — a `sloc`-only pass over the corpus is minutes where a full re-run
is hours. `--results-dir` writes rows somewhere else, so an A/B wave (say
`--auto-force`) can be compared with `aggregate.py --compare` without
overwriting the baseline it is being compared to.

## The 2026-07-27 re-run

`sh launch_full_0727.sh` re-runs the same corpus and budgets against a newer
pinned binary, writing to `results-0727/` so `results/` survives as the thing to
compare with. Read it with `python3 aggregate.py --results results-0727`.

| | 2026-07-26 (`results/`) | 2026-07-27 (`results-0727/`) |
|---|---:|---:|
| projects measured | 453 | 463 |
| targets discovered | 1,048,530 | 1,098,877 |
| attempted | 3,608 | 3,594 |
| **built + fuzzed** | **1,028 (28.5%)** | **1,057 (29.4%)** |
| findings | 304 | 354 |

Four defects came out of it, each in `CHANGELOG.md`: a cyclic C++ construction
recipe that consumed 12 GiB and got 22 projects OOM-killed during DISCOVERY,
POSIX/GLib scalar typedefs misread as opaque handles, a `java.io.File` parameter
that could not be driven, and two ways the blocker histogram destroyed its own
grouping key. One is still open — see `docs/open-defects-discovery-cost.md`.

**A stale baseline lies about what is fixed.** Half of `results/`'s largest
blocker rows (`Cannot find module "X"); run "X"`, `target module "X"torch"X"`,
the PHP row that read `  thrown in PATH on line N`) were already fixed by the
binary that produced them being older than the fix. Re-run before mining a row;
the fastest check is to reproduce the row on a five-line fixture with the CURRENT
binary, which takes a minute and settles it.

## Results

See `results/` for the raw rows, `charts/` for the figures, and
`docs/site/sweep-500.md` for the written comparison. `baseline-w0/` holds the
pre-fix measurement of the same one-project-per-language smoke wave, which is
what the before/after figure compares against.
