<!-- SPDX-License-Identifier: Apache-2.0 -->
# The recommended GovFuzz sweep

One command for the usual job: point GovFuzz at a source tree you control, let it
find and fuzz what it can, and get a supply-chain and static picture of the rest.

```sh
govfuzz auto /path/to/source-tree \
  --work-dir govfuzz_work \
  --jobs 4 \
  --per-target-time 60 \
  --campaign-time 3600 \
  --max-targets 40 \
  --unsafe-search-and-run-build-commands \
  --force \
  --static \
  --sbom \
  --sloc sloc.txt \
  --debug
```

Read the outcome in `govfuzz_work/auto/summary.txt`; the full report is
`auto/run.md` and `auto/run.json`, findings are in `auto/findings.csv`.

## What each flag does, and how to size it

| Flag | Why it is here |
|---|---|
| `--work-dir govfuzz_work` | Everything the run produces — harnesses, corpora, findings, reports. **Keep it OUTSIDE the tree being scanned**, or the next run discovers GovFuzz's own generated harnesses as targets. |
| `--jobs 4` | Candidates built and fuzzed concurrently. Default is half the host's cores. Peak memory is roughly `jobs × --rss-limit-mb`, so on a small or cgroup-capped box lower it before raising it. Ada targets build serially regardless — they share one staged source tree. |
| `--per-target-time 60` | Per-target fuzz wall clock, split across the three passes (empty / rng / fuzz-driven) under one shared deadline. This is the libFuzzer `-max_total_time` / AFL `-V` knob. 60s finds shallow bugs; raise it for a real campaign. |
| `--campaign-time 3600` | Hard outer cap for the whole sweep, charged from the first build attempt — discovery and preflight are not billed to it, so a large tree that takes minutes to index still fuzzes. Once exceeded, no new targets are started (the in-flight one finishes). |
| `--max-targets 40` | Stop once 40 targets have actually **fuzzed**. Unsupported parameters and failed builds do not consume the cap, so lower-ranked viable endpoints are backfilled instead of being starved by a nonviable prefix. Pair with `--max-attempts` to also bound how many candidates are inspected. |
| `--unsafe-search-and-run-build-commands` | **Runs code from the scanned tree.** Finds the project's own build entry point (`build.sh`, autotools, CMake, Meson, SCons, Waf, Bazel) and executes it under GovFuzz's compiler-interception shim to recover the real compile flags. This is what turns "cannot build" into "builds" on most real C/C++ trees. Only use it on sources you trust; drop it for untrusted code and pass `--build-command` instead if you know the command. |
| `--force` | Second phase over whatever phase one could not fuzz: fabricate a driver for an undrivable parameter, stub whatever the compiler reports missing, and never hard-fail (report-only is the floor). It cannot lower the fuzzed count — phase one runs unforced first. Findings from a forced build are stamped low-confidence with a caveat note, because a fabricated value can crash on its own account. |
| `--static` | Run the static analyzer over the whole tree in addition to fuzzing, so files with no fuzzable entry point are still analyzed and a target that fuzzed also gets static coverage. Findings merge into the same report. |
| `--sbom` | Emit an evidence-graded SBOM + VEX bundle at campaign end. Generated where the evidence is freshest: components a harness actually drove are marked exercised rather than merely present. Off by default because it costs time. |
| `--sloc sloc.txt` | Per-language SLOC breakdown of the tree beside the other outputs. A `.json` extension emits JSON instead of a table. Useful for reporting coverage per unit of code. |
| `--debug` | Capture a backtrace if GovFuzz itself panics, keep going past a file that crashes it, and enrich `bug-report.json`. Cheap; leave it on. |

## Variations worth knowing

- **Untrusted source.** Drop `--unsafe-search-and-run-build-commands`. GovFuzz
  still recovers what it can from `compile_commands.json` and its own probes.
- **A quick look rather than a campaign.** `--per-target-time 5 --max-targets 10`
  and drop `--sbom`.
- **One lane only.** `--languages c,cpp` (all sixteen lanes are on by default:
  Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript,
  TypeScript, Ruby, Lua, PHP).
- **Resuming.** `--resume` over the same work dir re-runs only what has not
  completed. `--resume --force` keeps every target that already fuzzed and
  forces only the rest.
- **A second engine.** `--engine builtin,afl++` runs both for native C/C++ when
  AFL++ is installed.
- **Broken or incomplete Ada/C/C++ drops.** See the offline auto runbook
  (`AUTO-OFFLINE-RUNBOOK.md` in a distribution, `docs/site/offline-auto-runbook.md`
  in the repository) for the strongest known-build and unknown-build recipes and
  how the recovery flags combine.

## Reading the result honestly

`summary.txt` separates outcomes on purpose:

- **built+fuzzed** — a harness was built and really executed the target.
- **static-only / report_only** — GovFuzz could not build it and fell back to
  static analysis. The residual-blocker histogram printed at the end says why.
- **skipped** — no driver could be synthesized for the parameters. `--force`
  is what retries these.
- **forced** — built on fabricated inputs or stubs. Their findings are floored
  to low confidence and carry a caveat note; treat them as leads, not defects.
