<!-- SPDX-License-Identifier: Apache-2.0 -->

# Auto

`govfuzz auto <PATH>` is the point-and-shoot entry point. It takes a source tree
in any of the sixteen supported languages (Ada, C, C++, Rust, Java, Python, Perl,
Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP) — including
code with broken `#include` chains, undefined externs, missing types, missing
`with` clauses, or no runtime environment — and produces a fuzz lab plus a
findings report without manual harnessing.

Optional LLM assistance is not part of this pipeline and `auto` never calls a
model. Use the [LLM and MCP guide](../llm/) to plan a bounded run, diagnose an
artifact, or review findings after the deterministic command has produced
evidence. Model output does not change target ranking, build status, coverage,
finding verdicts, replay, or minimization.

```sh
govfuzz auto path/to/src --work-dir govfuzz_work --per-target-time 60
```

## What It Does

For each candidate function discovered in the source tree:

1. Generate a lane-specific harness. Ada/C/C++ use the same generator as the
   narrower `generate-harness` subcommand; the other lanes use their dedicated
   `auto` builders. C first-parameter handle APIs and C++ class methods with
   visible same-class setup methods are tried as lifecycle sequence harnesses
   first, then fall back to direct-call harnesses.
2. Try to build it. On build failure, classify the diagnostics, synthesise the
   smallest repair that lets the build progress, retry. Retries stop at a
   configurable safety cap (`--max-repair-rounds`, default 16), but the loop
   breaks the moment a round applies no new repair — so the real cost is bounded
   by how many distinct repairs a target needs (deep flight-software
   type/config chains surface one new dependency per
   round), not by the cap. Repairs are cumulative.
3. Run the built harness through three fuzz passes (Empty, Rng, FuzzDriven)
   with the runtime virtualisation shim loaded. Each pass runs until its
   wall-clock budget is spent (no fixed iteration cap; `--iterations N` caps it
   explicitly). `--per-target-time` is the per-target TOTAL fuzz wall: the
   passes split it evenly and share one deadline, so the per-target wall ≈ the
   requested total regardless of pass count (#402). A target stops early once it
   hits `--per-target-finding-count` distinct findings, if set.
4. Capture findings, runtime-audit events, and the prosthetic ledger into
   `run.md` / `run.json`.

Rust and Java take a shorter path: their harnesses are generated and built
before this loop (attempt Step 0/0a) and skip the C/Ada harness-gen + repair
loop entirely, then drop straight into the step-3 fuzz cascade.

Python, Perl, and Go likewise bypass the C/Ada harness-gen + repair loop. Their
"build" is done by the interpreter/compiler itself before the fuzz cascade —
`py_compile` + an import smoke-test (Python), `perl -c` + a `require` smoke-test
(Perl), and `go build` to a native fork-server binary (Go) — and an
un-importable/uncompilable target skips cleanly rather than entering repair.

The remaining lanes follow the same "pre-build then fuzz" pattern with their own
toolchains: COBOL via GnuCOBOL (`cobc`), Fortran via `gfortran` with ASan, C#
via `dotnet` + SharpFuzz IL instrumentation, JavaScript/TypeScript under a warm
Node process (TypeScript transpiled with esbuild), and Ruby, Lua, and PHP under
their own interpreters with in-process edge coverage.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--work-dir <DIR>` | `./govfuzz_work/` | Output root |
| `--max-work-dir-mb <MiB>` | `4096` | Stop starting new targets once the allocated work-directory size reaches the ceiling. Completed and in-flight targets are preserved and reported, so parallel jobs can overshoot by their final artifacts. `0` disables the ceiling; findings are never deleted to meet it |
| `--max-corpus-mb <MiB>` | `64` | Per-target retained coverage-corpus ceiling for both memory and `corpus/<harness-id>/queue/`. Finding testcases are separate and always preserved |
| `--config <PATH>` | auto-load `.govfuzz.toml` | Load run options from a TOML file so a project's runs are reproducible; CLI flags always override it. Keys are the flag names in kebab-case (`per-target-time = 30`, `cxx-std = "gnu++14"`, `extra-include = ["deps/inc"]`). Without this flag, a `.govfuzz.toml` in the scanned tree root is auto-loaded — but since that tree is untrusted, an auto-loaded config honors only SAFE knobs; the build-EXECUTING keys (`build-command`, `run-untrusted`, `unsafe-search-and-run-build-commands`) are ignored unless the config is passed explicitly with `--config` |
| `--dry-run` | off | Plan only: discover + rank targets, run the toolchain preflight, report the build-recovery plan, then EXIT without building or fuzzing — validate scope, config, and toolchains before a long run |
| `--per-target-time <SECS>` | `60` | **Total** per-target fuzz wall, split evenly across the passes under one shared deadline (so the per-target wall ≈ this, not × pass count). libFuzzer `-max_total_time` / AFL `-V` parity (#402) |
| `--per-target-finding-count <N>` | unset (collect all) | Stop a target as soon as it has produced N **distinct** findings (crash signatures), or when its `--per-target-time` is spent — whichever first. Checked mid-pass (stops the instant the Nth lands; remaining passes skipped). `1` ≈ libFuzzer stop-on-first-crash |
| `--total-time <SECS>` | unset | **Deprecated** alias of `--per-target-time` (overrides it when set); retained for existing benchmark/parity invocations. Hidden from `--help` |
| `--iterations <N>` | unset (wall-clock governs) | Per-pass execution cap (libFuzzer `-runs`); `0`/unset lets `--per-target-time` govern depth. Retired the old hardcoded 1024 cap |
| `--rss-limit-mb <MB>` | dynamic | Per-harness resident-set cap; defaults to one quarter of available host/cgroup memory, clamped to 512..8192 MiB. An over-budget input is killed and reported as a GF-209 OOM finding instead of OOM-killing the host; pass an exact value or `0` to disable |
| `--max-targets <N>` | unset (all) | Keep only the top-N highest-scored targets after ranking, before the build/fuzz sweep. `--dry-run` prints this bounded plan; `--list-targets` still prints the FULL ranked list. The kept-vs-total count is logged, never a silent truncation. Bounds *which* targets a huge tree attempts |
| `--campaign-time <SECS>` | unset (run all) | Whole-**run** budget across all targets. Default: an OUTER wall-clock cap — once exceeded, `auto` stops STARTING new (ranked) targets (the in-flight one finishes) and reports how many of the N discovered were reached. With `--min-target-time`, switches to SPLIT mode (see below). Bounds *how long* a huge-tree sweep runs |
| `--min-target-time <SECS>` | unset | SPLIT-mode floor, used **only** with `--campaign-time` (errors otherwise): divide the campaign budget across the N attempted targets — each gets `max(min, campaign / N)` of fuzz time, and only the top `floor(campaign / per_target)` ranked targets are attempted (the rest logged unfuzzed), never less than this floor. Overrides `--per-target-time` |
| `--jobs <N>` / `-j <N>` | `1` (serial) | Build+fuzz up to N targets CONCURRENTLY via a bounded worker pool. Child allowance is `jobs × --rss-limit-mb`, but total peak also includes the parent declaration index/results, compilers, and the OS. Results aggregate deterministically regardless of completion order |
| `--passes <SET>` | all (`empty,rng,fuzz`) | Restrict the per-target cascade to a comma list of passes (`empty`, `rng`, `fuzz`). E.g. `--passes fuzz` runs only the fuzz-driven pass — ~3× the throughput of the full 3-pass cascade. Mutually exclusive with `--single-pass` |
| `--single-pass` | off | Convenience for `--passes fuzz`: run ONLY the fuzz-driven pass per target |
| `--max-repair-rounds <N>` | `16` | Ceiling on build-fail → repair → retry rounds per target. The default covers all 95 successful clean/damaged samples in the strengthened 53-repository matrix (p95 6, p99/max 14 rounds); the no-progress early-break still applies, so it is a cap, not a fixed cost |
| _(discovery cache)_ | **on** | Discovery is cached by default to `<work>/discovery-cache.json` and reused on a re-run when a **build-stable** content fingerprint of the target source (file paths + sizes + content hashes + dir-filter) is unchanged, skipping the tree-sitter re-parse + re-rank — the dominant re-run cost on a big tree. The fingerprint depends only on the fuzzed code (not on which govfuzz build computed it), so rebuilding govfuzz does not invalidate it. A mismatch recomputes and rewrites the cache; a stale cache is never used silently |
| `--discovery-cache <PATH>` | `<work>/discovery-cache.json` | Put the default-on cache at an explicit path, useful when work directories change or the cache belongs on a known volume |
| `--fresh-discovery` | off | Force a fresh discovery this run (ignore any cache), then overwrite the cache with the new result |
| `--no-discovery-cache` | off | Disable the discovery cache entirely (never read or write it) |
| `--resume` | off | Resume a prior sweep over the SAME work-dir: reload targets that already completed and re-run only the rest. A per-target `harnesses/<id>/result.json` is written the moment each target finishes (so an INTERRUPTED run is resumable), and on a re-run it is loaded back into the report FULLY re-integrated — its outcome bucket, repair manifest, findings, and per-pass detail all appear in the new `run.json`/`run.md` exactly as if it had been re-run, plus a `resumed` count of how many were carried over. Requires the discovery cache to hit (target source unchanged); on a source change every target is re-attempted to avoid stale results |
| `--reuse-discovery` | — | Deprecated no-op (caching is now the default); accepted for back-compat |
| `--sanitizers <asan,ubsan,msan,tsan,lsan \| none>` | none | Arm the named matrix for native C/C++ builds (the other lanes own their instrumentation). `none` builds native C/C++ coverage-only with no `-fsanitize=` (crash-only, zero ASan/UBSan false positives). Operator `<SAN>_OPTIONS` (suppressions / FP-killers) are merged, not clobbered. See [Sanitizers](../sanitizers/) |
| `--comparison-progress` | off | Enable laf-intel comparison-progress coverage (#421); rewards an input that matches more leading bytes of a multi-byte magic/format gate. Alias `--cmp-progress` |
| `--engine <LIST>` | `builtin` | Fuzz engine(s) for the per-target fuzz phase, comma-separated. `builtin` is the in-process coverage-guided engine; `afl++` drives AFL++ on the auto-recovered build (C/C++ only; needs `afl-fuzz` + `afl-clang-fast`, else falls back to builtin with a warning). `--engine builtin,afl++` runs both per target, splitting `--per-target-time` between them |
| `--differential <A:B>` | unset | Two-compiler differential fuzzing (C/C++), e.g. `clang:gcc`: after the normal run, rebuild each C/C++ harness under both compilers and replay the corpus through both, flagging any input whose exit/crash behavior diverges (a codegen- or UB-dependent bug) as a GF-301 finding |
| `--seed-file <PATH>` | none | Seed-input file whose bytes bootstrap every target's corpus; repeatable |
| `--seed-dir <DIR>` | none | Directory of seed inputs (one per regular file); repeatable |
| `--extra-include <DIR>` | none | Extra C/C++ include dirs for dependency headers outside the swept tree; seeded onto every harness `-I` ahead of synthesized placeholders. Read from local disk only; repeatable |
| `--ada-deps <DIR>` | none | Local Ada dependency-source dirs put on the build path (offline: never fetched); repeatable. Locally-cached Alire deps are picked up automatically |
| `--probe-build` | off | Run the project's own build offline to recover real compile flags and generated headers. Detects + drives CMake, Meson, Visual Studio, Make/autotools (compiler-interposing wrapper), Ninja, and — under interception — Bazel/SCons. EXECUTES untrusted build scripts (sandboxed when bwrap/firejail is present) |
| `--build-command <CMD>` | unset | Recover flags from any CUSTOM build (a `build.sh`, Waf, a vendor RTOS build) by running `<CMD>` under (1) a front-of-`PATH` compiler shim for `cc`/`gcc`/`clang` + named vendor compilers (Diab, Green Hills, QNX, Keil/IAR, TI) + cross-prefixed toolchains invoked by name, and (2) an `LD_PRELOAD` exec-interposer for compilers invoked by absolute path or `posix_spawn`. The universal escape hatch; takes precedence over the auto-detected tier. Accepts either a script (`--build-command ./build.sh`) or a full command (`--build-command "make -C src lib"`), run via `sh -c`. EXECUTES the command (sandboxed when available). When builds fail and a custom build script is present, `auto` prints a ready-to-run hint with this flag |
| `--cxx-std <STD>` | auto | Pin the C++ standard for every harness build (`gnu++14`, `c++03`, …) for legacy C++. By default `auto` builds C++ at the modern standard and, on a dialect failure, automatically retries successively older standards (`gnu++17`→`gnu++14`→…→`gnu++98`) until one builds — the chosen standard is cached per project, so no flag is needed for old code unless you want to override the search |
| `--grammar <PATH>` | unset | JSON grammar describing the target's input format for structure-aware generation (a Nautilus-style grammar mutator), applied to every fuzzed target. Each rule maps a non-terminal to production strings where `{NAME}` references another rule; the start symbol is `START` or the first rule. Validated up front (a bad grammar fails the run fast) |
| `--max-len <N \| auto>` | `auto` | Maximum fuzz input length. `auto` grows the effective length adaptively per target — free up to ~1 MiB, and beyond that only while longer inputs keep finding new coverage — so a large-object target (image, archive, firmware) is handled WITHOUT a seed corpus, and a small-format one is not grown pointlessly. A positive integer sets a fixed cap |
| `--timeout <DUR>` | `10s` | Per-execution timeout (e.g. `10s`, `500ms`); an input exceeding it is a hang/timeout |
| `--run-untrusted` | off | Consent umbrella for `--probe-build` plus an Ada (`alr build` / `gprbuild`) build probe that materializes Alire config + codegen — **required** for Ada pre-build context recovery; implies `--probe-build`. EXECUTES untrusted scripts |
| `--unsafe-search-and-run-build-commands` | off | UNSAFE convenience: search the tree for its own build entry point and EXECUTE it to recover flags, instead of you passing `--build-command`. Finds a custom build (build.sh, autotools bootstrap/autogen/configure, SCons, Waf, Bazel) and runs it under the compiler-intercepting shim, and enables the `--probe-build` tiers (CMake/Meson/Make) + the Ada build probe. Runs sandboxed when available, but it executes UNTRUSTED code from the scanned tree — use only on sources you trust. An explicit `--build-command` overrides the search |
| `--deps-only` | off | Build each target as far as possible, emit the missing-dependency manifest, and SKIP fuzzing — the fast "what does this tree need?" scan |
| `--static` | off | Run the static analyzer over the WHOLE tree in addition to fuzzing — not only as a fallback when a target can't be built/fuzzed. Findings (classification `static_scan`, ids `F-STATIC-*`) merge into the unified report (findings.csv, run.json, SARIF) next to the fuzz findings, so a target that built+fuzzed still gets static coverage and files with no fuzzable subprogram are analyzed too. Same engine as the standalone `govfuzz static-scan`. GovFuzz's own generated harnesses/stubs under the work-dir are excluded, and dependency/build/cache trees such as `node_modules`, virtualenvs, `dist`, vendored deps, and generated JS `compiled/` bundles are pruned before analysis — the scan reports the target tree, not scaffolding or dependency payloads |
| `--external-tools` | off | Also drive installed EXTERNAL analyzers (gosec/Bandit/semgrep/GNATcheck) as **subprocesses** (never linked), parse their SARIF into the report (ids `F-EXT-*`), and let the fuzz-confirmation join confirm/downgrade them too. Each tool runs only if the active license profile (`GOVFUZZ_PROFILE`, default `strict-permissive`) permits its subprocess — the default runs NONE, so the default profile never invokes a GPL tool; set `GOVFUZZ_PROFILE=external-tools` to opt in. Missing tools are skipped. Implies `--static` |
| `--force` / `--force-fuzz` | off | Adds a SECOND pass. The sweep first runs exactly as it would without the flag, then re-attempts only the targets that did not reach the fuzz phase — forced: a best-effort driver for opaque/function-pointer/unknown params, stubs for whatever the compiler reports undefined, and no hard failure (report-only is the floor). The managed lanes have their own force paths: Go drives an undrivable parameter as its type's zero value and calls a method on a zero receiver, and C# allocates a receiver whose type has no accessible parameterless constructor without running one. A forced retry may only ever *replace* a target's outcome by fuzzing it, so `--force` cannot lower the fuzzed count; it also cannot rescue a target whose parameters were never the problem. Findings from a forced build are floored to **Low** confidence with a `forced` note and counted separately — a forced crash may be a stub artifact, not a real defect. With `--resume` over a finished campaign it keeps every target that already fuzzed and forces only the rest, without repeating the unforced attempt. Persistence honors `--max-repair-rounds`; does not imply `--static` |
| `--static-dynamic` | off | Run in static-dynamic mode: add a `scan_type` column to `findings.csv` labeling each row — `static-dynamic` for a static-scan result (govfuzz's static + fuzz-confirmation pipeline) and `dynamic` for a fuzzed result. Off by default so the CSV schema is unchanged unless requested |
| `--install-deps` | off | After the sweep, fetch still-blocking deps from the manifest (apt-get / `alr get`). Opt-in and the only ONLINE part of `auto`; nothing is fatal |
| `--list-fakes` | — | Print the fake-resource plugin inventory and exit |
| `--languages <LIST>` (alias `--lang`) | all languages found | Restrict the sweep to a comma-separated subset of source languages. Accepts any of the sixteen fuzzable languages: `ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`, `cobol`, `fortran`, `csharp`, `javascript`, `typescript`, `ruby`, `lua`, `php`. Candidates in any other language are dropped **after** discovery (so one discovery cache serves every language subset) and **before** `--list-targets` and `--max-targets`, so the ranked list and the top-N both reflect the filter. Common spellings are accepted (`c++`/`cxx`/`cc`→cpp, `rs`→rust, `py`→python, `pl`→perl, `golang`→go); matching is case-insensitive. The SBOM/SCA pass is unaffected — it always scans the whole tree across all ecosystems regardless of this fuzzing-lane filter |
| `--target <NAME>` | all discovered targets | Exact target-name filter; repeat to run a small named subset |
| `--target-file <PATH>` | all discovered source files | Exact source-file filter; accepts absolute paths or paths relative to the sweep root |
| `--harness-id <ID>` | all discovered harness ids | Exact stable harness-id filter from a prior auto report |
| `--exclude-path <TEXT>` | none | Drop targets whose normalized relative source path contains `TEXT`; repeatable |
| `--exclude <tests,tools,examples>` | none | Drop common project areas before attempts run |
| `--no-stubs` | off | Skip build-time auto-stubbing (diagnostics only) |
| `--mode reporting\|attacking` | `reporting` | Actionability profile and, in attacking mode, target scheduling |
| `--verbose` / `-v` | off | Per-target outcome detail: skip/fail reason, repairs applied, per-pass exec/finding counts |

## Outputs and disk cleanup

The primary human handoff is `<work>/FINDINGS.md`, ordered by impact with source
locations, confidence, evidence links, remediation, and replay commands.
`<work>/findings.csv` is the machine-readable root-cause index and
`<work>/findings/` contains complete evidence bundles. Historical integrations
can continue reading `<work>/auto/findings.csv`. Campaign mechanics and coverage
caveats remain in `auto/run.md`, `run.json`, and `summary.txt`.

GovFuzz deletes Rust Cargo `target/` trees as soon as their final replay harness
is linked. To reclaim the same caches from an older/interrupted run plus scratch
files, without deleting findings, reports, corpora, result checkpoints, generated
source, or replay binaries, run:

```sh
govfuzz clean govfuzz_work --compact
```

At startup, `auto` also removes stale private Cargo target trees left by older
GovFuzz releases. At the end of a run it compacts disposable scratch data. The
4 GiB work-directory ceiling is based on allocated filesystem blocks, does not
follow symlinks, and stops target admission instead of deleting evidence. Targets
already running are allowed to finish, so parallel runs can overshoot the limit
by their final artifacts. The report records that the output limit stopped the
campaign; `--max-work-dir-mb 0` disables only this admission ceiling.

## Expert-parity harness behavior

The auto generators checkpoint entry immediately before the selected call in all
sixteen lanes. A driver that merely decodes input, loads a module, or runs setup is
reported as built-but-not-entered rather than successful fuzzing. Target ranking is
identifier-token aware and prioritizes public parsers, decoders, whole-artifact
entrypoints, and stateful execution surfaces while demoting debug/reporting helpers.

The lane-specific generators also recover call setup an expert would normally
write by hand: path arguments are backed by temporary files in JavaScript, Ruby,
and COBOL; asynchronous JavaScript calls are awaited before cleanup; Go can mine a
one-input feeder followed by a zero-argument terminal; PHP recursively constructs
bounded typed value objects; C++ supports defaulted arguments, common public member
templates, and byte-string instantiation; Fortran emits descriptors for assumed-
shape character arrays; and C# instruments project IL in a separate target
assembly. Go coverage retries the exact selected package when module-wide
instrumentation is blocked by unrelated platform packages.

These behaviors and their residual limits are measured in the
[200-project expert-parity audit](./harness-parity-audit.md). They do not make
every project automatically harnessable: private Rust in-crate targets, generated
or platform-specific build graphs, framework hosts, scientific arrays with coupled
dimensions, and general constructor/feed/execute/cleanup protocols remain explicit
gaps rather than silently fabricated successes.

### Scaling to large trees

The default sweep — every discovered target, the full three-pass cascade, one
target at a time — is the wrong shape for a tree with tens of thousands of
candidates. The flags above compose into a bounded triage sweep:

```sh
govfuzz auto path/to/huge-tree \
  --max-targets 500 \
  --single-pass \
  --max-repair-rounds 3 \
  --jobs 2 \
  --campaign-time 3600
```

That run reuses a prior discovery (skipping the tree-sitter re-parse + re-rank),
keeps only the top-500 ranked targets, fuzzes each with the fuzz-driven pass
only (~3× throughput), gives up on un-buildable targets after 3 repair rounds,
builds+fuzzes 2 targets concurrently, and stops starting new targets after one
hour of wall-clock. The three bounds are orthogonal: `--max-targets` bounds
*which* targets are attempted, `--campaign-time` bounds *how long* the whole
sweep runs, and `--jobs` bounds throughput against host RAM (peak ≈
the child allowance plus parent/index/compiler/report overhead).
Every bound is logged — the kept-vs-total target count and the campaign-time
cutoff both print — so a bounded run is never silently mistaken for full
coverage.

For a 10M+ SLOC tree, 8 GiB is a practical minimum only for a deliberately
serial run (`--jobs 1`, normally `--rss-limit-mb 1536`); 16 GiB is recommended
for whole-tree static analysis and build recovery. Under `auto`, each target's
in-memory and persisted coverage corpus shares the explicit `--max-corpus-mb`
budget (64 MiB by default), and its entry allowance is derived from that byte
budget and `--max-len`. `GOVFUZZ_MAX_CORPUS_ENTRIES` can impose a stricter entry
count; standalone `govfuzz fuzz` retains the memory-derived
`GOVFUZZ_MAX_CORPUS_BYTES` behavior. Captured target
diagnostics/event deltas use memory-aware defaults with explicit environment
overrides. Discovery still retains a compact
declaration/candidate index and final reports retain attempted-target metadata,
so use `--max-targets`, `--campaign-time`, and `--per-target-finding-count` to
bound high-cardinality sweeps. See the README's Resource Requirements for the
static-analysis ceiling and per-file safeguards.

The memory-aware defaults can all be replaced when a target needs more depth:

| Environment override | Controls |
|---|---|
| `--max-corpus-mb`, `GOVFUZZ_MAX_CORPUS_ENTRIES` | Per-auto-target mutation and on-disk coverage-corpus retention |
| `GOVFUZZ_MAX_CORPUS_BYTES` | Standalone `govfuzz fuzz` mutation-corpus bytes |
| `GOVFUZZ_MAX_SOURCE_FILE_BYTES`, `GOVFUZZ_MAX_FILE_BYTES` | Auto/discovery and static-analysis source-file admission |
| `GOVFUZZ_MAX_SUBPROCESS_OUTPUT_BYTES`, `GOVFUZZ_MAX_HARNESS_OUTPUT_BYTES` | Build-command and target-diagnostic capture per stream |
| `GOVFUZZ_MAX_EVENT_DELTA_BYTES`, `GOVFUZZ_MAX_RUNTRACE_PARSE_BYTES` | Dynamic runtrace data admitted per execution/log |
| `GOVFUZZ_MAX_SINK_TRACKING_BYTES`, `GOVFUZZ_MAX_SINK_SUBJECTS` | Cross-execution tainted-sink evidence retention |
| `GOVFUZZ_MAX_EXTERNAL_TOOL_OUTPUT_BYTES` | External analyzer JSON/SARIF capture |

Values are bytes except `GOVFUZZ_MAX_CORPUS_ENTRIES` and
`GOVFUZZ_MAX_SINK_SUBJECTS`. Additional specialist overrides are named in the
warning emitted when their safeguard is reached. These are in-process retention
budgets, so a run can briefly exceed one budget because parsers, compiler
processes, reports, other workers, and allocator overhead remain live too. Use an
OS/cgroup limit when a strict hard boundary is required.

**Stop a target once it has enough findings.** `--per-target-finding-count N`
ends a target's cascade the instant it has produced N distinct findings, instead
of spending the whole `--per-target-time` budget collecting duplicates of the
same bug. `--per-target-finding-count 1` is the classic libFuzzer
stop-on-first-crash; a higher N keeps fuzzing for a few distinct bugs per target
before moving on. It composes with everything above — a split-mode target still
stops early on its finding count.

**Split a fixed budget evenly across targets.** Pair `--campaign-time` with
`--min-target-time` to switch from the outer-cap guillotine to an even split:
the campaign budget is divided across the attempted targets, each getting
`max(min, campaign / N)` of fuzz time, and only the top
`floor(campaign / per_target)` ranked targets are attempted (the rest logged
unfuzzed). E.g. `--campaign-time 600 --min-target-time 30` over 40 ranked
targets gives every target 30s (`600 / 40 = 15 < 30`, so the floor binds) and
attempts the top `floor(600 / 30) = 20`; with only 10 targets each would instead
get the even `600 / 10 = 60s`. Use it when you want a predictable per-target
floor rather than "best-ranked first until the clock runs out."

### Actionability in auto runs

Auto run reports include actionability counts by verdict and impact. In
attacking mode, candidate scheduling prefers real source targets and dangerous
sink evidence, but verdicts are still derived from collected finding evidence.
Generated stubs, fake resources, missing-environment injections, and mocks force
the verdict to `lab_only`; missing real resources without a substitution produce
`blocked`.

### Fuzz-confirmation (the differentiator)

govfuzz is the only tool that both statically scans **and** fuzzes the same tree,
so a fuzz run can *confirm* a static finding. After the sweep, govfuzz joins each
static finding (`--static` / static-only, `F-STATIC-*` / `F-RO-*`) against the
run's runtime findings (fuzz crashes + oracle hits) by source site (file:line):

- **Match** → the static finding is upgraded in place to
  `confirmation: fuzz_confirmed`, its confidence boosted to `high`, and it is
  **clustered with the confirming crash** so the report renders ONE issue row
  (the crash as representative, the static finding a member with a unioned CWE)
  instead of two orphaned rows. A site reached only through a proven
  non-attacker-reachable entry is confirmed but capped to `lab_only`.
- **No match** → the static finding stays `confirmation: static`. It is **not**
  downgraded: the fuzzer not reaching a site does not prove the site unreachable,
  so silence never manufactures a false negative.

Every row in `findings.csv` and every SARIF result carries a `confirmation`
column/property with the provenance (`static` | `fuzz` | `runtime` |
`fuzz_confirmed`), and `run.json`'s summary reports a `fuzz_confirmed` count. A
`fuzz_confirmed` finding is not a maybe — it is a defect a fuzzer walked into at
the exact line the scanner flagged.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | At least one target built and ran |
| 1 | Candidates discovered, none built |
| 2 | No candidates discovered (empty tree or wrong path) |

## Discovery

Walks the source tree with the same exclusions the `scan` subcommand uses
(`.git`, `target`, `build`, `govfuzz_work`, `harnesses`,
`generated_harnesses`, `node_modules`). Per-file dispatch by extension:

| Extension | Parser | Ranker |
|---|---|---|
| `.ads`, `.adb` | `ada_parser::reconcile::build_structural_ast` | `target_rank::rank_targets` |
| `.c` | `c_parser::parse_c_functions` | `target_rank::rank_c_targets` |
| `.h` | C or C++ parser, selected by header contents | matching C/C++ ranker |
| `.cpp`, `.cc`, `.cxx`, `.C`, `.hpp`, `.hh`, `.hxx` | `cpp_parser::parse_cpp_functions` | `target_rank::rank_cpp_targets` |
| `.rs` | `rust_parser::parse_rust_functions` | `target_rank::rank_rust_targets` |
| `.java` | `java_parser::parse_java_methods` | `target_rank::rank_java_targets` |
| `.py` | `python_parser::parse_python_functions` | `target_rank::rank_python_targets` |
| `.pl`, `.pm` | `perl_parser::parse_perl_subs` | `target_rank::rank_perl_targets` |
| `.go` (skips `_test.go`) | `go_parser::parse_go_functions` | `target_rank::rank_go_targets` |
| `.cob`, `.cbl`, `.cobol`, `.cble` | lane-specific `parse_cobol` | byte-buffer `LINKAGE` / `USING` eligibility |
| `.f`, `.for`, `.f77`, `.f90`, `.f95`, `.f03`, `.f08` | lane-specific `parse_fortran` | character-argument eligibility |
| `.cs` | lane-specific `parse_csharp` | public byte/string/stream input methods |
| `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts` | lane-specific `parse_js` | exported functions/public exported-class methods (`.d.ts` skipped) |
| `.rb` | lane-specific `parse_ruby` | callable input methods |
| `.lua` | lane-specific `parse_lua` | callable input functions |
| `.php` | lane-specific `parse_php` | functions/public methods with an input channel |

Candidates with unsupported parameter types are dropped before the attempt
loop runs, so the report does not carry pre-doomed entries.

C and C++ harnesses are Makefile-based. Auto uses `clang` / `clang++` for the
default coverage-guided sanitizer build unless `CC` / `CXX` are set. See
[C and C++ Fuzzing](../c-cpp/) for supported C++ parameter shapes and
limitations. Nearby `compile_commands.json` files are used when present to
carry project include paths, defines, and standard flags into generated
Makefiles. Rust targets instead build a `cargo` staticlib (sancov + ASan)
linked into the C fork-server driver, and Java targets compile with `javac` /
`maven` / `gradle` under govfuzz's own JVM bytecode coverage agent; both are
built before the attempt loop and bypass the C/Ada repair path. Python and Perl
targets "build" by interpreter check (`py_compile` + import smoke-test;
`perl -c` + `require`) and run under a persistent CPython / `perl -d:GovfuzzCov`
process over the framed fork-server protocol; Go targets compile with `go build`
(against the target package via a module `replace`) to a native framed
fork-server binary. COBOL, Fortran, C#, JavaScript/TypeScript, Ruby, Lua, and PHP
likewise use their lane-specific pre-build/interpreter paths described above.
All of these lanes bypass the Ada/C/C++ repair path.

## Repair Synthesis

Build errors are matched against compiler diagnostics by the `build_classifier`
crate and dispatched to language-specific repair planners. Repair synthesis
applies to the C/C++ and Ada lanes only. Every other lane is prebuilt or
interpreter-checked before the attempt loop and never enters the
diagnostics-driven repair path.

C / C++ (`crates/c_stub_gen`):

| Error class | Repair |
|---|---|
| `MissingHeader{path}` | Synthesised placeholder header under `<harness>/repairs/auto_includes/<path>`, added to `-I` |
| `MissingType{name}` | `typedef void *T;` appended to `<harness>/repairs/auto_types.h` |
| `UndefinedSymbol{name}` | Looked up in the declaration index. Match → declared stub. No match → blind `void(void)` stub. Appended to `<harness>/repairs/auto_stubs.c` |
| `MissingSharedLib{name}` | Not auto-repaired. Flows to `needed_for_build.missing_libraries` and the `missing-deps` manifest; the target is marked `unrecoverable_link` |
| `ConfigGuardError{file,line}` | A `#error` a build-config guard reached (libssh's `#error "no strtoull function found"`). The conditional owning the `#error` is read and the macro it tests is `#define`d into `auto_defines.h`, with the value the guard requires (`#if (DEPTH != 8)` → `8`, a plain feature test → `1`). An undecidable guard — a comparison, a compound condition, or an error that fires *because* a macro is defined — is refused rather than guessed |

Ada (`crates/stub_gen`):

| GNAT diagnostic | Repair |
|---|---|
| `file ".+\.ads" not found` | Empty `PackageSpec` under `<harness>/repairs/auto_ada/` |
| `"X" is undefined` | `Identifier` stub |
| `"X.Y" is not visible` | `Visibility` stub |
| `missing body for unit "X"` | Empty `PackageBody` |
| `cannot find "X.gpr"` | Not auto-repaired; flows to `needed_for_build.missing_gpr_imports` |

The declaration index is built once per `auto` run before the attempt loop
and held in memory across all targets.

## Three-Pass Cascade

Each built harness runs three passes back-to-back. The shim's behaviour for
fake resources is set per pass via `GOVFUZZ_RUNTRACE_MODE`:

- `empty` — fake `read()` returns EOF on first call. Catches "external world
  absent" code paths.
- `rng` — each fake resource serves bytes from its own xorshift RNG, seeded
  by `(harness_id, resource_name, fuzz_seed)`. Catches length-field and
  type-confusion bugs in code that parses external bytes.
- `fuzz_driven` — fake reads pull from a shared memfd populated each fuzz
  iteration. The engine's coverage feedback learns to route interesting
  bytes to whichever fake resource gates a code path.

By default all three passes run because they exercise orthogonal paths. An
explicit `--passes`/`--single-pass`, the shared deadline, or
`--per-target-finding-count` can stop or skip remaining passes.

The runtime-virtualisation shim that backs these passes is Linux-only. It is
armed for native C/C++/Ada/Rust/Go/COBOL/Fortran harnesses and interposes the
Python/Perl/Ruby/Lua/PHP interpreters. It is deliberately off for Java, C#, and
JavaScript/TypeScript (where managed-runtime startup activity would create false
positives) and for cross-compiled or emulated (qemu/wine) targets. Those
configurations do not receive the GF-405/GF-304/GF-417/GF-305 runtrace oracles.

## Outputs

```
<work>/
├── auto/
│   ├── run.md                                  # human report
│   ├── run.json                                # machine report
│   ├── missing-deps.json                       # missing-dependency manifest (#418)
│   └── missing-deps.txt                        # same, human-readable
├── harnesses/<harness-id>/
│       ├── main.c | main.cpp | main.adb
│       ├── Makefile | H_<id>.gpr
│       ├── repairs/
│       │   ├── auto_stubs.c
│       │   ├── auto_types.h
│       │   ├── auto_includes/…
│       │   └── auto_ada/…
│       ├── result.json                         # per-target resume marker
│       └── runtrace.jsonl                      # per-target shim events
├── build/<harness-id>/
├── corpus/<harness-id>/queue/                  # persisted coverage-minimal corpus (#401)
├── findings/F-0001-…/
└── fuzz_runs/<harness-id>-latest.json
```

### `run.md`

Top section summarises discovery, build outcomes, and finding counts. If any
target fuzzed STUB-ONLY, a loud `## ⚠ STUB-ONLY (FALSE CLEAN)` block leads,
naming each false-clean target and its blind-stub fraction (see
[`stub_execution`](#stub_execution-false-clean-guard)). A `## Targets` section
follows with one line per target — every target, not a truncated top-N. Each
built-and-fuzzed line shows the outcome label and a per-pass breakdown
(`empty=4123execs/1000exec_s/0f rng=… fuzz_driven=…`) plus the total
`cov=Nedges`; a `[!]` note marks a target whose fuzzed parameters are not an
attacker-controlled input channel. The `Upstream delta` section is the
prosthetic ledger described below.

### `run.json`

The machine report. Each `built_and_fuzzed` target carries, under
`targets[].outcome`, throughput and budget fields for libFuzzer
`average_exec_per_sec` / AFL `execs_per_sec` parity (#405):

- `executions_per_sec` — target-level throughput (time-weighted Σexecs / Σelapsed
  across passes, not a mean of per-pass rates).
- `per_pass_budget_secs` / `total_wall_budget_secs` — the per-pass and effective
  total fuzz wall budgets (#402).
- `passes[]` — one entry per pass, each with `executions`, `coverage_edges`,
  `elapsed_secs` (measured, not budget), `executions_per_sec`, and `findings`.

The top-level `summary` carries `fuzz_confirmed` — how many static findings a
fuzz/oracle hit confirmed at the same source site (omitted when zero). See
[Fuzz-confirmation](#fuzz-confirmation-the-differentiator).

### `stub_execution` (false-clean guard)

Each `built_and_fuzzed` target in `run.json` carries a `targets[].stub_execution`
object (omitted for non-fuzzed outcomes) summarising
how much of the harness's external symbol surface was real vs stubbed:
`blind_stubbed_symbols`, `declared_stubbed_symbols`, `real_linked_symbols`,
`resolved_called_symbols`, `blind_stub_fraction`, and the boolean `stub_only`.
`stub_only` is set when **≥ 90 % of the external symbols the harness called were
satisfied by blind stubs and no real dependency source was linked** — i.e. the
run fuzzed only invented empty function bodies, never the real library. Such a
target is a **FALSE CLEAN**: a 0-finding result over millions of executions does
*not* mean the library is safe (the only other tell is harness-only coverage).
`run.md`, the terminal summary, and the per-target outcome label
(`built+fuzzed (STUB-ONLY)`) all flag it loudly, and the summary counts it under
`summary.fuzzed_stub_only`. Supply the missing dependency sources (see
[`missing-deps`](#missing-deps)) and re-run to fuzz the real code.

### `needed_for_build`

Aggregates every prosthetic the sweep applied plus everything it could not
fix. One entry per resource, with a `referenced_by_targets` array and a
`count`. Four layers:

| Layer | Source |
|---|---|
| A — build-time | Synthesised headers, declared/blind stubs, typedef placeholders, Ada package stubs |
| B — link-time, not auto-repaired | `-l<name>` misses, missing `.gpr` imports, glibc version mismatches |
| C — runtime, observed during fuzzing | env vars, missing files, missing devices, network endpoints, `dlopen` / `gethostbyname` failures |
| D — unrecoverable | Build-time repairs we tried and could not synthesise (e.g., struct-by-value return without a declaration) |

### `missing-deps`

A dependency checkpoint is created before project build probing or target discovery,
refreshed immediately after an opted-in build probe, then atomically replaced after
every completed target (including parallel jobs). The JSON carries
`complete` and `completed_targets`, so an operator can distinguish a final list
from the last valid checkpoint left by an interrupt or parent-process OOM. The
last terminal line always points at the human file with blocking/substituted
counts.

The text report puts compatible compilers, target runtimes/emulators, generated
source/codegen tools, unfetched Git submodules, and absent declared Alire source
first. Rows include a `declared`, `observed`, or `inferred` basis plus evidence.
GovFuzz reports exact path/URL/version/output/tool data when project metadata or
diagnostics provide it; it does not guess a proprietary vendor, version, ABI, or
semantics from an otherwise unidentified missing type.

A `failed_build` is never opaque. Every unresolved final diagnostic — missing
header, type, symbol, build-config macro, malformed/codegen declarator, or any
unclassified error — is recorded in `missing-deps.json` / `missing-deps.txt` as a
still-blocking entry with an acquisition hint, and each failed target is
guaranteed at least one entry (#418). A missing configure/cmake-generated header
(e.g. c-ares' `ares_build.h`) is detected by a sibling `.in` / `.dist` /
`.cmake` / `.cmake.in` template and gets a configure-step remediation (run the
project's configure step, or `--probe-build`) instead of a dead-end apt-file
hint. `--deps-only` writes this manifest without paying for the fuzz phase;
`--install-deps` fetches the still-blocking entries.

### Per-Finding Replay

Each finding's `finding.json` records the pass, fuzz seed, env vars injected,
and the active fake-resource list. `govfuzz replay --finding <F>` reuses the
same mode and env.

## Re-Runs

`govfuzz auto <same path>` reuses any per-target `repairs/` files surviving
from a prior run, so cumulative repairs are not redone. Discovery caching is on
by default: an unchanged source/filter fingerprint reuses
`<work>/discovery-cache.json`; a mismatch rebuilds the index, and
`--fresh-discovery` forces that rebuild. Use `govfuzz clean --all <work>` to
wipe state.

The coverage-guided corpus is persisted to `corpus/<harness-id>/queue/`
(content-hash-named, seeds included) at the end of each run (#401), so it
survives across passes and runs and stays replayable for coverage measurement
and `corpus minimize`. The queue and the active mutation pool share the
`--max-corpus-mb` retention ceiling; finding testcases are stored separately and
are never evicted by it. Every pass after the first reseeds from a bounded subset
of this queue, so deep code reached once stays reachable instead of each pass
restarting from the tiny built-in seeds.

## Limitations

- **Stub soundness.** A blind `void log_warn(void)` stub compiles but the
  call site may pass arguments the stub ignores. Fine for fuzzing, not for
  verification. When *every* symbol the harness calls is blind-stubbed the run
  exercises only stubs — `run.json` flags this as `stub_execution.stub_only`
  (see above) so it is never mistaken for a real fuzz of the library.
- **Static linking.** LD_PRELOAD does not apply to static binaries. The
  build-time sweep still runs; the runtime audit falls back to a strace-style
  audit (no faking).
- **Cross-arch.** Out of scope for `auto`. Use the manual flow with
  `govfuzz build --target …` for cross compilation.
- **Multi-threaded targets.** The shim is thread-safe, but fake-data RNGs
  are single-state per resource — two threads reading the same fake fd race
  for bytes.
- **Runtime virtualisation by lane.** The LD_PRELOAD behavioral/taint shim is
  armed for native Ada/C/C++/Rust/Go/COBOL/Fortran and for the
  Python/Perl/Ruby/Lua/PHP interpreter processes. It is not armed for Java, C#,
  JavaScript/TypeScript, or cross/emulated targets. Those configurations retain
  their documented fuzz coverage and crash/exception oracles;
  GF-405/GF-304/GF-417/GF-305 runtrace findings are the unavailable layer.
- **C++ API lifecycle.** C++ harnesses cover both direct-call and
  lifecycle-sequence shapes but remain partly heuristic. Template
  metaprogramming and user-defined literals, abstract receivers that require
  non-default constructors, and operator-overload / `shared_ptr` receivers are
  still partial and usually need a wrapper or more manual flags.
- **Go coverage fallback.** Go normally gets real block feedback from
  `go build -cover -covermode=atomic`; each input's executed-block set is folded
  into the shared edge map. If module-wide `-coverpkg` fails, the lane retries the
  exact selected package before falling back safely to black-box mode instead of
  discarding the target or inventing coverage.
- **Expert-only setup remains possible.** Private Rust targets that require an
  in-package harness, complex generated/platform build graphs, framework hosts,
  coherent scientific array/dimension synthesis, and longer state/resource
  protocols can still require a manual wrapper. See the
  [expert-parity audit](./harness-parity-audit.md) for measured residuals.

See [Runtime Virtualisation](../runtime-virtualisation/) for the shim's
intercept list, env-var contract, and replay envelope.
