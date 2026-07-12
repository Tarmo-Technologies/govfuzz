// SPDX-License-Identifier: Apache-2.0

//! `govfuzz auto <PATH>` — orchestrate `discover` + per-candidate
//! `attempt` + final `write_reports` into a single subcommand.
//! `--per-target-time` and `--no-stubs` are threaded through
//! `AttemptOptions` so they actually take effect inside the loop.

use crate::auto::attempt::AttemptOptions;
use crate::auto::decl_index::DeclarationIndex;
use crate::auto::discovery::DirFilter;
use crate::auto::report::write_reports;
use crate::target_filter::{path_matches_exclusion, ExcludeCategory};
use anyhow::{Context, Result};
use chrono::Utc;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct AutoArgs {
    /// Source root to sweep.
    pub path: PathBuf,

    /// Work directory. Default ./govfuzz_work/.
    #[arg(long, default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Explicit discovery-cache file for `--reuse-discovery`, overriding the
    /// default `<work-dir>/discovery-cache.json`. Pin it to a stable absolute
    /// path so the cache is found regardless of the current directory or work
    /// dir, and can live on a known-good volume. Read/written only with
    /// `--reuse-discovery`.
    #[arg(long = "discovery-cache", value_name = "PATH")]
    pub discovery_cache: Option<PathBuf>,

    /// Load run options from a TOML config file. Persists common flags so a project's
    /// runs are reproducible; CLI flags always override it. Without this, a
    /// `.govfuzz.toml` in the scanned tree root is auto-loaded — but an auto-loaded
    /// config honors only SAFE knobs (fields that EXECUTE the tree's own build, like
    /// `build-command`, require this explicit flag). Keys are the flag names in
    /// kebab-case (e.g. `per-target-time = 30`, `cxx-std = "gnu++14"`).
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Path to a JSON grammar describing the target's input format for structure-aware
    /// generation (a Nautilus-style grammar mutator), applied to every fuzzed target.
    /// Each rule maps a non-terminal to production strings where `{NAME}` references
    /// another rule; the start symbol is `START` or the first rule. See
    /// `govfuzz fuzz --grammar`.
    #[arg(long = "grammar", value_name = "PATH")]
    pub grammar_file: Option<PathBuf>,

    /// Maximum fuzz input length. `auto` (the default) grows the effective length
    /// adaptively per target — free up to ~1 MiB, and beyond that only while longer
    /// inputs keep finding new coverage — so a large-object target (image, archive,
    /// firmware) is handled WITHOUT a seed corpus, and a small-format one is never
    /// grown into huge inputs pointlessly. A positive integer sets a fixed cap instead.
    #[arg(long = "max-len", default_value = "auto")]
    pub max_len: String,

    /// Per-execution timeout (e.g. `10s`, `500ms`); an input exceeding it is a
    /// hang/timeout. Default: the engine's 10s.
    #[arg(long = "timeout", value_parser = crate::fuzz::parse_duration)]
    pub timeout: Option<std::time::Duration>,

    /// Force the C++ standard for every harness build (e.g. `gnu++14`, `c++03`),
    /// pinning the dialect for legacy C++. Without it, `auto` builds C++ at the modern
    /// default and, on a dialect failure, automatically retries successively older
    /// standards until one builds — so an explicit value is only needed to override
    /// that search.
    #[arg(long = "cxx-std", value_name = "STD")]
    pub cxx_std: Option<String>,

    /// TOTAL per-target fuzz wall-clock budget in seconds, split evenly across the
    /// passes (`auto` runs empty / rng / fuzz-driven) under one shared deadline,
    /// so the per-target wall ≈ this regardless of pass count. libFuzzer
    /// `-max_total_time` / AFL `-V` / honggfuzz `--run_time` parity. For a
    /// whole-RUN cap across all targets use `--campaign-time`.
    #[arg(long, default_value_t = 60)]
    pub per_target_time: u64,

    /// DEPRECATED alias of `--per-target-time` (overrides it when set). Retained
    /// so existing benchmark/parity invocations keep working; prefer
    /// `--per-target-time`. Hidden from help.
    #[arg(long, hide = true)]
    pub total_time: Option<u64>,

    /// Stop fuzzing a target as soon as it has produced this many DISTINCT
    /// findings (crash signatures), or when its `--per-target-time` budget is
    /// spent — whichever comes first. Checked mid-pass, so the target stops the
    /// instant the Nth finding lands and remaining passes are skipped. `1` mimics
    /// libFuzzer's stop-on-first-crash. Unset (default) = collect every finding
    /// within the time budget (current behavior).
    #[arg(long = "per-target-finding-count", value_name = "N")]
    pub per_target_finding_count: Option<usize>,

    /// Whole-run budget in seconds across ALL targets. Default mode: a hard OUTER
    /// wall-clock cap — once exceeded, `auto` stops STARTING new (ranked) targets
    /// (the in-flight one finishes) and reports how many of the N discovered were
    /// reached. With `--min-target-time`, switches to SPLIT mode: this becomes the
    /// total fuzz budget DIVIDED across the attempted targets. Unset (default) =
    /// run every target with its own `--per-target-time`.
    #[arg(long)]
    pub campaign_time: Option<u64>,

    /// SPLIT-mode floor (seconds), used only with `--campaign-time`: divide the
    /// campaign budget across the N attempted targets, giving each
    /// `max(min, campaign / N)` of fuzz time and attempting only the top
    /// `floor(campaign / per_target)` ranked targets (the rest logged unfuzzed) —
    /// never less than this floor per target. Requires `--campaign-time`;
    /// overrides `--per-target-time`.
    #[arg(
        long = "min-target-time",
        value_name = "SECS",
        requires = "campaign_time"
    )]
    pub min_target_time: Option<u64>,

    /// Keep only the top-N highest-scored targets after discovery + ranking, before
    /// the build/fuzz sweep. On a huge tree (140k+ discovered targets) this caps the
    /// sweep to the best candidates instead of grinding all of them. `--list-targets`
    /// still prints the FULL ranked list; the truncation only bounds what is built /
    /// fuzzed, and the kept count vs. total is logged (never a silent truncation).
    /// Unset (default) = attempt every discovered target.
    #[arg(long = "max-targets", value_name = "N")]
    pub max_targets: Option<usize>,

    /// Cap on build-fail -> repair -> retry rounds per target (default 48). Each
    /// round only runs when the previous one applied a NEW repair (the no-progress
    /// early-break is preserved), so this is a ceiling, not a fixed cost. A LOW
    /// value (2-3) fails un-buildable targets fast — useful for a quick triage
    /// sweep over a huge tree where deep multi-file dependency convergence isn't
    /// worth the per-target build time.
    #[arg(long = "max-repair-rounds", default_value_t = crate::auto::attempt::DEFAULT_MAX_REPAIR_ROUNDS)]
    pub max_repair_rounds: usize,

    /// Restrict the per-target fuzz cascade to a comma-separated subset of passes
    /// instead of all three. Names: `empty`, `rng`, `fuzz` (alias for
    /// `fuzz_driven`). E.g. `--passes fuzz` runs only the fuzz-driven pass — ~3x
    /// the throughput of the default 3-pass cascade for a triage sweep. Order is
    /// preserved as given. Unset (default) = all passes (empty, rng, fuzz_driven).
    /// Ignored under `--deps-only` (which fuzzes nothing).
    #[arg(long = "passes", value_name = "SET", conflicts_with = "single_pass")]
    pub passes: Option<String>,

    /// Convenience for `--passes fuzz`: run ONLY the fuzz-driven pass per target,
    /// skipping the empty/rng passes. ~3x a triage sweep's throughput. Mutually
    /// exclusive with `--passes`.
    #[arg(long = "single-pass")]
    pub single_pass: bool,

    /// Number of candidates to build+fuzz CONCURRENTLY (default 1 = serial, exactly
    /// today's behavior). With N>1, up to N targets' build+fuzz run in parallel via a
    /// bounded worker pool. MEMORY: each concurrent fuzz uses up to `--rss-limit-mb`
    /// of RAM, so effective peak memory is roughly `jobs x rss-limit-mb` — size it to
    /// the host (a too-high value OOM-kills, e.g. inside a cgroup MemoryMax slice).
    /// Results are aggregated deterministically regardless of completion order.
    #[arg(long = "jobs", short = 'j', default_value_t = 1, value_name = "N")]
    pub jobs: usize,

    /// DEPRECATED no-op: discovery caching is now ON BY DEFAULT (this flag is
    /// accepted for back-compat and does nothing). See `--no-discovery-cache` to
    /// opt out and `--fresh-discovery` to force a re-discovery.
    #[arg(long = "reuse-discovery", hide = true)]
    pub reuse_discovery: bool,

    /// Disable the discovery cache entirely: do not read or write
    /// `<work-dir>/discovery-cache.json`; always run a fresh tree-sitter parse +
    /// rank. (Discovery caching is on by default — a re-run over an unchanged
    /// source tree reuses the prior ranked candidate list, skipping the dominant
    /// cost of a big-tree re-run. A content fingerprint of the target source +
    /// dir-filter guards every load, so any source/`--exclude-dir`/`--include-dir`
    /// change auto-invalidates it; a stale cache is never used silently.)
    #[arg(long = "no-discovery-cache")]
    pub no_discovery_cache: bool,

    /// Force a fresh discovery THIS run, ignoring any existing cache, then
    /// overwrite the cache with the new result. Use when you deliberately want to
    /// re-discover (the cache otherwise only re-runs discovery when the target
    /// source or dir-filter actually changed). No effect with
    /// `--no-discovery-cache`.
    #[arg(long = "fresh-discovery")]
    pub fresh_discovery: bool,

    /// Resume a prior sweep over the SAME work-dir: skip targets that already
    /// completed (a per-target `harnesses/<id>/result.json` marker is written the
    /// moment each target's attempt finishes, so an INTERRUPTED run is resumable),
    /// re-running only the not-yet-attempted ones. Requires the discovery cache to
    /// hit (target source unchanged) — otherwise the prior per-target results may
    /// be stale and every target is re-attempted. Each skipped target's prior
    /// artifacts (`harnesses/<id>/`, `findings/`, `fuzz_runs/`) remain on disk; the new
    /// run's report counts them as `resumed`.
    #[arg(long = "resume")]
    pub resume: bool,

    /// Per-pass execution cap. Unset (or `0`) lets `--per-target-time` govern
    /// depth; a positive value caps each fuzz pass (libFuzzer `-runs`). The old
    /// hardcoded 1024 cap is retired — without this flag wall-clock governs.
    #[arg(long)]
    pub iterations: Option<usize>,

    /// Per-harness resident-set memory cap in MB. A test case that allocates
    /// past this is killed and reported as an OOM finding (GF-209) instead of
    /// OOM-killing the host. Mirrors libFuzzer's `-rss_limit_mb`; default 2048.
    #[arg(long = "rss-limit-mb", default_value_t = 2048)]
    pub rss_limit_mb: usize,

    /// Skip auto-stubbing entirely (diagnostics-only).
    #[arg(long)]
    pub no_stubs: bool,

    /// Print the fake-resource plugin inventory and exit.
    #[arg(long)]
    pub list_fakes: bool,

    /// Attempt only targets whose discovered name exactly matches this value.
    /// Repeatable. Useful when a source drop contains vendored support code
    /// but the sweep should exercise a known wrapper target.
    #[arg(long = "target")]
    pub targets: Vec<String>,

    /// Attempt only targets whose stable harness id exactly matches this value.
    /// Repeatable. Useful for rerunning a target printed by auto/run reports.
    #[arg(long = "harness-id")]
    pub harness_ids: Vec<String>,

    /// Attempt only targets discovered in this source file. Accepts an absolute
    /// path or a path relative to the sweep root. Repeatable.
    #[arg(long = "target-file", value_name = "PATH")]
    pub target_files: Vec<PathBuf>,

    /// Exclude paths whose normalized relative path contains this text. Repeatable.
    #[arg(long = "exclude-path")]
    pub exclude_paths: Vec<String>,

    /// Exclude common project areas. Accepts comma-separated values: tests, tools, examples.
    #[arg(long = "exclude", value_enum, value_delimiter = ',')]
    pub exclude: Vec<ExcludeCategory>,

    /// Additional local directories of dependency source to put on the Ada
    /// build path (offline: never fetched). Point at vendored/air-gapped
    /// dependency crates so a project that `with`s an external library (e.g.
    /// ada-util's `Util.Encoders`) can build. Repeatable. Locally-cached Alire
    /// dependencies under the project are also picked up automatically.
    #[arg(long = "ada-deps", value_name = "DIR")]
    pub ada_deps: Vec<PathBuf>,

    /// Seed input file whose bytes bootstrap every target's fuzz corpus.
    /// Provide valid/structured examples (a real `.zip`, `.bz2`, a sample
    /// document) so parser/decompressor targets reach deep code instead of
    /// bouncing off the header check. Repeatable.
    #[arg(long = "seed-file", value_name = "PATH")]
    pub seed_files: Vec<PathBuf>,

    /// Directory of seed inputs; each regular file's bytes become a seed.
    /// Repeatable.
    #[arg(long = "seed-dir", value_name = "DIR")]
    pub seed_dirs: Vec<PathBuf>,

    /// Actionability profile to optimize for.
    #[arg(long, default_value_t = actionability::RunMode::Reporting)]
    pub mode: actionability::RunMode,

    /// Fuzz engine(s) for the per-target fuzz phase, comma-separated. `builtin`
    /// (default) is the in-process coverage-guided engine. `afl++` drives AFL++
    /// on the auto-recovered build (C/C++ targets only; needs `afl-fuzz` +
    /// `afl-clang-fast` on PATH, else it falls back to builtin with a warning).
    /// `--engine builtin,afl++` runs BOTH per target, splitting `--per-target-time`
    /// evenly across them. For a non-C/C++ target an `afl++` selection falls back
    /// to builtin (logged, never silently skipped).
    #[arg(long = "engine", default_value = "builtin", value_name = "LIST")]
    pub engine: String,

    /// Print an extra indented line per target explaining the outcome:
    /// why a target was skipped or failed, which repairs auto applied,
    /// and per-pass execution/finding counts.
    #[arg(short, long)]
    pub verbose: bool,

    /// Recover the project's real compile wiring by running its own build
    /// (CMake configure, or `make` under a compiler-interposing wrapper) once,
    /// offline, before harnessing. Produces `<tree>/.govfuzz-build/
    /// compile_commands.json` (and any generated headers) so each harness builds
    /// with the exact `-I`/`-D`/`-std` flags of the real translation unit.
    ///
    /// This EXECUTES the project's untrusted build scripts; it runs under
    /// govfuzz's sandbox (bwrap/firejail) when one is available and degrades to a
    /// direct run otherwise. Off by default.
    #[arg(long = "probe-build")]
    pub probe_build: bool,

    /// Dependency-scan mode: discover, build each target as far as possible
    /// (stubbing whatever is missing), and emit the missing-dependency manifest —
    /// but SKIP fuzzing. The fast "what does this tree need?" pass: find every
    /// missing dependency in one go (see `<work>/auto/missing-deps.txt`) so you
    /// can bring them all to the offline machine at once, instead of
    /// build-hit-copy-repeat. A normal `auto` run also writes the manifest; this
    /// just gets it without paying for the fuzz phase.
    #[arg(long = "deps-only")]
    pub deps_only: bool,

    /// Discovery dry-run: print the ranked fuzz targets the engine would harness
    /// (highest score first, with file:line, language, and input-reachability) and
    /// exit WITHOUT building or fuzzing anything. The fast way to see what `auto`
    /// considers the best places to fuzz in a project — and to validate the
    /// entry-point ranking on a new codebase before committing a full run.
    #[arg(long = "list-targets")]
    pub list_targets: bool,

    /// Plan only: discover + rank targets, run the toolchain preflight, and report the
    /// build-recovery plan, then EXIT without building or fuzzing. Validate scope,
    /// config, and toolchains before committing to a long run.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Extra directory NAMES to skip during discovery, on top of the built-in
    /// defaults (tests/examples/benchmarks/vendored deps/docs). Matched on the
    /// exact path component, case-insensitively. Repeatable. Use it when a project
    /// keeps non-library code under an unusual dir name.
    #[arg(long = "exclude-dir", value_name = "NAME")]
    pub exclude_dir: Vec<String>,

    /// Directory NAMES to KEEP in discovery even though a built-in default would
    /// skip them — e.g. `--include-dir samples` for a project whose real fuzzable
    /// code lives under `samples/`. Repeatable; overrides the default exclusions.
    #[arg(long = "include-dir", value_name = "NAME")]
    pub include_dir: Vec<String>,

    /// Restrict the sweep to a comma-separated subset of source languages:
    /// `ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`. Candidates in
    /// any other language are dropped after discovery — before the build/fuzz
    /// sweep and before `--list-targets`, so the ranked list reflects the filter
    /// too. Common spellings are accepted (`c++`/`cxx`/`cc`→cpp, `rs`→rust,
    /// `py`→python, `pl`→perl, `golang`→go); matching is case-insensitive.
    /// Unset (default) = fuzz every language govfuzz can build in the tree. The
    /// SBOM/SCA pass is unaffected — it always scans the whole tree across all
    /// ecosystems regardless of this fuzzing-lane filter.
    #[arg(
        long = "languages",
        visible_alias = "lang",
        value_enum,
        value_delimiter = ',',
        ignore_case = true,
        value_name = "LIST"
    )]
    pub languages: Vec<crate::auto::candidate::LangSelector>,

    /// Run the CPP-lite preprocessor over C/C++ before parsing for discovery
    /// (§27.6): resolve `#ifdef`/`#if` branches and expand object-like macros so a
    /// function compiled out under the active config is not discovered, with a
    /// preprocessed->original line map keeping reported locations accurate.
    /// `auto` (default) preprocesses only files with heavy conditional compilation;
    /// `always` forces it on every C/C++ file; `never` parses raw source.
    #[arg(
        long = "preprocess",
        value_enum,
        default_value = "auto",
        value_name = "MODE"
    )]
    pub preprocess: crate::auto::discovery::PreprocessMode,

    /// After the sweep, attempt to fetch the still-blocking dependencies from the
    /// manifest using whatever package managers are present (apt-get for known
    /// headers/libs, `alr get` for Ada units). Opt-in and ONLINE — the only part
    /// of `auto` that touches the network. Nothing is fatal: a manager that's
    /// absent or fails (no root for apt, offline, unknown package) is reported
    /// with the command to run by hand. Re-run `auto` afterward to build against
    /// the installed dependencies. Pairs well with `--deps-only` for a fast
    /// scan-then-fetch.
    #[arg(long = "install-deps")]
    pub install_deps: bool,

    /// Consent gate for running the project's own (untrusted) build/codegen to
    /// materialize generated dependencies before harnessing — the umbrella for
    /// `--probe-build` (CMake/Make configure+codegen) plus an Ada build probe
    /// (`alr build` / `gprbuild`) that generates Alire config + codegen outputs.
    /// Implies `--probe-build`. EXECUTES untrusted scripts; runs under govfuzz's
    /// sandbox (bwrap/firejail) when one is available, degrading to a direct run
    /// otherwise. Off by default — without it, govfuzz stubs generated deps and
    /// records them in the manifest instead of running anything.
    #[arg(long = "run-untrusted")]
    pub run_untrusted: bool,

    /// Recover compile flags from a CUSTOM build by running this exact command
    /// (e.g. `--build-command ./build.sh`, `--build-command "bazel build //lib"`,
    /// `--build-command scons`) under a compiler-intercepting shim: every
    /// `cc`/`gcc`/`clang` — and named vendor compilers (Wind River Diab,
    /// Green Hills, QNX, Keil/IAR, TI) plus cross-prefixed GNU/LLVM toolchains —
    /// is logged into a `compile_commands.json`. The universal escape hatch for
    /// build systems govfuzz doesn't natively probe (Bazel, SCons, Waf, a bare
    /// `build.sh`, a vendor RTOS build). EXECUTES the command (via `sh -c`) and
    /// runs under govfuzz's sandbox when one is available. Implies the build
    /// probe; takes precedence over the auto-detected CMake/Meson/Make tier.
    #[arg(long = "build-command", value_name = "CMD")]
    pub build_command: Option<String>,

    /// UNSAFE: search the tree for its own build entry point and EXECUTE it to recover
    /// compile flags — the auto-run govfuzz otherwise gates behind explicit consent
    /// (see `--build-command`). Detects a custom build (build.sh, autotools
    /// bootstrap/autogen/configure, SCons, Waf, Bazel) and runs it under the
    /// compiler-intercepting shim, and enables the `--probe-build` tiers
    /// (CMake/Meson/Make) plus the Ada build probe. Runs under govfuzz's sandbox when
    /// one is available, but you are running UNTRUSTED code from the scanned tree —
    /// only use it on sources you trust. An explicit `--build-command` overrides the
    /// search.
    #[arg(long = "unsafe-search-and-run-build-commands")]
    pub unsafe_search_and_run_build_commands: bool,

    /// Extra include directories for C/C++ harness builds. Point at dependency
    /// headers that live outside the swept tree — e.g. cFE's OSAL/PSP includes,
    /// a vendored SDK's `include/` — so real struct layouts and typedefs compile
    /// in. Seeded onto every harness `-I` path before the repair loop (so real
    /// headers win over synthesized placeholders) and folded into cross-dir
    /// header resolution. Read from local disk only; nothing is fetched.
    /// Repeatable.
    #[arg(long = "extra-include", value_name = "DIR")]
    pub extra_includes: Vec<PathBuf>,

    /// Additional C/C++ source files (`.c`/`.cpp`) to compile and link into the
    /// harness. Use this for a multi-file library whose target function's
    /// dependencies live in sibling translation units the auto-linker would
    /// otherwise blind-stub (e.g. libACPI's `AMLParserProcessBuffer` calling
    /// across `AMLRouter.c`/`AMLName.c`/…): pass the real sources so the symbols
    /// resolve and nothing is stubbed. Read from local disk only; nothing is
    /// fetched. Repeatable.
    #[arg(long = "extra-source", value_name = "FILE")]
    pub extra_sources: Vec<PathBuf>,

    /// Enable laf-intel comparison-progress coverage (#421): the C/C++ driver
    /// records, per compare site, how many LEADING bytes of each comparison an
    /// input matched, and the engine rewards an input that matches more — a
    /// gradient that defeats multi-byte magic / format gates (bzip2/lz4/libpng/
    /// expat) which a whole-compare edge gives no signal on. Opt-in; composes
    /// with cmplog, value-profile, ASan, and the #420 hit-count buckets.
    #[arg(long = "comparison-progress", alias = "cmp-progress")]
    pub comparison_progress: bool,

    /// Sanitizer matrix to arm for the harnesses `auto` BUILDS and RUNS,
    /// comma-separated (asan, ubsan, msan, tsan, lsan). Each C/C++ harness is
    /// compiled+linked with exactly the requested `-fsanitize=` set (plus the
    /// engine's coverage instrumentation) instead of the default `address,undefined`,
    /// and every fuzz pass runs with the matching `<SAN>_OPTIONS`
    /// (`abort_on_error=1:halt_on_error=1:detect_leaks=1`) so UBSan/LSan reports
    /// become crashes the engine saves instead of silently-printed warnings — the
    /// same arming `govfuzz fuzz --sanitizers` does, now for the auto pipeline.
    /// Default (empty) leaves the build and run env unchanged. Compatible set is
    /// `asan,ubsan,lsan`; `msan`/`tsan` are mutually exclusive with those and each
    /// other. The special value `none` (standalone — not combinable with a
    /// sanitizer) builds each native C/C++ harness with coverage but NO
    /// `-fsanitize=`, i.e. crash-only fuzzing with zero ASan/UBSan false positives
    /// — the escape hatch for shared-memory / custom-allocator / RTOS code that
    /// FP-storms under ASan. Inert on the Ada and cross-compiled (qemu-user / wine)
    /// paths.
    ///
    /// To tame (rather than disable) the FP storm, export the sanitizer's own
    /// options before running — govfuzz MERGES your inherited `<SAN>_OPTIONS` and
    /// keeps its required keys last, e.g.
    /// `ASAN_OPTIONS=verify_asan_link_order=0:detect_container_overflow=0:suppressions=$PWD/asan.supp`
    /// and `LSAN_OPTIONS=suppressions=$PWD/lsan.supp` (#435).
    #[arg(long = "sanitizers", value_delimiter = ',')]
    pub sanitizers: Vec<String>,

    /// Emit an evidence-graded SBOM + VEX bundle at campaign end, into
    /// `<work-dir>/sbom/`. The bundle is generated where `FuzzReached` evidence is
    /// freshest: the scanned tree's components are enriched with the campaign's
    /// own `auto/run.json` (and any produced binary inventories), so libraries a
    /// harness actually drove are marked exercised. Off by default to keep `auto`
    /// fast — turn it on for a supply-chain deliverable. Writes all artifacts
    /// (sbom.json, cyclonedx.json, vulnerabilities.json, openvex.json, sbom.csv);
    /// use the standalone `govfuzz sbom` for finer `--emit`/`--ecosystems` control.
    #[arg(long = "sbom")]
    pub sbom: bool,

    /// Always run the static analyzer over the whole scanned tree, IN ADDITION to
    /// fuzzing — not only when a target can't be built/fuzzed. Its findings
    /// (classification `static_scan`) are merged into the unified report next to
    /// the fuzz findings, so a target that built+fuzzed still gets static coverage
    /// and files with no fuzzable subprogram are analyzed too. Same engine as the
    /// standalone `govfuzz scan`.
    #[arg(long = "static")]
    pub static_scan: bool,

    /// Also drive installed EXTERNAL static analyzers (gosec/Bandit/semgrep/
    /// GNATcheck) as subprocesses and merge their findings into the report (so the
    /// fuzz-confirmation join confirms them too). Each tool runs only if the active
    /// license profile permits its subprocess — `strict-permissive` runs none, so
    /// the default profile never invokes a GPL tool. Missing tools are skipped.
    /// Implies `--static`.
    #[arg(long = "external-tools")]
    pub external_tools: bool,

    /// Force-fuzz mode: attempt EVERY discovered C/C++/Ada function even when a
    /// parameter type can't be driven or a type/symbol is undefined — synthesize a
    /// best-effort driver, stub whatever the compiler reports missing, and never
    /// hard-fail (report-only is the floor). Findings from a forced/stub-heavy build
    /// are stamped low-confidence. Repair persistence honors `--max-repair-rounds`.
    #[arg(long = "force", visible_alias = "force-fuzz")]
    pub force: bool,

    /// Two-compiler differential fuzzing (C/C++). Format `A:B`, e.g. `clang:gcc`:
    /// after the normal run, rebuild each C/C++ harness under both compilers via a
    /// portable build and replay the fuzz corpus through both, flagging any input
    /// on which their exit/crash behavior diverges (a codegen- or UB-dependent bug
    /// one compiler exposes and the other hides) as a GF-301 finding.
    #[arg(long, value_name = "A:B")]
    pub differential: Option<String>,

    /// Write an accurate per-language SLOC breakdown (LANGUAGE, FILES, TOTAL,
    /// COMMENTS, BLANKS, SLOC) of the source tree, then continue the normal run. A
    /// relative path lands beside the other run outputs in `<work-dir>/auto/`; an
    /// absolute path is written as given. A `.json` extension emits JSON; anything
    /// else emits an aligned text table. Uses the scanner's dependency/build-tree
    /// pruning and language-aware comment stripping.
    #[arg(long)]
    pub sloc: Option<PathBuf>,

    /// Run in static-dynamic mode: add a `scan_type` column to findings.csv
    /// (`static-dynamic` for static-scan results, `dynamic` for fuzzed results).
    #[arg(long = "static-dynamic")]
    pub static_dynamic: bool,

    /// Configurable C/C++ decoder synthesis caps (§27.11): `--max-decode-depth`,
    /// `--max-array-elems`, `--max-decl-bytes` (C) and `--container-size-max`,
    /// `--bitset-max-size`, `--array-max-size` (C++). Each unset flag keeps the
    /// historical default, so omitting them all leaves harness emission unchanged.
    #[command(flatten)]
    pub decoder_limits: crate::generate_harness::DecoderLimitArgs,
}

/// Load user seed inputs: each `--seed-file`'s bytes, plus each regular file in
/// every `--seed-dir`. Unreadable entries are warned and skipped (best-effort —
/// a missing seed shouldn't abort the sweep).
///
/// Seeds longer than the mutator's max input length are TRUNCATED to it. The
/// builtin engine never generates an input longer than `DEFAULT_MAX_LEN`
/// (libFuzzer's `-max_len`, 4096), so the tail of an oversized seed is
/// unreachable by mutation — keeping it only makes every pass replay and mutate
/// a huge buffer, which collapses throughput. (Observed: a 5.9 MB SoundFont seed
/// dropped a tsf run from ~2700 exec/s to 0.2 exec/s — a >10000x slowdown — until
/// the seed was truncated.) Truncating keeps the structural prefix (RIFF/chunk
/// headers, where parser bugs live) while restoring normal throughput.
fn load_seed_inputs(seed_files: &[PathBuf], seed_dirs: &[PathBuf]) -> Vec<Vec<u8>> {
    let cap = crate::fuzz::DEFAULT_MAX_LEN;
    let mut seeds = Vec::new();
    let mut push_capped = |path: &std::path::Path, mut bytes: Vec<u8>| {
        if bytes.len() > cap {
            eprintln!(
                "govfuzz auto: seed '{}' is {} bytes; truncating to {cap} (the fuzz \
                 mutator's max input length — bytes past it are never generated and \
                 only slow fuzzing)",
                path.display(),
                bytes.len()
            );
            bytes.truncate(cap);
        }
        seeds.push(bytes);
    };
    for file in seed_files {
        match std::fs::read(file) {
            Ok(bytes) => push_capped(file, bytes),
            Err(error) => eprintln!(
                "govfuzz auto: skipping seed file '{}': {error}",
                file.display()
            ),
        }
    }
    for dir in seed_dirs {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(bytes) = std::fs::read(&path) {
                            push_capped(&path, bytes);
                        }
                    }
                }
            }
            Err(error) => eprintln!(
                "govfuzz auto: skipping seed dir '{}': {error}",
                dir.display()
            ),
        }
    }
    seeds
}

pub fn run(args: AutoArgs) -> i32 {
    if args.list_fakes {
        print!("{}", crate::list_fakes::render());
        return 0;
    }
    // The auto sweep owns the terminal with a live progress line; silence the
    // per-harness "Generated ... harness at ..." banners so they don't interleave
    // with the in-place progress line and garble it (e.g.
    // "generating harnessGenerated C++ harness"). Harness dirs stay in the report.
    crate::generate_harness::silence_generation_banner(true);
    // Top-level guard: an internal panic that escaped every per-target/per-file
    // `bug_report::catch` would otherwise abort the process before write_reports
    // runs, leaving no bug report. Catch it here — the panic hook already recorded
    // and flushed the report to the run's work dir — and exit cleanly.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_inner(args))) {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            eprintln!("error: {error:#}");
            1
        }
        Err(_panic) => {
            let n = crate::auto::bug_report::flush_after_panic();
            eprintln!(
                "govfuzz: run aborted by an internal panic — {n} issue(s) recorded in the bug \
                 report (path printed above)."
            );
            2
        }
    }
}

/// Plan a SPLIT-mode campaign: divide a total fuzz budget `total` across `n`
/// ranked targets with a per-target floor `min`. Returns
/// `(per_target_budget, targets_to_run)`.
///
/// When the even share `total / n` is at least `min`, every target runs that
/// share (all `n` attempted). Otherwise each attempted target runs exactly
/// `min` and only the top `floor(total / min)` targets are attempted — the
/// lower-ranked remainder is dropped (the caller logs it as unfuzzed). This is
/// the `--campaign-time` + `--min-target-time` behavior: it never gives a target
/// less than the floor, trading target COUNT for per-target depth.
fn plan_campaign_split(
    total: std::time::Duration,
    min: std::time::Duration,
    n: usize,
) -> (std::time::Duration, usize) {
    if n == 0 {
        return (min, 0);
    }
    let even = total / n as u32;
    if even >= min {
        return (even, n);
    }
    // The floor binds: fit as many whole `min` slices as the total allows,
    // capped at the target count. A zero floor would divide-by-zero, so treat
    // it as "no floor" and run every target.
    let fit = if min.is_zero() {
        n
    } else {
        (total.as_secs_f64() / min.as_secs_f64()).floor() as usize
    };
    (min, fit.min(n))
}

/// On Windows, `Path::canonicalize` returns an extended-length `\\?\` (or
/// `\\?\UNC\`) verbatim prefix. The `?` is a make/shell metacharacter govfuzz's
/// build-safety check rejects, and verbatim paths confuse `make`/clang recipes,
/// so strip the prefix back to an ordinary path. No-op off Windows. Applied to
/// the sweep root + work dir so every derived source/include path stays clean.
#[cfg(windows)]
pub(crate) fn strip_verbatim_prefix(p: std::path::PathBuf) -> std::path::PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        std::path::PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        std::path::PathBuf::from(rest)
    } else {
        p
    }
}
#[cfg(not(windows))]
pub(crate) fn strip_verbatim_prefix(p: std::path::PathBuf) -> std::path::PathBuf {
    p
}

/// The license profile for gating external-tool subprocesses under `--external-tools`,
/// from `GOVFUZZ_PROFILE` (`strict-permissive` | `external-tools` | `research-lab`).
/// An explicit `GOVFUZZ_PROFILE` wins; otherwise the `--external-tools` flag itself
/// opts into the `external-tools` profile so the flag does something useful without a
/// second env var — mirroring `static-scan`. This resolver is only consulted after the
/// operator has already opted in via the flag, so the default strict-permissive posture
/// still holds for every run that does not pass `--external-tools`.
fn resolve_license_profile() -> config::Profile {
    std::env::var("GOVFUZZ_PROFILE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(config::Profile::ExternalTools)
}

/// Detect a CUSTOM build entry point in the tree root that govfuzz does NOT auto-probe
/// (a bare build.sh, autotools, SCons, Waf, Bazel), returning `(marker, suggested
/// --build-command value)`. CMake/Make/Meson are intentionally excluded — those are
/// already auto-probed. Returns the first match; used only to hint after a failed build.
fn detect_custom_build(root: &Path) -> Option<(String, String)> {
    const CANDIDATES: &[(&str, &str)] = &[
        ("build.sh", "./build.sh"),
        ("bootstrap.sh", "./bootstrap.sh && make"),
        ("autogen.sh", "./autogen.sh && ./configure && make"),
        ("configure", "./configure && make"),
        ("SConstruct", "scons"),
        ("wscript", "./waf configure build"),
        ("WORKSPACE", "bazel build //..."),
        ("WORKSPACE.bazel", "bazel build //..."),
    ];
    CANDIDATES
        .iter()
        .find(|(name, _)| root.join(name).is_file())
        .map(|(name, cmd)| ((*name).to_owned(), (*cmd).to_owned()))
}

fn run_inner(mut args: AutoArgs) -> Result<i32> {
    let started_at = Utc::now().to_rfc3339();
    let run_start = std::time::Instant::now();
    let path = strip_verbatim_prefix(
        args.path
            .canonicalize()
            .with_context(|| format!("canonicalize sweep root {}", args.path.display()))?,
    );
    // Create the work dir up front so canonicalize() succeeds whether
    // the caller passed a fresh relative path or a pre-existing tree.
    std::fs::create_dir_all(&args.work_dir)
        .with_context(|| format!("create work dir {}", args.work_dir.display()))?;
    let work = strip_verbatim_prefix(
        args.work_dir
            .canonicalize()
            .unwrap_or(args.work_dir.clone()),
    );
    // Register the report dir NOW so an uncaught panic anywhere below (discovery,
    // IDL/CORBA scaffolding, ranking, report) can still flush the bug report.
    crate::auto::bug_report::set_output_dir(work.join("auto"));

    // Project config (--config <PATH>, or an auto-loaded .govfuzz.toml in the tree):
    // fill options the CLI left at their default. Applied BEFORE the env-publish and
    // build-recovery blocks below, which read the resulting args.
    for note in crate::auto::config::apply(&mut args, &path).map_err(|e| anyhow::anyhow!("{e}"))? {
        eprintln!("govfuzz auto: {note}");
    }

    // A `--grammar` applies to every target this run fuzzes. Validate it up front so a
    // typo fails fast (not per-target), then publish it via GOVFUZZ_GRAMMAR: the
    // builtin engine's grammar load reads that env on the auto path, and multicore
    // workers inherit it — no need to thread a path through every programmatic-run
    // argument. Set before any worker thread/process spawns (edition 2021: safe).
    if let Some(grammar) = &args.grammar_file {
        crate::fuzz::load_grammar_for_run(Some(grammar)).map_err(|e| anyhow::anyhow!("{e}"))?;
        std::env::set_var("GOVFUZZ_GRAMMAR", grammar);
    }

    // --max-len / --timeout apply to every fuzzed target; publish via env for the
    // builtin engine's programmatic path (multicore workers inherit it). Validate
    // --max-len ("auto" or a positive integer) so a typo fails fast, not per-target.
    {
        let spec = args.max_len.trim();
        if !spec.eq_ignore_ascii_case("auto")
            && spec.parse::<usize>().ok().filter(|&v| v > 0).is_none()
        {
            anyhow::bail!("--max-len must be \"auto\" or a positive integer, got {spec:?}");
        }
        std::env::set_var("GOVFUZZ_MAX_LEN", spec);
    }
    if let Some(timeout) = args.timeout {
        std::env::set_var("GOVFUZZ_EXEC_TIMEOUT", timeout.as_millis().to_string());
    }
    // --cxx-std pins the C++ dialect for every harness build (disabling the ladder).
    // Validate the shape so a typo fails fast rather than every C++ build silently.
    if let Some(std) = &args.cxx_std {
        let s = std.trim();
        if !(s.starts_with("c++") || s.starts_with("gnu++")) {
            anyhow::bail!("--cxx-std must be a C++ standard like c++14 / gnu++03, got {s:?}");
        }
        std::env::set_var("GOVFUZZ_CXX_STD", s);
    }

    // --unsafe-search-and-run-build-commands: the explicit opt-in to auto-executing the
    // project's own build to recover flags (the auto-run 1c gates behind consent). Find
    // a custom build script and route it through the `--build-command` path, and enable
    // the probe tiers (CMake/Meson/Make + Ada) that also execute the build. An explicit
    // `--build-command` still wins.
    if args.unsafe_search_and_run_build_commands {
        if args.build_command.is_none() {
            if let Some((marker, cmd)) = detect_custom_build(&path) {
                eprintln!(
                    "govfuzz auto: --unsafe-search-and-run-build-commands — found {marker}, \
                     executing to recover build flags: {cmd}"
                );
                args.build_command = Some(cmd);
            } else {
                eprintln!(
                    "govfuzz auto: --unsafe-search-and-run-build-commands — no custom build \
                     script found; probing recognized build systems (CMake/Meson/Make/Ada)"
                );
            }
        }
        // Consent for the probe tiers + Ada build probe, which also EXECUTE the build.
        args.run_untrusted = true;
    }

    // --sloc: write a per-language SLOC breakdown of the source tree up front,
    // independent of build/fuzz outcomes. A failure here shouldn't abort the run.
    // A relative path lands beside the other run outputs in `<work>/auto/`, not the
    // caller's CWD; an absolute path is honored as given.
    if let Some(sloc_path) = &args.sloc {
        let resolved = if sloc_path.is_absolute() {
            sloc_path.clone()
        } else {
            work.join("auto").join(sloc_path)
        };
        let _ = crate::static_scan::write_sloc_report(&path, &resolved);
    }

    #[cfg(not(target_os = "linux"))]
    eprintln!(
        "govfuzz auto: runtime audit is Linux-only; running on this OS without \
         LD_PRELOAD hooks. Build-time stubbing remains active."
    );

    // `--run-untrusted` is the umbrella consent gate: it implies `--probe-build`
    // (CMake/Make) and additionally runs an Ada build probe (alr/gprbuild).
    // `--build-command` is its own trigger: an explicit command to intercept.
    if args.probe_build || args.run_untrusted || args.build_command.is_some() {
        let sandbox = crate::auto::build_probe::resolve_sandbox_program();
        eprintln!(
            "govfuzz auto: running the project's build offline{} to recover compile flags / generated files",
            match &sandbox {
                Some(program) => format!(" under {}", program.display()),
                None => " (no sandbox found; direct run)".to_owned(),
            }
        );
        // An explicit `--build-command` takes precedence over the auto-detected
        // tier: it intercepts compilers from whatever build the user names.
        let recovered = if let Some(command) = &args.build_command {
            eprintln!(
                "govfuzz auto: --build-command: intercepting `{command}` to recover compile flags"
            );
            crate::auto::build_probe::probe_build_command(&path, command, sandbox.as_deref())
        } else {
            crate::auto::build_probe::probe_build(&path, sandbox.as_deref())
        };
        match recovered {
            Some(db) => eprintln!(
                "govfuzz auto: recovered compile database at {}",
                db.display()
            ),
            None => eprintln!(
                "govfuzz auto: no compile database produced; continuing with include auto-detection"
            ),
        }
        // The Ada side: alr/gprbuild generate the Alire config package + any
        // gpr-declared codegen. Only under --run-untrusted (executes the
        // project's build); degrades gracefully when no Ada project or toolchain.
        if args.run_untrusted {
            crate::auto::build_probe::probe_ada_build(&path, sandbox.as_deref());
        }
    }

    // Auto-generate CORBA/IDL scaffolding from any `.idl` files in the tree so an
    // Ada CORBA project's harnesses build without a manual `fake-corba` step.
    // govfuzz's own IDL parser — executes no project code — so it runs by default.
    let idl_mapped = crate::fake_corba::auto_generate_from_tree(&path, &work);
    if idl_mapped > 0 {
        eprintln!(
            "govfuzz auto: generated CORBA scaffolding from {idl_mapped} in-tree .idl file(s)"
        );
    }

    eprintln!("govfuzz auto: discovering targets under {}", path.display());
    let dir_filter =
        DirFilter::new(&args.exclude_dir, &args.include_dir).with_work_dir(&args.work_dir);
    // Discovery caching is ON by default; `--no-discovery-cache` opts out and
    // `--fresh-discovery` forces a re-discovery + cache rewrite. `--reuse-discovery`
    // is a deprecated no-op (the behavior it enabled is now the default).
    let _ = args.reuse_discovery;
    let (mut candidates, discovery_cache_hit) = discover_or_reuse(
        &path,
        &dir_filter,
        &work,
        !args.no_discovery_cache,
        args.fresh_discovery,
        args.discovery_cache.as_deref(),
        args.preprocess,
    )?;
    if !args.exclude_paths.is_empty() || !args.exclude.is_empty() {
        candidates.retain(|candidate| {
            !path_matches_exclusion(
                &candidate.source_path,
                &path,
                &args.exclude_paths,
                &args.exclude,
            )
        });
    }
    if !args.targets.is_empty() {
        candidates.retain(|candidate| {
            args.targets
                .iter()
                .any(|selected| target_name_filter_matches(&candidate.name, selected))
        });
    }
    if !args.harness_ids.is_empty() {
        let selected: std::collections::HashSet<&str> =
            args.harness_ids.iter().map(String::as_str).collect();
        candidates.retain(|candidate| selected.contains(candidate.harness_id.as_str()));
    }
    if !args.target_files.is_empty() {
        let selected: std::collections::HashSet<PathBuf> = args
            .target_files
            .iter()
            .map(|target_file| normalize_target_file_filter(&path, target_file))
            .collect();
        candidates.retain(|candidate| {
            let candidate_path = candidate
                .source_path
                .canonicalize()
                .unwrap_or_else(|_| candidate.source_path.clone());
            selected.contains(&candidate_path)
        });
    }
    // Language filter (`--languages`): keep only the requested source-language
    // lanes. Applied AFTER discovery (which is language-agnostic, so one
    // discovery cache serves every language subset) and BEFORE `--list-targets`
    // and any `--max-targets` truncation, so the ranked list and the top-N both
    // reflect the filter. Empty = fuzz every language found.
    if !args.languages.is_empty() {
        let selected = selected_lang_set(&args.languages);
        let (kept, dropped) = retain_languages(&mut candidates, &selected);
        eprintln!(
            "  language filter [{}] kept {kept} candidate(s), dropped {dropped}",
            render_selected_langs(&args.languages),
        );
    }
    if args.mode == actionability::RunMode::Attacking {
        sort_attacking_candidates(&mut candidates, |path| {
            std::fs::read_to_string(path).unwrap_or_default()
        });
    }
    eprintln!("  discovered {} candidate(s)", candidates.len());

    // Toolchain preflight: which lanes are present and whether their toolchains exist,
    // so a missing one is an explicit banner (not a silent skip that reads like a pass).
    // Kept for the end-of-run triage.
    let preflight = crate::auto::preflight::run(&candidates);
    eprint!("{}", preflight.render());

    // --dry-run: show the plan (toolchains + ranked targets + build-recovery note) and
    // exit without building or fuzzing, so a long run can be validated first.
    if args.dry_run {
        eprintln!("\ngovfuzz auto: --dry-run — plan only, nothing is built or fuzzed:");
        print_ranked_targets(&candidates, &path);
        if let Some((marker, cmd)) = detect_custom_build(&path) {
            eprintln!(
                "  build recovery: this tree has its own build ({marker}); \
                 pass --build-command {cmd:?} (or --unsafe-search-and-run-build-commands) if targets fail to build"
            );
        }
        eprintln!(
            "  would fuzz {} target(s){}",
            candidates.len(),
            if preflight.any_missing() {
                " — but some toolchains are MISSING (see above); those lanes won't build"
            } else {
                ""
            }
        );
        return Ok(0);
    }

    if args.list_targets {
        print_ranked_targets(&candidates, &path);
        return Ok(0);
    }
    if candidates.is_empty() {
        // --static is a whole-tree scan independent of fuzzable targets, so it
        // must run even when discovery finds nothing to fuzz (config files,
        // non-fuzzable code, an unbuildable tree still deserve static coverage).
        if args.static_scan {
            let n = crate::auto::report_only::emit_tree_static_findings(&path, &work);
            eprintln!(
                "govfuzz auto: --static — static scan wrote {n} finding(s) (no fuzzable targets discovered)"
            );
        }
        let finished_at = Utc::now().to_rfc3339();
        write_reports(
            &path,
            &[],
            &work,
            &started_at,
            &finished_at,
            false,
            args.mode,
            0,
            0,
            args.static_dynamic,
            args.force,
        )?;
        // A --static scan that produced findings is a successful run (0), not the
        // "nothing to do" code (2).
        let had_static =
            args.static_scan && !crate::auto::report::tree_static_finding_ids(&work).is_empty();
        return Ok(if had_static { 0 } else { 2 });
    }

    // Resolve cross-dir headers from the whole project (nearest `.git` ancestor)
    // even on a subdir run, so a `MissingHeader` finds the real header (PX4
    // `lib/perf/perf_counter.h`). The header-path walk is parse-free; type/symbol
    // parsing stays scoped to `path`, and discovery/attempts below stay scoped.
    let header_root = crate::auto::decl_index::project_index_root(&path);
    if header_root != path {
        eprintln!(
            "govfuzz auto: resolving cross-dir headers from project root {}",
            header_root.display()
        );
    }
    let mut idx = DeclarationIndex::build_indexed(&path, &header_root)?;
    // Extra C/C++ include dirs (`--extra-include`): dependency headers outside
    // the swept tree (OSAL/PSP for cFE, a vendored SDK include/). Fold them into
    // the cross-dir header index so type modeling resolves the real defs, and
    // forward them to the harness build path below. Read from disk only.
    let extra_include_dirs: Vec<PathBuf> = args
        .extra_includes
        .iter()
        .filter_map(|dir| dir.canonicalize().ok())
        .collect();
    if !extra_include_dirs.is_empty() {
        idx.add_header_search_roots(&extra_include_dirs)?;
        // Also index the DEFINITION sources (`.c`/`.cpp`) under those roots so an
        // undefined target-library symbol (cJSON's `cJSON_Parse`) is resolved by
        // AddSource-ing its real defining translation unit rather than a blind
        // `void` stub that returns a garbage register and crashes the harness in
        // `free(garbage)` (#388).
        idx.add_definition_search_roots(&extra_include_dirs)?;
        eprintln!(
            "govfuzz auto: {} extra C/C++ include dir(s) on the harness build path",
            extra_include_dirs.len()
        );
    }
    // Extra C/C++ source files (`--extra-source`): real translation units to
    // compile+link so a multi-file library's cross-file symbols resolve instead
    // of being blind-stubbed. Seeded into the build's extra_sources before the
    // first attempt.
    let extra_source_files: Vec<PathBuf> = args
        .extra_sources
        .iter()
        .filter_map(|file| file.canonicalize().ok())
        .collect();
    if !extra_source_files.is_empty() {
        eprintln!(
            "govfuzz auto: {} extra C/C++ source file(s) linked into the harness build",
            extra_source_files.len()
        );
    }
    // Dependency source on the Ada build path: explicit --ada-deps plus any
    // Alire dependency crates already cached locally under the project. All
    // read from local disk; nothing is fetched, so offline use is unchanged.
    let mut ada_dep_dirs: Vec<PathBuf> = args
        .ada_deps
        .iter()
        .filter_map(|dir| dir.canonicalize().ok())
        .collect();
    for cached in discover_local_alire_dep_dirs(&path) {
        if !ada_dep_dirs.contains(&cached) {
            ada_dep_dirs.push(cached);
        }
    }
    if !ada_dep_dirs.is_empty() {
        eprintln!(
            "govfuzz auto: {} local Ada dependency dir(s) on the build path",
            ada_dep_dirs.len()
        );
    }
    let user_seeds = load_seed_inputs(&args.seed_files, &args.seed_dirs);
    if !user_seeds.is_empty() {
        eprintln!(
            "govfuzz auto: {} user seed input(s) added to each target's corpus",
            user_seeds.len()
        );
    }
    // Dependency-scan mode builds each target (stubbing as it goes) but runs no
    // fuzz passes — an empty pass list makes `attempt` return `Built`, and the
    // manifest is emitted as usual.
    if args.deps_only {
        eprintln!(
            "govfuzz auto: --deps-only — building each target to surface missing dependencies; fuzzing skipped"
        );
    }
    let passes = if args.deps_only {
        Vec::new()
    } else {
        resolve_passes(args.single_pass, args.passes.as_deref())?
    };
    // Time-flag clarity (#auto-scaling): when BOTH a per-target total and a
    // per-pass budget are given, --total-time wins and --per-target-time is
    // ignored. Operators have been bitten by silently getting total/passes per
    // pass; say so loudly. (Heuristic for "explicitly set": per_target_time
    // differs from its default of 60 — the field always carries a value.)
    if let (false, Some(total)) = (args.deps_only, args.total_time) {
        if args.per_target_time != 60 {
            let pass_count = passes.len().max(1) as u64;
            eprintln!(
                "govfuzz auto: WARNING: both --total-time ({total}s) and --per-target-time \
                 ({}s) are set — --total-time WINS and --per-target-time is IGNORED. \
                 --total-time is a PER-TARGET budget apportioned across {pass_count} pass(es), \
                 so each pass gets total / passes ≈ {}s. Pass only one of the two to silence this.",
                args.per_target_time,
                total / pass_count,
            );
        }
    }
    if !args.deps_only && (args.single_pass || args.passes.is_some()) {
        eprintln!(
            "govfuzz auto: fuzzing {} of 3 pass(es) per target [{}]",
            passes.len(),
            passes
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // --jobs > 1: parallel sweep. Each concurrent fuzz uses up to --rss-limit-mb,
    // so warn the operator that effective peak memory scales with the job count
    // (a too-high value OOM-kills, e.g. inside a cgroup MemoryMax slice).
    let jobs = args.jobs.max(1);
    if jobs > 1 {
        eprintln!(
            "govfuzz auto: running up to {jobs} candidate(s) concurrently (--jobs {jobs}); \
             effective peak memory ≈ jobs x rss-limit-mb = {} MB — size it to the host",
            jobs.saturating_mul(args.rss_limit_mb)
        );
    }
    // Parse `--sanitizers asan,ubsan,…` once via the same validator the standalone
    // `govfuzz fuzz` path uses, so every harness in the sweep builds+runs with the
    // requested matrix. An unknown name aborts the whole sweep with a precise error
    // rather than silently fuzzing without the sanitizer the operator asked for.
    let sanitizers = crate::fuzz::parse_sanitizer_args(&args.sanitizers)
        .map_err(|error| anyhow::anyhow!(error))?;
    match &sanitizers {
        multicore_fuzz::SanitizerSelection::Set(_) => eprintln!(
            "govfuzz auto: arming sanitizer matrix [{}] on each C/C++ harness build + run",
            args.sanitizers.join(", ")
        ),
        multicore_fuzz::SanitizerSelection::None => eprintln!(
            "govfuzz auto: --sanitizers none — building each C/C++ harness with coverage but \
             no -fsanitize= (native crash-only, zero ASan/UBSan false positives)"
        ),
        multicore_fuzz::SanitizerSelection::Default => {}
    }
    // `--engine builtin|afl++[,…]`: the per-target fuzz-engine preference list.
    // Parsed once; an unknown name aborts the sweep with a precise error. AFL is
    // gated to C/C++ targets per-candidate inside the attempt loop.
    let requested_engines = crate::fuzz::parse_engine_list(&args.engine)
        .map_err(|error| anyhow::anyhow!("--engine: {error}"))?;
    // Probe the AFL toolchain ONCE for the whole run; if AFL was requested but
    // `afl-fuzz`/`afl-clang-fast` are missing, warn once and fall back to builtin
    // rather than failing every C/C++ target's afl build (mirrors the GNAT-less
    // skip convention).
    let afl_requested = requested_engines.contains(&crate::fuzz::FuzzEngine::AflPlusPlus);
    let afl_available = crate::auto::attempt::afl_toolchain_available();
    let engines =
        crate::auto::attempt::prune_engines_for_toolchain(&requested_engines, afl_available);
    if afl_requested && !afl_available {
        eprintln!(
            "govfuzz auto: --engine afl++ requested but afl-fuzz/afl-clang-fast not on PATH — \
             falling back to the builtin engine for this run"
        );
    }
    let mut options = AttemptOptions {
        per_target_time: std::time::Duration::from_secs(args.per_target_time),
        total_time: args.total_time.map(std::time::Duration::from_secs),
        per_target_finding_count: args.per_target_finding_count,
        no_stubs: args.no_stubs,
        passes,
        source_root: Some(path.clone()),
        ada_dep_dirs,
        mode: args.mode,
        user_seeds,
        extra_include_dirs,
        extra_sources: extra_source_files,
        iterations: args.iterations,
        rss_limit_mb: args.rss_limit_mb,
        max_repair_rounds: args.max_repair_rounds,
        comparison_progress: args.comparison_progress,
        sanitizers,
        dir_filter: dir_filter.clone(),
        engines,
        // Ada project-Main units (declared `for Main use (...)` in a .gpr under the
        // tree) are program entry points, not library subprograms — the attempt
        // loop pre-skips them with a precise reason instead of failing their build.
        ada_main_sources: crate::auto::discovery::gpr_main_sources(&path, &dir_filter),
        // §27.11: CLI-configured C/C++ decoder caps, threaded to harness gen.
        decoder_limits: args.decoder_limits.clone(),
        force: args.force,
    };
    // #6: the fully-ranked candidate count BEFORE any --max-targets / campaign
    // split cap, so the report can surface how many targets the cap dropped from
    // the sweep instead of silently reporting only the swept count.
    let discovered_total = candidates.len();
    // --max-targets <N>: keep only the top-N highest-scored candidates before the
    // build/fuzz sweep (candidates are already rank-sorted; the attacking-mode
    // re-sort above is the last sort, so the kept set is the highest-scored).
    // `--list-targets` already returned the FULL ranked list above; this only
    // bounds what gets built/fuzzed, and the kept count is logged — never a silent
    // truncation.
    if let Some(cap) = args.max_targets {
        if candidates.len() > cap {
            eprintln!(
                "govfuzz auto: --max-targets {cap}: keeping the top {cap} of {} ranked target(s) for the sweep",
                candidates.len()
            );
            candidates.truncate(cap);
        } else {
            eprintln!(
                "govfuzz auto: --max-targets {cap}: only {} target(s) discovered; keeping all",
                candidates.len()
            );
        }
    }

    // --campaign-time + --min-target-time: SPLIT mode. Divide the campaign fuzz
    // budget across the (post-`--max-targets`) ranked candidates with a per-target
    // floor — each attempted target gets `max(min, campaign / N)` of fuzz time and
    // only the top `floor(campaign / per_target)` targets are attempted; the rest
    // are dropped (logged, never silent). The split budget OVERRIDES
    // `--per-target-time`, and the wall-clock guillotine is disabled because the
    // attempted-target count × per-target budget already bounds the run.
    let split_mode = match (args.campaign_time, args.min_target_time) {
        (Some(campaign), Some(min)) => {
            let n = candidates.len();
            let (per_target, keep) = plan_campaign_split(
                std::time::Duration::from_secs(campaign),
                std::time::Duration::from_secs(min),
                n,
            );
            eprintln!(
                "govfuzz auto: --campaign-time {campaign}s split across {n} target(s) \
                 (--min-target-time {min}s floor): {per_target_secs}s/target, attempting the \
                 top {keep}, dropping {dropped} below the floor",
                per_target_secs = per_target.as_secs(),
                dropped = n.saturating_sub(keep),
            );
            candidates.truncate(keep);
            options.per_target_time = per_target;
            options.total_time = None; // the split budget IS the per-target total
            true
        }
        _ => false,
    };

    // `--resume`: when discovery hit the cache (target source unchanged), the
    // per-target results from a prior sweep over this work-dir are still valid, so
    // RELOAD targets that already completed (so they are fully re-integrated into
    // this run's report — outcome buckets, repair bags, findings, pass detail)
    // and re-run only the rest. Gated on the cache hit: if the source changed,
    // prior results may be stale, so re-attempt everything.
    let mut resumed_results: Vec<crate::auto::attempt::AttemptResult> = Vec::new();
    if args.resume && discovery_cache_hit {
        candidates.retain(|c| {
            match crate::auto::report::load_resumed_result(&work, &c.harness_id) {
                Some(prior) => {
                    resumed_results.push(prior);
                    false // remove from the to-attempt set
                }
                None => true,
            }
        });
        if resumed_results.is_empty() {
            eprintln!("govfuzz auto: --resume: no completed targets to reload");
        } else {
            eprintln!(
                "govfuzz auto: --resume: reloaded {} completed target(s); re-running {} remaining",
                resumed_results.len(),
                candidates.len()
            );
        }
    } else if args.resume {
        eprintln!(
            "govfuzz auto: --resume: target source changed (discovery cache miss); re-attempting all targets to avoid stale results"
        );
    }
    let resumed = resumed_results.len();

    // Directed fuzzing (--static): run the whole-tree static scan UP FRONT and fuzz
    // the candidates whose file carries a flagged sink FIRST. Under a `--campaign-time`
    // / `--max-targets` cap this steers the budget at the sites that can be
    // fuzz-CONFIRMED, instead of discovering them only after the budget is spent.
    // Stable partition, so rank order is preserved within the sink-bearing and the
    // rest. The post-loop static emit is then skipped (already written).
    let mut static_emitted = false;
    if args.static_scan {
        let n = crate::auto::report_only::emit_tree_static_findings(&path, &work);
        eprintln!("govfuzz auto: --static — static scan wrote {n} finding(s) into the report");
        static_emitted = true;
        let sink_files = crate::auto::confirm::static_finding_files(&work);
        if !sink_files.is_empty() {
            let directed = candidates
                .iter()
                .filter(|c| {
                    c.source_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| sink_files.contains(&n.to_ascii_lowercase()))
                })
                .count();
            candidates.sort_by_key(|c| {
                let hit = c
                    .source_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| sink_files.contains(&n.to_ascii_lowercase()));
                u8::from(!hit) // sink-bearing (false -> 0) sorts first; stable within groups
            });
            if directed > 0 {
                eprintln!(
                    "govfuzz auto: directed fuzzing — {directed} candidate(s) carrying a static-finding sink fuzzed first"
                );
            }
        }
    }

    let total = candidates.len();
    let live_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    // --campaign-time alone: a whole-run wall-clock guillotine measured from
    // `run_start` — once exceeded, stop STARTING new candidates (the in-flight one
    // finishes). In SPLIT mode the per-target budgets already bound the run, so the
    // guillotine is disabled (build/repair overhead must not cut off targets the
    // split intended to fuzz).
    let campaign_deadline = if split_mode {
        None
    } else {
        args.campaign_time
            .map(|secs| run_start + std::time::Duration::from_secs(secs))
    };

    let results = if jobs <= 1 {
        // --jobs 1 (default): the historical serial sweep, byte-identical when no
        // --campaign-time is set (the deadline check is a no-op while None).
        let mut results = Vec::new();
        for (i, candidate) in candidates.into_iter().enumerate() {
            if let Some(deadline) = campaign_deadline {
                if std::time::Instant::now() >= deadline {
                    eprintln!(
                        "govfuzz auto: --campaign-time reached; stopping after {} of {total} target(s)",
                        results.len()
                    );
                    break;
                }
            }
            let prefix = format!(
                "[{:>4}/{:>4}] {} {}",
                i + 1,
                total,
                candidate.harness_id,
                candidate.name
            );
            // On a TTY the progress sink owns the line and rewrites it in
            // place per phase/tick; piped output keeps the historical
            // static "… attempting" line so CI logs are unchanged.
            if !live_tty {
                eprintln!("{prefix} … attempting");
            }
            let progress =
                crate::auto::progress::TerminalProgress::new(prefix.clone(), args.verbose);
            // Catch a govfuzz-internal panic at the per-target boundary: record it
            // in the bug report and keep sweeping instead of aborting the whole run
            // on one malformed input. The panicked target is surfaced as a skip
            // whose reason points at bug-report.json.
            let attempt_ctx = crate::auto::bug_report::IssueContext {
                phase: "attempt".to_owned(),
                file: Some(
                    candidate
                        .source_path
                        .strip_prefix(&path)
                        .unwrap_or(&candidate.source_path)
                        .display()
                        .to_string(),
                ),
                target: Some(candidate.name.clone()),
                language: Some(format!("{:?}", candidate.lang)),
            };
            let result = match crate::auto::bug_report::catch(attempt_ctx, || {
                crate::auto::attempt::attempt_with_progress(
                    &candidate,
                    &work,
                    &idx,
                    options.clone(),
                    &progress,
                )
            }) {
                Ok(inner) => inner?,
                Err(reason) => crate::auto::attempt::AttemptResult {
                    candidate: candidate.clone(),
                    outcome: crate::auto::attempt::Outcome::UnsupportedParams { reason },
                    harness_dir: crate::auto::layout::harness_dir(&work, &candidate.harness_id),
                },
            };
            crate::auto::progress::ProgressSink::clear(&progress);
            eprintln!("{prefix} → {}", outcome_label(&result.outcome));
            if args.verbose {
                for line in verbose_detail(&result.outcome) {
                    eprintln!("    {line}");
                }
            }
            // Persist the full result the moment this target finishes, so a
            // `--resume` run (or one after an interrupt mid-sweep) reloads it.
            crate::auto::report::persist_target_result(&work, &result);
            results.push(result);
        }
        results
    } else {
        run_parallel_sweep(
            candidates,
            total,
            jobs,
            &work,
            &idx,
            &options,
            args.verbose,
            campaign_deadline,
        )?
    };

    // Re-integrate `--resume`-reloaded targets into the report alongside the
    // freshly-attempted ones, restoring discovery (score-descending) order so the
    // combined report reads the same as a single uninterrupted run.
    let mut results = results;
    results.append(&mut resumed_results);
    results.sort_by(|a, b| {
        b.candidate
            .score
            .cmp(&a.candidate.score)
            .then_with(|| a.candidate.harness_id.cmp(&b.candidate.harness_id))
    });

    // --static: run a whole-tree static scan alongside fuzzing, writing its
    // findings BEFORE the report is generated so the loader renders them next to
    // the fuzz findings. Runs regardless of per-target build/fuzz outcomes.
    if (args.static_scan && !static_emitted) || args.external_tools {
        let n = crate::auto::report_only::emit_tree_static_findings(&path, &work);
        eprintln!("govfuzz auto: --static — static scan wrote {n} finding(s) into the report");
    }

    // #486 Phase 3: external static-analysis adapters (gosec/Bandit/semgrep/
    // GNATcheck), subprocess-only and gated by the license profile — strict-
    // permissive (the default) runs none. Their findings merge into the report and
    // the fuzz-confirmation join below.
    if args.external_tools {
        let profile = resolve_license_profile();
        let n = crate::auto::external_tools::run_external_adapters(&path, &work, profile);
        eprintln!(
            "govfuzz auto: --external-tools ({}) — external analyzers wrote {n} finding(s)",
            profile.as_str()
        );
    }

    // MemorySanitizer corpus replay (C): replay the ASan pass's corpus through a
    // separate MSan build to surface uninitialized-memory reads (CWE-457) that
    // ASan/UBSan miss — no second fuzz loop. Runs before the confirmation join so an
    // MSan crash can also confirm a static finding at the same site.
    let msan = crate::auto::msan::run_msan_replay(&work);
    if msan > 0 {
        eprintln!(
            "govfuzz auto: MemorySanitizer — {msan} uninitialized-memory read(s) found by corpus replay"
        );
    }

    // ThreadSanitizer corpus replay (C): replay the ASan pass's corpus through a
    // separate TSan build to surface data races (CWE-362) that ASan/UBSan miss — no
    // second fuzz loop. Only targets that spawn threads per input surface a race.
    let tsan = crate::auto::tsan::run_tsan_replay(&work);
    if tsan > 0 {
        eprintln!("govfuzz auto: ThreadSanitizer — {tsan} data race(s) found by corpus replay");
    }

    // Memory-consumption profile (C/C++): replay the corpus in fresh processes and
    // flag an input whose peak resident set is far above baseline and amplified vs its
    // size — uncontrolled memory consumption (CWE-400) a crash-only fuzzer misses.
    let memfindings = crate::auto::memprofile::run_mem_profile(&work);
    if memfindings > 0 {
        eprintln!(
            "govfuzz auto: memory profile — {memfindings} uncontrolled-consumption input(s) found by corpus replay"
        );
    }

    // JVM sink-reachability oracle: the coverage agent records input-reachable
    // dangerous sinks (deserialization / exec / eval / SQL / LDAP) into each Java
    // harness's sink_report.txt; turn each reached sink into a behavioral finding.
    let jsinks = crate::auto::sink_oracle::run_sink_oracle(&work);
    if jsinks > 0 {
        eprintln!("govfuzz auto: JVM sink oracle — {jsinks} input-reachable sink(s) recorded");
    }

    // COBOL crash attribution: replay each COBOL crash to recover libcob's
    // `<file>.cob:<line>: error: <what>` diagnostic and enrich the generic SIGSEGV
    // finding with the COBOL source site + mapped CWE (out-of-bounds ref-mod →
    // CWE-125, zero divide → CWE-369, size overflow → CWE-190, ...).
    let cobol_attributed = crate::auto::cobol_oracle::run_cobol_attribution(&work);
    if cobol_attributed > 0 {
        eprintln!(
            "govfuzz auto: COBOL attribution — {cobol_attributed} crash(es) mapped to a COBOL runtime error + CWE"
        );
    }

    // Build-recovery provenance (C): for a crash found on a stub-stitched build,
    // rebuild a poisoned variant (`make prov`) in which every value-returning stub
    // aborts on call, and replay the crash's min input. A stub on the crash path ->
    // the crash needed a fabricated value -> `stub_artifact` (demoted to lab_only);
    // the crash reproducing with none on its path -> `real_defect` (confidence
    // raised). Cheap no-op for harnesses with no injected value stubs.
    let prov = crate::auto::provenance::run_stub_provenance(&work, args.mode);
    if prov.total() > 0 {
        eprintln!(
            "govfuzz auto: build-recovery provenance — {} real defect(s) certified, {} crash(es) attributed to a stub artifact",
            prov.real_defects, prov.stub_artifacts
        );
    }

    // Fuzz-driven capability profiling: replay baseline (unstructured) inputs vs the
    // coverage-guided corpus through the shim and diff the OS capabilities each
    // exercised. A capability reached only under structured input is input-triggered
    // attack surface (GF-668) — a map of what an attacker who controls the input can
    // make the program DO, which crash-only fuzzing never reports. Writes
    // `auto/capabilities.json` and one clustered finding per (harness, kind).
    let capabilities = crate::auto::capability::run_capability_profile(&work);
    if capabilities > 0 {
        eprintln!(
            "govfuzz auto: capability profiling — {capabilities} input-triggered capability finding(s) (GF-668)"
        );
    }

    // #484: fuzz-confirmation join. Match static findings (--static / report-only)
    // against the run's runtime crashes + oracle hits by source site; upgrade the
    // ones a fuzz input actually reached to `fuzz_confirmed`. Runs regardless of
    // `--static` because report-only (F-RO-*) findings can be confirmed too. Cheap
    // no-op when there are no static or no runtime findings.
    let confirmed = crate::auto::confirm::confirm_static_findings(&work, args.mode).confirmed;
    if confirmed > 0 {
        eprintln!(
            "govfuzz auto: fuzz-confirmation — {confirmed} static finding(s) confirmed by a fuzz/oracle hit"
        );
    }

    // #486 Phase 2 (reachability downgrade — the mirror of the join): demote a
    // still-`static` finding to `lab_only` when it sits inside a function fuzzing
    // PROVED is not attacker-reachable, so the report deprioritizes it. Built from
    // the attempt results' candidate reachability (the CLI owns that signal).
    let reachability_sites: Vec<crate::auto::confirm::ReachabilitySite> = results
        .iter()
        .filter_map(|result| {
            let non_attacker_reachable = match result.candidate.input_reachability? {
                target_rank::InputReachability::ReachabilityUnproven
                | target_rank::InputReachability::OutputSerializer => true,
                target_rank::InputReachability::AttackerReachable
                | target_rank::InputReachability::IpcChannelReachable => false,
            };
            let basename = result
                .candidate
                .source_path
                .file_name()
                .map(|name| name.to_string_lossy().to_ascii_lowercase())?;
            Some(crate::auto::confirm::ReachabilitySite {
                basename,
                start_line: u64::from(result.candidate.line),
                non_attacker_reachable,
            })
        })
        .collect();
    let demoted = crate::auto::confirm::downgrade_unreachable_static_findings(
        &work,
        &reachability_sites,
        args.mode,
    );
    if demoted > 0 {
        eprintln!(
            "govfuzz auto: reachability — {demoted} static finding(s) demoted to lab_only (not attacker-reachable)"
        );
    }

    // Compiled-lane line coverage for negative confirmation: build a source-coverage
    // variant of each C/C++ harness and replay the corpus to learn which lines the
    // campaign executed (the interpreted lanes get this from their tracers directly).
    crate::auto::coverage_replay::run_coverage_replay(&work);

    // Negative fuzz-confirmation: a static finding whose exact line the fuzzer
    // EXECUTED (recorded in a covered-lines sidecar) yet never crashed/tripped an
    // oracle is marked `fuzz_exercised` — exercised-and-survived, weak FP evidence.
    let exercised = crate::auto::confirm::mark_fuzz_exercised_findings(&work, args.mode);
    if exercised > 0 {
        eprintln!(
            "govfuzz auto: negative confirmation — {exercised} static finding(s) marked fuzz_exercised (line executed, no crash/oracle)"
        );
    }

    // Two-compiler differential (`--differential A:B`): rebuild each C/C++ harness
    // under both compilers and replay the corpus through both, flagging inputs on
    // which their exit/crash behavior diverges (GF-301). Runs last so it sees the
    // finalized corpus and its findings land before the report is written.
    if let Some(spec_str) = args.differential.as_deref() {
        match crate::auto::differential_post::parse_spec(spec_str) {
            Ok(spec) => {
                let diffs = crate::auto::differential_post::run_differential(&work, &spec);
                if diffs > 0 {
                    eprintln!(
                        "govfuzz auto: differential ({}:{}) — {diffs} cross-compiler divergence(s) found by corpus replay (GF-301)",
                        spec.cc_a, spec.cc_b
                    );
                }
            }
            Err(error) => eprintln!("govfuzz auto: --differential ignored: {error}"),
        }
    }

    let finished_at = Utc::now().to_rfc3339();
    write_reports(
        &path,
        &results,
        &work,
        &started_at,
        &finished_at,
        false,
        args.mode,
        resumed,
        discovered_total,
        args.static_dynamic,
        args.force,
    )?;

    // --install-deps: read the just-written manifest and fetch what we can
    // (online, opt-in). Re-run afterward to build against the real deps.
    if args.install_deps {
        let manifest_path = work.join("auto").join("missing-deps.json");
        match std::fs::read_to_string(&manifest_path).ok().and_then(|s| {
            serde_json::from_str::<crate::auto::dep_manifest::DependencyManifest>(&s).ok()
        }) {
            Some(manifest) if !manifest.is_empty() => {
                eprintln!("govfuzz auto: --install-deps — fetching missing dependencies (online)");
                let report = crate::auto::install_deps::run_installs(&manifest);
                eprint!("{}", report.render());
            }
            _ => eprintln!("govfuzz auto: --install-deps — no missing dependencies to fetch"),
        }
    }

    let summary = AutoSummary::collect(
        &path,
        &work,
        args.mode,
        run_start.elapsed(),
        &results,
        resumed,
        discovered_total,
    );

    let rendered = summary.render();
    eprintln!();
    eprint!("{rendered}");
    // Persist the same block next to the reports so it survives the
    // scrollback and can be grepped/attached later.
    let summary_path = work.join("auto").join("summary.txt");
    if let Err(error) = std::fs::write(&summary_path, &rendered) {
        eprintln!(
            "warning: could not write {}: {error}",
            summary_path.display()
        );
    }

    // End-of-run UX: the most severe findings (what matters, with a reproduce command)
    // followed by a next-steps triage (aggregate failure causes → the exact lever),
    // so the operator doesn't have to open run.json / the SARIF to know what to do.
    eprint!("{}", crate::auto::triage::render_top_findings(&work, 8));
    eprint!(
        "{}",
        crate::auto::triage::render_triage(&crate::auto::triage::TriageInputs {
            built_and_fuzzed: summary.built_and_fuzzed,
            failed_build: summary.failed_build,
            skipped: summary.skipped,
            report_only: summary.report_only,
            findings: summary.findings,
            preflight: &preflight,
            custom_build: detect_custom_build(&path),
        })
    );

    // --sbom: emit the evidence-graded SBOM + VEX bundle at campaign end, where
    // FuzzReached evidence is freshest. Over the scanned tree, enriched with this
    // campaign's auto/run.json. Best-effort: a bundle failure must not fail the
    // fuzz run (the campaign already succeeded), so it only warns.
    if args.sbom {
        emit_campaign_sbom(&path, &work);
    }

    // M22 (campaign fix): a 100%-legacy run produces only `report_only` outcomes
    // (discovered + statically analyzed, not fuzzed) — that is a SUCCESSFUL scan,
    // not a failure. Count report-only targets and any emitted finding toward
    // success so CI does not treat every legacy-dialect scan as a hard failure.
    Ok(
        if summary.built + summary.built_and_fuzzed + summary.report_only > 0
            || summary.findings > 0
        {
            0
        } else {
            1
        },
    )
}

/// Emit the `--sbom` bundle for a finished campaign: the scanned tree's
/// components, enriched with this campaign's `auto/run.json` so libraries a
/// harness drove carry `FuzzReached`. Best-effort — warns instead of failing the
/// (already-successful) fuzz run. Writes into `<work>/sbom/`.
fn emit_campaign_sbom(root: &Path, work: &Path) {
    let run_json = work.join("auto").join("run.json");
    let options = governance::SbomOptions {
        root: root.to_path_buf(),
        out_dir: work.join("sbom"),
        run_json: run_json.is_file().then_some(run_json),
        ..Default::default()
    };
    match governance::write_sbom(&options) {
        Ok(summary) => {
            eprintln!(
                "govfuzz auto: --sbom wrote {} component(s), {} vulnerability match(es) to {}",
                summary.components,
                summary.matches,
                options.out_dir.display()
            );
            // An empty SBOM is almost always "no dependency manifests in the
            // scanned path", not a failure — the catalogers read declared
            // dependencies (Cargo.toml, package.json, go.mod, pom.xml/build.gradle,
            // requirements.txt/pyproject, composer.json, *.csproj, vcpkg.json,
            // conanfile). A legacy C/C++/Ada tree with vendored sources declares
            // none. Say so, and note the common footgun of scanning a subdirectory
            // below where the manifests live.
            if summary.components == 0 {
                eprintln!(
                    "govfuzz auto: --sbom found no dependency manifests under {} \
                     (Cargo.toml / package.json / go.mod / pom.xml / requirements.txt / …); \
                     an SBOM catalogs DECLARED dependencies, so a manifest-less tree yields an \
                     empty one. If the manifests live above the scanned path, point govfuzz at \
                     the repository root.",
                    root.display()
                );
            }
        }
        Err(error) => {
            eprintln!("govfuzz auto: --sbom bundle could not be written: {error:#}");
        }
    }
}

/// Discover candidates. Without `--reuse-discovery` this is exactly the prior
/// behavior: a fresh `discover_with_dir_filter` with no cache I/O, no fingerprint
/// walk, and no extra logging (byte-identical default). With `reuse` set, the
/// discovery cache is consulted: on a fingerprint match the ranked list is loaded
/// from `<work>/discovery-cache.json` (skipping the tree-sitter re-parse); on a
/// miss (absent cache, changed tree, or changed dir-filter) discovery runs fresh
/// and the cache is rewritten so the NEXT `--reuse-discovery` run hits. The
/// fingerprint guards correctness — a stale cache is never used silently — and
/// which path was taken is always logged.
fn discover_or_reuse(
    path: &Path,
    dir_filter: &DirFilter,
    work: &Path,
    cache_enabled: bool,
    fresh: bool,
    cache_override: Option<&Path>,
    preprocess: crate::auto::discovery::PreprocessMode,
) -> Result<(Vec<crate::auto::candidate::Candidate>, bool)> {
    // `--no-discovery-cache`: never read or write a cache. (Second tuple element
    // is `cache_hit` — whether the candidate list came from a validated cache, ie
    // the source tree is unchanged; `--resume` only skips completed targets then.)
    if !cache_enabled {
        return Ok((
            crate::auto::discovery::discover_with_options(path, dir_filter, preprocess)?,
            false,
        ));
    }

    use crate::auto::discovery::{discover_with_options, source_fingerprint};
    use crate::auto::discovery_cache::{self, DiscoveryCache};

    // `--discovery-cache <path>` overrides the default `<work>/discovery-cache.json`.
    let cache_file = discovery_cache::resolve_cache_path(work, cache_override);
    // Fold the preprocess mode into the fingerprint: it changes WHICH functions are
    // discovered (and their lines), so a cache built under a different mode must not
    // be reused (§27.6). The base fingerprint stays the content+dir-filter digest.
    let fingerprint = format!("{}-pp:{preprocess}", source_fingerprint(path, dir_filter));
    if fresh {
        eprintln!(
            "govfuzz auto: --fresh-discovery: ignoring any cache at {} and recomputing discovery (fingerprint {fingerprint})",
            cache_file.display()
        );
    } else if let Some(cached) = discovery_cache::load_if_valid(&cache_file, path, &fingerprint) {
        eprintln!(
            "govfuzz auto: discovery loaded from cache {} ({} target(s); source tree unchanged, fingerprint {fingerprint})",
            cache_file.display(),
            cached.len()
        );
        return Ok((cached, true));
    } else {
        // Distinguish WHY it missed so a surprising re-discovery is explainable
        // (absent vs format-version vs fingerprint vs root mismatch).
        let reason = discovery_cache::miss_reason(&cache_file, path, &fingerprint);
        eprintln!(
            "govfuzz auto: discovery cache miss at {} ({reason}); recomputing discovery (fingerprint {fingerprint}). \
             Pass --no-discovery-cache to disable caching.",
            cache_file.display()
        );
    }
    let candidates = discover_with_options(path, dir_filter, preprocess)?;
    // Persist the freshly ranked list for a later --reuse-discovery run. The cache
    // is a re-run optimization, so a write failure is logged, never fatal.
    let cache = DiscoveryCache::build(path, fingerprint, &candidates);
    match discovery_cache::write(&cache_file, &cache) {
        Ok(()) => eprintln!(
            "govfuzz auto: discovery computed ({} target(s)); cache written to {}",
            candidates.len(),
            cache_file.display()
        ),
        Err(error) => eprintln!(
            "govfuzz auto: discovery computed ({} target(s)); could not write discovery cache to {}: {error}",
            candidates.len(),
            cache_file.display()
        ),
    }
    Ok((candidates, false))
}

/// Resolve the per-target fuzz pass set from `--single-pass` / `--passes`.
/// Neither given → all three passes (`Pass::ALL`, unchanged default).
/// `--single-pass` → only the fuzz-driven pass. `--passes empty,rng,fuzz` → the
/// named subset in the given order (deduped); `fuzz` aliases `fuzz_driven`. An
/// unknown name is a hard error so a typo can't silently run the wrong set.
fn resolve_passes(single_pass: bool, passes: Option<&str>) -> Result<Vec<crate::auto::pass::Pass>> {
    use crate::auto::pass::Pass;
    if single_pass {
        return Ok(vec![Pass::FuzzDriven]);
    }
    let Some(spec) = passes else {
        return Ok(Pass::ALL.to_vec());
    };
    let mut out: Vec<Pass> = Vec::new();
    for raw in spec.split(',') {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let pass = match name.to_ascii_lowercase().as_str() {
            "empty" => Pass::Empty,
            "rng" => Pass::Rng,
            "fuzz" | "fuzz_driven" | "fuzzdriven" | "fuzz-driven" => Pass::FuzzDriven,
            other => anyhow::bail!(
                "unknown --passes name '{other}' (valid: empty, rng, fuzz/fuzz_driven)"
            ),
        };
        if !out.contains(&pass) {
            out.push(pass);
        }
    }
    if out.is_empty() {
        anyhow::bail!("--passes parsed to an empty set; give a comma list like 'empty,rng,fuzz'");
    }
    Ok(out)
}

/// Run the cross-candidate sweep with up to `jobs` candidates built+fuzzed
/// concurrently (used only for `--jobs > 1`; `--jobs 1` keeps the serial loop in
/// `run_inner`). A bounded pool of `jobs` scoped threads pulls candidates off a
/// shared atomic cursor; results land in position-indexed slots so aggregation
/// is deterministic regardless of completion order. Per-candidate work is already
/// isolated by `harness_id` (`<work>/harnesses/<id>/`, `<work>/corpus/<id>/`) and env
/// is threaded per child `Command` (no process-global `set_var`), so the only
/// shared state is the (immutable) declaration index and the stderr lock.
///
/// Parallel mode uses the no-op progress sink and static per-candidate lines:
/// the in-place TTY progress rewrites a single owned line, which concurrent
/// workers would corrupt. `campaign_deadline`, when set, stops handing out new
/// candidates (in-flight ones finish).
#[allow(clippy::too_many_arguments)]
fn run_parallel_sweep(
    candidates: Vec<crate::auto::candidate::Candidate>,
    total: usize,
    jobs: usize,
    work: &Path,
    idx: &DeclarationIndex,
    options: &AttemptOptions,
    verbose: bool,
    campaign_deadline: Option<std::time::Instant>,
) -> Result<Vec<crate::auto::attempt::AttemptResult>> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    let n = candidates.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    // Position-indexed slots: deterministic aggregation no matter which worker
    // finishes first (report order matches the ranked order).
    let slots: Mutex<Vec<Option<Result<crate::auto::attempt::AttemptResult>>>> =
        Mutex::new((0..n).map(|_| None).collect());
    let cursor = AtomicUsize::new(0);
    let reached = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    let stderr_lock = Mutex::new(());
    let worker_count = jobs.min(n);

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| loop {
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                if let Some(deadline) = campaign_deadline {
                    if std::time::Instant::now() >= deadline {
                        stopped.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                let i = cursor.fetch_add(1, Ordering::SeqCst);
                if i >= n {
                    break;
                }
                let candidate = &candidates[i];
                let prefix = format!(
                    "[{:>4}/{:>4}] {} {}",
                    i + 1,
                    total,
                    candidate.harness_id,
                    candidate.name
                );
                {
                    let _g = stderr_lock.lock().unwrap();
                    eprintln!("{prefix} … attempting");
                }
                // NoProgress sink (via `attempt`): concurrent in-place TTY line
                // rewrites would corrupt the terminal, so use static lines.
                // Catch a per-target govfuzz-internal panic (recorded in the bug
                // report) so one bad input doesn't kill the whole parallel sweep.
                let attempt_ctx = crate::auto::bug_report::IssueContext {
                    phase: "attempt".to_owned(),
                    file: Some(candidate.source_path.display().to_string()),
                    target: Some(candidate.name.clone()),
                    language: Some(format!("{:?}", candidate.lang)),
                };
                let synth_candidate = candidate.clone();
                let result = match crate::auto::bug_report::catch(attempt_ctx, || {
                    crate::auto::attempt::attempt(candidate, work, idx, options.clone())
                }) {
                    Ok(inner) => inner,
                    Err(reason) => Ok(crate::auto::attempt::AttemptResult {
                        candidate: synth_candidate.clone(),
                        outcome: crate::auto::attempt::Outcome::UnsupportedParams { reason },
                        harness_dir: crate::auto::layout::harness_dir(
                            work,
                            &synth_candidate.harness_id,
                        ),
                    }),
                };
                {
                    let _g = stderr_lock.lock().unwrap();
                    match &result {
                        Ok(r) => {
                            eprintln!("{prefix} → {}", outcome_label(&r.outcome));
                            if verbose {
                                for line in verbose_detail(&r.outcome) {
                                    eprintln!("    {line}");
                                }
                            }
                        }
                        Err(error) => eprintln!("{prefix} → error: {error:#}"),
                    }
                }
                reached.fetch_add(1, Ordering::SeqCst);
                slots.lock().unwrap()[i] = Some(result);
            });
        }
    });

    let done = reached.load(Ordering::SeqCst);
    if done < n {
        eprintln!(
            "govfuzz auto: --campaign-time reached; stopped after {done} of {total} target(s)"
        );
    }

    // Collect in index order; propagate the first error (serial fail-fast parity).
    let mut results = Vec::with_capacity(done);
    for slot in slots.into_inner().unwrap() {
        match slot {
            Some(Ok(r)) => {
                crate::auto::report::persist_target_result(work, &r);
                results.push(r);
            }
            Some(Err(error)) => return Err(error),
            // Not reached (campaign-time cutoff): omit, like the serial break.
            None => {}
        }
    }
    Ok(results)
}

/// Aggregate end-of-run statistics for the human summary printed to the
/// terminal and written to `<work>/auto/summary.txt`. `auto` otherwise
/// ends on the last per-target line, leaving the run's shape (how long it
/// took, what built, what languages, where the outputs are) invisible.
struct AutoSummary {
    source: PathBuf,
    work: PathBuf,
    mode: actionability::RunMode,
    duration: std::time::Duration,
    discovered: usize,
    /// #6: total ranked candidates BEFORE any `--max-targets` / campaign-split
    /// cap. Equals `discovered` for an uncapped run; larger when a cap dropped
    /// lower-ranked targets from the sweep.
    discovered_total: usize,
    /// `--resume`: targets skipped because they completed in a prior sweep.
    resumed: usize,
    built_and_fuzzed: usize,
    /// #417: of `built_and_fuzzed`, the FALSE-CLEAN subset whose harness fuzzed
    /// only blind stubs and never the real library. Surfaced distinctly in the
    /// terminal summary so the run's headline count isn't misread.
    fuzzed_stub_only: usize,
    built: usize,
    skipped: usize,
    failed_build: usize,
    link_errors: usize,
    runtime_errors: usize,
    /// M22: targets discovered + statically analyzed but not fuzzed.
    report_only: usize,
    findings: usize,
    /// Total built-in fuzz executions across every pass and target.
    executions: usize,
    /// #405: total measured fuzz wall (seconds) summed across every pass and
    /// target — the denominator for the campaign-level exec/s figure. NOT the
    /// run duration (which includes discovery/build/repair).
    total_elapsed_secs: f64,
    /// Peak edge coverage any target reached (#385); 0 when no harness carried a
    /// coverage runtime.
    coverage_edges: usize,
    files_fuzzed: usize,
    files_with_targets: usize,
    /// (language, targets, built) in a stable order, languages with
    /// zero discovered targets omitted.
    per_language: Vec<(&'static str, usize, usize)>,
}

impl AutoSummary {
    #[allow(clippy::too_many_arguments)]
    fn collect(
        source: &Path,
        work: &Path,
        mode: actionability::RunMode,
        duration: std::time::Duration,
        results: &[crate::auto::attempt::AttemptResult],
        resumed: usize,
        discovered_total: usize,
    ) -> Self {
        use crate::auto::attempt::Outcome::*;
        use crate::auto::candidate::Lang;
        use std::collections::BTreeSet;

        let is_built =
            |o: &crate::auto::attempt::Outcome| matches!(o, Built { .. } | BuiltAndFuzzed { .. });

        let mut built_and_fuzzed = 0;
        let mut fuzzed_stub_only = 0;
        let mut built = 0;
        let mut skipped = 0;
        let mut failed_build = 0;
        let mut link_errors = 0;
        let mut runtime_errors = 0;
        let mut report_only = 0;
        let mut findings = 0;
        let mut executions = 0;
        let mut total_elapsed_secs = 0.0;
        let mut coverage_edges = 0;
        let mut files_with_targets: BTreeSet<&Path> = BTreeSet::new();
        let mut files_fuzzed: BTreeSet<&Path> = BTreeSet::new();

        for r in results {
            files_with_targets.insert(r.candidate.source_path.as_path());
            match &r.outcome {
                BuiltAndFuzzed { passes, .. } => {
                    built_and_fuzzed += 1;
                    // #417: track the false-clean subset for the summary line.
                    if r.outcome.stub_execution().is_some_and(|se| se.stub_only) {
                        fuzzed_stub_only += 1;
                    }
                    findings += passes.iter().map(|p| p.findings.len()).sum::<usize>();
                    executions += passes.iter().map(|p| p.executions).sum::<usize>();
                    // #405: accumulate measured fuzz wall so the campaign exec/s
                    // is executions ÷ Σelapsed (true throughput), not divided by
                    // the wall budget that overstates available time.
                    total_elapsed_secs += passes.iter().map(|p| p.elapsed_secs).sum::<f64>();
                    // Coverage accumulates across a target's passes, so the
                    // largest per-pass value is that target's total; take the peak
                    // across all targets for the rollup.
                    coverage_edges = coverage_edges
                        .max(passes.iter().map(|p| p.coverage_edges).max().unwrap_or(0));
                }
                Built { .. } => built += 1,
                UnsupportedParams { .. } => skipped += 1,
                FailedBuild { .. } => failed_build += 1,
                UnrecoverableLink { .. } => link_errors += 1,
                UnrecoverableRuntime { .. } => runtime_errors += 1,
                ReportOnly {
                    static_findings, ..
                } => {
                    report_only += 1;
                    // M22 (campaign fix): report-only static findings are real
                    // CWE-tagged findings — surface them in the headline count.
                    findings += static_findings;
                }
            }
            if is_built(&r.outcome) {
                files_fuzzed.insert(r.candidate.source_path.as_path());
            }
        }
        // `--static`: whole-tree static findings live in the findings dir (not on
        // any result) — fold their count into the headline total shown on the CLI.
        findings += crate::auto::report::tree_static_finding_ids(work).len();

        let per_language = [(Lang::Ada, "Ada"), (Lang::C, "C"), (Lang::Cpp, "C++")]
            .into_iter()
            .filter_map(|(lang, name)| {
                let targets = results.iter().filter(|r| r.candidate.lang == lang).count();
                if targets == 0 {
                    return None;
                }
                let built = results
                    .iter()
                    .filter(|r| r.candidate.lang == lang && is_built(&r.outcome))
                    .count();
                Some((name, targets, built))
            })
            .collect();

        Self {
            source: source.to_path_buf(),
            work: work.to_path_buf(),
            mode,
            duration,
            discovered: results.len(),
            discovered_total: discovered_total.max(results.len()),
            resumed,
            executions,
            total_elapsed_secs,
            coverage_edges,
            built_and_fuzzed,
            fuzzed_stub_only,
            built,
            skipped,
            failed_build,
            link_errors,
            runtime_errors,
            report_only,
            findings,
            files_fuzzed: files_fuzzed.len(),
            files_with_targets: files_with_targets.len(),
            per_language,
        }
    }

    /// The full human block, terminated by a newline. Used verbatim for
    /// both the terminal print and `summary.txt`.
    fn render(&self) -> String {
        use std::fmt::Write;
        let auto_dir = crate::auto::layout::reports_dir(&self.work);
        let harness_root = crate::auto::layout::harness_root(&self.work);
        let mut s = String::new();

        let _ = writeln!(s, "GovFuzz auto summary");
        let _ = writeln!(s, "  Source:       {}", self.source.display());
        let _ = writeln!(s, "  Mode:         {}", self.mode.as_str());
        let _ = writeln!(s, "  Duration:     {}", fmt_duration(self.duration));

        // Outcome breakdown — omit zero categories so the line stays short.
        // #417: when some "built+fuzzed" targets were STUB-ONLY false cleans,
        // annotate the count inline so the headline figure is never misread.
        let mut outcomes = if self.fuzzed_stub_only > 0 {
            vec![format!(
                "{} built+fuzzed ({} STUB-ONLY)",
                self.built_and_fuzzed, self.fuzzed_stub_only
            )]
        } else {
            vec![format!("{} built+fuzzed", self.built_and_fuzzed)]
        };
        if self.built > 0 {
            outcomes.push(format!("{} built", self.built));
        }
        if self.skipped > 0 {
            outcomes.push(format!("{} skipped", self.skipped));
        }
        if self.failed_build > 0 {
            outcomes.push(format!("{} failed build", self.failed_build));
        }
        if self.link_errors > 0 {
            outcomes.push(format!("{} link error", self.link_errors));
        }
        if self.runtime_errors > 0 {
            outcomes.push(format!("{} runtime error", self.runtime_errors));
        }
        if self.report_only > 0 {
            outcomes.push(format!("{} static-only", self.report_only));
        }
        let resumed_note = if self.resumed > 0 {
            format!(" ({} resumed, skipped)", self.resumed)
        } else {
            String::new()
        };
        // #6: when a cap dropped lower-ranked targets, annotate the discovered
        // count so the swept figure is never read as the full discovered set.
        let dropped_by_cap = self.discovered_total.saturating_sub(self.discovered);
        let cap_note = if dropped_by_cap > 0 {
            format!(
                " (of {} ranked, {dropped_by_cap} dropped by cap)",
                self.discovered_total
            )
        } else {
            String::new()
        };
        let _ = writeln!(
            s,
            "  Targets:      {} discovered{cap_note}{resumed_note} — {}",
            self.discovered,
            outcomes.join(", ")
        );
        let _ = writeln!(
            s,
            "  Source files: {} fuzzed / {} with targets",
            self.files_fuzzed, self.files_with_targets
        );
        let langs: Vec<String> = self
            .per_language
            .iter()
            .map(|(name, targets, built)| format!("{name} {targets} ({built} built)"))
            .collect();
        if !langs.is_empty() {
            let _ = writeln!(s, "  Languages:    {}", langs.join(", "));
        }
        let _ = writeln!(s, "  Findings:     {}", self.findings);
        let _ = writeln!(s, "  Executions:   {}", self.executions);
        // #405: campaign throughput — executions ÷ measured fuzz wall. Shown
        // only when some wall was measured (a no-fuzz reporting run has none).
        if self.total_elapsed_secs > 0.0 {
            let _ = writeln!(
                s,
                "  Throughput:   {:.0} exec/s",
                self.executions as f64 / self.total_elapsed_secs
            );
        }
        if self.coverage_edges > 0 {
            let _ = writeln!(s, "  Coverage:     {} edges", self.coverage_edges);
        }
        // #417: loud false-clean warning. A stub-only target reports clean while
        // having fuzzed only empty stubs, so call it out explicitly here.
        if self.fuzzed_stub_only > 0 {
            let _ = writeln!(
                s,
                "  ⚠ WARNING:    {} target(s) fuzzed STUB-ONLY (blind stubs, no real library \
                 code) — a clean result there is a FALSE CLEAN; see run.md / run.json \
                 stub_execution",
                self.fuzzed_stub_only
            );
        }

        let _ = writeln!(s);
        let _ = writeln!(s, "Output:");
        let _ = writeln!(s, "  report:    {}", auto_dir.join("run.md").display());
        let _ = writeln!(s, "             {}", auto_dir.join("run.json").display());
        let _ = writeln!(s, "  harnesses: {}/<harness-id>/", harness_root.display());
        if self.findings > 0 {
            let _ = writeln!(s, "  findings:  {}/", self.work.join("findings").display());
        }
        let _ = writeln!(s, "  summary:   {}", auto_dir.join("summary.txt").display());
        s
    }
}

/// `2m 14s` for a minute or more, `14.3s` below that.
fn fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

/// Print the ranked discovery candidates for `--list-targets`: what `auto` would
/// harness, best-first, with the signals behind the ranking (language, whether the
/// input is attacker-reachable, file:line) so the entry-point choice can be judged
/// at a glance without building anything.
fn print_ranked_targets(candidates: &[crate::auto::candidate::Candidate], root: &Path) {
    use crate::auto::candidate::Lang;
    use target_rank::InputReachability;
    println!(
        "# govfuzz auto: {} ranked target(s) under {} (highest score first; no build)",
        candidates.len(),
        root.display()
    );
    println!(
        "{:>4}  {:>6}  {:<4}  {:<18}  {:<32}  file:line",
        "rank", "score", "lang", "reachability", "target"
    );
    for (i, c) in candidates.iter().enumerate() {
        let lang = match c.lang {
            Lang::C => "C",
            Lang::Cpp => "C++",
            Lang::Ada => "Ada",
            Lang::Rust => "Rust",
            Lang::Java => "Java",
            Lang::Python => "Py",
            Lang::Perl => "Perl",
            Lang::Go => "Go",
            Lang::Cobol => "COBOL",
            Lang::Fortran => "Fortran",
            Lang::CSharp => "C#",
            Lang::Js => "JS",
        };
        let reach = match c.input_reachability {
            Some(InputReachability::AttackerReachable) => "attacker-reachable",
            Some(InputReachability::OutputSerializer) => "output/serializer",
            Some(InputReachability::ReachabilityUnproven) => "unproven",
            // Dynamic (post-run) — never set at discovery, so --list-targets
            // (a no-build listing) won't show it, but the match must be exhaustive.
            Some(InputReachability::IpcChannelReachable) => "ipc-channel",
            None => "-",
        };
        let rel = c.source_path.strip_prefix(root).unwrap_or(&c.source_path);
        println!(
            "{:>4}  {:>6}  {:<4}  {:<18}  {:<32}  {}:{}",
            i + 1,
            c.score,
            lang,
            reach,
            c.name,
            rel.display(),
            c.line
        );
    }
}

fn normalize_target_file_filter(root: &Path, target_file: &Path) -> PathBuf {
    let path = if target_file.is_absolute() {
        target_file.to_path_buf()
    } else {
        root.join(target_file)
    };
    path.canonicalize().unwrap_or(path)
}

/// Collect the `--languages` selectors into the internal [`Lang`] set used to
/// filter candidates. Deduplicates (`--languages c,c` is one entry).
fn selected_lang_set(
    selectors: &[crate::auto::candidate::LangSelector],
) -> std::collections::HashSet<crate::auto::candidate::Lang> {
    selectors
        .iter()
        .map(|selector| selector.to_lang())
        .collect()
}

/// Drop every candidate whose language is not in `selected`, in place. Returns
/// `(kept, dropped)`. An empty `selected` is a no-op (the default: fuzz every
/// language found) — but callers gate on `args.languages.is_empty()` first, so
/// this is only reached with a non-empty set.
fn retain_languages(
    candidates: &mut Vec<crate::auto::candidate::Candidate>,
    selected: &std::collections::HashSet<crate::auto::candidate::Lang>,
) -> (usize, usize) {
    if selected.is_empty() {
        return (candidates.len(), 0);
    }
    let before = candidates.len();
    candidates.retain(|candidate| selected.contains(&candidate.lang));
    let kept = candidates.len();
    (kept, before - kept)
}

/// Render the selected language canonical names for the filter log line, in the
/// stable enum order (not the order given on the command line) and deduplicated,
/// so the message reads the same regardless of how the operator spelled them.
fn render_selected_langs(selectors: &[crate::auto::candidate::LangSelector]) -> String {
    use crate::auto::candidate::Lang;
    let selected = selected_lang_set(selectors);
    const ORDER: &[(Lang, &str)] = &[
        (Lang::Ada, "ada"),
        (Lang::C, "c"),
        (Lang::Cpp, "cpp"),
        (Lang::Rust, "rust"),
        (Lang::Java, "java"),
        (Lang::Python, "python"),
        (Lang::Perl, "perl"),
        (Lang::Go, "go"),
    ];
    ORDER
        .iter()
        .filter(|(lang, _)| selected.contains(lang))
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn target_name_filter_matches(candidate_name: &str, selected: &str) -> bool {
    if candidate_name == selected {
        return true;
    }
    if candidate_name.starts_with(&format!("{selected}(")) {
        return true;
    }
    candidate_name.rsplit_once("::").is_some_and(|(_, simple)| {
        simple == selected || simple.starts_with(&format!("{selected}("))
    })
}

fn sort_attacking_candidates(
    candidates: &mut [crate::auto::candidate::Candidate],
    mut read_source: impl FnMut(&Path) -> String,
) {
    let mut source_cache: BTreeMap<PathBuf, String> = BTreeMap::new();
    candidates.sort_by_cached_key(|candidate| {
        let source = source_cache
            .entry(candidate.source_path.clone())
            .or_insert_with(|| read_source(&candidate.source_path));
        (
            Reverse(actionability::attacking_target_score(
                candidate.score,
                source,
                &candidate.name,
            )),
            candidate.name.clone(),
            candidate.source_path.clone(),
            candidate.line,
            candidate.harness_id.clone(),
        )
    });
}

/// The single human-facing label for a target outcome, shared by the
/// live progress line and `run.md` so the two never drift. The machine
/// `run.json` `outcome` tag is separate (serde `rename_all = snake_case`)
/// and stays stable for tooling — e.g. `unsupported_params` there vs.
/// `skipped: could not auto-harness` here.
pub(crate) fn outcome_label(o: &crate::auto::attempt::Outcome) -> &'static str {
    use crate::auto::attempt::Outcome::*;
    match o {
        Built { .. } => "built",
        // #417: a fuzz that only exercised blind stubs is a FALSE CLEAN — give it
        // a distinct human label so the live progress line and run.md never read
        // it as a real built+fuzzed campaign. (The machine `outcome` tag stays
        // `built_and_fuzzed`; the structured signal is run.json `stub_execution`.)
        BuiltAndFuzzed { .. } if o.stub_execution().is_some_and(|se| se.stub_only) => {
            "built+fuzzed (STUB-ONLY)"
        }
        BuiltAndFuzzed { .. } => "built+fuzzed",
        FailedBuild { .. } => "failed_build",
        // A deliberate skip, not a missing feature or a bad input: auto
        // could not synthesise a fuzz harness for this function's
        // signature (e.g. a function-pointer or opaque-userdata param it
        // can't drive from a byte buffer).
        UnsupportedParams { .. } => "skipped: could not auto-harness",
        UnrecoverableLink { .. } => "unrecoverable_link",
        UnrecoverableRuntime { .. } => "unrecoverable_runtime",
        // M22: discovered + statically analyzed, not fuzzed.
        ReportOnly { .. } => "static-only (not fuzzed)",
    }
}

/// Extra indented lines printed under `--verbose` for one target. Each
/// returned string is one line, without the leading indent the caller
/// adds. Surfaces the reason auto skipped or failed a target, the
/// repairs it applied, and per-pass execution/finding counts — the
/// "what just happened" a human watching the sweep wants.
fn verbose_detail(outcome: &crate::auto::attempt::Outcome) -> Vec<String> {
    use crate::auto::attempt::Outcome::*;
    let mut lines = Vec::new();
    match outcome {
        BuiltAndFuzzed {
            repairs, passes, ..
        } => {
            if let Some(summary) = summarize_repairs(repairs) {
                lines.push(format!("repairs: {summary}"));
            }
            let passes = summarize_passes(passes);
            if !passes.is_empty() {
                lines.push(passes);
            }
        }
        Built { repairs, .. } => {
            if let Some(summary) = summarize_repairs(repairs) {
                lines.push(format!("repairs: {summary}"));
            }
        }
        FailedBuild { last_errors, .. } => {
            if let Some(err) = last_errors.last() {
                lines.push(format!("last error: {}", build_error_brief(err)));
            }
        }
        UnsupportedParams { reason } => lines.push(reason.clone()),
        UnrecoverableLink { missing, .. } => {
            if !missing.is_empty() {
                lines.push(format!("missing libraries: {}", missing.join(", ")));
            }
        }
        UnrecoverableRuntime {
            reason,
            consecutive_crashes,
            ..
        } => lines.push(format!(
            "{reason} (after {consecutive_crashes} consecutive crash(es))"
        )),
        ReportOnly {
            reason,
            dialect,
            static_findings,
            ..
        } => {
            let dia = dialect
                .as_deref()
                .and_then(lang_profile::Dialect::from_str)
                .map(|d| format!(" [{}]", d.label()))
                .unwrap_or_default();
            lines.push(format!("not fuzzed{dia}: {reason}"));
            if *static_findings > 0 {
                lines.push(format!("static findings: {static_findings}"));
            }
        }
    }
    lines
}

fn summarize_passes(passes: &[crate::auto::attempt::PassRun]) -> String {
    passes
        .iter()
        .map(|pr| {
            format!(
                "{}={}ex/{}f",
                pr.pass.as_str(),
                pr.executions,
                pr.findings.len()
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Dependency-crate source directories that Alire has already cached on local
/// disk for this project (from a prior `alr build`). Read-only filesystem
/// discovery — nothing is fetched — so air-gapped/offline use is unaffected;
/// when no cache exists this returns empty and behavior is unchanged. Walks up
/// from the scanned root to a project that has an `alire/` tree.
fn discover_local_alire_dep_dirs(scanned: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dir = scanned;
    let mut project_manifest: Option<PathBuf> = None;
    for _ in 0..8 {
        let manifest = dir.join("alire.toml");
        if project_manifest.is_none() && manifest.is_file() {
            project_manifest = Some(manifest);
        }
        // Alire vendors deps under alire/cache/dependencies/<crate>/ (and, in
        // newer layouts, alire/build/<crate>/) when `alr build` ran in-tree.
        for sub in ["alire/cache/dependencies", "alire/build"] {
            let cache = dir.join(sub);
            let Ok(entries) = std::fs::read_dir(&cache) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Ok(canon) = path.canonicalize() {
                        if !out.contains(&canon) {
                            out.push(canon);
                        }
                    }
                }
            }
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    // Resolve the crates the project declares in its `alire.toml` (transitively)
    // against the per-user global Alire cache, where `alr` materializes fetched
    // crates shared across projects. This is the dominant real-world Ada blocker:
    // a project that `with`s an external crate (usb_embedded's `hal`/`bbqueue`)
    // builds only once those crate sources are on the path. Read-only discovery —
    // nothing is fetched — so a machine that has run `alr` even once for any
    // project, or has a populated cache, resolves the deps offline; with no cache
    // this adds nothing and behavior is unchanged.
    if let Some(manifest) = project_manifest {
        let deps = parse_alire_dep_names(&manifest);
        if !deps.is_empty() {
            for resolved in resolve_deps_against_caches(&deps, &alire_global_cache_roots()) {
                if !out.contains(&resolved) {
                    out.push(resolved);
                }
            }
        }
    }
    out
}

/// Crate names that are toolchains/build tools, not library dependencies to put
/// on the source path (they have no fuzzable Ada source to add).
fn is_alire_toolchain_crate(name: &str) -> bool {
    matches!(
        name,
        "gnat" | "gnat_native" | "gnat_external" | "gprbuild" | "gnatcov" | "gnatprove"
    )
}

/// Parse the library crate names a project depends on from its `alire.toml`
/// `[[depends-on]]` / `[depends-on]` tables. Toolchain crates (gnat, gprbuild)
/// are excluded — they are compilers, not source dependencies. Returns lowercase
/// crate names. Read-only; an unreadable manifest yields an empty list.
///
/// A small hand scanner rather than a TOML parser: only the crate *keys* inside
/// `depends-on` tables are needed, and pulling a TOML crate into the production
/// dependency tree would require a license-matrix entry for no real gain.
fn parse_alire_dep_names(alire_toml: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(alire_toml) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    let mut in_depends = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            // `[depends-on]` and `[[depends-on]]` both reduce to "depends-on".
            let header = line.trim_matches('[').trim_matches(']').trim();
            in_depends = header == "depends-on";
            continue;
        }
        if in_depends {
            if let Some((key, _)) = line.split_once('=') {
                let key = key.trim().trim_matches('"');
                if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    let lower = key.to_ascii_lowercase();
                    if !is_alire_toolchain_crate(&lower) {
                        names.insert(lower);
                    }
                }
            }
        }
    }
    names.into_iter().collect()
}

/// Whether a cache directory name (`hal_1.0.0_<hash>`, `hal_1.0.0`, or `hal`)
/// belongs to crate `crate_name`. The version segment after `<crate>_` must
/// start with a digit, so `hal_helper_1.0` is not mistaken for `hal`.
fn alire_dir_is_crate(dir_name: &str, crate_name: &str) -> bool {
    let dir = dir_name.to_ascii_lowercase();
    if dir == crate_name {
        return true;
    }
    dir.strip_prefix(crate_name)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(|version| version.starts_with(|ch: char| ch.is_ascii_digit()))
}

/// Resolve the named crates (and, transitively, their own dependencies) to local
/// crate source directories found in `cache_roots`. Read-only filesystem
/// discovery — nothing is fetched. Each resolved crate's own `alire.toml` is read
/// to follow transitive dependencies, so a single direct dependency pulls in its
/// whole resolved closure when those crates are present in the cache.
fn resolve_deps_against_caches(initial_deps: &[String], cache_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut frontier: Vec<String> = initial_deps.to_vec();

    // Bounded BFS over the dependency closure (guards against a cyclic manifest
    // graph). Each round resolves the new crate names against every cache root,
    // then enqueues the transitive dependencies declared by the crates found.
    for _ in 0..16 {
        frontier.retain(|name| seen.insert(name.clone()));
        if frontier.is_empty() {
            break;
        }
        let mut next: Vec<String> = Vec::new();
        for root in cache_roots {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !frontier
                    .iter()
                    .any(|crate_name| alire_dir_is_crate(dir_name, crate_name))
                {
                    continue;
                }
                let canon = path.canonicalize().unwrap_or(path);
                if !out.contains(&canon) {
                    out.push(canon.clone());
                }
                // Follow the resolved crate's own dependencies.
                let manifest = canon.join("alire.toml");
                if manifest.is_file() {
                    next.extend(parse_alire_dep_names(&manifest));
                }
            }
        }
        frontier = next;
    }
    out
}

/// The per-user global Alire cache roots where `alr` materializes fetched crate
/// sources shared across projects. Covers the `ALIRE_SETTINGS_DIR` override and
/// the standard per-user locations, each in both the `cache/dependencies` (alr
/// 1.x) and `builds` (alr 2.x) layouts.
fn alire_global_cache_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut add_base = |base: PathBuf| {
        // alr 2.x materializes fetched crate *source* under cache/releases/ and
        // build artifacts under cache/builds/; alr 1.x used cache/dependencies/
        // and a top-level builds/. Search all so any installed alr version
        // resolves.
        let cache = base.join("cache");
        roots.push(cache.join("releases"));
        roots.push(cache.join("dependencies"));
        roots.push(cache.join("builds"));
        roots.push(base.join("builds"));
    };
    if let Some(dir) = std::env::var_os("ALIRE_SETTINGS_DIR") {
        add_base(PathBuf::from(dir));
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in [
            ".config/alire",
            ".local/share/alire",
            ".alire",
            ".cache/alire",
        ] {
            add_base(home.join(sub));
        }
    }
    roots
}

/// Count repairs by kind into a compact phrase, e.g.
/// `synthesized 1 header, stubbed 2 symbols`. Returns `None` when no
/// repairs were applied so the caller can omit the line entirely.
fn summarize_repairs(repairs: &[crate::auto::repair::Repair]) -> Option<String> {
    use crate::auto::repair::Repair::*;
    if repairs.is_empty() {
        return None;
    }
    let (
        mut headers,
        mut types,
        mut macros,
        mut symbols,
        mut sources,
        mut envs,
        mut ada,
        mut incdirs,
        mut platforms,
    ) = (0, 0, 0, 0, 0, 0, 0, 0, 0);
    for repair in repairs {
        match repair {
            HeaderPlaceholder { .. } | ConfigHeaderSynth { .. } => headers += 1,
            AddIncludeDir { .. } => incdirs += 1,
            TypePlaceholder { .. } | TypeAlias { .. } | ConfigTypeAlias { .. } => types += 1,
            MacroDefine { .. } | IncludeStdHeader { .. } => macros += 1,
            StubDeclared { .. } | StubBlind { .. } => symbols += 1,
            AddSource { .. } | AddAdaSource { .. } => sources += 1,
            EnvVarInjection { .. } => envs += 1,
            AdaPackageStub { .. } | AdaPackageBodyStub { .. } | OverrideAdaBodyStub { .. } => {
                ada += 1
            }
            PlatformStub { .. } | Win32Pack => platforms += 1,
        }
    }
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let mut parts = Vec::new();
    if headers > 0 {
        parts.push(format!("synthesized {headers} header{}", plural(headers)));
    }
    if incdirs > 0 {
        parts.push(format!("resolved {incdirs} header dir{}", plural(incdirs)));
    }
    if types > 0 {
        parts.push(format!("synthesized {types} type{}", plural(types)));
    }
    if macros > 0 {
        parts.push(format!("defined {macros} macro{}", plural(macros)));
    }
    if symbols > 0 {
        parts.push(format!("stubbed {symbols} symbol{}", plural(symbols)));
    }
    if sources > 0 {
        parts.push(format!("added {sources} source{}", plural(sources)));
    }
    if envs > 0 {
        parts.push(format!("injected {envs} env var{}", plural(envs)));
    }
    if ada > 0 {
        parts.push(format!("stubbed {ada} Ada unit{}", plural(ada)));
    }
    if platforms > 0 {
        parts.push(format!(
            "stub-isolated {platforms} platform{}",
            plural(platforms)
        ));
    }
    Some(parts.join(", "))
}

fn build_error_brief(err: &build_classifier::BuildErrorKind) -> String {
    use build_classifier::BuildErrorKind::*;
    match err {
        MissingHeader { path } => format!("missing header '{path}'"),
        MissingType { name } => format!("unknown type '{name}'"),
        IncompleteType { name } => format!("incomplete type '{name}' (definition unavailable)"),
        MissingMacro { name, .. } => format!("undefined build-config macro '{name}'"),
        UndefinedSymbol { name } => format!("undefined symbol '{name}'"),
        MissingSharedLib { name } => format!("missing shared library '{name}'"),
        MissingAdaWith { unit } => format!("missing Ada unit '{unit}'"),
        MissingAdaSymbol { unit, symbol } => format!("missing Ada symbol '{unit}.{symbol}'"),
        MissingAdaPackageBody { unit } => format!("missing Ada package body '{unit}'"),
        UncompilableAdaBody { source } => format!("uncompilable Ada body '{source}'"),
        MalformedFunctionDecl { file, line } => {
            format!("malformed function declaration (body-less declarator) at {file}:{line}")
        }
        MissingGprImport { path } => format!("missing GPR import '{path}'"),
        Other { tail } => {
            // The tail is the last few lines of build output. GNAT prints
            // warnings before the fatal error, so the first tail line is often
            // a harmless warning (e.g. "unit X is not referenced") that masks
            // the real cause. Prefer the first line that names an error.
            let pick = tail
                .lines()
                .find(|line| {
                    let l = line.to_ascii_lowercase();
                    l.contains("error:") || l.contains("fatal error")
                })
                .or_else(|| tail.lines().next())
                .unwrap_or("unclassified error");
            pick.trim().to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::candidate::{Candidate, Lang};

    #[test]
    fn detect_custom_build_finds_scripts_and_skips_probed_systems() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Nothing custom, and CMake/Make are auto-probed (not hinted) -> None.
        std::fs::write(root.join("CMakeLists.txt"), "").unwrap();
        std::fs::write(root.join("Makefile"), "").unwrap();
        assert!(detect_custom_build(root).is_none());
        // A custom build.sh is the classic --build-command case.
        std::fs::write(root.join("build.sh"), "#!/bin/sh\n").unwrap();
        let (marker, cmd) = detect_custom_build(root).expect("build.sh detected");
        assert_eq!(marker, "build.sh");
        assert_eq!(cmd, "./build.sh");
    }

    #[test]
    fn engine_flag_defaults_to_builtin_and_parses_list() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            auto: AutoArgs,
        }
        let d = TestCli::try_parse_from(["govfuzz", "tree"]).unwrap().auto;
        assert_eq!(d.engine, "builtin");
        let both = TestCli::try_parse_from(["govfuzz", "tree", "--engine", "builtin,afl++"])
            .unwrap()
            .auto;
        assert_eq!(both.engine, "builtin,afl++");
        // The parsed list threads through parse_engine_list at run() time.
        assert_eq!(
            crate::fuzz::parse_engine_list(&both.engine).unwrap(),
            vec![
                crate::fuzz::FuzzEngine::Builtin,
                crate::fuzz::FuzzEngine::AflPlusPlus
            ]
        );
    }

    fn mk_candidate(lang: Lang, name: &str) -> Candidate {
        Candidate {
            harness_id: format!("H-{name}"),
            lang,
            source_path: PathBuf::from(format!("/s/{name}")),
            line: 1,
            name: name.to_owned(),
            score: 0,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        }
    }

    #[test]
    fn languages_flag_parses_aliases_and_defaults_to_empty() {
        use crate::auto::candidate::LangSelector;
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            auto: AutoArgs,
        }
        // Unset (default) = empty = fuzz every language found.
        let def = TestCli::try_parse_from(["govfuzz", "tree"]).expect("parses");
        assert!(def.auto.languages.is_empty());

        // Comma-separated canonical names, one flag.
        let csv = TestCli::try_parse_from(["govfuzz", "tree", "--languages", "c,rust,go"])
            .expect("parses")
            .auto;
        assert_eq!(
            csv.languages,
            vec![LangSelector::C, LangSelector::Rust, LangSelector::Go]
        );

        // Aliases (incl. the `--lang` flag alias) map onto the canonical lanes,
        // case-insensitively.
        let aliased = TestCli::try_parse_from(["govfuzz", "tree", "--lang", "C++,Py,RS,pl,golang"])
            .expect("parses")
            .auto;
        assert_eq!(
            aliased.languages,
            vec![
                LangSelector::Cpp,
                LangSelector::Python,
                LangSelector::Rust,
                LangSelector::Perl,
                LangSelector::Go,
            ]
        );

        // The COBOL/Fortran/C# lanes and their aliases parse onto the canonical lanes.
        let managed =
            TestCli::try_parse_from(["govfuzz", "tree", "--languages", "cobol,f90,cs,c#,dotnet"])
                .expect("parses")
                .auto;
        assert_eq!(
            managed.languages,
            vec![
                LangSelector::Cobol,
                LangSelector::Fortran,
                LangSelector::CSharp,
                LangSelector::CSharp,
                LangSelector::CSharp,
            ]
        );

        // Unknown language is a hard parse error, not a silent skip.
        assert!(
            TestCli::try_parse_from(["govfuzz", "tree", "--languages", "haskell"]).is_err(),
            "an unsupported language must error at parse time"
        );
    }

    #[test]
    fn force_flag_and_alias_parse() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            auto: AutoArgs,
        }
        // Default = off; every non-force path must stay unchanged.
        let def = TestCli::try_parse_from(["govfuzz", "tree"]).expect("parses");
        assert!(!def.auto.force);

        // `--force` sets it.
        let forced = TestCli::try_parse_from(["govfuzz", "tree", "--force"])
            .expect("parses")
            .auto;
        assert!(forced.force);

        // `--force-fuzz` alias sets it too.
        let aliased = TestCli::try_parse_from(["govfuzz", "tree", "--force-fuzz"])
            .expect("parses")
            .auto;
        assert!(aliased.force);
    }

    #[test]
    fn lang_selector_maps_every_variant_to_its_lane() {
        use crate::auto::candidate::LangSelector;
        assert_eq!(LangSelector::Ada.to_lang(), Lang::Ada);
        assert_eq!(LangSelector::C.to_lang(), Lang::C);
        assert_eq!(LangSelector::Cpp.to_lang(), Lang::Cpp);
        assert_eq!(LangSelector::Rust.to_lang(), Lang::Rust);
        assert_eq!(LangSelector::Java.to_lang(), Lang::Java);
        assert_eq!(LangSelector::Python.to_lang(), Lang::Python);
        assert_eq!(LangSelector::Perl.to_lang(), Lang::Perl);
        assert_eq!(LangSelector::Go.to_lang(), Lang::Go);
    }

    #[test]
    fn retain_languages_keeps_only_selected_lanes() {
        use crate::auto::candidate::LangSelector;
        let mut candidates = vec![
            mk_candidate(Lang::C, "c_fn"),
            mk_candidate(Lang::Cpp, "cpp_fn"),
            mk_candidate(Lang::Rust, "rust_fn"),
            mk_candidate(Lang::Java, "java_fn"),
            mk_candidate(Lang::Python, "py_fn"),
        ];
        let selected = selected_lang_set(&[LangSelector::C, LangSelector::Rust]);
        let (kept, dropped) = retain_languages(&mut candidates, &selected);
        assert_eq!((kept, dropped), (2, 3));
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["c_fn", "rust_fn"]);
    }

    #[test]
    fn retain_languages_empty_set_is_a_no_op() {
        let mut candidates = vec![
            mk_candidate(Lang::C, "c_fn"),
            mk_candidate(Lang::Go, "go_fn"),
        ];
        let selected = selected_lang_set(&[]);
        let (kept, dropped) = retain_languages(&mut candidates, &selected);
        assert_eq!((kept, dropped), (2, 0));
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn render_selected_langs_is_dedup_and_stable_order() {
        use crate::auto::candidate::LangSelector;
        // Given out of canonical order and duplicated, the log line is dedup'd
        // and printed in the fixed enum order so it reads the same every run.
        let rendered = render_selected_langs(&[
            LangSelector::Go,
            LangSelector::C,
            LangSelector::C,
            LangSelector::Ada,
        ]);
        assert_eq!(rendered, "ada, c, go");
    }

    #[test]
    fn extra_source_flag_parses_into_repeatable_extra_sources() {
        // `--extra-source` lets a multi-file library's real translation units be
        // linked into the harness so cross-file symbols resolve instead of being
        // blind-stubbed (libACPI's AML parser spans ~10 .c files).
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            auto: AutoArgs,
        }
        let cli = TestCli::try_parse_from([
            "govfuzz",
            "tree",
            "--extra-source",
            "src/a.c",
            "--extra-source",
            "src/b.c",
        ])
        .expect("parses");
        assert_eq!(
            cli.auto.extra_sources,
            vec![PathBuf::from("src/a.c"), PathBuf::from("src/b.c")]
        );
        // Default is empty when the flag is absent.
        let none = TestCli::try_parse_from(["govfuzz", "tree"]).expect("parses");
        assert!(none.auto.extra_sources.is_empty());
    }

    #[test]
    fn scaling_flags_parse_with_expected_defaults_and_values() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            auto: AutoArgs,
        }
        // Defaults: serial, all repair rounds, no caps, no reuse.
        let def = TestCli::try_parse_from(["govfuzz", "tree"]).expect("parses");
        assert_eq!(def.auto.jobs, 1);
        assert_eq!(
            def.auto.max_repair_rounds,
            crate::auto::attempt::DEFAULT_MAX_REPAIR_ROUNDS
        );
        assert_eq!(def.auto.max_targets, None);
        assert_eq!(def.auto.campaign_time, None);
        assert!(!def.auto.reuse_discovery);
        assert!(!def.auto.single_pass);
        assert_eq!(def.auto.passes, None);
        assert_eq!(def.auto.discovery_cache, None);
        // --sbom is off by default so `auto` stays fast.
        assert!(!def.auto.sbom);

        // Explicit values thread through.
        let set = TestCli::try_parse_from([
            "govfuzz",
            "tree",
            "--max-targets",
            "7",
            "--max-repair-rounds",
            "2",
            "--passes",
            "empty,fuzz",
            "--jobs",
            "4",
            "--reuse-discovery",
            "--campaign-time",
            "900",
            "--discovery-cache",
            "/tmp/disc.json",
            "--sbom",
        ])
        .expect("parses");
        assert_eq!(set.auto.max_targets, Some(7));
        assert_eq!(set.auto.max_repair_rounds, 2);
        assert_eq!(set.auto.passes.as_deref(), Some("empty,fuzz"));
        assert_eq!(set.auto.jobs, 4);
        assert!(set.auto.reuse_discovery);
        assert_eq!(set.auto.campaign_time, Some(900));
        assert_eq!(
            set.auto.discovery_cache,
            Some(PathBuf::from("/tmp/disc.json"))
        );
        assert!(set.auto.sbom);

        // --passes and --single-pass are mutually exclusive.
        assert!(
            TestCli::try_parse_from(["govfuzz", "tree", "--passes", "rng", "--single-pass",])
                .is_err()
        );
    }

    #[test]
    fn campaign_split_even_share_when_above_floor() {
        use std::time::Duration;
        // total/n >= min: every target runs the even share and all are attempted.
        let (per_target, k) =
            plan_campaign_split(Duration::from_secs(80), Duration::from_secs(2), 8);
        assert_eq!(per_target, Duration::from_secs(10));
        assert_eq!(k, 8);
    }

    #[test]
    fn campaign_split_floors_to_min_and_caps_target_count() {
        use std::time::Duration;
        // Operator example: total=10s, min=2s, 8 targets. The even share (1.25s)
        // is below the floor, so each attempted target runs the 2s floor and only
        // floor(10/2)=5 targets are attempted; the bottom 3 are dropped.
        let (per_target, k) =
            plan_campaign_split(Duration::from_secs(10), Duration::from_secs(2), 8);
        assert_eq!(per_target, Duration::from_secs(2));
        assert_eq!(k, 5);
    }

    #[test]
    fn campaign_split_drops_all_when_budget_below_one_floor_slice() {
        use std::time::Duration;
        // total < min: not even one full floor slice fits -> 0 targets fuzzed.
        let (per_target, k) =
            plan_campaign_split(Duration::from_secs(1), Duration::from_secs(2), 8);
        assert_eq!(per_target, Duration::from_secs(2));
        assert_eq!(k, 0);
    }

    #[test]
    fn campaign_split_zero_targets_is_empty() {
        use std::time::Duration;
        let (_per_target, k) =
            plan_campaign_split(Duration::from_secs(10), Duration::from_secs(2), 0);
        assert_eq!(k, 0);
    }

    #[test]
    fn budget_flags_parse_and_min_target_time_requires_campaign() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            auto: AutoArgs,
        }
        let def = TestCli::try_parse_from(["govfuzz", "tree"]).expect("parses");
        assert_eq!(def.auto.per_target_finding_count, None);
        assert_eq!(def.auto.min_target_time, None);
        assert_eq!(def.auto.per_target_time, 60);

        let fc = TestCli::try_parse_from(["govfuzz", "tree", "--per-target-finding-count", "3"])
            .expect("parses");
        assert_eq!(fc.auto.per_target_finding_count, Some(3));

        // --min-target-time REQUIRES --campaign-time.
        assert!(
            TestCli::try_parse_from(["govfuzz", "tree", "--min-target-time", "2"]).is_err(),
            "--min-target-time without --campaign-time must error"
        );
        let split = TestCli::try_parse_from([
            "govfuzz",
            "tree",
            "--campaign-time",
            "10",
            "--min-target-time",
            "2",
        ])
        .expect("parses with campaign-time");
        assert_eq!(split.auto.campaign_time, Some(10));
        assert_eq!(split.auto.min_target_time, Some(2));

        // --total-time still parses (deprecated alias, hidden from help).
        let tt =
            TestCli::try_parse_from(["govfuzz", "tree", "--total-time", "90"]).expect("parses");
        assert_eq!(tt.auto.total_time, Some(90));
    }

    #[test]
    fn emit_campaign_sbom_writes_bundle_with_fuzz_reached_from_run_json() {
        // The `auto --sbom` end-of-campaign hook: over the scanned tree, enriched
        // with the work dir's auto/run.json. A dlopen failure in run.json creates a
        // runtime component the FuzzReached pass annotates — proving the campaign's
        // own run.json fed the bundle. No toolchain needed.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("tree");
        let work = tmp.path().join("govfuzz_work");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/tls.c"),
            "int parse_tls(const char*s){return 0;}\n",
        )
        .unwrap();
        std::fs::create_dir_all(work.join("auto")).unwrap();
        std::fs::write(
            work.join("auto/run.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": "govfuzz.auto.v1",
                "needed_for_build": {
                    "dlopen_failures": [{
                        "name": "libssl.so.1.1",
                        "referenced_by_targets": ["H-SSL"]
                    }]
                },
                "targets": [{
                    "harness_id": "H-SSL",
                    "source": root.join("src/tls.c"),
                    "name": "parse_tls",
                    "outcome": { "outcome": "built_and_fuzzed", "passes": [{ "executions": 42 }] }
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        emit_campaign_sbom(&root, &work);

        let sbom_dir = work.join("sbom");
        // Default emit = all four files.
        for name in [
            "sbom.json",
            "cyclonedx.json",
            "vulnerabilities.json",
            "openvex.json",
        ] {
            assert!(sbom_dir.join(name).is_file(), "--sbom should write {name}");
        }
        let sbom: serde_json::Value =
            serde_json::from_slice(&std::fs::read(sbom_dir.join("sbom.json")).unwrap()).unwrap();
        let reached = sbom["components"].as_array().unwrap().iter().any(|c| {
            c["evidence"]
                .as_str()
                .is_some_and(|s| s.contains("fuzz_reached"))
        });
        assert!(
            reached,
            "campaign run.json should mark a component exercised: {sbom:#}"
        );
    }

    #[test]
    fn load_seed_inputs_reads_files_and_dir_entries_and_skips_missing() {
        let base = std::env::temp_dir().join(format!("govfuzz-seeds-{}", std::process::id()));
        let dir = base.join("seeds");
        std::fs::create_dir_all(&dir).unwrap();
        let file = base.join("one.bin");
        std::fs::write(&file, b"AAA").unwrap();
        std::fs::write(dir.join("a.bin"), b"BB").unwrap();
        std::fs::write(dir.join("b.bin"), b"C").unwrap();

        let seeds = load_seed_inputs(
            &[file, base.join("missing.bin")],
            std::slice::from_ref(&dir),
        );

        // 1 readable file (missing one skipped) + 2 dir entries.
        assert_eq!(seeds.len(), 3);
        assert!(seeds.contains(&b"AAA".to_vec()));
        assert!(seeds.contains(&b"BB".to_vec()));
        assert!(seeds.contains(&b"C".to_vec()));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn load_seed_inputs_truncates_oversized_seeds_to_max_len() {
        let base = std::env::temp_dir().join(format!("govfuzz-bigseed-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        // A seed far larger than the mutator's max input length: keeping it whole
        // would make every pass replay/mutate a huge buffer and collapse
        // throughput, so it must be truncated to the cap (bytes past it are never
        // generated). A small in-cap seed is kept verbatim.
        let big = base.join("big.bin");
        std::fs::write(&big, vec![0xABu8; crate::fuzz::DEFAULT_MAX_LEN * 4]).unwrap();
        let small = base.join("small.bin");
        std::fs::write(&small, b"hello").unwrap();

        let seeds = load_seed_inputs(&[big, small], &[]);

        assert_eq!(seeds.len(), 2);
        // The oversized seed is capped, not dropped, and its prefix is preserved.
        let truncated = seeds
            .iter()
            .find(|s| s.len() == crate::fuzz::DEFAULT_MAX_LEN);
        assert!(
            truncated.is_some_and(|s| s.iter().all(|&b| b == 0xAB)),
            "oversized seed must be truncated to DEFAULT_MAX_LEN with its prefix intact"
        );
        assert!(
            seeds.contains(&b"hello".to_vec()),
            "in-cap seed kept verbatim"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    fn alire_tmp(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-alire-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_alire_dep_names_reads_depends_on_excluding_toolchain() {
        let root = alire_tmp("toml");
        let toml = root.join("alire.toml");
        std::fs::write(
            &toml,
            "name = \"usb_embedded\"\n\
             [[depends-on]]\nhal = \"^1.0.0\"\nbbqueue = \"^1.0.0\"\n\
             [[depends-on]]\ngnat = \">=11\"\n",
        )
        .unwrap();

        let names = parse_alire_dep_names(&toml);

        assert!(names.contains(&"hal".to_owned()), "{names:?}");
        assert!(names.contains(&"bbqueue".to_owned()), "{names:?}");
        assert!(
            !names.contains(&"gnat".to_owned()),
            "gnat is a toolchain, not a source dep: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn alire_dir_is_crate_matches_versioned_dirs_only() {
        assert!(alire_dir_is_crate("hal_1.0.0_abc123", "hal"));
        assert!(alire_dir_is_crate("hal_1.0.0", "hal"));
        assert!(alire_dir_is_crate("hal", "hal"));
        // A different crate that merely shares a prefix is not a match.
        assert!(!alire_dir_is_crate("hal_helper_1.0.0", "hal"));
        assert!(!alire_dir_is_crate("unrelated_2.0.0", "hal"));
    }

    #[test]
    fn resolve_deps_against_caches_finds_named_crates_transitively() {
        let root = alire_tmp("cache");
        let deps = root.join("cache").join("dependencies");
        std::fs::create_dir_all(deps.join("hal_1.0.0_abc")).unwrap();
        std::fs::create_dir_all(deps.join("bbqueue_1.2.0_def").join("src")).unwrap();
        std::fs::create_dir_all(deps.join("unrelated_3.0.0")).unwrap();
        // `hal` transitively depends on `bbqueue`; resolving `hal` must pull it
        // in even though the project only names `hal`.
        std::fs::write(
            deps.join("hal_1.0.0_abc").join("alire.toml"),
            "name = \"hal\"\n[[depends-on]]\nbbqueue = \"^1.0.0\"\n",
        )
        .unwrap();
        std::fs::write(
            deps.join("bbqueue_1.2.0_def").join("alire.toml"),
            "name = \"bbqueue\"\n",
        )
        .unwrap();

        let found = resolve_deps_against_caches(&["hal".to_owned()], std::slice::from_ref(&deps));
        let names: Vec<String> = found
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
            .collect();

        assert!(names.iter().any(|n| n.starts_with("hal_")), "{names:?}");
        assert!(
            names.iter().any(|n| n.starts_with("bbqueue_")),
            "transitive dep must be resolved: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.starts_with("unrelated")),
            "only declared/transitive crates, not the whole cache: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn candidate(source: &str, line: u32, harness_id: &str) -> Candidate {
        Candidate {
            harness_id: harness_id.to_owned(),
            lang: Lang::C,
            source_path: PathBuf::from(source),
            line,
            name: "parse".to_owned(),
            score: 10,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        }
    }

    #[test]
    fn build_error_brief_prefers_error_line_over_leading_warning() {
        // GNAT emits unreferenced-unit warnings before the fatal error. The
        // brief for an unclassified failure must surface the real error, not
        // the warning that happens to come first in the tail.
        let err = build_classifier::BuildErrorKind::Other {
            tail: "main.adb:11:09: warning: unit \"Ada.Text_IO\" is not referenced [-gnatwu]\n\
                   main.adb:30:24: error: prefix must not be a generic package\n\
                   gprbuild: *** compilation phase failed"
                .to_owned(),
        };
        assert_eq!(
            build_error_brief(&err),
            "main.adb:30:24: error: prefix must not be a generic package"
        );
    }

    #[test]
    fn attacking_order_uses_deterministic_tiebreakers_after_score_and_name() {
        let mut candidates = vec![
            candidate("/src/b.c", 1, "H-C0002"),
            candidate("/src/a.c", 9, "H-C0003"),
            candidate("/src/a.c", 1, "H-C0002"),
            candidate("/src/a.c", 1, "H-C0001"),
        ];

        sort_attacking_candidates(&mut candidates, |_| String::new());

        let ordered = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.source_path.display().to_string(),
                    candidate.line,
                    candidate.harness_id.as_str(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ordered,
            vec![
                ("/src/a.c".to_owned(), 1, "H-C0001"),
                ("/src/a.c".to_owned(), 1, "H-C0002"),
                ("/src/a.c".to_owned(), 9, "H-C0003"),
                ("/src/b.c".to_owned(), 1, "H-C0002"),
            ]
        );
    }

    #[test]
    fn target_name_filter_matches_cpp_qualified_overload_families() {
        assert!(target_name_filter_matches(
            "tinyxml2::XMLDocument::Parse(const char *, size_t)",
            "tinyxml2::XMLDocument::Parse"
        ));
        assert!(target_name_filter_matches(
            "tinyxml2::XMLDocument::Parse(const char *, size_t)",
            "Parse"
        ));
        assert!(target_name_filter_matches("parse", "parse"));
        assert!(!target_name_filter_matches(
            "tinyxml2::XMLDocument::Parse(const char *, size_t)",
            "Reset"
        ));
    }

    #[test]
    fn attacking_order_reads_each_source_path_once_and_uses_cached_text_for_score() {
        let mut candidates = vec![
            candidate("/src/safe.c", 1, "H-C0001"),
            candidate("/src/danger.adb", 1, "H-C0002"),
            candidate("/src/danger.adb", 2, "H-C0003"),
        ];
        for candidate in &mut candidates {
            candidate.name = "worker".to_owned();
        }
        let mut reads = std::collections::BTreeMap::<PathBuf, usize>::new();

        sort_attacking_candidates(&mut candidates, |path| {
            *reads.entry(path.to_path_buf()).or_default() += 1;
            if path.ends_with("danger.adb") {
                "procedure Run is begin GNAT.OS_Lib.Spawn (Cmd, Args); end Run;".to_owned()
            } else {
                String::new()
            }
        });

        assert_eq!(candidates[0].source_path, PathBuf::from("/src/danger.adb"));
        assert_eq!(candidates[1].source_path, PathBuf::from("/src/danger.adb"));
        assert_eq!(candidates[2].source_path, PathBuf::from("/src/safe.c"));
        assert_eq!(reads[&PathBuf::from("/src/danger.adb")], 1);
        assert_eq!(reads[&PathBuf::from("/src/safe.c")], 1);
    }

    #[test]
    fn resolve_passes_defaults_to_all_three_in_order() {
        use crate::auto::pass::Pass;
        assert_eq!(resolve_passes(false, None).unwrap(), Pass::ALL.to_vec());
    }

    #[test]
    fn resolve_passes_single_pass_is_only_fuzz_driven() {
        use crate::auto::pass::Pass;
        assert_eq!(resolve_passes(true, None).unwrap(), vec![Pass::FuzzDriven]);
    }

    #[test]
    fn resolve_passes_parses_named_subset_with_alias_and_dedup() {
        use crate::auto::pass::Pass;
        // Order preserved; `fuzz` aliases `fuzz_driven`; duplicates collapse.
        assert_eq!(
            resolve_passes(false, Some("rng,fuzz")).unwrap(),
            vec![Pass::Rng, Pass::FuzzDriven]
        );
        assert_eq!(
            resolve_passes(false, Some("empty, rng , fuzz_driven")).unwrap(),
            vec![Pass::Empty, Pass::Rng, Pass::FuzzDriven]
        );
        assert_eq!(
            resolve_passes(false, Some("fuzz,fuzz,fuzz")).unwrap(),
            vec![Pass::FuzzDriven]
        );
    }

    #[test]
    fn resolve_passes_rejects_unknown_and_empty() {
        assert!(resolve_passes(false, Some("nonsense")).is_err());
        // Comma-only / whitespace parses to an empty set, which is an error rather
        // than a silent no-pass run.
        assert!(resolve_passes(false, Some(" , ")).is_err());
    }

    #[test]
    fn unsupported_params_label_reads_as_a_deliberate_skip() {
        use crate::auto::attempt::Outcome;
        let outcome = Outcome::UnsupportedParams {
            reason: "irrelevant".to_owned(),
        };
        assert_eq!(outcome_label(&outcome), "skipped: could not auto-harness");
    }

    #[test]
    fn verbose_detail_surfaces_the_skip_reason() {
        use crate::auto::attempt::Outcome;
        let reason = "C parameter 'pUser' of type 'void *' is not yet supported \
                      by the C harness emitter";
        let outcome = Outcome::UnsupportedParams {
            reason: reason.to_owned(),
        };
        assert_eq!(verbose_detail(&outcome), vec![reason.to_owned()]);
    }

    #[test]
    fn verbose_detail_summarizes_repairs_and_passes_for_built_and_fuzzed() {
        use crate::auto::attempt::{Outcome, PassRun};
        use crate::auto::pass::Pass;
        use crate::auto::repair::Repair;
        let outcome = Outcome::BuiltAndFuzzed {
            repairs: vec![
                Repair::HeaderPlaceholder {
                    virtual_path: "internal/log.h".to_owned(),
                },
                Repair::StubDeclared {
                    symbol: "decoder_create".to_owned(),
                    return_type: "int".to_owned(),
                    provenance: "declared".to_owned(),
                },
                Repair::StubBlind {
                    symbol: "decoder_free".to_owned(),
                },
            ],
            retries: 1,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 180,
            executions_per_sec: 119.5,
            passes: vec![
                PassRun {
                    pass: Pass::Empty,
                    engine: "builtin".to_owned(),
                    executions: 127,
                    coverage_edges: 0,
                    elapsed_secs: 1.0,
                    executions_per_sec: 127.0,
                    findings: vec![],
                },
                PassRun {
                    pass: Pass::Rng,
                    engine: "builtin".to_owned(),
                    executions: 112,
                    coverage_edges: 0,
                    elapsed_secs: 1.0,
                    executions_per_sec: 112.0,
                    findings: vec!["F-0001".to_owned()],
                },
            ],
            runtrace_events: vec![],
        };
        assert_eq!(
            verbose_detail(&outcome),
            vec![
                "repairs: synthesized 1 header, stubbed 2 symbols".to_owned(),
                "empty=127ex/0f rng=112ex/1f".to_owned(),
            ]
        );
    }

    #[test]
    fn verbose_detail_reports_the_last_build_error() {
        use crate::auto::attempt::Outcome;
        use build_classifier::BuildErrorKind;
        let outcome = Outcome::FailedBuild {
            repairs: vec![],
            retries: 2,
            last_errors: vec![
                BuildErrorKind::MissingHeader {
                    path: "a.h".to_owned(),
                },
                BuildErrorKind::MissingType {
                    name: "mz_alloc_func".to_owned(),
                },
            ],
        };
        assert_eq!(
            verbose_detail(&outcome),
            vec!["last error: unknown type 'mz_alloc_func'".to_owned()]
        );
    }

    #[test]
    fn summarize_repairs_is_none_when_no_repairs_applied() {
        assert_eq!(summarize_repairs(&[]), None);
    }

    #[test]
    fn fmt_duration_switches_units_at_a_minute() {
        use std::time::Duration;
        assert_eq!(fmt_duration(Duration::from_millis(14_300)), "14.3s");
        assert_eq!(fmt_duration(Duration::from_secs(134)), "2m 14s");
        assert_eq!(fmt_duration(Duration::from_secs(605)), "10m 05s");
    }

    #[test]
    fn collect_counts_outcomes_files_and_languages() {
        use crate::auto::attempt::{AttemptResult, Outcome, PassRun};
        use crate::auto::candidate::{Candidate, Lang};
        use crate::auto::pass::Pass;
        let mk = |lang, src: &str, outcome| AttemptResult {
            candidate: Candidate {
                harness_id: "H".to_owned(),
                lang,
                source_path: PathBuf::from(src),
                line: 1,
                name: "f".to_owned(),
                score: 0,
                is_static: false,
                foreign_guard: None,
                input_reachability: None,
                dialect: None,
            },
            outcome,
            harness_dir: PathBuf::from("/h"),
        };
        let results = vec![
            mk(
                Lang::C,
                "/s/a.c",
                Outcome::BuiltAndFuzzed {
                    repairs: vec![],
                    retries: 0,
                    per_pass_budget_secs: 60,
                    total_wall_budget_secs: 180,
                    executions_per_sec: 2.0,
                    passes: vec![PassRun {
                        pass: Pass::Rng,
                        engine: "builtin".to_owned(),
                        executions: 1,
                        coverage_edges: 0,
                        elapsed_secs: 0.5,
                        executions_per_sec: 2.0,
                        findings: vec!["F-0001".to_owned(), "F-0002".to_owned()],
                    }],
                    runtrace_events: vec![],
                },
            ),
            mk(
                Lang::C,
                "/s/a.c",
                Outcome::UnsupportedParams {
                    reason: "x".to_owned(),
                },
            ),
            mk(
                Lang::Ada,
                "/s/b.adb",
                Outcome::FailedBuild {
                    repairs: vec![],
                    retries: 0,
                    last_errors: vec![],
                },
            ),
        ];
        let summary = AutoSummary::collect(
            Path::new("/s"),
            Path::new("/w"),
            actionability::RunMode::Reporting,
            std::time::Duration::from_secs(1),
            &results,
            0,
            0,
        );
        assert_eq!(summary.discovered, 3);
        // discovered_total clamps up to the swept count when no cap was passed.
        assert_eq!(summary.discovered_total, 3);
        assert_eq!(summary.built_and_fuzzed, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.failed_build, 1);
        assert_eq!(summary.findings, 2);
        // a.c and b.adb have targets; only a.c produced a built target.
        assert_eq!(summary.files_with_targets, 2);
        assert_eq!(summary.files_fuzzed, 1);
        assert_eq!(summary.per_language, vec![("Ada", 1, 0), ("C", 2, 1)]);
        // #405: measured fuzz wall is summed across passes/targets (only the
        // one built+fuzzed target's single 0.5s pass here).
        assert_eq!(summary.total_elapsed_secs, 0.5);
    }

    #[test]
    fn render_lists_stats_and_output_locations() {
        let summary = AutoSummary {
            source: PathBuf::from("/src"),
            work: PathBuf::from("/w"),
            mode: actionability::RunMode::Reporting,
            duration: std::time::Duration::from_secs(134),
            discovered: 191,
            discovered_total: 191,
            resumed: 0,
            built_and_fuzzed: 12,
            fuzzed_stub_only: 0,
            built: 0,
            skipped: 171,
            failed_build: 8,
            link_errors: 0,
            runtime_errors: 0,
            report_only: 0,
            findings: 112,
            executions: 9876,
            total_elapsed_secs: 9.876,
            coverage_edges: 0,
            files_fuzzed: 1,
            files_with_targets: 2,
            per_language: vec![("C", 191, 12)],
        };
        let out = summary.render();
        assert!(out.contains("Duration:     2m 14s"), "{out}");
        // #405: campaign throughput = executions ÷ measured fuzz wall.
        assert!(out.contains("Throughput:   1000 exec/s"), "{out}");
        assert!(
            out.contains(
                "Targets:      191 discovered — 12 built+fuzzed, 171 skipped, 8 failed build"
            ),
            "{out}"
        );
        assert!(
            out.contains("Source files: 1 fuzzed / 2 with targets"),
            "{out}"
        );
        assert!(out.contains("Languages:    C 191 (12 built)"), "{out}");
        assert!(out.contains("Findings:     112"), "{out}");
        assert!(out.contains("report:    /w/auto/run.md"), "{out}");
        assert!(out.contains("findings:  /w/findings/"), "{out}");
        assert!(out.contains("summary:   /w/auto/summary.txt"), "{out}");
    }

    #[test]
    fn render_omits_findings_dir_when_no_findings() {
        let summary = AutoSummary {
            source: PathBuf::from("/src"),
            work: PathBuf::from("/w"),
            mode: actionability::RunMode::Reporting,
            duration: std::time::Duration::from_secs(3),
            discovered: 5,
            discovered_total: 5,
            resumed: 0,
            built_and_fuzzed: 0,
            fuzzed_stub_only: 0,
            built: 0,
            skipped: 5,
            failed_build: 0,
            link_errors: 0,
            runtime_errors: 0,
            report_only: 0,
            findings: 0,
            executions: 0,
            total_elapsed_secs: 0.0,
            coverage_edges: 0,
            files_fuzzed: 0,
            files_with_targets: 1,
            per_language: vec![("C", 5, 0)],
        };
        let out = summary.render();
        assert!(!out.contains("findings:  "), "{out}");
        // No fuzz wall measured → no throughput line (guarded on > 0).
        assert!(!out.contains("Throughput:"), "{out}");
        assert!(out.contains("0 built+fuzzed, 5 skipped"), "{out}");
    }

    #[test]
    fn render_annotates_targets_dropped_by_cap() {
        // #6: when --max-targets / the campaign split dropped lower-ranked
        // candidates, the console line surfaces the pre-cap total + dropped delta.
        let summary = AutoSummary {
            source: PathBuf::from("/src"),
            work: PathBuf::from("/w"),
            mode: actionability::RunMode::Reporting,
            duration: std::time::Duration::from_secs(3),
            discovered: 20,
            discovered_total: 150,
            resumed: 0,
            built_and_fuzzed: 20,
            fuzzed_stub_only: 0,
            built: 0,
            skipped: 0,
            failed_build: 0,
            link_errors: 0,
            runtime_errors: 0,
            report_only: 0,
            findings: 0,
            executions: 0,
            total_elapsed_secs: 0.0,
            coverage_edges: 0,
            files_fuzzed: 20,
            files_with_targets: 20,
            per_language: vec![("C", 20, 20)],
        };
        let out = summary.render();
        assert!(
            out.contains("20 discovered (of 150 ranked, 130 dropped by cap)"),
            "{out}"
        );
    }
}
