// SPDX-License-Identifier: Apache-2.0

use crate::auto::candidate::Candidate;
use crate::auto::cross_target::{
    executable_on_path, resolve_cross_target, CrossRunner, CrossTarget,
};
use crate::auto::decl_index::DeclarationIndex;
use crate::auto::repair::{Repair, RepairManifest};
use anyhow::Result;
use build_classifier::BuildErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

/// Re-export so external integration tests (`crates/cli/tests/`) constructing
/// [`AttemptOptions`] can name the engine type via `cli::auto::attempt::FuzzEngine`
/// (the `fuzz` module itself is crate-private).
pub use crate::fuzz::FuzzEngine;

/// Maximum number of build-fail -> repair -> retry cycles per candidate.
/// Each retry only happens when the previous round applied a *new* repair
/// (the loop breaks immediately on no progress), so this is a safety cap,
/// not a fixed cost. It must be high enough to converge a deep dependency
/// chain: pulling in a real multi-file library one undefined symbol at a
/// time (zlib's `minizip` -> `zip.c` -> `deflate.c` -> `trees.c`/`adler32.c`
/// /`zutil.c` -> ...) needs more than a handful of rounds. Doubled from the
/// original 3 so moderate multi-file/multi-package convergence completes,
/// while keeping a large tree's wall-clock bounded (each extra round only
/// runs when the previous one added a repair). A very deep chain is left to
/// the proper fix - transitive-closure source addition in a single round.
///
/// Set to 16 from the strengthened 53-repository broken-project validation
/// matrix. Across 95 successful clean and damaged samples, p95 was 6 rounds,
/// p99/max was 14, and 16 covered every success. Eight rounds would have lost
/// two valid builds; the no-progress break still stops exhausted plans early.
///
/// This is the DEFAULT; the cap is configurable per run via `auto
/// --max-repair-rounds` (threaded through `AttemptOptions::max_repair_rounds`),
/// so a triage sweep can fail un-buildable targets fast with a low value (2-3).
pub const DEFAULT_MAX_REPAIR_ROUNDS: usize = 16;

/// Placeholder "symbol" recorded in the repair ledger when the §26.1 whole-library
/// link fallback adds a project's already-built static archive to the harness link.
/// An archive resolves many symbols at once, so no single symbol name fits; this
/// records the action in `run.json` and makes [`stub_execution_summary`] count it as
/// real linked code (not a stub).
const WHOLE_LIBRARY_ARCHIVE_SYMBOL: &str = "<whole-library archive>";

/// Placeholder "symbol" recorded in the repair ledger when the §26.1 SECONDARY
/// whole-library fallback compiles+links the library's full recovered translation-
/// unit set (used when no prebuilt `*.a` exists — yaml-cpp's `file(GLOB)` sources).
/// Like the archive marker, this records the action in `run.json` and makes
/// [`stub_execution_summary`] count the linked TUs as real code, not stubs.
const WHOLE_LIBRARY_TU_SET_SYMBOL: &str = "<whole-library TU set>";

/// Minimum number of distinct undefined externals before the whole-library
/// TU-set link fires. Below this, a few missing symbols are almost always a
/// targeted helper (one sibling source) the per-symbol `AddSource` cascade
/// resolves precisely; the one-shot full-TU link is reserved for a genuine
/// library-wide link failure (yaml-cpp's ~176 undefined `file(GLOB)` symbols),
/// not a single `helper()`. Keeps the precise per-symbol repair as the default.
const WHOLE_LIBRARY_TU_MIN_UNDEFINED: usize = 5;

/// Maximum number of project translation units auto-repair may add to one
/// isolated harness across the whole repair loop. The stricter whole-set sweep
/// limit is 40, but precise source recovery needs more headroom: LevelDB's
/// current closure crosses 40 before it reaches its final utility definitions.
/// At 64, application-sized cascades such as Uncrustify remain bounded while
/// legitimate library recovery can continue. Once exhausted, undefined symbols
/// use the planner's typed/blind stub fallback.
const MAX_AUTO_PROJECT_SOURCES: usize = 64;

fn definition_source_for_undefined<'a>(
    error: &BuildErrorKind,
    decl_index: &'a DeclarationIndex,
    target_source: &Path,
) -> Option<&'a Path> {
    let BuildErrorKind::UndefinedSymbol { name } = error else {
        return None;
    };
    decl_index.lookup_definition_source_near(name, target_source)
}

/// A full translation-unit sweep is justified only when a broad link failure
/// contains enough symbols that cannot be closed by precise source additions.
/// Mapped symbols can all be added together in one round, while a small number of
/// genuinely deleted/external helpers should be stubbed without pulling unrelated
/// TUs; count only the imprecise subset against the library-wide threshold.
fn should_link_full_tu_set(
    errors: &[BuildErrorKind],
    decl_index: &DeclarationIndex,
    target_source: &Path,
) -> bool {
    let undefined: Vec<_> = errors
        .iter()
        .filter(|error| matches!(error, BuildErrorKind::UndefinedSymbol { .. }))
        .collect();
    undefined
        .iter()
        .filter(|error| {
            definition_source_for_undefined(error, decl_index, target_source)
                .is_none_or(|source| source == target_source)
        })
        .count()
        >= WHOLE_LIBRARY_TU_MIN_UNDEFINED
}

/// Tunables for a single `attempt()` call. Wired from the
/// `govfuzz auto` CLI flags `--per-target-time` and `--no-stubs`.
#[derive(Debug, Clone)]
pub struct AttemptOptions {
    /// TOTAL per-target fuzz wall-clock budget for the cascade against a freshly
    /// built harness, split evenly across the passes (`total / passes.len()`)
    /// under one shared deadline so the per-target wall ≈ this regardless of pass
    /// count. libFuzzer `-max_total_time` / AFL `-V` / honggfuzz `--run_time`
    /// parity (#402).
    pub per_target_time: Duration,
    /// Deprecated alias of [`per_target_time`](Self::per_target_time) — the old
    /// `--total-time`. Overrides `per_target_time` when set. Retained so existing
    /// benchmark/parity invocations keep working; new callers set
    /// `per_target_time`.
    pub total_time: Option<Duration>,
    /// Stop a target's cascade once it has produced this many DISTINCT findings
    /// (`--per-target-finding-count`), or when the time budget is spent —
    /// whichever first. Checked mid-pass (the engine breaks the instant the
    /// remaining-for-this-pass count is hit) and accumulated across passes, so the
    /// cascade stops as soon as the running total reaches the cap. `None`
    /// (default) collects every finding within the time budget.
    pub per_target_finding_count: Option<usize>,
    /// When true, skip the repair planner entirely and mark any
    /// failed build as `FailedBuild` (diagnostics mode).
    pub no_stubs: bool,
    /// Ordered list of fuzz passes to drive against the built
    /// harness. Each pass sets `GOVFUZZ_RUNTRACE_MODE` so the shim's
    /// fakes activate in the corresponding mode. Default = all three
    /// passes in `Pass::ALL` order (Empty, Rng, FuzzDriven).
    pub passes: Vec<crate::auto::pass::Pass>,
    /// Canonical source root from `govfuzz auto <PATH>`. Ada build
    /// preparation uses this to avoid scanning sibling directories
    /// when the work dir lives beside the source tree.
    pub source_root: Option<PathBuf>,
    /// #91: operator override for the governing Ada project (`auto --project PATH`).
    /// When set, this exact `.gpr` is used for generation analysis, source staging,
    /// scenario exclusions, and the final build — bypassing automatic target-source
    /// ownership selection. `None` = select the governing project automatically.
    pub project: Option<PathBuf>,
    /// Extra local directories of dependency source for the Ada build path
    /// (vendored / air-gapped crates, plus auto-detected local Alire caches).
    /// Read from disk only — never fetched — so offline use is unaffected.
    pub ada_dep_dirs: Vec<PathBuf>,
    /// Actionability profile forwarded to fuzz emission.
    pub mode: actionability::RunMode,
    /// User-provided seed inputs (`auto --seed-file`/`--seed-dir`), prepended to
    /// every target's fuzz corpus so parser/decompressor targets can reach deep
    /// code from valid examples instead of only the tiny built-in seeds.
    pub user_seeds: Vec<Vec<u8>>,
    /// Extra include directories for C/C++ harness builds (`auto
    /// --extra-include`). Seeded onto every harness's `-I` path *before* the
    /// repair loop, so real dependency headers that live outside the swept tree
    /// (e.g. cFE's OSAL `common_types.h`, a PSP `cfe_psp.h`) are found and the
    /// genuine struct layouts compile in — instead of being replaced by empty
    /// placeholder headers and `void *` type stubs. Read from disk only.
    pub extra_include_dirs: Vec<PathBuf>,
    /// Extra C/C++ source files (`auto --extra-source`) to compile+link into
    /// every harness, seeded into the build's `extra_sources` before the repair
    /// loop. Lets a multi-file library's cross-file symbols resolve to real
    /// translation units instead of being blind-stubbed (libACPI's AML parser
    /// spans ~10 `.c` files). Read from disk only.
    pub extra_sources: Vec<PathBuf>,
    /// Per-pass execution cap (`auto --iterations N`). `None` (default) or an
    /// explicit `0` lets `--per-target-time` govern depth; a positive value
    /// caps each pass. Retires the old hardcoded 1024 cap (#377).
    pub iterations: Option<usize>,
    /// Per-harness resident-set memory cap in MB (`auto --rss-limit-mb`). A single
    /// test case that allocates past this is killed and reported as an OOM finding
    /// (GF-209) instead of OOM-killing the host (#386). Mirrors libFuzzer's
    /// `-rss_limit_mb`; the default follows the auto CLI's available-memory
    /// calculation.
    pub rss_limit_mb: usize,
    /// Cap on build-fail -> repair -> retry rounds per target (`auto
    /// --max-repair-rounds`; default [`DEFAULT_MAX_REPAIR_ROUNDS`] = 16). Each
    /// round only runs when the previous one applied a new repair, so this is a
    /// ceiling, not a fixed cost. A low value (2-3) fails un-buildable targets
    /// fast for a quick triage sweep over a huge tree.
    pub max_repair_rounds: usize,
    /// laf-intel comparison-progress coverage (`auto --comparison-progress`,
    /// #421). When set, the driver's `GOVFUZZ_CMP_PROGRESS_SHM` map is wired up so
    /// an input that matches MORE leading bytes of a multi-byte gate is retained
    /// and energized — the gradient whole-compare edges cannot give on
    /// magic/format gates. Opt-in (default off); inert on harnesses without the
    /// driver runtime (Ada trace-pc path).
    pub comparison_progress: bool,
    /// Sanitizer selection for each harness `auto` BUILDS and RUNS
    /// (`auto --sanitizers asan,ubsan,… | none`). For [`SanitizerSelection::Set`]
    /// the C/C++ harness is compiled+linked with exactly the requested
    /// `-fsanitize=` set (plus the engine's `-fsanitize-coverage` flags) instead
    /// of the Makefile's default `address,undefined`, and each fuzz pass runs with
    /// the matching `<SAN>_OPTIONS` env so UBSan/LSan findings become crashes. For
    /// [`SanitizerSelection::None`] the harness is built with coverage but no
    /// `-fsanitize=` (native crash-only, zero ASan/UBSan false positives — #434).
    /// [`SanitizerSelection::Default`] leaves the build and run env byte-identical
    /// to before. Mirrors `govfuzz fuzz --sanitizers`. Inert on the Ada and
    /// cross-compiled (qemu-user / wine) paths, where host sanitizer
    /// instrumentation doesn't apply.
    pub sanitizers: multicore_fuzz::SanitizerSelection,
    /// Directory-name filter (`auto --exclude-dir`/`--include-dir`) — the SAME
    /// filter discovery uses to drop non-library dirs (tests/testsuite/examples/
    /// benchmarks/fuzz). Threaded into the Ada src-instrumentation walk so the
    /// BUILD source set matches the discovered TARGET set: a fixture dir that is
    /// not ranked for targets is not compiled either. Without it gnatcoll's
    /// `testsuite/` shipped `foo.adb`+`foo.c`, which gprbuild rejects ("same
    /// object file name") — failing every harness build on a real Ada tree.
    pub dir_filter: crate::auto::discovery::DirFilter,
    /// Ordered, de-duplicated engine preference list for the per-target fuzz
    /// phase (`auto --engine`). Default `[FuzzEngine::Builtin]` = today's
    /// behavior. AFL++ applies to C/C++ targets only ([`applicable_engines`]);
    /// a target never selects no engine (it falls back to builtin). When both
    /// engines run for a target, `per_target_time` splits evenly across them.
    pub engines: Vec<FuzzEngine>,
    /// Canonicalized Ada source files that are a project Main (declared
    /// `for Main use (...)` in some `.gpr` under the sweep tree), mapped to the
    /// `.gpr` file name that declared each. Computed once by
    /// [`crate::auto::discovery::gpr_main_sources`]. The attempt loop pre-skips an
    /// Ada candidate whose source file is one of these: a Main is a program ENTRY
    /// POINT, not a library subprogram a direct-call harness can name, so emitting
    /// `with Unit; ... Unit;` for it fails to compile. Skipped with a precise
    /// reason (`skipped`), never built (`failed_build`). Empty by default.
    pub ada_main_sources: HashMap<PathBuf, String>,
    /// Configurable C/C++ decoder synthesis caps (§27.11), threaded from the
    /// `auto` CLI flags to harness generation. `Default` (all flags unset)
    /// reproduces the historical hardcoded caps byte-for-byte.
    pub decoder_limits: crate::generate_harness::DecoderLimitArgs,
    /// Force-fuzz mode (`auto --force`/`--force-fuzz`). Strictly additive: bypasses
    /// the pre-build skip/degrade gates (static/internal-linkage, Ada project Main,
    /// C++ `.cpp`-only class, C++ undefined-return-type report-only) so a target
    /// that would normally be pre-skipped instead falls through to the build+repair
    /// path. Default `false` leaves every non-force path byte-for-byte unchanged.
    pub force: bool,
}

impl Default for AttemptOptions {
    fn default() -> Self {
        Self {
            per_target_time: Duration::from_secs(60),
            total_time: None,
            per_target_finding_count: None,
            no_stubs: false,
            passes: crate::auto::pass::Pass::ALL.to_vec(),
            source_root: None,
            project: None,
            ada_dep_dirs: Vec::new(),
            mode: actionability::RunMode::Reporting,
            user_seeds: Vec::new(),
            extra_include_dirs: Vec::new(),
            extra_sources: Vec::new(),
            iterations: None,
            rss_limit_mb: crate::auto::cli::default_auto_rss_limit_mb(),
            max_repair_rounds: DEFAULT_MAX_REPAIR_ROUNDS,
            comparison_progress: false,
            sanitizers: multicore_fuzz::SanitizerSelection::Default,
            dir_filter: crate::auto::discovery::DirFilter::default(),
            engines: vec![FuzzEngine::Builtin],
            ada_main_sources: HashMap::new(),
            decoder_limits: crate::generate_harness::DecoderLimitArgs::default(),
            force: false,
        }
    }
}

/// Resolve the per-pass execution cap for the auto fuzz loop (#377). The auto
/// loop always runs under a wall-clock budget (`per_target_time`), so an unset
/// or explicit-zero `--iterations` yields an effectively-unbounded cap (the
/// wall-clock budget governs depth); an explicit positive value caps the loop.
/// This retires the old hardcoded 1024-iteration cap that starved magic-byte /
/// length-gated parsers regardless of `--per-target-time`.
pub(crate) fn auto_iteration_cap(explicit: Option<usize>) -> usize {
    match explicit {
        Some(n) if n > 0 => n,
        _ => usize::MAX,
    }
}

/// #378: append the `{"e":"cmplog",...}` records from a pass's runtrace log to
/// the per-target cmplog snapshot, so comparison operands accumulate across
/// passes and feed the next pass's mutator (libFuzzer-style cmplog/RedQueen).
/// Runtrace event lines (non-cmplog) are skipped; absent/unreadable logs are a
/// no-op.
pub(crate) fn append_cmplog_records(runtrace_log: &std::path::Path, snapshot: &std::path::Path) {
    let Ok(contents) = std::fs::read_to_string(runtrace_log) else {
        return;
    };
    let mut records = String::new();
    for line in contents.lines() {
        if line.contains("\"e\":\"cmplog\"") {
            records.push_str(line);
            records.push('\n');
        }
    }
    if records.is_empty() {
        return;
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(snapshot)
    {
        let _ = file.write_all(records.as_bytes());
    }
}

/// Cap on inputs reseeded from the persisted corpus into a later pass (#383),
/// so a long-running target's queue can't blow the seed set up unboundedly.
pub(crate) const CORPUS_RESEED_CAP: usize = 256;

/// #383: load the per-target persisted corpus queue — one input per coverage
/// signature, written by `CorpusManager` at `<work>/corpus/<id>/queue/*.bin`,
/// so it is coverage-minimal by construction — into the seed set, so coverage
/// carries forward to the next pass instead of every pass restarting from the
/// tiny built-in seeds. Deduped against existing seeds and capped. Returns how
/// many were added.
pub(crate) fn reseed_from_corpus_queue(
    work_dir: &std::path::Path,
    harness_id: &str,
    seeds: &mut Vec<Vec<u8>>,
    cap: usize,
) -> usize {
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(entries) = std::fs::read_dir(&queue) else {
        return 0;
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort(); // deterministic order across runs
    let mut added = 0;
    for path in paths {
        if added >= cap {
            break;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            if !bytes.is_empty() && !seeds.contains(&bytes) {
                seeds.push(bytes);
                added += 1;
            }
        }
    }
    added
}

/// One pass of `run_fuzz_with_runtrace` against a built harness.
/// The cascade emits one of these per element in
/// `AttemptOptions::passes`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PassRun {
    pub pass: crate::auto::pass::Pass,
    /// Which fuzz engine produced this pass — `"builtin"` or `"afl++"` (`auto
    /// --engine`). Lets the report attribute exec counts / findings per engine.
    /// Always set at construction; `#[serde(default)]` matches the sibling fields
    /// (`PassRun` is Serialize-only — `run.json` is written, never read back).
    #[serde(default)]
    pub engine: String,
    pub executions: usize,
    /// Checkpoint emitted immediately before the selected project endpoint.
    /// This is stronger than "the harness launched" or driver-only coverage.
    #[serde(default)]
    pub target_entry_observed: bool,
    /// Distinct instrumented edges the harness hit during this pass (#385). 0 for
    /// harnesses without a govfuzz coverage runtime (only passthrough libFuzzer
    /// driver harnesses carry one today).
    #[serde(default)]
    pub coverage_edges: usize,
    /// #405: actual wall-clock seconds the engine spent fuzzing this pass — the
    /// measured run time, NOT the budget (`per_pass_budget_secs`); a pass can
    /// finish early or lose time to setup. 0.0 only when no time was measured.
    #[serde(default)]
    pub elapsed_secs: f64,
    /// #405: throughput for this pass (`executions / elapsed_secs`), for parity
    /// with libFuzzer `average_exec_per_sec` / AFL `execs_per_sec`.
    #[serde(default)]
    pub executions_per_sec: f64,
    pub findings: Vec<String>,
}

/// Target-level throughput across a cascade: total executions ÷ total measured
/// fuzz wall (seconds). Summing then dividing — rather than averaging per-pass
/// rates — weights each pass by its actual run time, matching libFuzzer's
/// `average_exec_per_sec`. Returns 0.0 when no measurable wall elapsed (#405).
pub fn aggregate_executions_per_sec(passes: &[PassRun]) -> f64 {
    let total_execs: usize = passes.iter().map(|p| p.executions).sum();
    let total_secs: f64 = passes.iter().map(|p| p.elapsed_secs).sum();
    if total_secs > 0.0 {
        total_execs as f64 / total_secs
    } else {
        0.0
    }
}

/// #417 threshold: a fuzzed target is classified `stub_only` when at least this
/// fraction of the *external* symbols its harness had to resolve at link time
/// were satisfied by **blind** stubs (`Repair::StubBlind` — an invented empty
/// body with no real declaration). Set at 0.90 ("all or nearly all") rather than
/// a strict 1.0 so a couple of declared stubs (which at least carry a genuine
/// signature) don't mask an otherwise blind-stubbed library. The classification
/// also hard-requires `real_linked == 0` (see [`stub_execution_summary`]), so the
/// flag fires only when essentially no real dependency source was linked — it
/// never mislabels a genuine fuzz that merely blind-stubbed a few deep leaf
/// helpers while linking real code.
const STUB_ONLY_BLIND_FRACTION: f64 = 0.90;

/// #417: how much of a fuzzed harness's external symbol surface was satisfied by
/// empty stubs vs real linked code. When (nearly) every external symbol the
/// harness called was a *blind* stub and no real dependency source was linked,
/// the run exercised only invented empty function bodies plus the target's own
/// translation unit — a clean 0-finding result there is a FALSE CLEAN, not
/// evidence the real library is safe (the original #417 report: libyaml fuzzed at
/// ~8M execs, 0 findings, every `yaml_parser_*` entry point blind-stubbed,
/// coverage 16 edges vs ~1400 for the real library). `stub_only` flags exactly
/// that state so it can never be mistaken for a real fuzz of the library.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StubExecution {
    /// Distinct symbols satisfied by a blind stub (`Repair::StubBlind`): an
    /// invented empty body, no real declaration. These execute nothing.
    pub blind_stubbed_symbols: usize,
    /// Distinct symbols satisfied by a declared stub (`Repair::StubDeclared`):
    /// an empty body synthesised from a real declaration/signature. Still no
    /// real behaviour, but the signature is genuine.
    pub declared_stubbed_symbols: usize,
    /// Distinct symbols satisfied by linking REAL dependency source
    /// (`Repair::AddSource`). These execute real library code.
    pub real_linked_symbols: usize,
    /// Total distinct external symbols the harness had to resolve = blind +
    /// declared + real. The denominator for `blind_stub_fraction`.
    pub resolved_called_symbols: usize,
    /// Fraction of resolved external symbols that were blind-stubbed
    /// (`blind / resolved`); `0.0` when nothing needed external resolution.
    pub blind_stub_fraction: f64,
    /// The FALSE-CLEAN flag (#417): true when the harness's external symbol
    /// surface was (nearly) all blind stubs and no real dependency source was
    /// linked. A clean 0-finding `built_and_fuzzed` with this set must NOT be
    /// read as "the real library is clean" — only empty stubs were fuzzed.
    pub stub_only: bool,
}

/// Whether an undefined-symbol link error names a symbol govfuzz cannot satisfy
/// from the swept tree — no in-tree C/C++ definition, and not a standard symbol a
/// header (`assert`) would provide. Such a symbol is the fingerprint of a missing
/// library translation unit, so it is the trigger for the §26.1 whole-library
/// link fallback (link the project's already-built `*.a`). Standard libc
/// *functions* never reach here: build_classifier excludes them from
/// `UndefinedSymbol` (they resolve from libc at link time).
fn undefined_symbol_needs_library_link(name: &str, decl_index: &DeclarationIndex) -> bool {
    decl_index.lookup_c_definition_source(name).is_none()
        && decl_index.lookup_cpp_definition_source(name).is_none()
        && c_stub_gen::c_std_symbol_header(name).is_none()
}

/// #417: derive the [`StubExecution`] summary from a target's repair ledger.
/// Pure and cheap, so it is recomputed wherever it's needed (report, terminal
/// summary, outcome label) rather than threaded through the [`Outcome`].
///
/// A symbol can appear in more than one ledger entry across repair retries (e.g.
/// an `AddSource` whose file failed to link, later blind-stubbed). We classify
/// each distinct symbol by its *strongest* evidence of real execution — linked
/// real source > declared stub > blind stub — so stubbing is never overstated.
pub fn stub_execution_summary(repairs: &[Repair]) -> StubExecution {
    use std::collections::BTreeSet;
    let mut blind: BTreeSet<&str> = BTreeSet::new();
    let mut declared: BTreeSet<&str> = BTreeSet::new();
    let mut real: BTreeSet<&str> = BTreeSet::new();
    for r in repairs {
        match r {
            Repair::StubBlind { symbol } => {
                blind.insert(symbol.as_str());
            }
            Repair::StubDeclared { symbol, .. } => {
                declared.insert(symbol.as_str());
            }
            Repair::AddSource { symbol, .. } => {
                real.insert(symbol.as_str());
            }
            _ => {}
        }
    }
    // Strongest-evidence-wins: a symbol ever backed by real source counts real;
    // a symbol declared-stubbed (real signature) outranks a blind stub.
    declared.retain(|s| !real.contains(s));
    blind.retain(|s| !real.contains(s) && !declared.contains(s));

    let blind_stubbed_symbols = blind.len();
    let declared_stubbed_symbols = declared.len();
    let real_linked_symbols = real.len();
    let resolved_called_symbols =
        blind_stubbed_symbols + declared_stubbed_symbols + real_linked_symbols;
    let blind_stub_fraction = if resolved_called_symbols > 0 {
        blind_stubbed_symbols as f64 / resolved_called_symbols as f64
    } else {
        0.0
    };
    // False-clean iff at least one blind stub, NO real dependency source linked,
    // and blind stubs dominate the resolved-external surface (>= threshold).
    let stub_only = blind_stubbed_symbols >= 1
        && real_linked_symbols == 0
        && blind_stub_fraction >= STUB_ONLY_BLIND_FRACTION;
    StubExecution {
        blind_stubbed_symbols,
        declared_stubbed_symbols,
        real_linked_symbols,
        resolved_called_symbols,
        blind_stub_fraction,
        stub_only,
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    BuiltAndFuzzed {
        repairs: Vec<Repair>,
        retries: usize,
        /// Per-pass executions + findings. One entry per element of
        /// `AttemptOptions::passes`. Earlier elements ran first; the
        /// cascade aborts and records what it has if any pass errors
        /// out, so this may be shorter than the configured passes.
        passes: Vec<PassRun>,
        /// #402: the per-pass fuzz wall budget (seconds) = the per-target TOTAL
        /// (`--per-target-time`, default 60) divided evenly across the passes
        /// (`total / passes.len()`). The passes share one deadline, so the
        /// per-target wall ≈ that total — NOT this × the pass count.
        /// (`--total-time` is a deprecated alias of `--per-target-time`, fed
        /// through the same split.)
        #[serde(default)]
        per_pass_budget_secs: u64,
        /// #402: the effective TOTAL per-target fuzz wall budget (seconds) =
        /// `--per-target-time` (or the deprecated `--total-time` alias if set);
        /// `per_pass_budget_secs` is this divided by the pass count. Lets a
        /// consumer reason about wall time without reverse-engineering the pass
        /// count.
        #[serde(default)]
        total_wall_budget_secs: u64,
        /// #405: target-level throughput across the cascade — total executions
        /// ÷ total measured fuzz wall (Σexecs / Σelapsed, time-weighted, not a
        /// mean of per-pass rates). 0.0 when no measurable wall elapsed.
        #[serde(default)]
        executions_per_sec: f64,
        /// Runtime audit events captured by libgovfuzz_runtrace.so
        /// during the fuzz pass(es). Empty when the shim wasn't
        /// loaded (audit-disabled mode).
        runtrace_events: Vec<crate::auto::runtrace::RuntraceEvent>,
    },
    /// #95: the harness BUILT and ran fuzz passes, but NO entry-instrumented
    /// pass observed the target-entry checkpoint (`PassRun::target_entry_observed`).
    /// The process executed only generated decoding, blind stubs, or bailed out
    /// before reaching the selected project endpoint — so it must NOT be counted
    /// as a fuzz success even though it ran normally. This outcome is emitted only
    /// for lanes that actually instrument target entry (C/C++/Ada — the templates
    /// inject `GOVFUZZ_TARGET_ENTER`/`AdaFuzz.Probe.Target_Entry`); interpreted and
    /// managed lanes have no entry probe, so their absence of proof is "not
    /// instrumented", never "not entered", and they keep `built_and_fuzzed`.
    /// All pass metrics + runtrace evidence are preserved for diagnosis.
    BuiltNotEntered {
        repairs: Vec<Repair>,
        retries: usize,
        /// Per-pass executions + findings, exactly as a `BuiltAndFuzzed` would
        /// carry them — the passes ran, they just never entered the target.
        passes: Vec<PassRun>,
        #[serde(default)]
        per_pass_budget_secs: u64,
        #[serde(default)]
        total_wall_budget_secs: u64,
        #[serde(default)]
        executions_per_sec: f64,
        runtrace_events: Vec<crate::auto::runtrace::RuntraceEvent>,
        /// Stable sub-category naming WHY the target was never entered:
        /// `"stub_only"` (every external symbol was a blind stub, so only empty
        /// bodies ran), `"no_execution"` (built but no fuzz iteration executed),
        /// or `"decode_or_bailout"` (inputs ran but were decode-rejected or the
        /// harness bailed before the endpoint). Never vague.
        entry_miss: String,
        /// Human-readable reason, named for the report + support bundle.
        reason: String,
    },
    Built {
        repairs: Vec<Repair>,
        retries: usize,
    },
    FailedBuild {
        repairs: Vec<Repair>,
        retries: usize,
        last_errors: Vec<BuildErrorKind>,
    },
    UnsupportedParams {
        reason: String,
    },
    UnrecoverableLink {
        repairs: Vec<Repair>,
        missing: Vec<String>,
    },
    /// Safety-rail outcome: the harness either crashed repeatedly in a
    /// row (suggesting a faulty stub / shim regression) or exceeded
    /// the absolute per-target wall-clock cap. We bail out to keep a
    /// misbehaving target from fork-bombing or wedging the host.
    UnrecoverableRuntime {
        repairs: Vec<Repair>,
        consecutive_crashes: usize,
        reason: String,
        /// Runtime audit events the shim recorded across the
        /// passes that did complete before the safety rail tripped.
        /// Kept so the upstream maintainer can still see the env /
        /// file / network / dlopen evidence even when the cascade
        /// gets killed by the wall-clock or crash-rate cap.
        #[serde(default)]
        runtrace_events: Vec<crate::auto::runtrace::RuntraceEvent>,
    },
    /// M22: the candidate was discovered and statically analyzed but NOT fuzzed.
    /// Its detected [`lang_profile::Dialect`] has no fuzzing lane yet (a legacy
    /// dialect awaiting its phase), the required legacy toolchain is absent, or
    /// the build could not be recovered — so instead of silently dropping the
    /// target, govfuzz degrades to discover + SBOM + static findings (each with
    /// a CWE). Surfaced as `report_only` in the summary and per-target report.
    ReportOnly {
        /// Human-readable reason the target was not fuzzed (named, never vague).
        reason: String,
        /// Detected dialect tag (`lang_profile::Dialect::as_str`), if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dialect: Option<String>,
        /// Count of static (report-only) findings emitted for this target.
        #[serde(default)]
        static_findings: usize,
        /// Finding ids (under `<work>/findings/<id>/`) emitted by the report-only
        /// static scan, so the report aggregators (findings.csv, run.md) surface
        /// them with their CWE like any other finding.
        #[serde(default)]
        finding_ids: Vec<String>,
    },
}

/// Uniform diagnostic envelope derived for every outcome. This intentionally
/// sits alongside the backward-compatible enum fields: older consumers still
/// read `reason`/`repairs`/`last_errors`, while support tooling no longer has to
/// interpret their absence as JSON `null` or guess whether a repair loop ran.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttemptTrace {
    pub terminal_stage: String,
    pub fallback_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_reason: Option<String>,
    pub repairs_attempted: bool,
    pub repair_count: usize,
    pub build_error_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub build_error_categories: Vec<String>,
}

impl Outcome {
    pub fn attempt_trace(&self) -> AttemptTrace {
        let repair_details = |repairs: &[Repair], retries: usize| {
            (retries > 0 || !repairs.is_empty(), repairs.len())
        };
        match self {
            Outcome::BuiltAndFuzzed {
                repairs, retries, ..
            } => {
                let (repairs_attempted, repair_count) = repair_details(repairs, *retries);
                AttemptTrace {
                    terminal_stage: "fuzz".to_owned(),
                    fallback_chain: vec![
                        "generated".to_owned(),
                        "built".to_owned(),
                        "fuzzed".to_owned(),
                    ],
                    reason_category: None,
                    terminal_reason: None,
                    repairs_attempted,
                    repair_count,
                    build_error_count: 0,
                    build_error_categories: Vec::new(),
                }
            }
            Outcome::BuiltNotEntered {
                repairs,
                retries,
                entry_miss,
                reason,
                ..
            } => {
                let (repairs_attempted, repair_count) = repair_details(repairs, *retries);
                AttemptTrace {
                    terminal_stage: "target_not_reached".to_owned(),
                    fallback_chain: vec![
                        "generated".to_owned(),
                        "built".to_owned(),
                        "ran".to_owned(),
                    ],
                    reason_category: Some(entry_miss.clone()),
                    terminal_reason: Some(reason.clone()),
                    repairs_attempted,
                    repair_count,
                    build_error_count: 0,
                    build_error_categories: Vec::new(),
                }
            }
            Outcome::Built { repairs, retries } => {
                let (repairs_attempted, repair_count) = repair_details(repairs, *retries);
                AttemptTrace {
                    terminal_stage: "build".to_owned(),
                    fallback_chain: vec!["generated".to_owned(), "built".to_owned()],
                    reason_category: None,
                    terminal_reason: None,
                    repairs_attempted,
                    repair_count,
                    build_error_count: 0,
                    build_error_categories: Vec::new(),
                }
            }
            Outcome::FailedBuild {
                repairs,
                retries,
                last_errors,
            } => {
                let (repairs_attempted, repair_count) = repair_details(repairs, *retries);
                let has_sequence = last_errors.iter().any(|error| {
                    matches!(error, BuildErrorKind::Other { tail } if tail.contains("sequence harness failed"))
                });
                AttemptTrace {
                    terminal_stage: "build".to_owned(),
                    fallback_chain: if has_sequence {
                        vec![
                            "sequence_build_failed".to_owned(),
                            "direct_build_failed".to_owned(),
                        ]
                    } else {
                        vec!["direct_build_failed".to_owned()]
                    },
                    reason_category: Some("compiler_or_linker".to_owned()),
                    terminal_reason: None,
                    repairs_attempted,
                    repair_count,
                    build_error_count: last_errors.len(),
                    build_error_categories: build_error_categories(last_errors),
                }
            }
            Outcome::UnsupportedParams { reason } => AttemptTrace {
                terminal_stage: "generation".to_owned(),
                fallback_chain: if reason.contains("sequence generation also failed first")
                    || reason.contains("sequence harness build also failed first")
                {
                    vec![
                        "sequence_failed".to_owned(),
                        "direct_unsupported".to_owned(),
                    ]
                } else {
                    vec!["direct_unsupported".to_owned()]
                },
                reason_category: Some(attempt_reason_category(reason).to_owned()),
                terminal_reason: Some(reason.clone()),
                repairs_attempted: false,
                repair_count: 0,
                build_error_count: 0,
                build_error_categories: Vec::new(),
            },
            Outcome::UnrecoverableLink { repairs, missing } => AttemptTrace {
                terminal_stage: "link".to_owned(),
                fallback_chain: vec!["build_repair".to_owned(), "link_unrecoverable".to_owned()],
                reason_category: Some("unresolved_link".to_owned()),
                terminal_reason: Some(format!("{} unresolved link symbol(s)", missing.len())),
                repairs_attempted: true,
                repair_count: repairs.len(),
                build_error_count: missing.len(),
                build_error_categories: vec!["undefined_symbol".to_owned()],
            },
            Outcome::UnrecoverableRuntime {
                repairs, reason, ..
            } => AttemptTrace {
                terminal_stage: "runtime".to_owned(),
                fallback_chain: vec!["built".to_owned(), "runtime_unrecoverable".to_owned()],
                reason_category: Some("runtime_safety_rail".to_owned()),
                terminal_reason: Some(reason.clone()),
                repairs_attempted: !repairs.is_empty(),
                repair_count: repairs.len(),
                build_error_count: 0,
                build_error_categories: Vec::new(),
            },
            Outcome::ReportOnly { reason, .. } => AttemptTrace {
                terminal_stage: "static_analysis".to_owned(),
                fallback_chain: vec![
                    "dynamic_unavailable".to_owned(),
                    "static_analysis".to_owned(),
                ],
                reason_category: Some(attempt_reason_category(reason).to_owned()),
                terminal_reason: Some(reason.clone()),
                repairs_attempted: false,
                repair_count: 0,
                build_error_count: 0,
                build_error_categories: Vec::new(),
            },
        }
    }

    /// #417: per-target stub-vs-real execution summary derived from the repair
    /// ledger, or `None` for outcomes that never fuzzed (only `BuiltAndFuzzed`
    /// carries a fuzz result). Recomputed from `repairs` on demand — see
    /// [`stub_execution_summary`].
    pub fn stub_execution(&self) -> Option<StubExecution> {
        match self {
            // #95: `BuiltNotEntered` also carries the repair ledger, so a
            // stub-only harness that never entered the target still reports its
            // blind-stub profile (that IS why entry was `stub_only`).
            Outcome::BuiltAndFuzzed { repairs, .. } | Outcome::BuiltNotEntered { repairs, .. } => {
                Some(stub_execution_summary(repairs))
            }
            _ => None,
        }
    }

    /// #(c): the foreign OS platform this target was STUB-ISOLATED for (its
    /// platform deps faked so it compiles natively) — every finding on it is
    /// REDUCED-FIDELITY. `None` for a normally-built target. Derived from the
    /// repair ledger so it is available on any outcome that carries repairs.
    pub fn platform_stub(&self) -> Option<String> {
        let repairs = match self {
            Outcome::BuiltAndFuzzed { repairs, .. }
            | Outcome::BuiltNotEntered { repairs, .. }
            | Outcome::Built { repairs, .. }
            | Outcome::FailedBuild { repairs, .. }
            | Outcome::UnrecoverableLink { repairs, .. }
            | Outcome::UnrecoverableRuntime { repairs, .. } => repairs.as_slice(),
            Outcome::UnsupportedParams { .. } | Outcome::ReportOnly { .. } => return None,
        };
        repairs.iter().find_map(|r| match r {
            Repair::PlatformStub { platform } => Some(platform.clone()),
            _ => None,
        })
    }
}

fn build_error_categories(errors: &[BuildErrorKind]) -> Vec<String> {
    let mut categories = errors
        .iter()
        .filter_map(|error| {
            serde_json::to_value(error)
                .ok()?
                .get("kind")?
                .as_str()
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    categories.sort();
    categories.dedup();
    categories
}

fn attempt_reason_category(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("blocked_by_concurrency") || lower.contains("task/protected") {
        "concurrency"
    } else if lower.contains("blocked_by_generic") || lower.contains("generic package") {
        "generic"
    } else if lower.contains("private") || lower.contains("not public") {
        "visibility"
    } else if lower.contains("no byte-buffer decoder") || lower.contains("parameter") {
        "decoder_or_parameter"
    } else if lower.contains("cannot construct") || lower.contains("constructor") {
        "construction"
    } else if lower.contains("header") && lower.contains("translation unit") {
        "translation_unit_context"
    } else if lower.contains("toolchain") || lower.contains("compiler") {
        "toolchain"
    } else if lower.contains("legacy") || lower.contains("k&r") {
        "legacy_dialect"
    } else {
        "other"
    }
}

#[derive(Debug)]
pub struct AttemptResult {
    pub candidate: Candidate,
    pub outcome: Outcome,
    pub harness_dir: PathBuf,
}

impl AttemptResult {
    /// Outcome trace enriched with generation-path evidence checkpointed in the
    /// harness directory. The outcome enum stays backward compatible, while a
    /// successful sequence/servant fallback is no longer indistinguishable from
    /// a first-choice direct harness in run.json and support reports.
    pub fn attempt_trace(&self) -> AttemptTrace {
        let mut trace = self.outcome.attempt_trace();
        let fallback = std::fs::read_to_string(self.harness_dir.join("generation-fallback.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| value.get("from")?.as_str().map(str::to_owned));
        let stage = match fallback.as_deref() {
            Some("sequence") => Some("sequence_generation_failed"),
            Some("servant_direct") => Some("servant_generation_failed"),
            _ => None,
        };
        if let Some(stage) = stage {
            trace.fallback_chain.insert(0, stage.to_owned());
            trace.fallback_chain.insert(1, "direct_fallback".to_owned());
        }
        trace
    }
}

/// Resolve the per-target fuzz budget plan. `per_target_time` is the TOTAL
/// wall-clock budget for the target (split evenly across `pass_count` passes
/// under one shared deadline); `total_time` is the deprecated `--total-time`
/// alias and overrides `per_target_time` when set. Returns
/// `(per_pass_budget, total_target_budget)`.
fn plan_pass_budget(
    per_target_time: Duration,
    total_time: Option<Duration>,
    pass_count: u32,
) -> (Duration, Duration) {
    let total = total_time.unwrap_or(per_target_time);
    (total / pass_count.max(1), total)
}

/// The leaf class name that owns a C++ method, given its qualified candidate name
/// (`json11::JsonParser::expect(int)` -> `JsonParser`). The owner is the
/// second-to-last `::` segment of the name's signature-free prefix. Returns `None`
/// for a free function (`foo`) or a bare namespaced free function — anything with
/// fewer than two `::` segments — so a namespace is never mistaken for a class.
fn cpp_owner_class(name: &str) -> Option<&str> {
    let prefix = name.split('(').next().unwrap_or(name).trim();
    let segments: Vec<&str> = prefix.split("::").filter(|s| !s.is_empty()).collect();
    if segments.len() >= 2 {
        Some(segments[segments.len() - 2])
    } else {
        None
    }
}

/// Mine the target source's string + integer literals into the harness AFL
/// `dictionary.txt` for the interpreted/managed lanes (Rust/Go/Java/Python/Perl),
/// so the builtin engine can splice constants past `==`/match guards. C/C++/Ada
/// already write their own dictionary at harness-gen, so they're skipped here.
/// Best-effort: a parse error is ignored, and an existing dictionary is not
/// clobbered (a lane's own harness-gen wins if it wrote one).
fn write_source_dictionary(
    harness_dir: &Path,
    source: Option<&str>,
    lang: crate::auto::candidate::Lang,
) {
    use crate::auto::candidate::Lang;
    let Some(source) = source else {
        return;
    };
    let tokens = match lang {
        Lang::Rust => rust_parser::extract_rust_dictionary_tokens(source).ok(),
        Lang::Go => go_parser::extract_go_dictionary_tokens(source).ok(),
        Lang::Java => java_parser::extract_java_dictionary_tokens(source).ok(),
        Lang::Python => python_parser::extract_python_dictionary_tokens(source).ok(),
        Lang::Perl => perl_parser::extract_perl_dictionary_tokens(source).ok(),
        // C#/JS carry no CmpLog in the managed/interpreted driver, so a source-mined
        // dictionary is the lever past a single multi-byte comparison gate (the same
        // reason the other managed lanes mine one). Scan the source's string/number
        // literals (JS also allows backtick template literals).
        Lang::CSharp => Some(crate::auto::lit_scan::scan_literal_tokens(source, false)),
        Lang::Js | Lang::Ts => {
            let mut toks = crate::auto::lit_scan::scan_literal_tokens(source, true);
            // Seed the prototype-pollution vectors + complete JSON payloads so the
            // fuzzer can reach an unsafe merge/set path (the GF-509 detector then
            // confirms the pollution). The full-payload tokens let a JSON.parse-based
            // merge — the common vulnerable shape — be reached by splicing one token.
            for v in [
                "__proto__",
                "constructor",
                "prototype",
                "{\"__proto__\":{\"gfpp\":1}}",
                "{\"constructor\":{\"prototype\":{\"gfpp\":1}}}",
                "__proto__.gfpp",
            ] {
                if !toks.iter().any(|t| t == v) {
                    toks.push(v.to_owned());
                }
            }
            Some(toks)
        }
        // Ruby carries no CmpLog in the interpreted driver, so a source-mined
        // dictionary is the lever past a multi-byte comparison gate.
        Lang::Ruby => Some(crate::auto::ruby::extract_ruby_dictionary_tokens(source)),
        Lang::Lua => Some(crate::auto::lua::extract_lua_dictionary_tokens(source)),
        Lang::Php => Some(crate::auto::php::extract_php_dictionary_tokens(source)),
        // COBOL/Fortran are fuzzed through the generated C; the dictionary comes from that C.
        Lang::Ada | Lang::C | Lang::Cpp | Lang::Cobol | Lang::Fortran => None,
    };
    let Some(tokens) = tokens else {
        return;
    };
    if tokens.is_empty() || harness_dir.join("dictionary.txt").exists() {
        return;
    }
    let _ = crate::generate_harness::write_harness_dictionary(harness_dir, &tokens);
}

/// The engines from the user's `--engine` preference list that actually apply to
/// a target of this language, preserving order. AFL++ is C/C++ only (the `afl`
/// make target + `#ifdef GOVFUZZ_AFL` persistent harness exist only for the C/C++
/// runtimes; Ada=gprbuild, Rust=cargo-fuzz, Java=Jazzer have no AFL path). If
/// filtering would leave nothing (e.g. `--engine afl++` on an Ada target), fall
/// back to the builtin engine so the target is never silently left unfuzzed.
/// #95: true when govfuzz's harness for this language injects a target-entry
/// probe that fires immediately before the selected project endpoint — C/C++
/// (`GOVFUZZ_TARGET_ENTER`, compiled into `main` via `-DGOVFUZZ_EXTERNAL_DRIVER`)
/// and Ada (`AdaFuzz.Probe.Target_Entry`, emitted unconditionally by the `.adb`
/// templates). Interpreted and managed lanes (Rust/Go/Java/Python/Perl/Ruby/Lua/
/// PHP/JS/C#/COBOL/Fortran) speak the framed protocol for coverage but do NOT
/// emit a target-entry event, so their `target_entry_observed` is always false;
/// the #95 success invariant must NOT be applied to them, because absence of
/// proof there is "not instrumented", not "not entered".
pub(crate) fn harness_emits_target_entry_proof(lang: crate::auto::candidate::Lang) -> bool {
    use crate::auto::candidate::Lang;
    matches!(lang, Lang::C | Lang::Cpp | Lang::Ada)
}

/// #95: decide whether a built+fuzzed cascade must be DEMOTED to
/// `built_not_entered` because it never entered the target, returning the stable
/// `(entry_miss, reason)` pair, or `None` when the run is a legitimate
/// `built_and_fuzzed`.
///
/// Returns `None` (no demotion) when the lane does not instrument target entry
/// (interpreted/managed lanes have no entry probe, so absence of proof is "not
/// instrumented", not "not entered"), when no entry-instrumented (builtin-engine)
/// pass ran so entry could not be proven either way (e.g. an afl-only native
/// cascade), or when at least one pass DID observe target entry. Otherwise the
/// target was genuinely never entered and the sub-reason names why.
pub(crate) fn entry_miss_classification(
    lang: crate::auto::candidate::Lang,
    pass_runs: &[PassRun],
    stub_only: bool,
) -> Option<(String, String)> {
    if !harness_emits_target_entry_proof(lang) {
        return None;
    }
    let entry_instrumented_pass_ran = pass_runs.iter().any(|p| p.engine == "builtin");
    let any_target_entry = pass_runs.iter().any(|p| p.target_entry_observed);
    if !entry_instrumented_pass_ran || any_target_entry {
        return None;
    }
    let total_execs: usize = pass_runs.iter().map(|p| p.executions).sum();
    Some(if stub_only {
        (
            "stub_only".to_owned(),
            format!(
                "harness executed {total_execs} time(s) but every external symbol was a blind \
                 stub — only empty stub bodies ran and the real target was never entered"
            ),
        )
    } else if total_execs == 0 {
        (
            "no_execution".to_owned(),
            "harness built but no fuzz iteration executed, so the target was never entered"
                .to_owned(),
        )
    } else {
        (
            "decode_or_bailout".to_owned(),
            format!(
                "harness executed {total_execs} time(s) but no pass reached the target-entry \
                 checkpoint — inputs were decode-rejected or the harness bailed before the endpoint"
            ),
        )
    })
}

pub(crate) fn applicable_engines(
    lang: crate::auto::candidate::Lang,
    requested: &[FuzzEngine],
) -> Vec<FuzzEngine> {
    use crate::auto::candidate::Lang;
    let is_c_family = matches!(lang, Lang::C | Lang::Cpp);
    let mut out: Vec<FuzzEngine> = requested
        .iter()
        .copied()
        .filter(|engine| match engine {
            FuzzEngine::Builtin => true,
            FuzzEngine::AflPlusPlus => is_c_family,
        })
        .collect();
    if out.is_empty() {
        out.push(FuzzEngine::Builtin);
    }
    out
}

/// True when both `afl-fuzz` and `afl-clang-fast` resolve on PATH — the minimum
/// to build `main_afl` and drive AFL. Probed once per run by the caller.
pub(crate) fn afl_toolchain_available() -> bool {
    which_on_path("afl-fuzz") && which_on_path("afl-clang-fast")
}

fn which_on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// Drop AFL++ from the engine list when its toolchain is absent, preserving
/// order; never returns empty (falls back to builtin). The run-level caller warns
/// once when AFL was requested but pruned.
pub(crate) fn prune_engines_for_toolchain(
    engines: &[FuzzEngine],
    afl_available: bool,
) -> Vec<FuzzEngine> {
    let mut out: Vec<FuzzEngine> = engines
        .iter()
        .copied()
        .filter(|engine| !matches!(engine, FuzzEngine::AflPlusPlus) || afl_available)
        .collect();
    if out.is_empty() {
        out.push(FuzzEngine::Builtin);
    }
    out
}

/// Split a per-target wall budget evenly across the engines running for that
/// target. Never returns zero for a positive input (a 1s budget over 4 engines
/// still gives each a nonzero slice).
pub(crate) fn per_engine_budget(per_target: Duration, engine_count: usize) -> Duration {
    let n = engine_count.max(1) as u32;
    let split = per_target / n;
    if per_target > Duration::ZERO && split.is_zero() {
        Duration::from_millis(1)
    } else {
        split
    }
}

pub fn attempt(
    candidate: &Candidate,
    work_dir: &Path,
    decl_index: &DeclarationIndex,
    options: AttemptOptions,
) -> Result<AttemptResult> {
    attempt_with_progress(
        candidate,
        work_dir,
        decl_index,
        options,
        &crate::auto::progress::NoProgress,
    )
}

pub fn attempt_with_progress(
    candidate: &Candidate,
    work_dir: &Path,
    decl_index: &DeclarationIndex,
    options: AttemptOptions,
    progress: &dyn crate::auto::progress::ProgressSink,
) -> Result<AttemptResult> {
    // M22: a candidate whose detected dialect has no fuzzing lane yet (a legacy
    // dialect awaiting its phase) is not silently dropped — it is discovered +
    // statically analyzed (CWE-tagged findings) and reported as report-only,
    // never fuzzed. This fires as soon as a lane's fallback discovery surfaces a
    // legacy-dialect candidate; modern dialects fall through to the normal path.
    if let Some(dialect) = candidate.dialect {
        if dialect.fuzz_support() == lang_profile::FuzzSupport::ReportOnly {
            let harness_dir = crate::auto::layout::harness_dir(work_dir, &candidate.harness_id);
            std::fs::create_dir_all(&harness_dir)?;
            let reason = format!(
                "{}: legacy dialect — discovered and statically analyzed, not fuzzed (M22)",
                dialect.label()
            );
            let outcome = crate::auto::report_only::emit_report_only(candidate, reason, work_dir);
            return Ok(AttemptResult {
                candidate: candidate.clone(),
                outcome,
                harness_dir,
            });
        }
    }
    // Prefer the richer sequence harness for lifecycle candidates, but a
    // sequence bundles several operations and one that won't compile (a
    // `#ifdef`-gated method, an inaccessible overload) sinks the whole
    // harness. If a sequence candidate fails to build, retry once forcing a
    // direct harness — a single target call + constructed receiver compiles
    // far more often — and keep it if it builds.
    let no_stubs = options.no_stubs;
    let force = options.force;
    // A sibling target in this same source already drove the repair cascade to
    // exhaustion and could not build. Nothing about THIS target changes the
    // closure, and the project-level repair state has not moved since (the memo
    // is discarded outright when it does), so re-running the cascade would spend
    // a full round budget reaching the identical verdict.
    let mut memo = crate::auto::closure_memo::ClosureMemo::load(work_dir, force);
    let memoized = memo
        .terminal_failure_for(&candidate.source_path)
        .map(|entry| Outcome::FailedBuild {
            repairs: Vec::new(),
            retries: entry.rounds,
            last_errors: entry.errors.clone(),
        });
    // A memo hit substitutes for the CASCADE, not for everything downstream. The
    // outcome still flows through the degradation below, so a target that hits
    // the memo reports exactly what its sibling reported — the memo changes what
    // work is done, never what is said about it.
    let result = match memoized {
        Some(outcome) => {
            let harness_dir = crate::auto::layout::harness_dir(work_dir, &candidate.harness_id);
            std::fs::create_dir_all(&harness_dir)?;
            AttemptResult {
                candidate: candidate.clone(),
                outcome,
                harness_dir,
            }
        }
        None => run_attempt(
            candidate,
            work_dir,
            decl_index,
            options.clone(),
            progress,
            false,
        )?,
    };
    let result = if matches!(result.outcome, Outcome::FailedBuild { .. })
        && auto_sequence_candidate(candidate)
    {
        let mut direct = run_attempt(candidate, work_dir, decl_index, options, progress, true)?;
        if matches!(
            direct.outcome,
            Outcome::BuiltAndFuzzed { .. }
                | Outcome::Built { .. }
                | Outcome::BuiltNotEntered { .. }
        ) {
            return Ok(direct);
        }
        retain_sequence_failure(&result.outcome, &mut direct.outcome);
        direct
    } else {
        result
    };
    // Remember an exhausted cascade so the next target in this source inherits
    // the verdict instead of rediscovering it. Only failures that describe the
    // CLOSURE are recorded; the memo declines anything naming the generated
    // harness, which is particular to this one target.
    if let Outcome::FailedBuild {
        last_errors,
        retries,
        ..
    } = &result.outcome
    {
        memo.record(&candidate.source_path, last_errors, *retries);
        memo.save(work_dir);
    }
    // Graceful degradation: a build that failed ONLY because it references types
    // undefined in the scanned tree — an external SDK/framework the offline lab
    // cannot supply (MFC `CString`/`CWnd`, a vendor CORBA type, a platform SDK
    // struct) — cannot be COMPILED here no matter what we stub. Rather than a bare
    // `failed_build`, run the static analyzer over the source (report-only,
    // CWE-tagged findings) with a reason that names the missing types, so the user
    // still gets value ("fuzz the source"). `--no-stubs` (diagnostics mode) keeps
    // the raw failure so the missing-type manifest blocker is surfaced verbatim.
    // Under `--force`, SKIP this early degradation: force stubs undefined types and
    // uses report-only only as a terminal floor (a later Phase-2 task), so here the
    // FailedBuild passes through unchanged instead of degrading to a static scan.
    if !no_stubs && !force {
        if let Outcome::FailedBuild {
            last_errors,
            repairs,
            ..
        } = &result.outcome
        {
            // A missing type the repair loop turned into a `TypePlaceholder` is a
            // SYNTHESIZABLE gap (a typedef the upstream maintainer didn't ship,
            // surfaced in `needed_for_build.synthesized_types` as an actionable
            // item) — not an unsynthesizable external-SDK type. Keeping it as a
            // `failed_build` preserves that manifest; only a type repair could NOT
            // stub (a pimpl `IncompleteType`, whose definition lives in an
            // uncompiled source) degrades to a report-only static scan.
            let synthesized: BTreeSet<String> = repairs
                .iter()
                .filter_map(|r| match r {
                    Repair::TypePlaceholder { type_name } => Some(type_name.clone()),
                    _ => None,
                })
                .collect();
            if let Some(missing) = undefined_external_types_for_lang(
                last_errors,
                decl_index,
                &synthesized,
                result.candidate.lang,
            ) {
                let reason = format!(
                    "requires type(s) the generated harness cannot construct offline ({}) — an \
                     external SDK/framework type (e.g. MFC/Win32, a vendor CORBA IDL) unavailable \
                     here, or a type whose definition is not visible to the harness translation \
                     unit; statically analyzed, not fuzzed",
                    missing.join(", ")
                );
                let harness_dir = result.harness_dir.clone();
                let outcome =
                    crate::auto::report_only::emit_report_only(&result.candidate, reason, work_dir);
                return Ok(AttemptResult {
                    candidate: result.candidate,
                    outcome,
                    harness_dir,
                });
            }
        }
    }
    // Terminal `--force` floor: force stubs aggressively (Task 4), but a target
    // that STILL won't build after `--max-repair-rounds` — a genuinely broken TU,
    // a type used by-value an opaque placeholder can't satisfy — must never surface
    // as a bare `failed_build`. Degrade any residual force `FailedBuild` to a
    // report-only static scan (CWE-tagged findings over the source) so a static
    // scan is the floor: report-only, never hard-fail. `--no-stubs` (diagnostics
    // mode) keeps the raw failure. Non-force is untouched.
    if force && !no_stubs {
        if let Outcome::FailedBuild {
            retries,
            last_errors,
            ..
        } = &result.outcome
        {
            let reason = format!(
                "forced: unbuildable after {} repair round(s) ({} residual build \
                 error(s) the diagnostic-driven stubbing could not resolve); \
                 statically analyzed, not fuzzed",
                retries,
                last_errors.len()
            );
            let harness_dir = result.harness_dir.clone();
            let outcome =
                crate::auto::report_only::emit_report_only(&result.candidate, reason, work_dir);
            return Ok(AttemptResult {
                candidate: result.candidate,
                outcome,
                harness_dir,
            });
        }
    }
    Ok(result)
}

fn retain_sequence_failure(sequence: &Outcome, direct: &mut Outcome) {
    let Outcome::FailedBuild {
        last_errors: sequence_errors,
        ..
    } = sequence
    else {
        return;
    };
    let sequence_json = serde_json::to_string(sequence_errors)
        .unwrap_or_else(|_| format!("{} classified error(s)", sequence_errors.len()));
    match direct {
        Outcome::FailedBuild { last_errors, .. } => {
            last_errors.push(BuildErrorKind::Other {
                tail: format!(
                    "sequence harness failed before the direct fallback; sequence diagnostics: {sequence_json}"
                ),
            });
        }
        Outcome::UnsupportedParams { reason } => {
            reason.push_str(&format!(
                "; sequence harness build also failed first: {sequence_json}"
            ));
        }
        _ => {}
    }
}

#[cfg(test)]
mod sequence_fallback_tests {
    use super::{retain_sequence_failure, Outcome};
    use build_classifier::BuildErrorKind;

    fn sequence_failure() -> Outcome {
        Outcome::FailedBuild {
            repairs: Vec::new(),
            retries: 2,
            last_errors: vec![BuildErrorKind::MissingType {
                name: "SequenceOnlyType".to_owned(),
            }],
        }
    }

    #[test]
    fn direct_unsupported_is_terminal_and_retains_sequence_diagnostic() {
        let mut direct = Outcome::UnsupportedParams {
            reason: "direct receiver cannot be initialized".to_owned(),
        };
        retain_sequence_failure(&sequence_failure(), &mut direct);
        let Outcome::UnsupportedParams { reason } = direct else {
            panic!("direct terminal outcome was replaced")
        };
        assert!(reason.contains("direct receiver cannot be initialized"));
        assert!(reason.contains("sequence harness build also failed first"));
        assert!(reason.contains("SequenceOnlyType"));
    }

    #[test]
    fn direct_build_failure_retains_both_error_chains() {
        let mut direct = Outcome::FailedBuild {
            repairs: Vec::new(),
            retries: 1,
            last_errors: vec![BuildErrorKind::Other {
                tail: "direct compile terminal".to_owned(),
            }],
        };
        retain_sequence_failure(&sequence_failure(), &mut direct);
        let Outcome::FailedBuild { last_errors, .. } = direct else {
            panic!("direct terminal outcome was replaced")
        };
        assert!(matches!(
            &last_errors[0],
            BuildErrorKind::Other { tail } if tail == "direct compile terminal"
        ));
        assert!(matches!(
            &last_errors[1],
            BuildErrorKind::Other { tail }
                if tail.contains("sequence harness failed") && tail.contains("SequenceOnlyType")
        ));
    }

    #[test]
    fn unsupported_trace_is_structured_and_never_implies_missing_repairs() {
        let outcome = Outcome::UnsupportedParams {
            reason: "C++ parameter 'value' has no byte-buffer decoder; sequence generation also failed first: constructor unavailable".to_owned(),
        };
        let trace = outcome.attempt_trace();
        assert_eq!(trace.terminal_stage, "generation");
        assert_eq!(
            trace.reason_category.as_deref(),
            Some("decoder_or_parameter")
        );
        assert!(!trace.repairs_attempted);
        assert_eq!(trace.repair_count, 0);
        assert_eq!(
            trace.fallback_chain,
            ["sequence_failed", "direct_unsupported"]
        );
        let json = serde_json::to_value(trace).unwrap();
        assert_eq!(json["repairs_attempted"], false);
        assert!(json["fallback_chain"].is_array());
    }
}

/// When a build failed and EVERY unresolved error is a type that is undefined in
/// the scanned tree (a non-codegen `MissingType` the repair loop could not resolve
/// from any in-tree definition), the target references an external SDK/framework
/// the offline lab cannot supply — MFC (`CString`/`CWnd`/`CDataExchange`), a
/// vendor CORBA IDL type, a platform SDK struct. Such a target can never COMPILE
/// here, so it should degrade to a report-only static scan rather than count as a
/// bare `failed_build`. Returns the sorted/deduped missing type names, or `None`
/// if the failure has ANY other cause (a link error, a missing header that maps to
/// a real package, or a codegen recovery artifact) that the dependency manifest
/// should keep surfacing as actionable.
#[cfg(test)]
fn undefined_external_types(
    last_errors: &[BuildErrorKind],
    decl_index: &DeclarationIndex,
    synthesized: &BTreeSet<String>,
) -> Option<Vec<String>> {
    undefined_external_types_for_lang(
        last_errors,
        decl_index,
        synthesized,
        crate::auto::candidate::Lang::Cpp,
    )
}

fn undefined_external_types_for_lang(
    last_errors: &[BuildErrorKind],
    decl_index: &DeclarationIndex,
    synthesized: &BTreeSet<String>,
    lang: crate::auto::candidate::Lang,
) -> Option<Vec<String>> {
    if last_errors.is_empty() {
        return None;
    }
    // Types the repair loop placeholder-synthesized (an opaque `void *`/scalar
    // `typedef`) for a missing type that is NOT defined anywhere in the compiled
    // source. Such a type is an unsuppliable EXTERNAL type (MFC `CString`, a vendor
    // SDK class). When the target uses it as a *class* — member calls, `->`,
    // construction — the opaque placeholder is wrong: the rebuild fails with generic
    // `Other` diagnostics ("called object type '…' is not a function", "… is not a
    // structure or union", "cannot initialize a member subobject") instead of the
    // original "unknown type name". Those residual errors are the placeholder's
    // fault, not a real codegen bug, so the target should still degrade to a
    // report-only scan. An in-tree synthesizable gap (a config typedef the tree
    // really is missing) is NOT in this set — it keeps its `failed_build` so the
    // `synthesized_types` manifest is preserved.
    let external_placeholders: Vec<&String> = synthesized
        .iter()
        .filter(|name| !decl_index.type_defined_in_compiled_source(name))
        .collect();
    let mut names: Vec<String> = Vec::new();
    let mut saw_placeholder_class_misuse = false;
    for err in last_errors {
        match err {
            // A `MissingType` the repair loop already placeholder-synthesized is an
            // actionable synthesized gap, not an unsynthesizable external type —
            // skip it so the attempt keeps its `synthesized_types` manifest.
            BuildErrorKind::MissingType { name } if synthesized.contains(name) => {}
            BuildErrorKind::MissingType { name } if c_stub_gen::c_std_header(name).is_some() => {
                // Standard/POSIX names are provided by the host SDK. A retained
                // sequence attempt may not carry the direct fallback's header
                // repair manifest, but that cannot turn `size_t` into an external
                // project dependency.
                return None;
            }
            BuildErrorKind::MissingType { name }
                if !build_classifier::is_codegen_error(err)
                    && !decl_index.type_defined_in_compiled_source(name) =>
            {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
            // A forward-declared-but-undefined type (pimpl / private impl). Its
            // definition lives either in a source the offline harness never compiles
            // OR in a header the generated harness TU does not `#include` — either
            // way the harness can never complete it (an `IncompleteType` is
            // deliberately never repaired, so a persistent one at the final outcome
            // is unrecoverable). Degrade to a report-only static scan.
            BuildErrorKind::IncompleteType { name }
                if matches!(lang, crate::auto::candidate::Lang::C)
                    && decl_index.type_defined_in_compiled_source(name) =>
            {
                // In C, a complete in-tree struct surfacing as incomplete is an
                // include/source-recovery problem, not an unavailable SDK type.
                // Preserve the failed build so the repair loop/report names the
                // actionable error (zlib's `struct inflate_state`). C++ pimpls
                // remain report-only because their private definition can be
                // intentionally invisible to an external harness.
                return None;
            }
            BuildErrorKind::IncompleteType { name } if c_stub_gen::c_std_header(name).is_none() => {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
            // A standard/POSIX incomplete type is a missing include, not an
            // unavailable external SDK. The repair planner injects its real host
            // header; if it persists, retain the build failure for diagnosis.
            BuildErrorKind::IncompleteType { .. } => return None,
            // A generic diagnostic left behind by placeholdering an out-of-tree type
            // that is actually a class. Tolerated ONLY when we DID placeholder such a
            // type and the tail is the tell-tale scalar-used-as-class shape; any
            // other `Other` (a genuine codegen bug, a link error) keeps the
            // failed_build so the dependency manifest still surfaces it.
            BuildErrorKind::Other { tail }
                if !external_placeholders.is_empty()
                    && other_error_is_placeholder_class_misuse(tail) =>
            {
                saw_placeholder_class_misuse = true;
            }
            _ => return None,
        }
    }
    if saw_placeholder_class_misuse {
        for name in &external_placeholders {
            if !names.contains(name) {
                names.push((*name).clone());
            }
        }
    }
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(names)
}

/// Whether an `Other` build diagnostic is the residue of placeholdering an
/// external CLASS type as an opaque scalar/`void *`: the compiler rejects the
/// class-shaped use of what is now a scalar. These phrasings only arise when a
/// value type is used with member/call/construction syntax it does not support,
/// so they are a reliable signal that the failure is downstream of an
/// unsuppliable external type — not a genuine govfuzz codegen bug (those carry
/// "no member named"/"use of undeclared identifier", handled by
/// `is_codegen_error`).
fn other_error_is_placeholder_class_misuse(tail: &str) -> bool {
    let lower = tail.to_ascii_lowercase();
    lower.contains("is not a function or function pointer")
        || lower.contains("is not a structure or union")
        || lower.contains("member reference base type")
        || lower.contains("cannot initialize a member subobject")
}

/// Clear and recreate a harness's `repairs/` directory at the start of an
/// attempt. Repair artefacts (auto_stubs.c, auto_types.h, synthesised headers)
/// are regenerated deterministically from the source + this run's build errors,
/// so a PRIOR run's artefacts must never carry over: the inner retry loop
/// appends to whatever auto_stubs.c it finds, so a reused work-dir would build
/// on a previous run's (possibly failed, possibly obsolete) stubs and re-break a
/// build the engine can otherwise compile. The corpus lives under
/// `<work>/corpus`, not here, so incremental corpus reuse across runs is
/// preserved — only the regenerable repair state is reset.
fn reset_repairs_dir(repairs_dir: &Path) -> std::io::Result<()> {
    if repairs_dir.exists() {
        std::fs::remove_dir_all(repairs_dir)?;
    }
    std::fs::create_dir_all(repairs_dir)
}

fn run_attempt(
    candidate: &Candidate,
    work_dir: &Path,
    decl_index: &DeclarationIndex,
    options: AttemptOptions,
    progress: &dyn crate::auto::progress::ProgressSink,
    force_direct: bool,
) -> Result<AttemptResult> {
    use crate::auto::progress::{Phase, ProgressUpdate};
    let harness_dir = crate::auto::layout::harness_dir(work_dir, &candidate.harness_id);
    std::fs::create_dir_all(&harness_dir)?;
    let repairs_dir = harness_dir.join("repairs");
    reset_repairs_dir(&repairs_dir)?;
    let mut manifest = RepairManifest::default();
    // Seed user-supplied `--extra-source` files so a multi-file library's real
    // translation units are compiled+linked on the first build attempt — the
    // cross-file symbols then resolve instead of being blind-stubbed (the repair
    // loop still AddSource-grows this for anything the user didn't pass).
    let mut extra_sources: Vec<PathBuf> = options.extra_sources.clone();
    // User-supplied --extra-source files are explicit and do not consume this
    // safety budget. Only project TUs selected automatically by repair count.
    let mut auto_project_sources = 0usize;
    // Seed user-supplied `--extra-include` dirs first so dependency headers
    // outside the swept tree resolve on the very first build attempt — before
    // the repair planner would otherwise placeholder them away.
    let mut extra_includes: Vec<PathBuf> = options.extra_include_dirs.clone();
    // The target's own source, read once, so the repair planner can synthesise a
    // real struct for a missing type the body field-accesses (cFE/PX4/fprime/seL4
    // overlay parsers) instead of an unusable `void *`. None for unreadable
    // sources; harmless for Ada (no C field_expression chains are found).
    let target_source = crate::source_text::read_source_text(&candidate.source_path).ok();

    // Magic-value dictionary for the interpreted/managed lanes. C/C++/Ada already
    // mine source literals into `dictionary.txt` at harness-gen; the Rust/Go/Java/
    // Python/Perl lanes otherwise fuzz "cold" and stall on `==`/match guards. Mine
    // their string+integer literals into the same AFL dictionary the builtin engine
    // loads (with LE/BE byte encodings of numeric constants). Best-effort — a parse
    // failure never fails the attempt, and we never clobber a dict already written.
    write_source_dictionary(&harness_dir, target_source.as_deref(), candidate.lang);

    // #402 budget plan. `--per-target-time` is the TOTAL per-target fuzz wall,
    // split evenly across the passes under one shared deadline; `--total-time`
    // (deprecated alias) overrides it when set. The per-target total is the
    // libFuzzer -max_total_time / AFL -V parity knob, regardless of pass count.
    let pass_count = options.passes.len().max(1) as u32;
    // Per-target engine selection (`auto --engine`): the run's engine list filtered
    // to those that apply to this candidate's language (AFL is C/C++ only; falls back
    // to builtin). The per-target fuzz budget splits evenly across the engines that
    // run for this target, so the per-target wall stays ≈ `--per-target-time`. For
    // the default single (builtin) engine this is byte-identical to before.
    let target_engines = applicable_engines(candidate.lang, &options.engines);
    let effective_total = options.total_time.unwrap_or(options.per_target_time);
    let engine_budget = per_engine_budget(effective_total, target_engines.len());
    let (per_pass_budget, total_wall_budget) = plan_pass_budget(engine_budget, None, pass_count);

    // Safety rails. The fuzz pass loop is the place where a shim
    // regression (eg. the void/void dlsym stub crash that killed a
    // VM last cycle) can fork-bomb the host: each non-zero exit
    // causes the orchestrator to respawn the worker. We brake on
    // two signals: 5 consecutive non-zero passes, or 3× the effective
    // per-target wall budget of fuzz-pass wall clock. Build and repair
    // time is excluded so large C++ projects don't get mislabeled as
    // runtime failures before their first fuzz pass.
    let absolute_cap = total_wall_budget
        .saturating_mul(3)
        .max(options.per_target_time.saturating_mul(10));
    const MAX_CRASHES_PER_TARGET: usize = 5;

    // Step 0 (Java, M2.1b/d): the native Java lane. Compile the target with javac,
    // generate + compile a govfuzz harness, and emit `harnesses/<id>/main` — a launcher
    // that runs the target in a persistent JVM under govfuzz's own coverage agent.
    // On success the build below is a pass-through that finds the launcher and
    // drops into the SAME builtin-engine fuzz cascade (the JVM speaks the framed
    // fork-server protocol + writes the shared coverage map, so the engine drives
    // it like any sancov harness). A missing JDK or an un-harnessable target skips
    // cleanly — the GNAT-less rule.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Java) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::java_build::build_java_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::java_build::JavaBuildResult::Built => {
                // harnesses/<id>/main now exists; the build pass-through finds it and
                // the shared fuzz cascade drives the JVM. Fall through.
            }
            crate::auto::java_build::JavaBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0 (Python, M3.1): the native Python lane. Generate a govfuzz harness
    // module + copy the python_runtime (decode/cov/driver), then emit
    // `harnesses/<id>/main` — a launcher that runs the target under a persistent CPython
    // speaking the framed fork-server protocol with `sys.monitoring` edge coverage.
    // On success the build below is a pass-through that finds the launcher and drops
    // into the SAME builtin-engine fuzz cascade. A missing `python3` or an
    // un-harnessable target skips cleanly — the GNAT-less rule.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Python) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::python_build::build_python_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::python_build::PythonBuildResult::Built => {
                // harnesses/<id>/main now exists; the build pass-through finds it and the
                // shared fuzz cascade drives the interpreter. Fall through.
            }
            crate::auto::python_build::PythonBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0 (Perl, M3.2): the native Perl lane. Generate a govfuzz harness module
    // + copy the perl_runtime (driver + Devel::GovfuzzCov), then emit
    // `harnesses/<id>/main` — a launcher that runs the target under `perl -d:GovfuzzCov`
    // speaking the framed fork-server protocol with DB::DB edge coverage. A missing
    // `perl` or an un-harnessable target skips cleanly — the GNAT-less rule.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Perl) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::perl_build::build_perl_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::perl_build::PerlBuildResult::Built => {}
            crate::auto::perl_build::PerlBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0 (Ruby, M3.9): the native Ruby lane. Generate a harness that requires the
    // target and calls the method, copy the ruby_runtime driver, emit the launcher,
    // then drop into the shared builtin-engine cascade. A missing `ruby` interpreter,
    // an un-loadable target, or an un-harnessable signature skips cleanly.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Ruby) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::ruby_build::build_ruby_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::ruby_build::RubyBuildResult::Built => {}
            crate::auto::ruby_build::RubyBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0 (Lua, M3.10): the native Lua lane. Generate a harness that `dofile`s the
    // target and calls the function, copy the lua_runtime driver, emit the launcher,
    // then drop into the shared builtin-engine cascade. A missing `lua` interpreter,
    // an un-loadable target, or an un-harnessable signature skips cleanly.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Lua) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::lua_build::build_lua_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::lua_build::LuaBuildResult::Built => {}
            crate::auto::lua_build::LuaBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0 (PHP, M3.11): the native PHP lane. Generate a harness that `require`s the
    // target and calls the function, copy the php_runtime driver, emit the launcher
    // (with pcov coverage), then drop into the shared builtin-engine cascade. A missing
    // `php` interpreter, an un-loadable target, or an un-harnessable signature skips
    // cleanly.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Php) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::php_build::build_php_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::php_build::PhpBuildResult::Built => {}
            crate::auto::php_build::PhpBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0 (Go, M3.3): the native Go lane. Generate a harness `main` that imports
    // the target package via a module `replace`, `go build` it to `harnesses/<id>/main`
    // (a framed fork-server binary that recovers panics into findings), then drop
    // into the shared builtin-engine cascade. A missing `go` toolchain, a target
    // outside a module, or an un-harnessable signature skips cleanly.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Go) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::go_build::build_go_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::go_build::GoBuildResult::Built => {}
            crate::auto::go_build::GoBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0: COBOL lane (M3.4). Translate the subprogram to C (`cobc -C`), wrap it
    // in a generated LLVMFuzzerTestOneInput glue that fills the PIC X(N) LINKAGE
    // buffer from the fuzz bytes, and build on the passthrough C fork-server path —
    // reusing edge coverage, cmplog, and ASan (plus libcob `-fec` runtime aborts).
    // On success the build below is a pass-through. A missing `cobc` or a program
    // with no fuzzable LINKAGE surface skips cleanly.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Cobol) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        match crate::auto::cobol_build::build_cobol_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
        ) {
            crate::auto::cobol_build::CobolBuildResult::Built => {}
            crate::auto::cobol_build::CobolBuildResult::Skip(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams { reason },
                    harness_dir,
                });
            }
            crate::auto::cobol_build::CobolBuildResult::Failed(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0: Fortran lane (M3.5). Compile the .f90 with gfortran (ASan + trace-pc
    // coverage + `-fcheck`), wrap it in a glue that calls the routine via the
    // gfortran C ABI, and build on the passthrough C fork-server path. ASan reports
    // memory corruption as a genuine crash with the `.f90:line` — no exit()
    // interposition needed (unlike COBOL).
    if matches!(candidate.lang, crate::auto::candidate::Lang::Fortran) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        let source_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        match crate::auto::fortran_build::build_fortran_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
            &source_root,
        ) {
            crate::auto::fortran_build::FortranBuildResult::Built => {}
            crate::auto::fortran_build::FortranBuildResult::Skip(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams { reason },
                    harness_dir,
                });
            }
            crate::auto::fortran_build::FortranBuildResult::Failed(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0: C# / .NET lane (M3.6). Build the target assembly (`dotnet build`),
    // instrument its IL with SharpFuzz (edge coverage into the shared map), and emit
    // a launcher `main` that drives a warm CLR over the framed fork-server protocol.
    // No native binary: the launcher execs `dotnet <harness>.dll` (like Java/Python).
    // A missing dotnet SDK / SharpFuzz tool, or a target with no fuzzable input
    // parameter, skips cleanly.
    if matches!(candidate.lang, crate::auto::candidate::Lang::CSharp) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        match crate::auto::csharp_build::build_csharp_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
        ) {
            crate::auto::csharp_build::CSharpBuildResult::Built => {}
            crate::auto::csharp_build::CSharpBuildResult::Skip(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams { reason },
                    harness_dir,
                });
            }
            crate::auto::csharp_build::CSharpBuildResult::Failed(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0: JavaScript / Node.js lane (M3.7). Resolve the target module, `node -c`
    // syntax-check it, copy the framed driver, and emit a launcher `main` that execs
    // `node` on the driver. No native binary: the driver drives the framed protocol +
    // V8 coverage (like Python/Perl). A missing node, or a target that no longer
    // parses, skips cleanly.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Js) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        match crate::auto::js_build::build_js_harness(candidate, work_dir, &candidate.harness_id) {
            crate::auto::js_build::JsBuildResult::Built => {}
            crate::auto::js_build::JsBuildResult::Skip(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams { reason },
                    harness_dir,
                });
            }
            crate::auto::js_build::JsBuildResult::Failed(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0: TypeScript lane (M3.8). Transpile the .ts target to CommonJS .js with
    // esbuild, then drive it with the same Node framed driver as the JS lane.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Ts) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        match crate::auto::js_build::build_ts_harness(candidate, work_dir, &candidate.harness_id) {
            crate::auto::js_build::JsBuildResult::Built => {}
            crate::auto::js_build::JsBuildResult::Skip(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams { reason },
                    harness_dir,
                });
            }
            crate::auto::js_build::JsBuildResult::Failed(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // Step 0a: the native Rust lane (M1.2). Generate the govfuzz harness, build
    // it as a sancov+ASan staticlib with rustc-nightly, and clang-link it with
    // the shared C fork-server driver to `<work>/harnesses/<id>/main`. On success the
    // build below is a no-op pass-through that drops straight into the SAME
    // builtin-engine fuzz cascade C/C++ uses (the binary is a native sancov +
    // fork-server harness, so the engine drives it unchanged). A missing nightly
    // toolchain or an un-harnessable signature skips cleanly with a precise
    // reason — the GNAT-less rule — instead of a spurious build failure.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Rust) {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        match crate::auto::rust_build::build_rust_harness(
            candidate,
            work_dir,
            &candidate.harness_id,
        ) {
            crate::auto::rust_build::RustBuildResult::Built => {
                // The binary now exists at harnesses/<id>/main; the repair loop's
                // try_build sees it (try_build_rust returns Success) and runs the
                // shared fuzz cascade. Fall through.
            }
            crate::auto::rust_build::RustBuildResult::Failed { reason, skip } => {
                if skip {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnsupportedParams { reason },
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::FailedBuild {
                        repairs: Vec::new(),
                        retries: 0,
                        last_errors: build_classifier::classify(&reason),
                    },
                    harness_dir,
                });
            }
        }
    }

    // The Rust lane already generated + built its harness in Step 0a (the
    // staticlib + driver are linked at `harnesses/<id>/main`), so it skips the
    // C/Ada-specific pre-skip, harness-gen, single-header, and foreign-strategy
    // steps below and goes straight to the repair loop, whose `try_build`
    // pass-through finds the prebuilt binary and drops into the shared fuzz
    // cascade.
    let is_rust = matches!(candidate.lang, crate::auto::candidate::Lang::Rust);
    // Rust AND Java already produced their `harnesses/<id>/main` in Step 0 (a native
    // sancov staticlib+driver / a JVM launcher), so both skip the C/Ada-specific
    // pre-skip, foreign-strategy, harness-gen, and single-header steps and go
    // straight to the repair loop's build pass-through + shared fuzz cascade.
    let is_prebuilt = is_rust
        || matches!(
            candidate.lang,
            crate::auto::candidate::Lang::Java
                | crate::auto::candidate::Lang::Python
                | crate::auto::candidate::Lang::Perl
                | crate::auto::candidate::Lang::Go
                | crate::auto::candidate::Lang::Cobol
                | crate::auto::candidate::Lang::Fortran
                | crate::auto::candidate::Lang::CSharp
                | crate::auto::candidate::Lang::Js
                | crate::auto::candidate::Lang::Ts
                | crate::auto::candidate::Lang::Ruby
                | crate::auto::candidate::Lang::Lua
                | crate::auto::candidate::Lang::Php
        );

    // Step 0: pre-skip targets that can never link/run from an
    // external harness. Cheaper than burning a build+repair cycle,
    // and the reason is precise instead of a compiler error.
    if !is_prebuilt
        && !options.force
        && candidate.is_static
        && !static_candidate_can_include_defining_source(candidate)
    {
        return Ok(AttemptResult {
            candidate: candidate.clone(),
            outcome: Outcome::UnsupportedParams {
                reason: "function has internal linkage (static) and this language path cannot \
                         include the defining source into the generated harness"
                    .to_owned(),
            },
            harness_dir,
        });
    }
    // Pre-skip an Ada compilation unit that is a project Main executable
    // (declared `for Main use (...)` in a `.gpr` under the sweep tree). A Main is
    // a program ENTRY POINT — it `with`s the library and runs as an executable —
    // not a library subprogram a separately compiled harness can call: a
    // direct-call harness emits `with Unit; ... Unit;`, which GNAT rejects with
    // "procedure or entry name expected". Skip with a precise reason instead of
    // burning a build that always fails (so a Main reads as `skipped`, never
    // `failed_build`). Matched by the SPECIFIC source file the gpr named (keys are
    // canonicalized), so an identically-named library unit elsewhere is unaffected.
    if !is_prebuilt && !options.force && matches!(candidate.lang, crate::auto::candidate::Lang::Ada)
    {
        let canonical = candidate
            .source_path
            .canonicalize()
            .unwrap_or_else(|_| candidate.source_path.clone());
        if let Some(gpr) = options.ada_main_sources.get(&canonical) {
            return Ok(AttemptResult {
                candidate: candidate.clone(),
                outcome: Outcome::UnsupportedParams {
                    reason: format!(
                        "Ada target '{}' is a project main executable (declared in {gpr} \
                         `for Main`) — an entry point, not a library subprogram; not \
                         auto-harnessable as a direct call.",
                        candidate.name
                    ),
                },
                harness_dir,
            });
        }
    }
    // Pre-skip a C++ method whose owning class is DEFINED only in a `.cpp`/`.cc`
    // translation unit and is never declared in any header. The generated harness
    // `#include`s the project header, so an out-of-line-only class (json11's
    // `JsonParser`, defined in json11.cpp, absent from json11.hpp) is an undefined
    // type in the harness TU — a guaranteed failed build. This is the C++ analog of
    // the Rust "reachable only through a private module" skip. A class declared
    // (even forward-declared) in a header, with its methods defined out-of-line in a
    // `.cpp`, is the NORMAL case and is NOT skipped; nor is a free function whose
    // qualified name carries only a namespace (never a recorded class name).
    //
    // Gated on the harness actually including a HEADER for this source: when the
    // defining `.cpp` has no header at all, the C++ harness `#include`s the `.cpp`
    // itself (cpp_generate's `include_source_for_receiver` fallback), making a
    // `.cpp`-local class fully visible and buildable — so a header-less single-TU
    // class (no public interface, the common "one .cpp" case) must NOT be skipped.
    if !is_prebuilt && !options.force && matches!(candidate.lang, crate::auto::candidate::Lang::Cpp)
    {
        if let Some(class) = cpp_owner_class(&candidate.name) {
            let source_dir = candidate
                .source_path
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let harness_includes_a_header = !crate::generate_harness::auto_detect_c_headers(
                &candidate.source_path,
                &source_dir,
            )
            .is_empty();
            if harness_includes_a_header
                && decl_index.cpp_class_defined_only_in_translation_unit(class)
            {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams {
                        reason: format!(
                            "C++ target '{}' is a member of class '{class}' defined only in a \
                             .cpp translation unit (not declared in any header) — not reachable \
                             from an external harness",
                            candidate.name
                        ),
                    },
                    harness_dir,
                });
            }
        }
    }
    // Pre-skip the DOOMED compile when a C++ target's RETURN type is a bare
    // identifier undefined anywhere in the scanned tree and not a primitive/std
    // type — an external framework type like MFC `CString`. The harness captures
    // the return by value (`<ret> R = _gf_receiver.method(...)`), so an undefined
    // return type is a guaranteed MissingType build failure; route it STRAIGHT to
    // the same report-only static scan the post-build fallback would produce, but
    // without burning the build. `--no-stubs` (diagnostics) keeps the raw compile.
    if !is_prebuilt
        && !options.force
        && !options.no_stubs
        && matches!(candidate.lang, crate::auto::candidate::Lang::Cpp)
    {
        if let Some(missing) = cpp_target_undefined_return_type(candidate, decl_index) {
            // A known Win32 typedef (`BOOL`, `DWORD`, `PUCHAR`, …) is NOT an
            // unsuppliable external type: the repair loop injects the Win32 stub pack
            // (real underlying typedefs), so let it proceed to build+repair instead of
            // pre-skipping to report-only. An MFC *class* return type (`CString`) is
            // NOT exempted — a minimal class stub can't satisfy real methods, so it
            // still degrades to the report-only scan.
            if !crate::auto::cross_target::is_win32_known_name(&missing) {
                let reason = format!(
                    "C++ target '{}' return type '{missing}' is undefined in the scanned tree — \
                     likely an external SDK/framework (e.g. MFC/Win32) unavailable offline; \
                     statically analyzed, not fuzzed",
                    candidate.name
                );
                let outcome =
                    crate::auto::report_only::emit_report_only(candidate, reason, work_dir);
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome,
                    harness_dir,
                });
            }
        }
    }
    // A foreign-platform/arch candidate (discovery tagged its definition with a
    // non-host `foreign_guard`) is NO LONGER pre-skipped. Pick a strategy:
    //   - Cross: an arch guard, OR a Windows guard with mingw+wine installed →
    //     cross-compile to the target binary/PE and fuzz under qemu-user / wine,
    //     exercising the target's REAL foreign behavior (#b).
    //   - StubIsolated: a Windows guard with NO mingw/wine → build NATIVELY with
    //     `_WIN32` defined and a fake `windows.h`, fuzzing the portable logic with
    //     real host ASan/coverage; findings are reduced-fidelity (#c).
    //   - else → skip with an actionable reason naming what's missing.
    // `Native` (no foreign_guard) is byte-identical to before.
    let strategy: ForeignStrategy = match &candidate.foreign_guard {
        // A prebuilt (Rust/Java) harness is always the Native path — cargo
        // resolves `#[cfg]` and the JVM is host-native, so no cross/stub applies.
        _ if is_prebuilt => ForeignStrategy::Native,
        Some(guard) => match resolve_foreign_strategy(candidate, guard) {
            Ok(strategy) => strategy,
            Err(reason) => {
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams { reason },
                    harness_dir,
                });
            }
        },
        None => ForeignStrategy::Native,
    };
    let cross_compiler = match &strategy {
        ForeignStrategy::Cross(target) => Some(cross_compiler_override(target)),
        ForeignStrategy::Native | ForeignStrategy::StubIsolated(_) => None,
    };
    let cross_runner = match &strategy {
        ForeignStrategy::Cross(target) => Some(cross_harness_wrapper(target)),
        ForeignStrategy::Native | ForeignStrategy::StubIsolated(_) => None,
    };

    // Resolve which engines actually RUN for this target now that cross-ness is
    // known. AFL applies only to NATIVE C/C++ targets — its compile-time
    // instrumentation (afl-clang-fast) is meaningless under qemu-user/wine
    // emulation. If AFL was the only selected engine but the target is
    // cross-compiled, fall back to the builtin (emulated) cascade so the target is
    // still fuzzed rather than silently left unfuzzed.
    let run_afl = target_engines.contains(&FuzzEngine::AflPlusPlus) && cross_runner.is_none();
    let run_builtin = target_engines.contains(&FuzzEngine::Builtin) || !run_afl;

    // Step 1: try to generate the harness up-front. (Rust + Java already generated
    // + built in Step 0, so they skip this C/Ada harness-gen path.)
    if !is_prebuilt {
        progress.update(&ProgressUpdate::phase(Phase::Generate));
        match generate_harness_for(
            candidate,
            &harness_dir,
            options.source_root.as_deref(),
            force_direct,
            &options.ada_dep_dirs,
            Some(crate::generate_harness::TreeTypeDefs {
                c: decl_index.c_type_defs.clone(),
                cpp: decl_index.cpp_type_defs.clone(),
                c_lifecycle: decl_index.c_tree_lifecycle.clone(),
            }),
            &options.decoder_limits,
            options.force,
        ) {
            Ok(()) => {}
            Err(reason) => {
                if generation_error_is_report_only(&reason) {
                    let outcome =
                        crate::auto::report_only::emit_report_only(candidate, reason, work_dir);
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome,
                        harness_dir,
                    });
                }
                return Ok(AttemptResult {
                    candidate: candidate.clone(),
                    outcome: Outcome::UnsupportedParams { reason },
                    harness_dir,
                });
            }
        }
    }

    // stb-style single-header fix: if the target's source gates its function
    // bodies behind `#ifdef <NAME>_IMPLEMENTATION`, `#define` the macro(s) up-front
    // so the bodies compile into the harness TU and the target links — otherwise
    // every stb/dr_libs/cute-style single-header target fails to build. Recorded
    // as a MacroDefine repair (force-included via auto_defines.h) so the report
    // shows it and the reactive loop won't redo it.
    if matches!(
        candidate.lang,
        crate::auto::candidate::Lang::C | crate::auto::candidate::Lang::Cpp
    ) {
        if let Some(source) = target_source.as_deref() {
            let mut field_struct_cache = std::collections::HashMap::new();
            for name in single_header_implementation_macros(source) {
                let repair = Repair::MacroDefine {
                    name,
                    as_value: false,
                };
                if manifest.already_attempted(&repair_key(&repair)) {
                    continue;
                }
                if crate::auto::repair::apply_repair_with_source(
                    &repair,
                    &repairs_dir,
                    decl_index,
                    Some(source),
                    &mut field_struct_cache,
                )
                .is_ok()
                {
                    manifest.repairs.push(repair);
                }
            }
        }
    }

    // #(c) stub-isolated build: for an OS-platform-guarded target we can't
    // cross-compile/emulate, define the platform guard so the foreign branch is
    // visible and drop fake platform headers beside the harness (resolved by the
    // Makefile's `-I .`) so it type-checks. The build is otherwise the normal host
    // build (real ASan + coverage); leftover platform symbols get stubbed by the
    // repair loop. Record a PlatformStub marker so the report flags the target's
    // findings as reduced-fidelity.
    if let ForeignStrategy::StubIsolated(stub) = &strategy {
        if let Err(error) = apply_platform_stub(stub, &harness_dir, &repairs_dir) {
            eprintln!(
                "govfuzz auto: warning: {}: platform stub setup failed: {error}",
                candidate.harness_id
            );
        } else {
            manifest.repairs.push(Repair::PlatformStub {
                platform: stub.platform.clone(),
            });
        }
    }

    // §26.1: the project's already-built static libraries (`*.a`) under its build/
    // probe dirs, discovered ONCE. Only the C/C++ lanes link via the clang command
    // line and surface `UndefinedSymbol` link errors — the Ada (gprbuild) and
    // prebuilt (Rust/Java) lanes never do — so the whole-library fallback applies
    // to C/C++ only; for the rest this stays empty (today's behavior), as it does
    // for a tree that ships no archive. Used to close a harness link that fails
    // with undefined externals naming no in-tree definition (a multi-TU library's
    // sibling objects that live only in the archive — zstd's lib/common, miniz).
    let library_archives: Vec<PathBuf> = if matches!(
        candidate.lang,
        crate::auto::candidate::Lang::C | crate::auto::candidate::Lang::Cpp
    ) {
        let tree_root = options
            .source_root
            .clone()
            .or_else(|| candidate.source_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| work_dir.to_path_buf());
        crate::auto::build_probe::discover_static_libraries(&tree_root)
    } else {
        Vec::new()
    };

    // §26.1 SECONDARY fallback set: the library's full recovered translation-unit
    // set, used ONLY when no prebuilt archive exists and the link fails with
    // undefined externals across many sibling TUs (yaml-cpp's `file(GLOB)`
    // `src/*.cpp`, which the static CMake inference cannot expand). Recovered once,
    // for the C/C++ lanes only, and only when there is no archive to prefer.
    let library_tus: Vec<PathBuf> = if matches!(
        candidate.lang,
        crate::auto::candidate::Lang::C | crate::auto::candidate::Lang::Cpp
    ) && library_archives.is_empty()
    {
        crate::generate_harness::recover_library_translation_units(
            &candidate.source_path,
            matches!(candidate.lang, crate::auto::candidate::Lang::Cpp),
        )
    } else {
        Vec::new()
    };
    // One-shot guard: the full TU set is linked at most once per target (it
    // resolves every sibling symbol together, so a second sweep adds nothing).
    let mut full_tu_set_linked = false;

    // The per-target repair cap (`auto --max-repair-rounds`); the no-progress
    // early-break below still stops a target that genuinely can't converge.
    let max_repair_rounds = options.max_repair_rounds;
    // Stable keys of self-target / otherwise-refused repairs, accumulated across
    // every round so an identical refused proposal is logged and re-processed
    // exactly once per target (campaign: yaml-cpp self-target livelock). A refused
    // repair never makes progress, so once the only proposals a round can offer are
    // already-refused or already-applied the loop stops cleanly instead of spinning.
    let mut refused_repairs: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Set once a semantic check has reported a failure that stopped this target
    // dead; from then on every round is a full build, because for this target the
    // check has demonstrably said something the compiler would not.
    let mut distrust_semantic_check = false;
    for retry in 0..=max_repair_rounds {
        progress.update(&ProgressUpdate::phase(Phase::Build { retry }));
        // Round 0 always builds outright, so a target that compiles as-is never
        // pays for a check it did not need.
        let round = if distrust_semantic_check { 0 } else { retry };
        match try_build(
            candidate,
            &harness_dir,
            &extra_sources,
            &extra_includes,
            options.source_root.as_deref(),
            &options.ada_dep_dirs,
            cross_compiler.as_ref(),
            &options.sanitizers,
            &options.dir_filter,
            options.project.as_deref(),
            round,
        ) {
            BuildOutcome::Success => {
                // Drive a cascade of fuzz passes against the freshly
                // built harness. Three tiny seeds + 1024 iterations is
                // enough to surface low-hanging crashes per pass; the
                // wall-clock budget comes from
                // `AttemptOptions::per_target_time` so the
                // `--per-target-time` CLI flag governs each pass.
                //
                // Pass 1 (empty env) runs without injection so the
                // runtrace shim can record every getenv NULL. After
                // pass 1 we collect EnvVarMissing events into
                // `env_injected` and the remaining passes inherit
                // those injections + their own GOVFUZZ_RUNTRACE_MODE.
                // Built-in tiny seeds, plus any user `--seed-file`/`--seed-dir`
                // inputs so parser/decompressor targets start from valid
                // examples rather than only empty/`A` bytes.
                let mut seeds = vec![b"".to_vec(), b"A".to_vec(), b"AAAAAAAA".to_vec()];
                seeds.extend(options.user_seeds.iter().cloned());
                // Start each target's edge-coverage bitmap empty; passes then
                // accumulate into it (#385).
                let _ = std::fs::remove_file(harness_dir.join("coverage.shm"));
                let _ = std::fs::remove_file(harness_dir.join("coverage_cnt.shm"));
                let _ = std::fs::remove_file(harness_dir.join("vp.shm"));
                // #377: the wall-clock `--per-target-time` budget governs depth
                // by default (unbounded cap); `--iterations N` caps each pass.
                let iterations = auto_iteration_cap(options.iterations);
                // #378: cmplog operands captured during each pass accumulate
                // here and feed the next pass's mutator (a magic byte mined in
                // pass 1 is spliced in pass 2). Start fresh per target.
                let cmplog_snapshot = harness_dir.join("cmplog.jsonl");
                let _ = std::fs::remove_file(&cmplog_snapshot);
                let mut pass_runs: Vec<PassRun> = Vec::new();
                let mut events: Vec<crate::auto::runtrace::RuntraceEvent> = Vec::new();
                let mut env_injected: Vec<(String, String)> = Vec::new();
                let mut consecutive_crashes = 0_usize;
                // `--per-target-finding-count`: distinct findings emitted across
                // this target's passes so far. Each pass is told how many MORE it
                // may emit before the target is done; once the running total
                // reaches the cap the cascade stops (remaining passes skipped).
                let mut findings_so_far = 0_usize;
                // Set once any pass shows the harness reading fuzz-driven data from
                // a virtualized IPC channel (shm / message queue / MMIO). Upgrades
                // a no-buffer-param target's reachability from "unproven" to
                // "ipc_channel_reachable" for findings + the report (the enhancement
                // surfaced by shared-memory RTOS dogfooding).
                let mut ipc_channel_observed = false;
                let fuzz_started = std::time::Instant::now();
                // #402: all passes share one per-target deadline so the
                // per-target wall stays ≈ the requested total (`--per-target-time`,
                // or the `--total-time` alias), regardless of pass count.
                let campaign_deadline = Some(fuzz_started + total_wall_budget);
                // Skip the builtin cascade entirely when this target runs AFL only
                // (`--engine afl++`): iterate an empty pass list so the AFL stage
                // below is the sole fuzz engine. For every other selection this is
                // the full `options.passes` — byte-identical to before.
                let builtin_passes: &[crate::auto::pass::Pass] =
                    if run_builtin { &options.passes } else { &[] };
                for (pass_idx, pass) in builtin_passes.iter().enumerate() {
                    // Wall-clock kill-switch: stop spawning fuzz
                    // passes once we've consumed the absolute cap of
                    // fuzz-pass wall clock. Catches livelock / busy-wait
                    // targets before they burn a whole core for hours.
                    if fuzz_started.elapsed() > absolute_cap {
                        return Ok(AttemptResult {
                            candidate: candidate.clone(),
                            outcome: Outcome::UnrecoverableRuntime {
                                repairs: manifest.repairs.clone(),
                                consecutive_crashes,
                                reason: format!(
                                    "exceeded absolute per-target cap of {absolute_cap:?}"
                                ),
                                runtrace_events: events.clone(),
                            },
                            harness_dir,
                        });
                    }
                    // #402: this pass's wall budget. With a shared campaign
                    // deadline, give the pass the smaller of its equal share and
                    // the time left, and stop the cascade once the total is spent.
                    let time_budget = match campaign_deadline {
                        Some(deadline) => {
                            let remaining =
                                deadline.saturating_duration_since(std::time::Instant::now());
                            if remaining.is_zero() {
                                break;
                            }
                            Some(remaining.min(per_pass_budget))
                        }
                        None => Some(per_pass_budget),
                    };
                    let pass_label = pass.as_str();
                    progress.update(&ProgressUpdate {
                        phase: Phase::Fuzz { pass: pass_label },
                        elapsed: Duration::ZERO,
                        budget: time_budget,
                        executions: 0,
                        findings: 0,
                        is_final: false,
                    });
                    let tick = |executions: usize, findings: usize, elapsed: Duration| {
                        progress.update(&ProgressUpdate {
                            phase: Phase::Fuzz { pass: pass_label },
                            elapsed,
                            budget: time_budget,
                            executions,
                            findings,
                            is_final: false,
                        });
                    };
                    let pass_started = std::time::Instant::now();
                    // #383: carry coverage forward — reseed this pass from the
                    // prior passes' persisted, signature-deduped corpus queue so
                    // deep code reached once stays reachable, instead of every
                    // pass restarting from the tiny built-in seeds.
                    if pass_idx > 0 {
                        reseed_from_corpus_queue(
                            work_dir,
                            &candidate.harness_id,
                            &mut seeds,
                            CORPUS_RESEED_CAP,
                        );
                    }
                    // Feed forward operands mined by earlier passes (#378).
                    let cmplog_log = cmplog_snapshot.exists().then(|| cmplog_snapshot.clone());
                    // How many MORE distinct findings this pass may emit before the
                    // target's `--per-target-finding-count` cap is reached.
                    let remaining_findings = options
                        .per_target_finding_count
                        .map(|cap| cap.saturating_sub(findings_so_far));
                    let result = run_fuzz_with_runtrace(
                        work_dir,
                        &candidate.harness_id,
                        &harness_dir,
                        seeds.clone(),
                        iterations,
                        time_budget,
                        remaining_findings,
                        options.rss_limit_mb,
                        *pass,
                        &env_injected,
                        options.mode,
                        cmplog_log,
                        options.comparison_progress,
                        cross_runner.clone(),
                        options.sanitizers.runtime_set(),
                        Some(&tick),
                    );
                    let (summary, mut ev) = match result {
                        Ok(p) => {
                            consecutive_crashes = 0;
                            p
                        }
                        Err(error) => {
                            eprintln!(
                                "govfuzz auto: fuzz pass `{pass_label}` failed for {}: {error}",
                                candidate.harness_id
                            );
                            // Crash-rate kill-switch: a shim regression
                            // that always crashes (eg. void/void dlsym
                            // stub jumping to garbage memory) would
                            // otherwise have the orchestrator respawn
                            // forever. Bail after MAX_CRASHES_PER_TARGET
                            // consecutive failures.
                            consecutive_crashes += 1;
                            if consecutive_crashes >= MAX_CRASHES_PER_TARGET {
                                return Ok(AttemptResult {
                                    candidate: candidate.clone(),
                                    outcome: Outcome::UnrecoverableRuntime {
                                        repairs: manifest.repairs.clone(),
                                        consecutive_crashes,
                                        reason: format!(
                                            "{consecutive_crashes} consecutive fuzz passes failed"
                                        ),
                                        runtrace_events: events.clone(),
                                    },
                                    harness_dir,
                                });
                            }
                            continue;
                        }
                    };
                    // #378: harvest this pass's cmplog operands (from the
                    // runtrace log it just wrote) into the snapshot so the next
                    // pass's mutator splices the magic bytes this pass observed.
                    append_cmplog_records(&harness_dir.join("runtrace.jsonl"), &cmplog_snapshot);
                    // Flush the pass's final counters. Live ticks are throttled
                    // and a sub-throttle pass emits none, so this is what makes a
                    // working run show real execs instead of the execs=0 start.
                    progress.update(&ProgressUpdate {
                        phase: Phase::Fuzz { pass: pass_label },
                        elapsed: pass_started.elapsed(),
                        budget: time_budget,
                        executions: summary.executions,
                        findings: summary.findings.len(),
                        is_final: true,
                    });
                    pass_runs.push(PassRun {
                        pass: *pass,
                        engine: "builtin".to_owned(),
                        executions: summary.executions,
                        target_entry_observed: summary.target_entry_observed,
                        coverage_edges: summary.coverage.edges,
                        // #405: the engine's own measured fuzz wall (excludes
                        // build/repair/reseed), carried up so run.json and
                        // fuzz_runs/<hid>-*.json report the same throughput.
                        elapsed_secs: summary.elapsed_secs,
                        executions_per_sec: summary.executions_per_sec,
                        findings: summary.findings.clone(),
                    });

                    // Stamp every finding this pass produced with its
                    // runtime_mode so `govfuzz replay` can replay it
                    // against the same environment. Best-effort — one
                    // bad finding.json shouldn't abort the cascade.
                    if ipc_channel_read_observed(&ev) {
                        ipc_channel_observed = true;
                    }
                    let reach_label = effective_reachability_label(
                        candidate.input_reachability,
                        ipc_channel_observed,
                    );
                    for fid in &summary.findings {
                        let finding_path = work_dir.join("findings").join(fid).join("finding.json");
                        if let Err(error) =
                            stamp_runtime_mode(&finding_path, *pass, &env_injected, reach_label)
                        {
                            eprintln!("govfuzz auto: warning: stamp {fid} runtime_mode: {error}");
                        }
                    }
                    events.append(&mut ev);
                    crate::auto::runtrace::dedupe_in_place(&mut events);
                    // After pass 1, collect env-var injections for
                    // subsequent passes. Skip when --no-stubs disabled
                    // prosthetics altogether.
                    if pass_idx == 0 && !options.no_stubs {
                        env_injected = env_injections_from_events(&events);
                        for (k, v) in &env_injected {
                            manifest.repairs.push(Repair::EnvVarInjection {
                                name: k.clone(),
                                value: v.clone(),
                            });
                        }
                    }

                    // `--per-target-finding-count`: accumulate this pass's distinct
                    // findings; stop the cascade once the running total reaches the
                    // cap (the engine already stopped this pass mid-run on the Nth).
                    findings_so_far += summary.findings.len();
                    if options
                        .per_target_finding_count
                        .is_some_and(|cap| findings_so_far >= cap)
                    {
                        break;
                    }
                }

                // AFL++ engine stage (`auto --engine afl++`): on a native C/C++
                // target, build the afl-instrumented `main_afl` with the SAME
                // recovered extras the `main` build used, then drive afl-fuzz for this
                // engine's budget slice. Crashes fold into the shared findings pipeline
                // and the run is recorded as an `afl++`-attributed PassRun. Any failure
                // (afl build or afl-fuzz) is logged and skipped — it never aborts the
                // target or discards the builtin results.
                if run_afl {
                    progress.update(&ProgressUpdate::phase(Phase::Fuzz { pass: "afl++" }));
                    let afl_built = crate::build::try_run_c_make_afl_build_with_extras(
                        work_dir,
                        &candidate.harness_id,
                        &extra_sources,
                        &extra_includes,
                    )
                    .status
                    .success();
                    if !afl_built {
                        eprintln!(
                            "govfuzz auto: warning: `make afl` failed for {} — AFL skipped, \
                             builtin results kept",
                            candidate.harness_id
                        );
                    } else {
                        // Seed AFL from the corpus the builtin passes grew (deep inputs
                        // reached once stay reachable), plus the base/user seeds.
                        let mut afl_seeds = seeds.clone();
                        reseed_from_corpus_queue(
                            work_dir,
                            &candidate.harness_id,
                            &mut afl_seeds,
                            CORPUS_RESEED_CAP,
                        );
                        match crate::fuzz::run_afl_plus_plus_programmatic(
                            work_dir,
                            &candidate.harness_id,
                            afl_seeds,
                            Some(engine_budget),
                            &env_injected,
                            options.mode,
                            options.rss_limit_mb,
                            options.sanitizers.runtime_set(),
                        ) {
                            Ok(summary) => {
                                let reach_label = effective_reachability_label(
                                    candidate.input_reachability,
                                    ipc_channel_observed,
                                );
                                for fid in &summary.findings {
                                    let finding_path =
                                        work_dir.join("findings").join(fid).join("finding.json");
                                    if let Err(error) = stamp_runtime_mode(
                                        &finding_path,
                                        crate::auto::pass::Pass::FuzzDriven,
                                        &env_injected,
                                        reach_label,
                                    ) {
                                        eprintln!(
                                            "govfuzz auto: warning: stamp {fid} runtime_mode: {error}"
                                        );
                                    }
                                }
                                pass_runs.push(PassRun {
                                    pass: crate::auto::pass::Pass::FuzzDriven,
                                    engine: "afl++".to_owned(),
                                    executions: summary.executions,
                                    target_entry_observed: summary.target_entry_observed,
                                    coverage_edges: summary.coverage.edges,
                                    elapsed_secs: summary.elapsed_secs,
                                    executions_per_sec: summary.executions_per_sec,
                                    findings: summary.findings.clone(),
                                });
                            }
                            Err(error) => eprintln!(
                                "govfuzz auto: warning: AFL run failed for {}: {error}",
                                candidate.harness_id
                            ),
                        }
                    }
                }

                if pass_runs.is_empty() {
                    // Cascade aborted before completing pass 1 — no
                    // fuzz signal at all. Downgrade to `Built` so the
                    // outer report still acknowledges the build.
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::Built {
                            repairs: manifest.repairs.clone(),
                            retries: retry,
                        },
                        harness_dir,
                    });
                }

                let executions_per_sec = aggregate_executions_per_sec(&pass_runs);
                // #417: a target whose entire external symbol surface was
                // blind-stubbed fuzzed only empty stubs, never the real library.
                // Surface that loudly here so a clean 0-finding result over
                // millions of executions is never silently read as "library is
                // safe". The structured signal lands in run.json `stub_execution`.
                let stub_exec = stub_execution_summary(&manifest.repairs);
                if stub_exec.stub_only {
                    let peak_cov = pass_runs
                        .iter()
                        .map(|p| p.coverage_edges)
                        .max()
                        .unwrap_or(0);
                    let findings: usize = pass_runs.iter().map(|p| p.findings.len()).sum();
                    eprintln!(
                        "govfuzz auto: WARNING: {} fuzzed STUB-ONLY — {}/{} called symbols were \
                         blind stubs (empty bodies) and no real dependency source was linked; the \
                         fuzz exercised stubs, not the real library, so its {} finding(s) at \
                         {} edge(s) coverage do NOT mean the library is clean",
                        candidate.harness_id,
                        stub_exec.blind_stubbed_symbols,
                        stub_exec.resolved_called_symbols,
                        findings,
                        peak_cov,
                    );
                }
                // #(c): a stub-isolated foreign target fuzzed its logic against
                // FAKE platform headers/types — findings are reduced-fidelity. Say
                // so loudly; the structured signal lands in run.json `platform_stub`.
                if let ForeignStrategy::StubIsolated(stub) = &strategy {
                    let findings: usize = pass_runs.iter().map(|p| p.findings.len()).sum();
                    eprintln!(
                        "govfuzz auto: NOTE: {} fuzzed STUB-ISOLATED for `{}` — its platform \
                         deps were faked (real {} behavior not modeled), so its {} finding(s) are \
                         REDUCED-FIDELITY and need confirmation on the real platform",
                        candidate.harness_id, stub.platform, stub.platform, findings,
                    );
                }
                // #95: target entry is a fuzz-SUCCESS invariant. C/C++/Ada
                // harnesses inject a target-entry probe (`GOVFUZZ_TARGET_ENTER` /
                // `AdaFuzz.Probe.Target_Entry`) that fires immediately before the
                // selected project endpoint, so a genuine fuzz of the library hits
                // it. If an entry-instrumented (builtin-engine) pass ran but NO
                // pass ever observed entry, the process executed only generated
                // decoding, blind stubs, or bailed out before the endpoint — record
                // `built_not_entered` (NOT `built_and_fuzzed`) so a stub-only or
                // decode-rejected run can never be counted as fuzzed. Interpreted
                // and managed lanes have no entry probe, so this is a no-op for them
                // (see `entry_miss_classification`).
                if let Some((entry_miss, reason)) =
                    entry_miss_classification(candidate.lang, &pass_runs, stub_exec.stub_only)
                {
                    eprintln!(
                        "govfuzz auto: {}: built but the target was NEVER entered ({entry_miss}) \
                         — recording built_not_entered, NOT a fuzz success ({reason})",
                        candidate.harness_id
                    );
                    return Ok(AttemptResult {
                        candidate: candidate_with_ipc_reachability(candidate, ipc_channel_observed),
                        outcome: Outcome::BuiltNotEntered {
                            repairs: manifest.repairs.clone(),
                            retries: retry,
                            passes: pass_runs,
                            per_pass_budget_secs: per_pass_budget.as_secs(),
                            total_wall_budget_secs: total_wall_budget.as_secs(),
                            executions_per_sec,
                            runtrace_events: events,
                            entry_miss,
                            reason,
                        },
                        harness_dir,
                    });
                }
                // A "fuzzed" outcome must reflect ACTUAL execution. An engine that
                // recorded a pass but ran ZERO iterations never exercised the target
                // — e.g. an exclusive `--engine afl++` run where afl-fuzz aborted
                // before executing any input. The #95 entry invariant above only
                // fires for entry-instrumented builtin passes, so an afl-only
                // cascade with 0 executions would otherwise be reported as a fuzz
                // success. Downgrade to Built (compiled, but no fuzz signal).
                let total_executions: usize = pass_runs.iter().map(|p| p.executions).sum();
                if total_executions == 0 {
                    eprintln!(
                        "govfuzz auto: {}: built but no fuzz iteration executed (0 executions) — \
                         recording built, NOT built_and_fuzzed",
                        candidate.harness_id
                    );
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::Built {
                            repairs: manifest.repairs.clone(),
                            retries: retry,
                        },
                        harness_dir,
                    });
                }
                // Honest-reporting (offline-legacy audit): a native entry-proof
                // lane (C/C++/Ada) that a builtin pass ENTERED and executed but
                // whose builtin passes recorded ZERO coverage edges was fuzzed
                // BLIND — the coverage instrumentation produced no signal, so
                // mutation had nothing to steer on. This is not a failure (the
                // target really ran, and a crash would still be caught), so the
                // outcome stays built_and_fuzzed; but say so loudly instead of
                // letting a zero-edge run read as a genuine coverage-guided
                // campaign. (After the GCC trace-pc SHM fix, zero edges on an
                // entered target means instrumentation is genuinely inert.)
                if harness_emits_target_entry_proof(candidate.lang) {
                    let builtin_entered_execed = pass_runs.iter().any(|p| {
                        p.engine == "builtin" && p.executions > 0 && p.target_entry_observed
                    });
                    let peak_builtin_edges = pass_runs
                        .iter()
                        .filter(|p| p.engine == "builtin")
                        .map(|p| p.coverage_edges)
                        .max()
                        .unwrap_or(0);
                    if builtin_entered_execed && peak_builtin_edges == 0 {
                        eprintln!(
                            "govfuzz auto: WARNING: {} entered and executed the target but recorded \
                             ZERO coverage edges — coverage instrumentation is inert, so this run \
                             fuzzed BLIND (no coverage-guided mutation). Findings are still valid, \
                             but absence of findings does NOT reflect coverage-guided depth.",
                            candidate.harness_id
                        );
                    }
                }
                return Ok(AttemptResult {
                    // Upgrade reachability to ipc_channel_reachable when this run
                    // drove the target through a virtualized IPC channel, so the
                    // report's per-target note reflects it (not "REACHABILITY
                    // UNPROVEN") — same signal the findings were stamped with.
                    candidate: candidate_with_ipc_reachability(candidate, ipc_channel_observed),
                    outcome: Outcome::BuiltAndFuzzed {
                        repairs: manifest.repairs.clone(),
                        retries: retry,
                        passes: pass_runs,
                        per_pass_budget_secs: per_pass_budget.as_secs(),
                        total_wall_budget_secs: total_wall_budget.as_secs(),
                        executions_per_sec,
                        runtrace_events: events,
                    },
                    harness_dir,
                });
            }
            BuildOutcome::Failed { errors } => {
                if retry == max_repair_rounds {
                    // Backstop: the per-target repair cap is exhausted. Say so
                    // explicitly so a long multi-round cascade that never converges
                    // is distinguishable from a one-shot failure, and the campaign
                    // moves on instead of appearing stuck on this target.
                    eprintln!(
                        "govfuzz auto: {}: repair cap reached ({max_repair_rounds} rounds) \
                         without a clean build; giving up on this target (failed_build) and \
                         advancing. Raise --max-repair-rounds to allow more repair rounds.",
                        candidate.harness_id
                    );
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::FailedBuild {
                            repairs: manifest.repairs.clone(),
                            retries: retry,
                            last_errors: errors,
                        },
                        harness_dir,
                    });
                }
                let unrecoverable: Vec<_> = errors
                    .iter()
                    .filter_map(|e| match e {
                        BuildErrorKind::MissingSharedLib { name } => Some(name.clone()),
                        // Under --force a missing external `with`ed GPR is NOT
                        // terminal: the repair loop below synthesizes an empty stub
                        // project (StubGprImport) so gprbuild loads the project, and
                        // the packages the code references from it get stubbed by
                        // the normal MissingAdaWith path. Let it fall through to the
                        // repair loop instead of short-circuiting to unrecoverable.
                        // Without --force it stays an honest unrecoverable missing
                        // dependency (surfaced in the missing-deps manifest).
                        BuildErrorKind::MissingGprImport { path } if !options.force => {
                            Some(path.clone())
                        }
                        _ => None,
                    })
                    .collect();
                if !unrecoverable.is_empty() {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::UnrecoverableLink {
                            repairs: manifest.repairs.clone(),
                            missing: unrecoverable,
                        },
                        harness_dir,
                    });
                }
                if options.no_stubs {
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::FailedBuild {
                            repairs: manifest.repairs.clone(),
                            retries: retry,
                            last_errors: errors,
                        },
                        harness_dir,
                    });
                }
                // §26.1: whole-library link fallback. When the link fails with
                // undefined externals that name NO in-tree definition — the
                // signature of sibling translation units that live only in the
                // project's already-built archive (zstd's lib/common+lib/compress
                // objects, miniz) — link that recovered static library wholesale
                // instead of resolving symbol-by-symbol (which burns the retry
                // budget on a large library and cannot reach a symbol whose `.c`
                // was never shipped). Preferred when an archive is present. Only
                // the in-tree-unresolvable case triggers it, so a symbol with a
                // real sibling source still takes the AddSource path below (no
                // duplicate-definition link error from linking both).
                if !library_archives.is_empty()
                    && errors.iter().any(|e| {
                        matches!(e, BuildErrorKind::UndefinedSymbol { name }
                            if undefined_symbol_needs_library_link(name, decl_index))
                    })
                {
                    let mut linked_any = false;
                    for archive in &library_archives {
                        if extra_sources.contains(archive) {
                            continue;
                        }
                        extra_sources.push(archive.clone());
                        manifest.repairs.push(Repair::AddSource {
                            symbol: WHOLE_LIBRARY_ARCHIVE_SYMBOL.to_owned(),
                            source_path: archive.clone(),
                        });
                        eprintln!(
                            "govfuzz auto: {}: undefined externals unresolved in the swept tree; \
                             linking recovered static library {} to close the link (§26.1)",
                            candidate.harness_id,
                            archive.display()
                        );
                        linked_any = true;
                    }
                    if linked_any {
                        progress.update(&ProgressUpdate::phase(Phase::Repair { retry: retry + 1 }));
                        continue;
                    }
                }
                // §26.1 SECONDARY fallback: full-TU-set whole-library link. When NO
                // prebuilt archive exists and the link still fails with undefined
                // externals, the missing symbols are sibling translation units of a
                // multi-TU library (yaml-cpp's emitterstate.cpp/… behind a CMake
                // `file(GLOB)` the static inference can't expand). Compile+link the
                // library's whole recovered TU set in ONE shot — but ONLY for a
                // library-wide link failure (>= WHOLE_LIBRARY_TU_MIN_UNDEFINED
                // undefined externals); a handful of missing symbols stays on the
                // precise per-symbol AddSource path below. The one-shot avoids the
                // slow cascade (one TU per round) that also stalls when the
                // declaration index mis-attributes a sibling symbol
                // to the target's own source (the yaml-cpp self-target livelock). If
                // genuine EXTERNAL deps remain undefined afterward, the per-symbol /
                // stub cascade below still handles them (the one-shot guard prevents
                // re-sweeping). Unlike the archive arm this also fires for symbols
                // that DO have an in-tree definition — that is exactly the case the
                // slow cascade churns on.
                if !full_tu_set_linked
                    && library_archives.is_empty()
                    && !library_tus.is_empty()
                    && library_tus
                        .iter()
                        .filter(|tu| !extra_sources.contains(tu))
                        .count()
                        <= MAX_AUTO_PROJECT_SOURCES.saturating_sub(auto_project_sources)
                    && should_link_full_tu_set(&errors, decl_index, &candidate.source_path)
                {
                    full_tu_set_linked = true;
                    let mut linked_any = false;
                    for tu in &library_tus {
                        if extra_sources.contains(tu) {
                            continue;
                        }
                        extra_sources.push(tu.clone());
                        auto_project_sources += 1;
                        manifest.repairs.push(Repair::AddSource {
                            symbol: WHOLE_LIBRARY_TU_SET_SYMBOL.to_owned(),
                            source_path: tu.clone(),
                        });
                        linked_any = true;
                    }
                    if linked_any {
                        eprintln!(
                            "govfuzz auto: {}: undefined externals across sibling TUs and no \
                             prebuilt archive; linking the library's full recovered TU set \
                             ({} source(s)) to close the link (§26.1)",
                            candidate.harness_id,
                            library_tus.len()
                        );
                        progress.update(&ProgressUpdate::phase(Phase::Repair { retry: retry + 1 }));
                        continue;
                    }
                }
                progress.update(&ProgressUpdate::phase(Phase::Repair { retry: retry + 1 }));
                // Field-struct synthesis must see every compiled source where the
                // missing type is dereferenced — including files pulled in by
                // earlier AddSource repairs (cFE `cfe_msg_init.c` etc.), not just
                // the original target. Rebuilt each round as extra_sources grows.
                let combined_source = {
                    let mut s = target_source.clone().unwrap_or_default();
                    for es in &extra_sources {
                        if let Ok(text) = crate::source_text::read_source_text(es) {
                            s.push('\n');
                            s.push_str(&text);
                        }
                    }
                    (!s.is_empty()).then_some(s)
                };
                // #373: memoize field-struct synthesis across this retry's
                // repairs (combined_source is stable within the retry), so a
                // type referenced by several build errors is parsed once.
                let mut field_struct_cache: std::collections::HashMap<String, Option<String>> =
                    std::collections::HashMap::new();
                let mut applied_any = false;
                let mut sources_added_this_round = std::collections::HashSet::new();
                // GAP #9: set when the ONLY repair the planner can offer for the
                // candidate's OWN target symbol is to re-add its already-compiled
                // source — proof the definition is conditionally compiled out (an
                // inactive CPU-feature/platform `#if`, e.g. sc's `crc32_hw` behind
                // `#if defined(HAVE_CRC32C)`). No repair can make it link, so we
                // skip honestly instead of looping to an opaque `failed_build`.
                let mut unavailable_target_blocker = false;
                for err in &errors {
                    // Several undefined symbols often live in one implementation
                    // source (XZ check.c defines init/update/finish). Once that
                    // source is added in this round, let the next build resolve all
                    // of them; treating the later symbols as "already attempted"
                    // and stubbing them creates duplicate or fake definitions.
                    if definition_source_for_undefined(err, decl_index, &candidate.source_path)
                        .is_some_and(|source| sources_added_this_round.contains(source))
                    {
                        continue;
                    }
                    if let Some(mut repair) =
                        crate::auto::repair::plan_repair_forced_with_source_policy(
                            err,
                            decl_index,
                            &manifest,
                            options.force,
                            auto_project_sources < MAX_AUTO_PROJECT_SOURCES,
                        )
                    {
                        if let Repair::AddSource {
                            symbol,
                            source_path,
                        } = &mut repair
                        {
                            if let Some(contextual) = decl_index
                                .lookup_definition_source_near(symbol, &candidate.source_path)
                            {
                                *source_path = contextual.to_path_buf();
                            }
                        }
                        if matches!(&repair, Repair::AddSource { source_path, .. }
                            if manifest.already_attempted(&source_path.display().to_string()))
                        {
                            let Some(fallback) =
                                crate::auto::repair::plan_repair_forced_with_source_policy(
                                    err,
                                    decl_index,
                                    &manifest,
                                    options.force,
                                    false,
                                )
                            else {
                                continue;
                            };
                            repair = fallback;
                        }
                        if repair_replaces_candidate_target(&repair, candidate) {
                            let unavailable_target =
                                repair_signals_unavailable_target(&repair, candidate);
                            if unavailable_target {
                                unavailable_target_blocker = true;
                            }
                            // Track refused repairs by stable key so an identical
                            // self-target proposal is logged and processed ONCE per
                            // target — not re-proposed every round (and not printed
                            // once per duplicate undefined-symbol error in a single
                            // round). yaml-cpp's `YAML::Emitter::Write` surfaced ~22
                            // sibling `EmitterState::Set*` symbols whose definition
                            // source the index mis-attributes to the target's own
                            // `emitter.cpp` (the shortest /src/ path wins the score
                            // tiebreak); each was planned as a self-target `AddSource`
                            // and refused, spamming the identical line dozens of times
                            // while the real `emitterstate.cpp` was added anyway. The
                            // A dependency symbol mis-attributed to the target source
                            // gets one source-disabled re-plan below, which can use a
                            // declaration-backed stub. The candidate's own symbol is
                            // never allowed through that fallback: stubbing it would
                            // produce a false-clean harness that fuzzes no real target.
                            if record_refused_repair(&mut refused_repairs, &repair) {
                                eprintln!(
                                    "govfuzz auto: refusing self-target repair {} for {}; \
                                     target appears unavailable in the active build",
                                    repair_key(&repair),
                                    candidate.harness_id
                                );
                            }
                            if unavailable_target {
                                continue;
                            }
                            let Some(fallback) = dependency_fallback_after_refused_source(
                                err,
                                decl_index,
                                &manifest,
                                candidate,
                                options.force,
                            ) else {
                                continue;
                            };
                            repair = fallback;
                        }
                        let key = repair_key(&repair);
                        if manifest.already_attempted(&key) {
                            continue;
                        }
                        match crate::auto::repair::apply_repair_with_source(
                            &repair,
                            &repairs_dir,
                            decl_index,
                            combined_source.as_deref(),
                            &mut field_struct_cache,
                        ) {
                            Ok(outcome) => {
                                if let Repair::AddSource { source_path, .. } = &repair {
                                    sources_added_this_round.insert(source_path.clone());
                                }
                                for s in outcome.extra_sources {
                                    if !extra_sources.contains(&s) {
                                        extra_sources.push(s);
                                        if matches!(&repair, Repair::AddSource { .. }) {
                                            auto_project_sources += 1;
                                        }
                                    }
                                }
                                for i in outcome.extra_includes {
                                    if !extra_includes.contains(&i) {
                                        extra_includes.push(i);
                                    }
                                }
                                manifest.repairs.push(repair);
                                applied_any = true;
                            }
                            Err(e) => {
                                // A repair the planner identified but the
                                // applier can't emit (e.g. an unsupported
                                // return type in c_stub_gen). Mark it
                                // attempted so we don't try again on the
                                // next retry, log a one-line note, and
                                // continue with the remaining errors.
                                // The candidate ultimately surfaces as
                                // FailedBuild with the originating error
                                // in last_errors.
                                eprintln!(
                                    "govfuzz auto: skipping repair for {}: {e}",
                                    repair_key(&repair)
                                );
                                manifest.repairs.push(repair);
                            }
                        }
                    }
                }
                // Force-fuzz: reconstruct a COMPILABLE stub of the used subset of
                // each missing external Ada library. Runs after the per-error
                // repairs (so its full-profile stubs supersede any empty
                // AdaPackageStub) and refines from this build's raw output — the
                // type-mismatch rounds classify as `Other` (no per-error repair),
                // so this is what drives them and keeps the loop converging.
                if options.force && matches!(candidate.lang, crate::auto::candidate::Lang::Ada) {
                    // First try reconstructing missing external library stubs; only
                    // when that is exhausted (short-circuit) fall back to dropping
                    // the offline-unbuildable bodies of non-target project units.
                    let progressed = refine_ada_external_stubs(
                        work_dir,
                        &candidate.harness_id,
                        &repairs_dir,
                        &errors,
                    ) || stub_out_unbuildable_bodies(
                        work_dir,
                        &candidate.harness_id,
                        &repairs_dir,
                        &candidate.source_path,
                        &candidate.name,
                    );
                    if progressed {
                        applied_any = true;
                    }
                }
                // Ada repair rounds after the first are driven by a SEMANTIC CHECK
                // rather than a full build. That is sound for finding work to do,
                // but `-gnatc` is not simply a cheaper build: GNAT enforces some
                // rules there that a code-generating compile never applies (a
                // private object in a preelaborated unit, for one). So a check can
                // report an error no real build would, and if that lands on the
                // round we give up, a target that actually compiles is written off
                // as unbuildable — a silent loss of coverage, the worst way to be
                // wrong.
                //
                // Before concluding, stop trusting the check for THIS target and
                // let the loop take one more round as a full build. It costs a
                // build only on a round the target was already being abandoned on,
                // so the savings are untouched, and once check and build are known
                // to disagree here the check is not consulted for this target again.
                if !applied_any
                    && retry > 0
                    && !distrust_semantic_check
                    && matches!(
                        candidate.lang,
                        crate::auto::candidate::Lang::Ada
                            | crate::auto::candidate::Lang::C
                            | crate::auto::candidate::Lang::Cpp
                    )
                {
                    distrust_semantic_check = true;
                    continue;
                }
                if !applied_any {
                    // GAP #9: the build is stuck solely because the candidate's own
                    // target symbol is undefined and re-adding its (already-compiled)
                    // source cannot help — its definition is conditionally compiled
                    // out. Report an honest skip naming the unavailable target rather
                    // than an opaque link `failed_build`.
                    if unavailable_target_blocker {
                        return Ok(AttemptResult {
                            candidate: candidate.clone(),
                            outcome: Outcome::UnsupportedParams {
                                reason: format!(
                                    "target `{}` has no definition in the active build: its own \
                                     source {} compiles but does not provide the symbol, so the \
                                     definition appears to be conditionally compiled out (typically \
                                     an inactive `#if` — e.g. a CPU-feature/ISA or build-capability \
                                     guard not enabled by govfuzz's portable `-O1` build). Re-adding \
                                     its own source cannot resolve the symbol, so this is skipped \
                                     rather than reported as a link failure; a portable sibling \
                                     target is the buildable one.",
                                    candidate.name,
                                    candidate.source_path.display()
                                ),
                            },
                            harness_dir,
                        });
                    }
                    return Ok(AttemptResult {
                        candidate: candidate.clone(),
                        outcome: Outcome::FailedBuild {
                            repairs: manifest.repairs.clone(),
                            retries: retry,
                            last_errors: errors,
                        },
                        harness_dir,
                    });
                }
            }
        }
    }
    unreachable!("retry loop returns before exiting")
}

enum BuildOutcome {
    Success,
    Failed { errors: Vec<BuildErrorKind> },
}

#[cfg(test)]
mod full_tu_gate_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn precise_definition_sources_prevent_unrelated_full_library_sweep() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-full-tu-gate-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target.c");
        fs::write(&target, "int target(void) { return 0; }\n").unwrap();
        let mut errors = Vec::new();
        for index in 0..WHOLE_LIBRARY_TU_MIN_UNDEFINED {
            let name = format!("helper_{index}");
            fs::write(
                root.join(format!("{name}.c")),
                format!("int {name}(void) {{ return {index}; }}\n"),
            )
            .unwrap();
            errors.push(BuildErrorKind::UndefinedSymbol { name });
        }
        let decls = DeclarationIndex::build(&root).unwrap();

        assert!(
            !should_link_full_tu_set(&errors, &decls, &target),
            "a single precise repair round can add every defining source"
        );
        for (index, error) in errors.iter_mut().enumerate() {
            *error = BuildErrorKind::UndefinedSymbol {
                name: format!("external_without_source_{index}"),
            };
        }
        assert!(
            should_link_full_tu_set(&errors, &decls, &target),
            "a broad link failure made up of unmapped symbols may need the TU sweep"
        );

        fs::remove_dir_all(root).unwrap();
    }
}

fn repair_key(repair: &Repair) -> String {
    match repair {
        Repair::HeaderPlaceholder { virtual_path } => virtual_path.clone(),
        Repair::HeaderForward { virtual_path, .. } => format!("forward-h:{virtual_path}"),
        Repair::ConfigHeaderSynth { virtual_path } => format!("config-h:{virtual_path}"),
        Repair::AddIncludeDir { dir } => dir.display().to_string(),
        Repair::IncludeTypeHeader { type_name, .. } => format!("type-header:{type_name}"),
        Repair::TypePlaceholder { type_name } => type_name.clone(),
        Repair::TypeAlias { type_name, .. } => type_name.clone(),
        Repair::ConfigTypeAlias { type_name, .. } => format!("config-alias:{type_name}"),
        Repair::MacroDefine { name, .. } => format!("macro:{name}"),
        Repair::IncludeStdHeader { symbol, .. } => format!("stdhdr:{symbol}"),
        Repair::DeclareFunction { symbol, .. } => format!("decl:{symbol}"),
        Repair::AddSource { source_path, .. } => source_path.display().to_string(),
        Repair::StubDeclared { symbol, .. } | Repair::StubBlind { symbol } => symbol.clone(),
        Repair::EnvVarInjection { name, .. } => name.clone(),
        Repair::AdaPackageStub { unit, .. } => format!("ada-spec:{unit}"),
        Repair::AdaPackageBodyStub { unit, .. } => format!("ada-body:{unit}"),
        Repair::OverrideAdaBodyStub { source, .. } => format!("ada-override:{}", source.display()),
        Repair::AddAdaSource { unit, .. } => format!("ada-src:{unit}"),
        Repair::StubGprImport { project } => format!("gpr-stub:{project}"),
        Repair::PlatformStub { platform } => format!("platform-stub:{platform}"),
        Repair::Win32Pack => "win32-pack".to_owned(),
    }
}

/// Record a refused (self-target / non-actionable) repair in the per-target
/// `refused` set, keyed by its stable [`repair_key`]. Returns `true` the FIRST time
/// a given repair is refused for a target and `false` for every later identical
/// proposal, so the attempt loop logs and re-processes an identical refused repair
/// exactly once — instead of re-printing it once per duplicate undefined-symbol
/// error (or once per round) and spinning the repair loop on it (campaign: yaml-cpp
/// self-target livelock). A refused repair is never applied and so never counts as
/// progress; once a round can only re-propose already-refused or already-applied
/// repairs, the loop stops cleanly.
fn record_refused_repair(refused: &mut std::collections::HashSet<String>, repair: &Repair) -> bool {
    refused.insert(repair_key(repair))
}

/// stb-style single-header libraries (stb_image.h, dr_libs, cute_*.h) keep the
/// function *declarations* always visible but gate the *definitions* behind a
/// `#ifdef <NAME>_IMPLEMENTATION`. A harness that only `#include`s such a header
/// sees the prototype but never the body, so the target fails to link ("undefined
/// reference"). Scan the target source for the impl-guard macro name(s) so the
/// build can `#define` them up-front and pull the bodies into the harness TU.
///
/// Returns the distinct UPPER_SNAKE identifiers that end in `_IMPLEMENTATION` or
/// `_IMPL` (the stb / dr_libs / cute / sokol idioms) and appear in a POSITIVE
/// preprocessor guard (`#ifdef` / `#if` / `#elif`) — never `#ifndef` (an include
/// guard) or `#undef`. Conservative on purpose: a non-stb source simply has no
/// such tokens and is unaffected.
fn single_header_implementation_macros(source: &str) -> Vec<String> {
    let mut macros: Vec<String> = Vec::new();
    for raw in source.lines() {
        let line = raw.trim_start();
        let Some(directive) = line.strip_prefix('#') else {
            continue;
        };
        let directive = directive.trim_start();
        // Positive impl guards only. `ifndef`/`undef` are intentionally excluded:
        // `starts_with("if")` would catch `ifndef`, so require a `defined`/space
        // boundary by matching the exact directive keywords.
        let is_positive_guard = ["ifdef", "if", "elif"].iter().any(|kw| {
            directive
                .strip_prefix(kw)
                .is_some_and(|rest| rest.starts_with([' ', '(', '\t']))
        });
        if !is_positive_guard {
            continue;
        }
        for token in identifier_tokens(directive) {
            if is_implementation_macro(&token) && !macros.contains(&token) {
                macros.push(token);
            }
        }
    }
    macros
}

/// True for an stb-style implementation-guard macro: an all-UPPER_SNAKE token
/// (with a prefix) ending in `_IMPLEMENTATION` or `_IMPL`. The prefix requirement
/// (`len > suffix.len()`) rejects a bare `_IMPL`; the all-caps requirement keeps
/// it off ordinary lower/mixed-case identifiers a `#if` expression might mention.
fn is_implementation_macro(token: &str) -> bool {
    let suffix_ok = ["_IMPLEMENTATION", "_IMPL"]
        .iter()
        .any(|suffix| token.ends_with(suffix) && token.len() > suffix.len());
    suffix_ok
        && token
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Split a string into C identifier tokens (`[A-Za-z0-9_]+` runs), discarding
/// punctuation/operators. Used to mine macro names out of a `#if` expression.
fn identifier_tokens(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// GAP #9: a refused self-target repair whose missing symbol IS the candidate's
/// own target — the strongest signal that the target's definition is unavailable
/// in the active build (conditionally compiled out under an inactive feature/
/// platform `#if`). The candidate's own source is always in the Makefile, so an
/// undefined *target* symbol can only mean its definition was guarded out; re-adding
/// the source (`AddSource`) or stubbing it (`Stub*`) would not produce a real,
/// fuzzable definition. Distinct from re-adding the candidate's source for some
/// OTHER (dependency) symbol, which is a different, dependency-missing story.
fn repair_signals_unavailable_target(repair: &Repair, candidate: &Candidate) -> bool {
    match repair {
        Repair::AddSource { symbol, .. }
        | Repair::StubDeclared { symbol, .. }
        | Repair::StubBlind { symbol } => symbol == &candidate.name,
        _ => false,
    }
}

fn repair_replaces_candidate_target(repair: &Repair, candidate: &Candidate) -> bool {
    match repair {
        Repair::StubDeclared { symbol, .. } | Repair::StubBlind { symbol } => {
            symbol == &candidate.name
        }
        Repair::AddSource {
            symbol,
            source_path,
        } => symbol == &candidate.name || source_path == &candidate.source_path,
        // Refuse to stub the *target's own* body (same file) — that would
        // neutralise the very subprogram being fuzzed.
        Repair::OverrideAdaBodyStub { source, .. } => {
            source.file_name() == candidate.source_path.file_name()
        }
        Repair::HeaderPlaceholder { .. }
        | Repair::HeaderForward { .. }
        | Repair::ConfigHeaderSynth { .. }
        | Repair::AddIncludeDir { .. }
        | Repair::IncludeTypeHeader { .. }
        | Repair::TypePlaceholder { .. }
        | Repair::TypeAlias { .. }
        | Repair::ConfigTypeAlias { .. }
        | Repair::MacroDefine { .. }
        | Repair::IncludeStdHeader { .. }
        | Repair::DeclareFunction { .. }
        | Repair::EnvVarInjection { .. }
        | Repair::AdaPackageStub { .. }
        | Repair::AdaPackageBodyStub { .. }
        | Repair::AddAdaSource { .. }
        | Repair::StubGprImport { .. }
        | Repair::PlatformStub { .. }
        | Repair::Win32Pack => false,
    }
}

fn dependency_fallback_after_refused_source(
    error: &BuildErrorKind,
    decl_index: &crate::auto::decl_index::DeclarationIndex,
    manifest: &RepairManifest,
    candidate: &Candidate,
    force: bool,
) -> Option<Repair> {
    let fallback = crate::auto::repair::plan_repair_forced_with_source_policy(
        error, decl_index, manifest, force, false,
    )?;
    (!repair_replaces_candidate_target(&fallback, candidate)).then_some(fallback)
}

/// One-shot warning latch so we don't print "shim not found" once
/// per candidate during a large sweep. First-failed-lookup prints
/// a single stderr line; every subsequent call is silent.
static SHIM_MISSING_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Run one fuzz pass with the runtrace shim loaded. Returns the
/// FuzzRunSummary plus the parsed event list (empty when the shim
/// isn't available on disk). `pass` selects the cascade mode —
/// its `as_str()` becomes `GOVFUZZ_RUNTRACE_MODE` in the child env.
///
/// Env threading is race-free: instead of mutating the parent
/// process via `std::env::set_var` (unsafe on Rust 1.74+ under
/// multi-threaded hosts; leaks on panic), we build `child_env`
/// locally and let every harness `Command` apply it via
/// `Command::env` at spawn time.
#[allow(clippy::too_many_arguments)]
fn run_fuzz_with_runtrace(
    work_dir: &std::path::Path,
    harness_id: &str,
    harness_dir: &std::path::Path,
    seeds: Vec<Vec<u8>>,
    iterations: usize,
    time_budget: Option<Duration>,
    stop_after_findings: Option<usize>,
    rss_limit_mb: usize,
    pass: crate::auto::pass::Pass,
    extra_env: &[(String, String)],
    mode: actionability::RunMode,
    cmplog_log: Option<std::path::PathBuf>,
    comparison_progress: bool,
    cross_wrapper: Option<crate::runner::HarnessWrapper>,
    sanitizers: &[multicore_fuzz::Sanitizer],
    progress: Option<crate::fuzz::FuzzProgressFn<'_>>,
) -> std::result::Result<
    (
        crate::fuzz::FuzzRunSummary,
        Vec<crate::auto::runtrace::RuntraceEvent>,
    ),
    String,
> {
    let runtrace_log = harness_dir.join("runtrace.jsonl");
    // Truncate any prior log so this pass's events stand alone.
    let _ = std::fs::write(&runtrace_log, "");

    let mut child_env: Vec<(String, String)> = vec![
        (
            "GOVFUZZ_RUNTRACE_LOG".to_owned(),
            runtrace_log.display().to_string(),
        ),
        ("GOVFUZZ_RUNTRACE_MODE".to_owned(), pass.as_str().to_owned()),
        // #378: capture str/mem comparison operands so an earlier pass mines the
        // magic bytes a later pass splices in (libFuzzer-style cmplog/RedQueen).
        ("GOVFUZZ_CMPLOG".to_owned(), "1".to_owned()),
        // Edge-coverage bitmap shared by every harness child (#385). Only the
        // passthrough govfuzz driver carries a runtime that writes it; other
        // harnesses ignore the variable, so the engine reports 0 edges for them.
        // The same path across passes makes coverage accumulate over the run.
        (
            "GOVFUZZ_COV_SHM".to_owned(),
            harness_dir.join("coverage.shm").display().to_string(),
        ),
        // Independent one-byte target-entry proof. The generated C/C++
        // harness checkpoints immediately before the selected call; Ada emits
        // the equivalent event through AdaFuzz.Probe. Keeping this separate
        // prevents driver-only execution/coverage from masquerading as a
        // successfully fuzzed endpoint.
        (
            "GOVFUZZ_TARGET_ENTRY_SHM".to_owned(),
            harness_dir.join("target_entry.shm").display().to_string(),
        ),
        // AFL-style per-exec hit-count map (#420), a PARALLEL channel to the
        // presence bitmap above: the C/C++ driver runtime saturating-increments
        // each edge's per-exec count here so the engine can bucket loop/recursion
        // depth (count_to_bucket). The engine zeroes it before every exec; the
        // harness only increments. Harnesses without the #420 runtime (and the
        // Ada trace-pc path) ignore the variable, leaving the bucket channel inert.
        (
            "GOVFUZZ_COV_CNT_SHM".to_owned(),
            harness_dir.join("coverage_cnt.shm").display().to_string(),
        ),
        // Value-profile token log the driver mines from comparison operands; the
        // engine folds it into the mutator dictionary so gated code is reachable
        // (#398). Ignored by harnesses without the driver's runtime.
        (
            "GOVFUZZ_VP_SHM".to_owned(),
            harness_dir.join("vp.shm").display().to_string(),
        ),
    ];
    // RedQueen/cmplog per-base operand capture (#400): the passthrough/driver
    // harness writes comparison operand pairs to this MAP_SHARED region; the
    // engine arms it only for the corpus entry it is about to mutate, then
    // splices the captured operands into the input at the offset they were
    // compared. Harnesses without the cmplog runtime ignore the variable.
    // `GOVFUZZ_DISABLE_REDQUEEN=1` is a kill-switch (used by the cold-solve
    // parity gate to A/B per-input capture against the dictionary-only path).
    if std::env::var("GOVFUZZ_DISABLE_REDQUEEN").as_deref() != Ok("1") {
        child_env.push((
            "GOVFUZZ_CMP_SHM".to_owned(),
            harness_dir.join("cmp.shm").display().to_string(),
        ));
    }
    // laf-intel comparison-progress map (#421, opt-in via `auto --comparison-progress`):
    // the C/C++ driver records, per compare site, the MAX number of LEADING bytes
    // matched of each comparison this exec; the engine folds a newly-reached match
    // LEVEL into a virgin map (the #420 hit-count bucket machinery) so an input that
    // gets one more byte of a multi-byte magic/format gate correct is retained and
    // energized — the gradient a whole-compare edge cannot give. Off by default: the
    // env is simply absent, leaving the channel inert and behavior byte-identical to a
    // run without the flag. Ignored by harnesses without the driver runtime.
    if comparison_progress {
        child_env.push((
            "GOVFUZZ_CMP_PROGRESS_SHM".to_owned(),
            harness_dir.join("cmp_progress.shm").display().to_string(),
        ));
    }
    // The native Java, C#, and JavaScript lanes run the target inside a managed
    // runtime (JVM / .NET CLR / Node V8) launched by a wrapper script. LD_PRELOAD-ing
    // the runtrace shim into `java`/`dotnet`/`node` would intercept the runtime's OWN
    // libc calls (class/assembly/module loading file opens, the .NET host's
    // `access()`→`open()` on libhostfxr.so, Node's `stat()`→`open()` on every
    // `require`, sockets, …) and the runtrace resource/open/TOCTOU oracles would fire
    // on normal runtime activity — false positives (e.g. GF-418 on the .NET host's
    // own startup). Each lane gets coverage from its own instrumentation (bytecode
    // agent / SharpFuzz IL / V8 block coverage → GOVFUZZ_COV_SHM, kept above) and
    // crash detection from the driver's hard-halt (exit 86), so none needs the shim.
    // Under the shim the CLR's heavy startup I/O also blows past the fork-server
    // handshake window, collapsing the run to slow per-spawn execs.
    let is_managed_harness = std::fs::read_to_string(harness_dir.join("main"))
        .map(|s| {
            s.contains("GOVFUZZ_JVM_LAUNCHER")
                || s.contains("GOVFUZZ_CS_LAUNCHER")
                || s.contains("GOVFUZZ_JS_LAUNCHER")
        })
        .unwrap_or(false);
    if cross_wrapper.is_some() || is_managed_harness {
        // no shim for emulated targets or the managed (JVM / .NET / Node) lanes
    } else if let Some(shim) = crate::auto::shim_path::locate() {
        let ld_preload = crate::auto::shim_path::ld_preload_value_with(
            &shim,
            std::env::var("LD_PRELOAD").ok().as_deref(),
        );
        child_env.push(("LD_PRELOAD".to_owned(), ld_preload));
    } else if SHIM_MISSING_WARNED.set(()).is_ok() {
        eprintln!(
            "govfuzz auto: libgovfuzz_runtrace.so not found beside govfuzz or in a \
             sibling govfuzz_runtrace_shim archive directory; \
             running fuzz without runtime audit"
        );
    }
    for (k, v) in extra_env {
        child_env.push((k.clone(), v.clone()));
    }

    // The host-native pass is unchanged — it goes through the engine's default
    // direct runner. A foreign-platform/arch pass instead builds an emulation
    // runner (qemu-user / wine) from the cross binary path and hands it to the
    // engine so the cross-built harness runs under emulation.
    let summary = match cross_wrapper {
        // Native host pass: the harness was built with the requested `-fsanitize=`
        // set, so name the sanitizers here too — `run_one_target_programmatic` (via
        // `prepare`) injects each `<SAN>_OPTIONS` env and records them in the run's
        // sanitizer summary. `&[]` for an empty matrix keeps this byte-identical to before.
        None => crate::fuzz::run_one_target_programmatic(
            work_dir,
            harness_id,
            seeds,
            iterations,
            time_budget,
            stop_after_findings,
            rss_limit_mb,
            &child_env,
            mode,
            cmplog_log,
            sanitizers,
            progress,
        )?,
        Some(wrapper) => {
            let harness = crate::fuzz::find_harness_executable(
                work_dir,
                harness_id,
                crate::fuzz::FuzzEngine::Builtin,
            )?;
            let runner = crate::runner::harness_runner_with_wrapper(
                harness,
                Some(wrapper),
                crate::runner::SandboxModeArg::Auto,
                None,
                false,
            );
            crate::fuzz::run_one_target_programmatic_with_runner(
                work_dir,
                harness_id,
                seeds,
                iterations,
                time_budget,
                stop_after_findings,
                rss_limit_mb,
                &child_env,
                mode,
                cmplog_log,
                Some(runner),
                // Cross builds drop sanitizer instrumentation (ASan's shadow memory
                // doesn't survive qemu-user); the emulated binary has no sanitizer
                // runtime, so arm none and keep the run record honest.
                &[],
                progress,
            )?
        }
    };
    let events = if runtrace_log.is_file() {
        crate::auto::runtrace::parse_log(&runtrace_log).unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok((summary, events))
}

#[allow(clippy::too_many_arguments)]
fn generate_harness_for(
    c: &Candidate,
    dir: &Path,
    source_root: Option<&Path>,
    force_direct: bool,
    ada_dep_dirs: &[PathBuf],
    tree_type_defs: Option<crate::generate_harness::TreeTypeDefs>,
    decoder_limits: &crate::generate_harness::DecoderLimitArgs,
    force: bool,
) -> std::result::Result<(), String> {
    let fallback_path = dir.join("generation-fallback.json");
    let _ = std::fs::remove_file(&fallback_path);
    let output_dir = dir.parent().expect("harness dir has parent").to_path_buf();
    let prefer_servant = ada_auto_servant_candidate(c);
    let prefer_sequence = !force_direct && auto_sequence_candidate(c);
    let res = if prefer_servant {
        crate::generate_harness::generate_for_path_with_kind(
            &c.source_path,
            &c.name,
            Some(c.line),
            &output_dir,
            &c.harness_id,
            "servant_direct",
            None,
            source_root,
            ada_dep_dirs,
            tree_type_defs.clone(),
            decoder_limits.clone(),
            force,
        )
    } else if prefer_sequence {
        crate::generate_harness::generate_for_path_with_kind(
            &c.source_path,
            &c.name,
            Some(c.line),
            &output_dir,
            &c.harness_id,
            "sequence",
            None,
            source_root,
            ada_dep_dirs,
            tree_type_defs.clone(),
            decoder_limits.clone(),
            force,
        )
    } else {
        crate::generate_harness::generate_for_path(
            &c.source_path,
            &c.name,
            Some(c.line),
            &output_dir,
            &c.harness_id,
            None,
            source_root,
            ada_dep_dirs,
            tree_type_defs.clone(),
            decoder_limits.clone(),
            force,
        )
    };
    match res {
        Ok(()) => Ok(()),
        Err(servant_error) if prefer_servant => {
            let direct = crate::generate_harness::generate_for_path(
                &c.source_path,
                &c.name,
                Some(c.line),
                &output_dir,
                &c.harness_id,
                None,
                source_root,
                ada_dep_dirs,
                tree_type_defs.clone(),
                decoder_limits.clone(),
                force,
            );
            match direct {
                Ok(()) => {
                    let _ = std::fs::write(
                        &fallback_path,
                        br#"{"schema_version":1,"from":"servant_direct","to":"direct"}"#,
                    );
                    Ok(())
                }
                Err(direct_error) => Err(format!(
                    "{direct_error:#}; servant-direct generation also failed first: {servant_error:#}"
                )),
            }
        }
        Err(sequence_error) if prefer_sequence => {
            let direct = crate::generate_harness::generate_for_path(
                &c.source_path,
                &c.name,
                Some(c.line),
                &output_dir,
                &c.harness_id,
                None,
                source_root,
                ada_dep_dirs,
                tree_type_defs.clone(),
                decoder_limits.clone(),
                force,
            );
            match direct {
                Ok(()) => {
                    let _ = std::fs::write(
                        &fallback_path,
                        br#"{"schema_version":1,"from":"sequence","to":"direct"}"#,
                    );
                    Ok(())
                }
                Err(direct_error) => Err(format!(
                    "{direct_error:#}; sequence generation also failed first: {sequence_error:#}"
                )),
            }
        }
        Err(error) => Err(format!("{error:#}")),
    }
}

/// Identify a checked-in legacy Ada servant operation from the same structural
/// evidence used by harness generation. Auto previously never selected the
/// existing `servant_direct` lane, so a concrete `Bar_Impl.Servant` receiver was
/// handed to the ordinary parameter decoder; derived-type resolution collapsed
/// it to `PortableServer.Servant` and emitted an ill-typed call.
fn ada_auto_servant_candidate(c: &Candidate) -> bool {
    use ada_parser::ast::{SubprogramOwner, TypeKind, TypeOwner};

    if c.lang != crate::auto::candidate::Lang::Ada {
        return false;
    }
    let Ok(source) = crate::source_text::read_source_text(&c.source_path) else {
        return false;
    };
    let Ok(ast) = ada_parser::reconcile::build_structural_ast(&source, None, &c.source_path) else {
        return false;
    };
    let Some(target) = ast
        .subprograms
        .iter()
        .find(|subprogram| {
            subprogram.decl_span.start_line == c.line
                && subprogram.name.eq_ignore_ascii_case(&c.name)
        })
        .or_else(|| {
            ast.subprograms
                .iter()
                .find(|subprogram| subprogram.name.eq_ignore_ascii_case(&c.name))
        })
    else {
        return false;
    };
    let SubprogramOwner::Package(package_id) = target.owner else {
        return false;
    };
    let Some(receiver) = target.params.first() else {
        return false;
    };
    let Some(receiver_leaf) = receiver.type_ref.name_path.last() else {
        return false;
    };
    if !receiver_leaf.to_ascii_lowercase().ends_with("servant") {
        return false;
    }
    let impl_package = ast
        .packages
        .iter()
        .find(|package| package.id == package_id)
        .is_some_and(|package| package.name.to_ascii_lowercase().ends_with("_impl"));
    let declared_servant = ast.types.iter().any(|type_ref| {
        type_ref.owner == TypeOwner::Package(package_id)
            && type_ref
                .name_path
                .last()
                .is_some_and(|name| name.eq_ignore_ascii_case(receiver_leaf))
            && (matches!(type_ref.kind, TypeKind::Tagged { .. })
                || type_ref
                    .constraints
                    .0
                    .to_ascii_lowercase()
                    .contains("servant"))
    });
    impl_package || declared_servant
}

fn generation_error_is_report_only(reason: &str) -> bool {
    reason.contains(crate::generate_harness::BLOCKED_BY_NON_SELF_CONTAINED_HEADER)
}

#[cfg(test)]
mod generation_outcome_tests {
    use super::{ada_auto_servant_candidate, generation_error_is_report_only};
    use crate::auto::candidate::{Candidate, Lang};

    #[test]
    fn non_self_contained_header_is_report_only_not_unsupported() {
        assert!(generation_error_is_report_only(
            "blocked_by_non_self_contained_header: legacy.hpp needs its owner TU"
        ));
        assert!(!generation_error_is_report_only(
            "C++ parameter has no byte-buffer decoder"
        ));
    }

    #[test]
    fn checked_in_derived_servant_operation_selects_servant_direct_lane() {
        let root = tempfile::Builder::new()
            .prefix("govfuzz-auto-servant-detect-")
            .tempdir()
            .unwrap();
        let source = root.path().join("bar_impl.ads");
        std::fs::write(
            &source,
            "with PortableServer;\npackage Bar_Impl is\n   type Servant is new PortableServer.Servant_Base with null record;\n   function Compute (Self : Servant; S : String) return Integer;\nend Bar_Impl;\n",
        )
        .unwrap();
        let candidate = Candidate {
            harness_id: "H-ASERVANT".to_owned(),
            lang: Lang::Ada,
            source_path: source,
            line: 4,
            name: "compute".to_owned(),
            score: 1,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        };

        assert!(ada_auto_servant_candidate(&candidate));
    }
}

fn auto_sequence_candidate(c: &Candidate) -> bool {
    match c.lang {
        crate::auto::candidate::Lang::C => c_auto_sequence_candidate(c),
        crate::auto::candidate::Lang::Cpp => cpp_auto_sequence_candidate(c),
        crate::auto::candidate::Lang::Ada => false,
        // Rust is pre-skipped before this is reached (M1.2). Stateful Rust
        // sequencing is harness-gen-internal, not the auto_sequence path.
        crate::auto::candidate::Lang::Rust => false,
        // Java is pre-skipped here in M2.1a (discovery only); the JVM driver owns
        // its own in-process input loop, not the C auto_sequence path.
        crate::auto::candidate::Lang::Java => false,
        // Python is prebuilt (Step 0) and the interpreter driver owns its own
        // input loop; the C auto_sequence path never applies (M3.1).
        crate::auto::candidate::Lang::Python => false,
        // Perl is prebuilt (Step 0); the interpreter driver owns its own input
        // loop (M3.2).
        crate::auto::candidate::Lang::Perl => false,
        // Go is prebuilt (Step 0); the compiled harness owns the framed loop (M3.3).
        crate::auto::candidate::Lang::Go => false,
        // COBOL is prebuilt (Step 0) into a C harness; no C auto_sequence path (M3.4).
        crate::auto::candidate::Lang::Cobol => false,
        // Fortran is prebuilt (Step 0) into a C harness; no C auto_sequence path (M3.5).
        crate::auto::candidate::Lang::Fortran => false,
        // C# is prebuilt (Step 0); the CLR driver owns the framed loop (M3.6).
        crate::auto::candidate::Lang::CSharp => false,
        // JS/TS are prebuilt (Step 0); the Node driver owns the framed loop (M3.7/3.8).
        crate::auto::candidate::Lang::Js | crate::auto::candidate::Lang::Ts => false,
        // Ruby is prebuilt (Step 0); the interpreter driver owns its own input loop (M3.9).
        crate::auto::candidate::Lang::Ruby => false,
        // Lua is prebuilt (Step 0); the interpreter driver owns its own input loop (M3.10).
        crate::auto::candidate::Lang::Lua => false,
        // PHP is prebuilt (Step 0); the interpreter driver owns its own input loop (M3.11).
        crate::auto::candidate::Lang::Php => false,
    }
}

fn static_candidate_can_include_defining_source(c: &Candidate) -> bool {
    match c.lang {
        crate::auto::candidate::Lang::C => true,
        crate::auto::candidate::Lang::Cpp => cpp_static_free_function_candidate(c),
        crate::auto::candidate::Lang::Ada => false,
        // Rust visibility makes "paste the defining source into the harness"
        // wrong — a future Rust lane depends on the crate by path (M1.2).
        crate::auto::candidate::Lang::Rust => false,
        // Java compiles against the classpath; "paste the defining source" never
        // applies (M2.1).
        crate::auto::candidate::Lang::Java => false,
        // Python imports the target module; "paste the defining source" never
        // applies (M3.1). The static pre-skip is bypassed for prebuilt lanes anyway.
        crate::auto::candidate::Lang::Python => false,
        // Perl `require`s the target module; "paste the defining source" never
        // applies (M3.2).
        crate::auto::candidate::Lang::Perl => false,
        // Go imports the target package via a module replace; "paste the defining
        // source" never applies (M3.3).
        crate::auto::candidate::Lang::Go => false,
        // COBOL builds a C harness in Step 0; "paste the defining source" never applies.
        crate::auto::candidate::Lang::Cobol => false,
        // Fortran builds a C harness in Step 0; "paste the defining source" never applies.
        crate::auto::candidate::Lang::Fortran => false,
        // C# builds through a project reference in Step 0; "paste the defining
        // source" never applies (M3.6).
        crate::auto::candidate::Lang::CSharp => false,
        // JS/TS `require` the (transpiled) module; "paste the defining source" never applies.
        crate::auto::candidate::Lang::Js | crate::auto::candidate::Lang::Ts => false,
        // Ruby `require`s the target file; "paste the defining source" never applies (M3.9).
        crate::auto::candidate::Lang::Ruby => false,
        // Lua `dofile`s the target; "paste the defining source" never applies (M3.10).
        crate::auto::candidate::Lang::Lua => false,
        // PHP `require`s the target; "paste the defining source" never applies (M3.11).
        crate::auto::candidate::Lang::Php => false,
    }
}

fn cpp_static_free_function_candidate(c: &Candidate) -> bool {
    let Ok(source) = crate::source_text::read_source_text(&c.source_path) else {
        return false;
    };
    let Ok(functions) = cpp_parser::parse_cpp_functions(&source) else {
        return false;
    };
    functions
        .iter()
        .find(|function| cpp_candidate_name_matches(function, &c.name) && function.line == c.line)
        .or_else(|| {
            functions
                .iter()
                .find(|function| cpp_candidate_name_matches(function, &c.name))
        })
        .is_some_and(|function| function.is_static && !function.api.is_method)
}

fn c_auto_sequence_candidate(c: &Candidate) -> bool {
    let Ok(source) = crate::source_text::read_source_text(&c.source_path) else {
        return false;
    };
    let Ok(functions) = c_parser::parse_c_functions(&source) else {
        return false;
    };
    let Some(target) = functions
        .iter()
        .find(|function| function.name == c.name && function.line == c.line)
        .or_else(|| functions.iter().find(|function| function.name == c.name))
    else {
        return false;
    };
    if target.is_static {
        return false;
    }
    let Some(target_handle) = target
        .params
        .first()
        .map(|param| canonical_c_lifecycle_type(&param.c_type))
        .filter(|ty| is_c_lifecycle_handle_type(ty))
    else {
        return false;
    };
    if is_c_lifecycle_init(&target.name) || is_c_lifecycle_end(&target.name) {
        return false;
    }
    // A real returning constructor is stronger evidence than an in-place helper
    // that merely starts with `Initialize`. Prefer the direct harness in that
    // case: it uses the constructor lifecycle table instead of zero-constructing
    // internal state (BrotliDecoderCreateInstance vs the static
    // InitializeCompoundDictionaryCopy helper).
    let has_returning_constructor = functions.iter().any(|function| {
        !function.is_static
            && is_c_lifecycle_init(&function.name)
            && canonical_c_lifecycle_type(&function.return_type) == target_handle
            && crate::generate_harness::c_neutral_ctor_args(
                function.params.iter().map(|param| param.c_type.as_str()),
            )
            .is_some()
    });
    if has_returning_constructor {
        return false;
    }
    functions.iter().any(|function| {
        function.name != target.name
            && function
                .params
                .first()
                .is_some_and(|param| canonical_c_lifecycle_type(&param.c_type) == target_handle)
            && (is_c_lifecycle_init(&function.name) || is_c_lifecycle_end(&function.name))
    })
}

#[cfg(test)]
mod c_auto_sequence_candidate_tests {
    use super::c_auto_sequence_candidate;
    use crate::auto::candidate::{Candidate, Lang};

    #[test]
    fn returning_constructor_outranks_static_initialize_helper() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-c-sequence-ctor-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("decode.c");
        std::fs::write(
            &source,
            "typedef struct DecoderState DecoderState;\n\
             typedef void *(*alloc_func)(void *, unsigned long);\n\
             typedef void (*free_func)(void *, void *);\n\
             DecoderState *DecoderCreateInstance(alloc_func a, free_func f, void *o) { return 0; }\n\
             void DecoderDestroyInstance(DecoderState *s) {}\n\
             static int InitializeDictionaryCopy(DecoderState *s, unsigned a) { return 0; }\n\
             int DecoderRun(DecoderState *s, const unsigned char *p, unsigned n) { return 0; }\n",
        )
        .unwrap();
        let candidate = Candidate {
            harness_id: "H-CCTOR".to_owned(),
            lang: Lang::C,
            source_path: source,
            line: 7,
            name: "DecoderRun".to_owned(),
            score: 1,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        };
        assert!(
            !c_auto_sequence_candidate(&candidate),
            "the direct harness must construct the handle through DecoderCreateInstance"
        );
        std::fs::remove_dir_all(dir).ok();
    }
}

fn cpp_auto_sequence_candidate(c: &Candidate) -> bool {
    let Ok(source) = crate::source_text::read_source_text(&c.source_path) else {
        return false;
    };
    let Ok(functions) = cpp_parser::parse_cpp_functions(&source) else {
        return false;
    };
    let Some(target) = functions
        .iter()
        .find(|function| cpp_candidate_name_matches(function, &c.name) && function.line == c.line)
        .or_else(|| {
            functions
                .iter()
                .find(|function| cpp_candidate_name_matches(function, &c.name))
        })
    else {
        return false;
    };
    if target.is_static && !target.api.is_method {
        return false;
    }
    if !target.api.is_method
        || target.api.class_name.is_none()
        || target.api.is_constructor
        || target.api.is_destructor
        || target.api.is_template
    {
        return false;
    }
    functions.iter().any(|function| {
        function.line != target.line
            && cpp_same_lifecycle_class(target, function)
            && !function.api.is_constructor
            && !function.api.is_destructor
            && !function.api.is_template
            && function
                .api
                .member_access
                .as_deref()
                .is_none_or(|access| access == "public")
            && function.params.iter().all(|param| {
                harness_gen::cpp_generate::cpp_parameter_type_supported(&param.cpp_type)
            })
    })
}

fn cpp_candidate_name_matches(function: &cpp_parser::CppFunction, requested: &str) -> bool {
    let requested_base = requested.split('(').next().unwrap_or(requested).trim();
    function.name == requested_base || cpp_qualified_name(function) == requested_base
}

/// See the pre-skip site in `run_attempt`: a C++ target whose RETURN type is a
/// bare identifier undefined anywhere in the scanned tree (and not a primitive/std
/// type) — MFC `CString`, a vendor SDK class. CONSERVATIVE: only a SINGLE
/// identifier return type (no `::`, `<`, `*`, `&`, cv/whitespace) is ever
/// considered, so a std/namespaced/template/pointer/qualified return can never
/// false-positive into a needless skip. Returns the offending leaf name.
fn cpp_target_undefined_return_type(
    candidate: &Candidate,
    decl_index: &DeclarationIndex,
) -> Option<String> {
    let source = crate::source_text::read_source_text(&candidate.source_path).ok()?;
    let functions = cpp_parser::parse_cpp_functions(&source).ok()?;
    let target = functions
        .iter()
        .find(|f| cpp_candidate_name_matches(f, &candidate.name) && f.line == candidate.line)
        .or_else(|| {
            functions
                .iter()
                .find(|f| cpp_candidate_name_matches(f, &candidate.name))
        })?;
    // Apply the call-site template instantiation (`T` -> `int`) so an INSTANTIATED
    // template's return type is judged as its concrete type. Without this, a
    // `template<typename T> T fold_as(..)` called `fold_as<int>(..)` — which
    // codegen builds fine as `int fold_as<int>(..)` — was wrongly pre-skipped as
    // "return type 'T' is undefined" and never fuzzed.
    let substituted;
    let ret = if !target.instantiation_args.is_empty()
        && target.instantiation_args.len() == target.template_type_params.len()
    {
        substituted = substitute_template_return_type(
            target.return_type.trim(),
            &target.template_type_params,
            &target.instantiation_args,
        );
        substituted.trim()
    } else {
        target.return_type.trim()
    };
    if ret.is_empty()
        || ret.contains("::")
        || ret.contains('<')
        || ret.contains('*')
        || ret.contains('&')
        || ret.contains(char::is_whitespace)
        || !ret.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    if is_cpp_builtin_or_std_leaf(ret) || decl_index.cpp_type_name_defined_in_tree(ret) {
        return None;
    }
    Some(ret.to_owned())
}

/// Replace template type parameters (`T`, `K`, `V`) with the concrete
/// instantiation arguments (`int`, ...) as whole identifiers only, so a return
/// type `T` becomes `int` and `std::vector<T>` becomes `std::vector<int>` while a
/// type merely *containing* the letter (`Tree`) is left untouched. `params` and
/// `args` are zipped positionally; a mismatched length leaves the type unchanged.
fn substitute_template_return_type(
    return_type: &str,
    params: &[String],
    args: &[String],
) -> String {
    if params.is_empty() || params.len() != args.len() {
        return return_type.to_owned();
    }
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(return_type.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if token.is_empty() {
            return;
        }
        let replacement = params
            .iter()
            .position(|param| param == token)
            .map(|idx| args[idx].as_str())
            .unwrap_or(token.as_str());
        out.push_str(replacement);
        token.clear();
    };
    for ch in return_type.chars() {
        if is_ident(ch) {
            token.push(ch);
        } else {
            flush(&mut token, &mut out);
            out.push(ch);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// A C++ return-type leaf that is a language primitive or a common `std::` type
/// spelled bare (a `using namespace std;` file returning `string`). Never treated
/// as an undefined external type.
fn is_cpp_builtin_or_std_leaf(name: &str) -> bool {
    matches!(
        name,
        "void"
            | "bool"
            | "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "unsigned"
            | "signed"
            | "auto"
            | "wchar_t"
            | "char8_t"
            | "char16_t"
            | "char32_t"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "intptr_t"
            | "uintptr_t"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "string"
            | "wstring"
            | "nullptr_t"
    )
}

fn cpp_qualified_name(function: &cpp_parser::CppFunction) -> String {
    let mut parts = function.api.namespace_path.clone();
    if let Some(class_name) = &function.api.class_name {
        parts.push(class_name.clone());
    }
    parts.push(function.name.clone());
    parts.join("::")
}

fn cpp_same_lifecycle_class(
    target: &cpp_parser::CppFunction,
    function: &cpp_parser::CppFunction,
) -> bool {
    target.api.class_name.is_some()
        && function.api.class_name == target.api.class_name
        && function.api.namespace_path == target.api.namespace_path
}

// Lifecycle clustering predicates are shared with harness generation
// (crate::generate_harness) so the auto eligibility gate can never
// disagree with the cluster the generator builds.
use crate::generate_harness::{
    canonical_c_lifecycle_type, is_c_lifecycle_end, is_c_lifecycle_handle_type, is_c_lifecycle_init,
};

#[allow(clippy::too_many_arguments)]
fn try_build(
    candidate: &Candidate,
    dir: &Path,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    source_root: Option<&Path>,
    ada_dep_dirs: &[PathBuf],
    cross_compiler: Option<&crate::build::CFamilyCompilerOverride>,
    sanitizers: &multicore_fuzz::SanitizerSelection,
    dir_filter: &crate::auto::discovery::DirFilter,
    project_override: Option<&Path>,
    round: usize,
) -> BuildOutcome {
    use crate::auto::candidate::Lang;
    let work_dir = dir
        .parent()
        .and_then(|p| p.parent())
        .expect("harness_dir has work-dir grandparent");
    let harness_id = dir
        .file_name()
        .and_then(|n| n.to_str())
        .expect("harness dir name");
    match candidate.lang {
        Lang::C | Lang::Cpp => try_build_c(
            work_dir,
            harness_id,
            extra_sources,
            extra_includes,
            cross_compiler,
            sanitizers,
            round,
        ),
        Lang::Ada => try_build_ada(
            work_dir,
            harness_id,
            candidate,
            extra_sources,
            source_root,
            ada_dep_dirs,
            dir_filter,
            project_override,
            round,
        ),
        // The Rust lane builds its harness in `run_attempt` Step 0a (the
        // sancov+ASan staticlib clang-linked with the C driver to
        // `harnesses/<id>/main`), BEFORE the repair loop. This pass-through reports
        // Success iff that binary exists, so the loop drops straight into the
        // shared builtin-engine fuzz cascade. The Rust diagnostic-driven repair
        // is build-time (build_classifier::cargo) inside Step 0a, not the C/Ada
        // header/stub repair loop, so there is nothing to retry here.
        Lang::Rust => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Rust harness binary missing (Step 0a build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // The Java lane built its launcher (`harnesses/<id>/main`) + classes in
        // `run_attempt` Step 0; this pass-through reports Success iff that launcher
        // exists, dropping the loop into the shared builtin-engine fuzz cascade.
        Lang::Java => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Java launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // The Python lane emitted its launcher (`harnesses/<id>/main`) + driver/runtime
        // in `run_attempt` Step 0; this pass-through reports Success iff that
        // launcher exists, dropping the loop into the shared builtin-engine cascade.
        Lang::Python => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Python launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // The Perl lane emitted its launcher (`harnesses/<id>/main`) + driver/runtime in
        // `run_attempt` Step 0; pass-through reports Success iff that launcher exists.
        Lang::Perl => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Perl launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // The Go lane compiled its harness binary (`harnesses/<id>/main`) in Step 0;
        // pass-through reports Success iff that binary exists.
        Lang::Go => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Go harness binary missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // COBOL compiled its C harness binary (`harnesses/<id>/main`) in Step 0 via
        // cobc -C + the passthrough driver; pass-through reports Success iff it exists.
        Lang::Cobol => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "COBOL harness binary missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // Fortran compiled its C harness binary in Step 0 (gfortran + passthrough driver).
        Lang::Fortran => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Fortran harness binary missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // C# built + instrumented its assembly and emitted the launcher `main` in
        // Step 0 (dotnet build + sharpfuzz); pass-through succeeds iff it exists.
        Lang::CSharp => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "C# harness launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // JS/TS emitted their `node` launcher `main` in Step 0 (TS transpiled first);
        // pass-through succeeds iff it exists.
        Lang::Js | Lang::Ts => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "JS/TS harness launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // Ruby emitted its `ruby` launcher `main` in Step 0; pass-through succeeds iff
        // it exists (M3.9).
        Lang::Ruby => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Ruby harness launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // Lua emitted its `lua` launcher `main` in Step 0; pass-through succeeds iff
        // it exists (M3.10).
        Lang::Lua => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "Lua harness launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
        // PHP emitted its `php` launcher `main` in Step 0; pass-through succeeds iff
        // it exists (M3.11).
        Lang::Php => {
            let main_bin = crate::auto::layout::harness_dir(work_dir, harness_id).join("main");
            if main_bin.is_file() {
                BuildOutcome::Success
            } else {
                BuildOutcome::Failed {
                    errors: build_classifier::classify(
                        "PHP harness launcher missing (Step 0 build did not produce harnesses/<id>/main)",
                    ),
                }
            }
        }
    }
}

fn try_build_c(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    cross_compiler: Option<&crate::build::CFamilyCompilerOverride>,
    sanitizers: &multicore_fuzz::SanitizerSelection,
    round: usize,
) -> BuildOutcome {
    use multicore_fuzz::SanitizerSelection;
    // `auto --sanitizers` arms an explicit `-fsanitize=` set for the native build.
    // A cross build already carries its own flag override (which deliberately drops
    // sanitizers — they don't survive qemu-user), so sanitizers only apply on the
    // host path. `Default` leaves the Makefile's `address,undefined` CFLAGS/CXXFLAGS
    // intact (byte-identical to before); `None` builds coverage-only (no
    // `-fsanitize=`); `Set` swaps in exactly the requested matrix.
    let sanitizer_override;
    let compiler = match cross_compiler {
        Some(cross) => Some(cross),
        None => match sanitizers {
            SanitizerSelection::Default => None,
            SanitizerSelection::None => {
                sanitizer_override = coverage_only_compiler_override();
                Some(&sanitizer_override)
            }
            SanitizerSelection::Set(set) => {
                sanitizer_override = sanitizer_compiler_override(set);
                Some(&sanitizer_override)
            }
        },
    };
    let harness_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let is_cpp = harness_dir.join("main.cpp").is_file();
    // C++ dialect selection: an explicit `--cxx-std` (GOVFUZZ_CXX_STD) wins; else a
    // standard the ladder already proved for this exact target/build context is
    // reused; else the baked default may be overridden on a failure. A project-wide
    // cache lets one C++11 TU poison unrelated C++17 targets.
    let explicit_std = std::env::var("GOVFUZZ_CXX_STD")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let cache_path = cxx_dialect_cache_path(work_dir, harness_id);
    let mut cached_std = std::fs::read_to_string(&cache_path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let chosen_std = explicit_std.clone().or_else(|| cached_std.clone());
    let build_succeeded = |output: &std::process::Output| {
        output.status.success() && harness_dir.join("main").is_file()
    };

    // From the first repair round on, ask the compiler to parse and analyse
    // without generating code or linking. Most rounds fail, and a failing round
    // only ever yields diagnostics — so the object code and the link are work
    // thrown away. Round 0 skips this: a target that compiles as-is is the common
    // case and should not pay for a check to learn what the build would say.
    //
    // A clean check is NOT success. Undefined symbols cannot appear in this mode
    // (nothing is linked), so the real build always runs before a target is
    // called built, and the dialect ladder and -fcommon retry below stay on the
    // real build where their evidence lives.
    if round > 0 {
        let check = crate::build::try_run_c_make_build_with_target(
            work_dir,
            harness_id,
            extra_sources,
            extra_includes,
            compiler,
            Some("syntaxcheck"),
            chosen_std.as_deref(),
        );
        if !check.status.success() {
            let raw = combined_build_output(&check);
            let errors = build_classifier::classify(&raw);
            if !errors.is_empty() {
                return BuildOutcome::Failed { errors };
            }
        }
    }
    let mut output = crate::build::try_run_c_make_build_with_target(
        work_dir,
        harness_id,
        extra_sources,
        extra_includes,
        compiler,
        None,
        chosen_std.as_deref(),
    );
    if build_succeeded(&output) {
        return BuildOutcome::Success;
    }
    let mut raw_output = combined_build_output(&output);
    let mut errors = build_classifier::classify(&raw_output);

    // GCC 10 and Clang 11 changed C's default from -fcommon to -fno-common.
    // Older projects often put tentative definitions (`int global;`) in public
    // headers, expecting the linker to merge them. Under the modern default,
    // ASan makes the failure especially recognizable as duplicate
    // `__odr_asan_gen_*` symbols. Retry only after a real C link exhibits a
    // duplicate-symbol failure, and keep the compatibility fragment only when
    // the retry removes that class of error. Every C Makefile lane includes the
    // same fragment, so AFL/MSan/TSan/coverage/differential replay stay aligned.
    let c_compat_path = work_dir.join("c_compat.mk");
    if !is_cpp
        && !c_compat_path.is_file()
        && output_may_require_fcommon(&raw_output)
        && std::fs::write(&c_compat_path, "C_COMPAT_FLAGS := -fcommon\n").is_ok()
    {
        let compat_output = crate::build::try_run_c_make_build_with_target(
            work_dir,
            harness_id,
            extra_sources,
            extra_includes,
            compiler,
            None,
            None,
        );
        if build_succeeded(&compat_output) {
            return BuildOutcome::Success;
        }
        let compat_raw = combined_build_output(&compat_output);
        if !output_may_require_fcommon(&compat_raw) {
            raw_output = compat_raw;
            errors = build_classifier::classify(&raw_output);
        } else {
            // Function duplicates and accidentally repeated source files are
            // not fixed by -fcommon; do not weaken later targets for them.
            let _ = std::fs::remove_file(&c_compat_path);
        }
    }

    // A project-level cached legacy standard can become invalid after a repair
    // exposes more of the real include graph. For example, an early uncrustify
    // build with missing generated headers made gnu++03 look cheaper than the
    // modern rungs; once those headers were supplied, libstdc++ correctly said
    // the TU requires C++11. Re-probe from the default instead of pinning every
    // later retry/target to a standard that cannot compile its headers.
    //
    // Inspect the RAW output. The structured classifier deliberately omits an
    // `Other` when the same invocation also contains a recognized missing type,
    // so checking only `errors` loses this decisive diagnostic.
    if is_cpp
        && explicit_std.is_none()
        && cached_std.is_some()
        && output_requires_newer_cxx_standard(&raw_output)
    {
        let _ = std::fs::remove_file(&cache_path);
        cached_std = None;
        output = crate::build::try_run_c_make_build_with_target(
            work_dir,
            harness_id,
            extra_sources,
            extra_includes,
            compiler,
            None,
            None,
        );
        if build_succeeded(&output) {
            return BuildOutcome::Success;
        }
        raw_output = combined_build_output(&output);
        errors = build_classifier::classify(&raw_output);
    }

    // Legacy-dialect ladder: a modern default (gnu++20) rejects old C++ (`register`,
    // dynamic exception specs, removed stdlib). On a first C++ COMPILE failure with no
    // explicit or cached standard, retry successively older ones — the first that BUILDS
    // wins and is cached for the rest of the project. If none build, adopt the
    // fewest-errors dialect so the repair loop continues under the right one instead of
    // the default.
    //
    // A C++ standard governs COMPILE-stage acceptance only; it cannot change which
    // symbols are DEFINED at link time. So a pure link failure (every error an undefined
    // external) is never a dialect problem — and running the ladder on one is actively
    // harmful: the pre-C++11 rungs (gnu++03/98) fail to compile the harness's own
    // libstdc++ headers with a single "requires ISO C++ 2011" error, which the
    // fewest-errors rule mistakes for an improvement over the honest undefined externals
    // and caches — pre-empting the repair loop's full-TU-set / archive / per-symbol link
    // fallbacks (regression: auto_full_tu_link). Skip the ladder unless a compile-stage
    // error is present.
    let is_pure_link_failure = !errors.is_empty()
        && errors
            .iter()
            .all(|e| matches!(e, BuildErrorKind::UndefinedSymbol { .. }));
    if is_cpp && explicit_std.is_none() && cached_std.is_none() && !is_pure_link_failure {
        let mut best: Option<(&'static str, Vec<BuildErrorKind>)> = None;
        for std in CXX_DIALECT_LADDER {
            let out = crate::build::try_run_c_make_build_with_target(
                work_dir,
                harness_id,
                extra_sources,
                extra_includes,
                compiler,
                None,
                Some(std),
            );
            if build_succeeded(&out) {
                if let Some(parent) = cache_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&cache_path, std);
                return BuildOutcome::Success;
            }
            let raw = combined_build_output(&out);
            let errs = build_classifier::classify(&raw);
            // Never down-select to a standard so old the stdlib headers reject it
            // outright ("requires ISO C++ 20xx"): that build can't compile the harness
            // at all, so its small error count is a regression, not an improvement.
            // Check raw output because recognized errors otherwise suppress `Other`.
            if output_requires_newer_cxx_standard(&raw) {
                continue;
            }
            if best.as_ref().is_none_or(|(_, b)| errs.len() < b.len()) {
                best = Some((std, errs));
            }
        }
        if let Some((_std, errs)) = best {
            // Adopt the fewest-errors dialect for the repair loop even on a TIE
            // (`<=`, offline-legacy audit #10). A legacy TU commonly swaps
            // gnu++20's UNREPAIRABLE dialect rejection (a removed-syntax `Other`)
            // for an equal count of REPAIRABLE errors under an older rung (a
            // missing type the loop can stub). With strict `<` the tie kept the
            // default's dialect error, which the planner can't act on, so the
            // target failed immediately and never fuzzed. Returning the older
            // rung's errors lets the loop stub the missing type; the ladder
            // re-runs next round and BUILDS under that older std once the stub is
            // in place — so convergence needs no persisted (and possibly wrong)
            // failed dialect. Gated behind !is_pure_link_failure above, so a pure
            // link failure never mis-selects a pre-C++11 std (auto_full_tu_link).
            if errs.len() <= errors.len() {
                return BuildOutcome::Failed { errors: errs };
            }
        }
    }
    BuildOutcome::Failed { errors }
}

fn cxx_dialect_cache_path(work_dir: &Path, harness_id: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let harness_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let mut hasher = Sha256::new();
    hasher.update(b"govfuzz-cxx-dialect-context-v2\0");
    for name in ["Makefile", "main.cpp"] {
        hasher.update(name.as_bytes());
        if let Ok(bytes) = std::fs::read(harness_dir.join(name)) {
            hasher.update(bytes);
        }
    }
    let repairs = harness_dir.join("repairs");
    if let Ok(entries) = std::fs::read_dir(&repairs) {
        let mut files = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        files.sort();
        for file in files {
            if let Some(name) = file.file_name() {
                hasher.update(name.to_string_lossy().as_bytes());
            }
            if let Ok(bytes) = std::fs::read(file) {
                hasher.update(bytes);
            }
        }
    }
    let digest = hasher.finalize();
    let key = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    work_dir.join("cxx_dialects").join(format!("{key}.txt"))
}

fn output_requires_newer_cxx_standard(output: &str) -> bool {
    output.contains("requires compiler and library support for the ISO C++")
        || output.contains("c++0x_warning.h")
}

fn output_may_require_fcommon(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("multiple definition of") || lower.contains("duplicate symbol")
}

#[cfg(test)]
mod cxx_dialect_output_tests {
    use super::{
        cxx_dialect_cache_path, output_may_require_fcommon, output_requires_newer_cxx_standard,
        CXX_DIALECT_LADDER,
    };
    use std::fs;

    #[test]
    fn dialect_ladder_never_selects_a_standard_the_driver_cannot_compile() {
        assert_eq!(CXX_DIALECT_LADDER, ["gnu++17", "gnu++14", "gnu++11"]);
    }

    #[test]
    fn raw_output_keeps_stdlib_floor_signal_among_classified_errors() {
        let output = "/usr/include/c++/13/bits/c++0x_warning.h:32:2: error: \
                      This file requires compiler and library support for the ISO C++ 2011 standard\n\
                      target.cpp:9:3: error: unknown type name 'generated_type'\n";
        assert!(output_requires_newer_cxx_standard(output));
    }

    #[test]
    fn ordinary_compile_failure_is_not_a_stdlib_floor_signal() {
        assert!(!output_requires_newer_cxx_standard(
            "target.cpp:9:3: error: unknown type name 'generated_type'"
        ));
    }

    #[test]
    fn legacy_common_linker_diagnostics_trigger_compatibility_probe() {
        assert!(output_may_require_fcommon(
            "/usr/bin/ld: b.o:(.bss+0x0): multiple definition of `__odr_asan_gen_context'; a.o:first defined here"
        ));
        assert!(output_may_require_fcommon(
            "duplicate symbol '_legacy_global' in: a.o b.o"
        ));
        assert!(!output_may_require_fcommon(
            "undefined reference to `legacy_global'"
        ));
    }

    #[test]
    fn dialect_cache_is_target_and_repair_context_scoped() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("harnesses/H-X1");
        let second = temp.path().join("harnesses/H-X2");
        fs::create_dir_all(first.join("repairs")).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("Makefile"), "CXXFLAGS += -DAPI=1\n").unwrap();
        fs::write(first.join("main.cpp"), "int main() { return 0; }\n").unwrap();
        fs::write(second.join("Makefile"), "CXXFLAGS += -DAPI=2\n").unwrap();
        fs::write(second.join("main.cpp"), "int main() { return 0; }\n").unwrap();

        let before = cxx_dialect_cache_path(temp.path(), "H-X1");
        let other = cxx_dialect_cache_path(temp.path(), "H-X2");
        assert_ne!(
            before, other,
            "unrelated TUs must not share a dialect cache"
        );
        fs::write(
            first.join("repairs/auto_cpp_includes.h"),
            "#include <span>\n",
        )
        .unwrap();
        let after = cxx_dialect_cache_path(temp.path(), "H-X1");
        assert_ne!(
            before, after,
            "a repair-induced include graph change must invalidate the dialect choice"
        );
    }
}

/// Successively older C++ standards the dialect ladder retries after the default
/// (gnu++20) fails — newest first, so a target builds at the newest standard it can.
// The generated driver uses C++11 library/language facilities. Advertising
// gnu++03/98 retries was false: those rungs failed in the harness itself and the
// "fewest errors" heuristic could cache that failure as if it were progress.
// C++98 project code is still commonly accepted by gnu++11; genuinely
// pre-standard code is handled by the explicit report-only dialect lane.
const CXX_DIALECT_LADDER: [&str; 3] = ["gnu++17", "gnu++14", "gnu++11"];

fn combined_build_output(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
}

/// How a foreign-platform/arch candidate is built+fuzzed once it is NO LONGER
/// pre-skipped. `Native` is the ordinary host path (no `foreign_guard`).
enum ForeignStrategy {
    Native,
    /// Cross-compile + emulate under qemu-user / wine (#b) — arch guards.
    Cross(CrossTarget),
    /// Build natively with the platform guard defined + fake platform headers,
    /// fuzzing the logic with real host ASan/coverage (#c) — OS-platform guards.
    /// Findings are reduced-fidelity.
    StubIsolated(crate::auto::cross_target::PlatformStub),
}

/// Pick the build strategy for a foreign candidate, or `Err(reason)` with an
/// ACTIONABLE skip reason.
///
/// PRECEDENCE IS INTENTIONAL — for an OS-platform guard (Windows) on a C/C++
/// target we PREFER real Windows execution: cross-compile to a PE with mingw and
/// fuzz under wine (`Cross`). The driver is now Windows-buildable (Win32 file
/// mapping, `_setmode` binary stdio, `__sanitizer_cov_trace_pc` coverage, and a
/// vectored exception handler for crash detection), so the mingw build links and
/// runs — exercising the target's REAL Win32 behavior with coverage + cmplog.
/// Only when that toolchain is ABSENT do we fall back to the reduced-fidelity
/// native stub-isolated build (`_WIN32` defined + a fake `windows.h`), which
/// fuzzes the portable logic with host ASan but fakes the platform surface.
///
/// Arch/SIMD guards never platform-stub; they always take cross-compile/emulation
/// (#b), or skip with an actionable reason when no cross toolchain is installed.
///
/// FUTURE: also demote `StubIsolated` to a post-`FailedBuild` fallback, so a
/// Windows target that mingw cannot cross-compile (MSVC-only intrinsics, SDK
/// headers mingw lacks) still gets fuzzed via the stub rather than reported as a
/// build failure.
fn resolve_foreign_strategy(
    candidate: &Candidate,
    guard: &str,
) -> std::result::Result<ForeignStrategy, String> {
    if matches!(
        candidate.lang,
        crate::auto::candidate::Lang::C | crate::auto::candidate::Lang::Cpp
    ) {
        if let Some(stub) = crate::auto::cross_target::foreign_platform_stub(guard) {
            // Windows OS guard: prefer real PE-under-wine, fall back to the native
            // stub-isolated build only when mingw/wine is not installed here.
            return match resolve_foreign_candidate_target(candidate, guard) {
                Ok(target) => Ok(ForeignStrategy::Cross(target)),
                Err(_) => Ok(ForeignStrategy::StubIsolated(stub)),
            };
        }
    }
    resolve_foreign_candidate_target(candidate, guard).map(ForeignStrategy::Cross)
}

/// Decide whether a foreign-arch candidate can be cross-compiled and fuzzed on
/// this host. Returns the resolved `CrossTarget`, or `Err(reason)` carrying an
/// ACTIONABLE skip reason naming what to install. (Host-native candidates never
/// reach here — their `foreign_guard` is `None`.)
fn resolve_foreign_candidate_target(
    candidate: &Candidate,
    guard: &str,
) -> std::result::Result<CrossTarget, String> {
    let Some(target) = resolve_cross_target(guard) else {
        return Err(format!(
            "definition is guarded by platform conditional `{guard}`, which govfuzz has no \
             cross toolchain mapping for on this host"
        ));
    };
    // Ada cross-compilation needs a matching GNAT cross toolchain + runtime the
    // C/C++ make path doesn't drive; skip with a precise reason for now.
    if matches!(candidate.lang, crate::auto::candidate::Lang::Ada) {
        return Err(format!(
            "foreign-platform Ada target (guard `{guard}`) needs a matching GNAT cross \
             toolchain; govfuzz auto currently cross-compiles only C/C++ (would target {})",
            target.toolchain_hint()
        ));
    }
    // The runner emulator + cross CC must be installed; a C++ candidate also
    // needs the cross C++ compiler. Name every missing piece so the skip is
    // actionable.
    let mut missing = target.missing_tools();
    if matches!(candidate.lang, crate::auto::candidate::Lang::Cpp)
        && !executable_on_path(&target.cxx)
    {
        missing.push(target.cxx.as_str());
    }
    if !missing.is_empty() {
        return Err(format!(
            "foreign target (guard `{guard}`) needs the {}, not installed on this host \
             (missing: {})",
            target.toolchain_hint(),
            missing.join(", ")
        ));
    }
    Ok(target)
}

/// Synthesise a stub-isolated build for an OS-platform target: write the fake
/// platform headers beside the harness (so the Makefile's `-I .` resolves the
/// target's `#include <windows.h>`) and `#define` the platform guard to `1` in
/// the force-included `auto_defines.h` (so the foreign branch compiles and both
/// `#ifdef GUARD` / `#if GUARD` forms are satisfied). The build is otherwise the
/// normal host build; leftover platform functions are stubbed by the repair loop.
fn apply_platform_stub(
    stub: &crate::auto::cross_target::PlatformStub,
    harness_dir: &Path,
    repairs_dir: &Path,
) -> std::io::Result<()> {
    // auto_cpp_includes.h + auto_defines.h are both force-included (build.rs
    // `repair_force_includes`) at the top of EVERY TU, before its first line.
    let cpp_includes = repairs_dir.join(crate::auto::repair::AUTO_CPP_INCLUDES_FILE);
    let mut includes = std::fs::read_to_string(&cpp_includes).unwrap_or_default();
    for header in &stub.headers {
        // Header names are fixed library constants (e.g. `windows.h`), never
        // attacker-derived, but keep them flat under the harness dir regardless.
        let name = Path::new(&header.name)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("platform.h"));
        std::fs::write(harness_dir.join(name), &header.content)?;
        // Force-include the fake header into every TU so the harness `main.c`'s
        // `extern <PlatformType> target(...)` forward declaration type-checks too,
        // not only the target source's own `#include <name>`. The quote include
        // resolves via the Makefile's `-I .` (the harness dir we just wrote into).
        let line = format!("#include \"{}\"\n", name.to_string_lossy());
        if !includes.contains(&line) {
            includes.push_str(&line);
        }
    }
    std::fs::write(&cpp_includes, includes)?;
    // Define the platform guard to `1` so both `#ifdef GUARD` / `#if GUARD` forms
    // compile the foreign branch.
    let defines = repairs_dir.join(crate::auto::repair::AUTO_DEFINES_FILE);
    let mut content = std::fs::read_to_string(&defines).unwrap_or_default();
    let define_line = format!("#define {} 1\n", stub.define);
    if !content.contains(&define_line) {
        content.push_str(&define_line);
        std::fs::write(&defines, content)?;
    }
    Ok(())
}

/// Cross compiler + replacement flags for a foreign build. The native harness
/// Makefile bakes clang's `-fsanitize-coverage=trace-pc-guard,trace-cmp` and
/// `-fsanitize=address,undefined` into `CFLAGS`/`CXXFLAGS`. The cross GCCs reject
/// `trace-pc-guard` outright, so an arch (qemu-user) build drops coverage + ASan
/// entirely and compiles plain `-O1 -g` — the harness still runs and hard crashes
/// (SIGSEGV / SIGABRT) are still caught, just without coverage or ASan.
///
/// A Windows (mingw + wine) build does better: mingw-w64 gcc DOES accept
/// `trace-pc` + `trace-cmp` (just not the guard variant), so we arm them — the
/// Windows driver implements the guard-less `__sanitizer_cov_trace_pc` hook and
/// the cmplog operand hooks, giving real coverage-guided, input-to-state fuzzing
/// under wine. ASan still has no mingw runtime, so memory bugs surface via the
/// driver's vectored exception handler (a fault → distinctive crash exit) rather
/// than ASan shadow checks.
fn cross_compiler_override(target: &CrossTarget) -> crate::build::CFamilyCompilerOverride {
    let mut cflags = vec!["-O1".to_owned(), "-g".to_owned()];
    let mut cxxflags = vec!["-O1".to_owned(), "-g".to_owned(), "-std=gnu++17".to_owned()];
    if matches!(target.runner, CrossRunner::Wine { .. }) {
        let coverage = "-fsanitize-coverage=trace-pc,trace-cmp".to_owned();
        cflags.push(coverage.clone());
        cxxflags.push(coverage);
        // Link fully static so the PE carries no mingw DLL dependency
        // (libstdc++-6.dll, libgcc_s_seh-1.dll, libwinpthread-1.dll) that wine
        // cannot resolve at load time — a dynamically-linked C++ harness fails to
        // start under wine with STATUS_DLL_NOT_FOUND and never fuzzes.
        cflags.push("-static".to_owned());
        cxxflags.push("-static".to_owned());
    }
    crate::build::CFamilyCompilerOverride {
        cc: target.cc.clone(),
        cxx: target.cxx.clone(),
        cflags,
        cxxflags,
    }
}

/// clang `-fsanitize=` name for a sanitizer (the compile-time spelling, distinct
/// from the run-time `<SAN>_OPTIONS` env key).
fn sanitizer_fsanitize_name(s: multicore_fuzz::Sanitizer) -> &'static str {
    match s {
        multicore_fuzz::Sanitizer::Asan => "address",
        multicore_fuzz::Sanitizer::Msan => "memory",
        multicore_fuzz::Sanitizer::Ubsan => "undefined",
        multicore_fuzz::Sanitizer::Tsan => "thread",
        multicore_fuzz::Sanitizer::Lsan => "leak",
    }
}

/// Native clang compile flags for `auto --sanitizers`. Replicates the harness
/// Makefile's default CFLAGS/CXXFLAGS structure — `-O1 -g`, the engine's
/// `-fsanitize-coverage=trace-pc-guard,trace-cmp` (edge coverage #385 + cmplog
/// #398/#400), and the UBSan check subtractions OSS-Fuzz also drops — but swaps the
/// baked-in `-fsanitize=address,undefined` for EXACTLY the requested set, so a user
/// can build an MSan/TSan harness (or pin ASan-only) instead of the default. Only the
/// `-fsanitize=` group is replaced; COMPILE_DB_FLAGS / INCLUDES / AUTO_EXTRA_* are
/// separate make variables and stay intact. C++ uses `gnu++17` (matching the cross
/// override) since overriding CXXFLAGS drops the template's detected standard.
///
/// Sanitizers that conflict (e.g. `asan` + `msan`, or `msan` + `tsan`) will fail to
/// compile — clang rejects the combination — which surfaces as a normal build error;
/// `address,undefined,leak` are the compatible set. MSan/TSan are best-effort: without
/// a fully-instrumented libc they can report false positives, but the harness still
/// builds and runs.
fn sanitizer_compiler_override(
    sanitizers: &[multicore_fuzz::Sanitizer],
) -> crate::build::CFamilyCompilerOverride {
    let fsanitize = format!(
        "-fsanitize={}",
        sanitizers
            .iter()
            .map(|s| sanitizer_fsanitize_name(*s))
            .collect::<Vec<_>>()
            .join(",")
    );
    let has_ubsan = sanitizers.contains(&multicore_fuzz::Sanitizer::Ubsan);
    native_coverage_override(Some(fsanitize), has_ubsan)
}

/// Native clang compile flags for `auto --sanitizers none` (#434): the same
/// `-O1 -g` + engine coverage (`-fsanitize-coverage=trace-pc-guard,trace-cmp`)
/// structure as [`sanitizer_compiler_override`], but with NO `-fsanitize=` group.
/// The harness gets coverage-guided, crash-only fuzzing (SIGSEGV/SIGABRT still
/// caught) with zero ASan/UBSan false positives — the escape hatch for code that
/// FP-storms under ASan (shared memory, custom allocators, RTOS). Replaces the
/// Makefile's baked-in `-fsanitize=address,undefined`.
fn coverage_only_compiler_override() -> crate::build::CFamilyCompilerOverride {
    native_coverage_override(None, false)
}

/// Shared builder for the native override: `-O1 -g`, an optional `-fsanitize=`
/// group, the UBSan check subtractions (only when UBSan is present and a
/// `-fsanitize=` group is set), then the engine's coverage flags last. Only the
/// `-fsanitize=` group differs across callers; COMPILE_DB_FLAGS / INCLUDES /
/// AUTO_EXTRA_* are separate make variables and stay intact. C++ uses `gnu++17`
/// (matching the cross override) since overriding CXXFLAGS drops the template's
/// detected standard.
///
/// Conflicting sanitizers (e.g. `asan`+`msan`) make clang reject the build — a
/// normal build error; `address,undefined,leak` are the compatible set. MSan/TSan
/// are best-effort without an instrumented libc but still build and run.
fn native_coverage_override(
    fsanitize: Option<String>,
    has_ubsan: bool,
) -> crate::build::CFamilyCompilerOverride {
    let coverage = "-fsanitize-coverage=trace-pc-guard,trace-cmp".to_owned();
    let mut cflags = vec!["-O1".to_owned(), "-g".to_owned()];
    let mut cxxflags = vec![
        "-O1".to_owned(),
        "-g".to_owned(),
        "-std=gnu++17".to_owned(),
        // Keep the generated C++ Makefile's compatibility suppression when
        // --sanitizers replaces CXXFLAGS. Clang 18 otherwise rejects the
        // pre-C++11 `"%" PRId64`/`"text"MACRO` idiom as a hard error.
        "-Wno-reserved-user-defined-literal".to_owned(),
    ];
    if let Some(fsanitize) = fsanitize {
        cflags.push(fsanitize.clone());
        cxxflags.push(fsanitize);
        // The `function`/`vptr`/`alignment` checks fire on pervasive harmless
        // patterns; subtract them only when UBSan is in the set (the subtraction
        // must follow `-fsanitize=undefined`), mirroring the Makefile default.
        if has_ubsan {
            let no_sanitize = "-fno-sanitize=function,vptr,alignment".to_owned();
            cflags.push(no_sanitize.clone());
            cxxflags.push(no_sanitize);
        }
    }
    cflags.push(coverage.clone());
    cxxflags.push(coverage);
    crate::build::CFamilyCompilerOverride {
        cc: "clang".to_owned(),
        cxx: "clang++".to_owned(),
        cflags,
        cxxflags,
    }
}

/// Build the emulation wrapper that launches a cross-built harness: qemu-user
/// (with a `-L <sysroot>` pair when the cross sysroot is present so the dynamic
/// loader / libs resolve) or wine (which needs no extra args).
fn cross_harness_wrapper(target: &CrossTarget) -> crate::runner::HarnessWrapper {
    match &target.runner {
        CrossRunner::QemuUser { exe } => crate::runner::HarnessWrapper::QemuUser {
            exe: PathBuf::from(exe),
            args: qemu_user_args(target),
        },
        CrossRunner::Wine { exe } => crate::runner::HarnessWrapper::Wine {
            exe: PathBuf::from(exe),
        },
    }
}

/// `-L <sysroot>` for qemu-user when `/usr/<triple>` exists, so a dynamically
/// linked cross harness finds its target-arch loader and shared libs. Empty when
/// no sysroot is present (a static harness needs none).
fn qemu_user_args(target: &CrossTarget) -> Vec<String> {
    let sysroot = PathBuf::from("/usr").join(&target.triple);
    if sysroot.is_dir() {
        vec!["-L".to_owned(), sysroot.display().to_string()]
    } else {
        Vec::new()
    }
}

/// #91: resolve the governing Ada project for a candidate. An operator
/// `--project` override wins outright; otherwise select the project that OWNS the
/// candidate's source (see [`crate::auto::gpr_scenario::select_governing_gpr`]),
/// which itself falls back to the legacy first-`.gpr` selection when nothing owns
/// it. `None` only when there is no project at all (a gprless source tree).
fn resolve_governing_gpr(
    candidate_source: &Path,
    source_root: &Path,
    project_override: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(explicit) = project_override {
        return Some(explicit.to_path_buf());
    }
    crate::auto::gpr_scenario::select_governing_gpr(candidate_source, source_root)
}

#[cfg(test)]
mod project_override_tests {
    use super::resolve_governing_gpr;
    use std::path::Path;

    #[test]
    fn explicit_project_override_wins_over_auto_selection() {
        // #91: `--project` is an unambiguous operator override — it is returned
        // verbatim regardless of which project would own the candidate's source.
        let chosen = Path::new("/repo/chosen.gpr");
        let got = resolve_governing_gpr(
            Path::new("/repo/src/parser.adb"),
            Path::new("/repo"),
            Some(chosen),
        );
        assert_eq!(got.as_deref(), Some(chosen));
    }
}

#[allow(clippy::too_many_arguments)]
fn try_build_ada(
    work_dir: &Path,
    harness_id: &str,
    candidate: &Candidate,
    extra_sources: &[PathBuf],
    source_root: Option<&Path>,
    ada_dep_dirs: &[PathBuf],
    dir_filter: &crate::auto::discovery::DirFilter,
    project_override: Option<&Path>,
    round: usize,
) -> BuildOutcome {
    // The Ada build pipeline (prepare_layout in crate::build) requires
    // two preconditions auto doesn't otherwise satisfy:
    //   - <work_dir>/src_instrumented/ populated with instrumented
    //     copies of every Ada source the harness links against (the
    //     standalone `govfuzz instrument` subcommand creates this
    //     directory per source);
    //   - <work_dir>/generated_harnesses/<id>/main.adb mirroring the
    //     harness `attempt()` already wrote to <work_dir>/harnesses/<id>/.
    // Both are idempotent — retries reuse what's already there.
    let fallback_root = candidate
        .source_path
        .parent()
        .unwrap_or(&candidate.source_path);
    let root = source_root.unwrap_or(fallback_root);
    // #91: resolve the governing project ONCE (operator --project override, else
    // target-source ownership selection) and use it for BOTH source staging /
    // scenario exclusions and the final build, so a multi-project layout can't
    // stage against one project and build against another.
    let governing_gpr = resolve_governing_gpr(&candidate.source_path, root, project_override);
    // Name the target's Ada unit so the build can be restricted to its
    // with-closure (#GAP-C) instead of compiling the whole swept tree.
    let target_unit = ada_source_unit_name(&candidate.source_path);
    let excluded_bodies = load_excluded_bodies(
        &crate::auto::layout::harness_dir(work_dir, harness_id).join("repairs"),
    );
    if let Err(reason) = ensure_ada_src_instrumented(
        work_dir,
        root,
        ada_dep_dirs,
        dir_filter,
        target_unit.as_deref(),
        governing_gpr.as_deref(),
        &excluded_bodies,
    ) {
        return BuildOutcome::Failed {
            errors: vec![build_classifier::BuildErrorKind::Other { tail: reason }],
        };
    }
    // Force-fuzz: overlay synthesized stub bodies onto the freshly-staged sources
    // so they shadow the extended project's offline-unbuildable originals.
    apply_stub_bodies(work_dir, harness_id);
    if let Err(reason) = mirror_harness_into_generated_harnesses(work_dir, harness_id) {
        return BuildOutcome::Failed {
            errors: vec![build_classifier::BuildErrorKind::Other { tail: reason }],
        };
    }
    if let Err(reason) = stage_ada_c_repair_sources(work_dir, harness_id, extra_sources) {
        return BuildOutcome::Failed {
            errors: vec![build_classifier::BuildErrorKind::Other { tail: reason }],
        };
    }

    // #91: build against the SAME governing project used for staging/exclusions.
    run_ada_build_once(work_dir, harness_id, governing_gpr.as_deref(), round)
}

/// The generic repair loop records selected real C definitions and generated C
/// stubs in `extra_sources`. Native C/C++ builds pass those paths to Make; Ada's
/// synthesized GPR instead compiles its Source_Dirs, so mirror C repair sources
/// into the existing `repairs/ada_stubs` source directory before each retry.
fn stage_ada_c_repair_sources(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
) -> Result<(), String> {
    let destination =
        crate::auto::layout::harness_dir(work_dir, harness_id).join("repairs/ada_stubs");
    std::fs::create_dir_all(&destination)
        .map_err(|error| format!("create {}: {error}", destination.display()))?;
    for source in extra_sources {
        if !source
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("c"))
        {
            continue;
        }
        let Some(name) = source.file_name() else {
            continue;
        };
        let target = destination.join(name);
        if source == &target {
            continue;
        }
        std::fs::copy(source, &target).map_err(|error| {
            format!(
                "stage Ada C repair source {} -> {}: {error}",
                source.display(),
                target.display()
            )
        })?;
    }
    Ok(())
}

/// Run the Ada build pipeline once for `harness_id` and classify the result.
/// `BuildArgs` defaults mirror clap's value-enum defaults for the build
/// subcommand (host_file probe, libfuzzer engine — the latter irrelevant here).
fn run_ada_build_once(
    work_dir: &Path,
    harness_id: &str,
    source_project: Option<&Path>,
    round: usize,
) -> BuildOutcome {
    let build_args = crate::build::BuildArgs {
        work_dir: work_dir.to_path_buf(),
        source_project: source_project.map(Path::to_path_buf),
        harness: Some(harness_id.to_owned()),
        target: None,
        runtime: None,
        toolchain: None,
        probe_backend: crate::probe_backend::ProbeBackend::HostFile,
        c_engine: crate::build::CEngine::Libfuzzer,
    };
    // Persist the raw combined output so the force-fuzz external-stub refiner
    // (which needs GNAT's `expected/found` type pairs, not just the classified
    // errors) can read it in the repair loop.
    let persist_raw = |raw: &str| {
        let log = crate::auto::layout::harness_dir(work_dir, harness_id)
            .join("repairs")
            .join(ADA_BUILD_OUTPUT_LOG);
        if let Some(parent) = log.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&log, raw);
    };
    let classify_captured = |captured: crate::build::CapturedBuild| {
        let combined = format!("{}\n{}", captured.stderr, captured.stdout);
        let outcome = if captured.status_success {
            BuildOutcome::Success
        } else {
            BuildOutcome::Failed {
                errors: build_classifier::classify(&combined),
            }
        };
        (outcome, combined)
    };
    let as_failure = |reason: String| {
        (
            BuildOutcome::Failed {
                errors: vec![build_classifier::BuildErrorKind::Other {
                    tail: reason.clone(),
                }],
            },
            reason,
        )
    };
    // One build under whatever `-gnatXXXX` the dialect cache currently selects
    // (Ada 2022 by default); returns the classified outcome + raw output.
    //
    // From the FIRST REPAIR ROUND ON, a semantic check runs first. The repair loop
    // only ever consumes GNAT's diagnostics, so once a target is known to need
    // repair, paying for code generation, binding and linking before knowing
    // whether the closure even resolves is waste that multiplies by the round cap.
    // When the check is clean the full build still runs — it is the only thing
    // that produces the executable, and link errors surface nowhere else — so a
    // SUCCESS always means a real linked harness.
    //
    // Round 0 goes straight to the full build. A target that compiles as-is is the
    // common case on a healthy project, and it should not pay for a check pass to
    // learn what the build itself would have told it. This matters more with the
    // shared object directory: once the project's closure is compiled, a later
    // target's full build is little more than its own main plus the link, and a
    // check pass in front of that would be nearly pure overhead.
    let one_build = || {
        let checked = round > 0;
        if checked {
            match crate::build::try_run_ada_check_capturing(&build_args) {
                Ok(captured) if !captured.status_success => return classify_captured(captured),
                Ok(_) => {}
                Err(reason) => return as_failure(reason),
            }
        }
        match crate::build::try_run_ada_build_capturing(&build_args) {
            Ok(captured) => classify_captured(captured),
            Err(reason) => as_failure(reason),
        }
    };

    let (outcome, raw) = one_build();
    persist_raw(&raw);
    // Legacy-dialect ladder: -gnat2022 rejects some pre-2012 Ada (a now-reserved
    // word used as an identifier — `interface`/`overriding`/...; a removed
    // feature). On such a failure, and only when no dialect is cached yet, retry
    // under successively older standards; the first that BUILDS is cached for the
    // rest of the project (and for any synthesized stub bodies). Mirrors the C++
    // ladder. A pure external/link failure is never a dialect problem, so require
    // an actual dialect diagnostic before laddering.
    let build_dir = work_dir.join("build").join(harness_id);
    let cache_path = crate::build::ada_dialect_cache_path(&build_dir);
    if matches!(outcome, BuildOutcome::Failed { .. })
        && !cache_path.exists()
        && output_has_ada_dialect_error(&raw)
    {
        for switch in ["-gnat12", "-gnat05", "-gnat95"] {
            let _ = std::fs::write(&cache_path, switch);
            let (retry, retry_raw) = one_build();
            persist_raw(&retry_raw);
            if matches!(retry, BuildOutcome::Success) {
                return retry; // cache kept: the whole project builds under `switch`
            }
        }
        // None of the older standards built; drop back to the default.
        let _ = std::fs::remove_file(&cache_path);
        persist_raw(&raw);
    }
    outcome
}

/// True when GNAT output shows a DIALECT rejection an OLDER `-gnatXXXX` would
/// accept: a now-reserved word used as an identifier, or a construct flagged as a
/// newer-standard feature/extension. gprbuild reports only the FIRST error per
/// file, so a reserved word in a declaration surfaces just as `"function" or
/// "procedure" expected` (GNAT parses `overriding`/`interface` as a keyword) —
/// that form is included too.
fn output_has_ada_dialect_error(raw: &str) -> bool {
    raw.lines().any(|line| {
        line.contains("cannot be used as identifier")
            || line.contains("reserved word")
            || line.contains("\"function\" or \"procedure\" expected")
            || (line.contains(" is an Ada ")
                && (line.contains(" feature") || line.contains(" extension")))
    })
}

/// File under a target's `repairs/` holding the last Ada build's raw combined
/// output, read by the force-fuzz external-stub refiner.
pub(crate) const ADA_BUILD_OUTPUT_LOG: &str = "ada_build_output.log";

/// The reconstructed external-library model, held at WORK-DIR (project) scope
/// rather than under a target's `repairs/`.
///
/// Which libraries are missing, and what the project's code calls in them, is a
/// property of the PROJECT — every target in a sweep faces the same missing
/// GNATColl. Rebuilding the model per target meant each one re-derived an
/// identical stub set from scratch, paying a full repair cascade of gprbuild
/// rounds to relearn what the previous target already knew. Persisting it here
/// lets the first target converge and every later one start from the converged
/// stub set. The model only ever ADDS entities and resolves placeholders against
/// GNAT's oracle for the real library API, so carrying it forward is monotone;
/// a target needing more of the library keeps refining on top.
pub(crate) const ADA_EXTERNAL_MODEL: &str = "ada_external_model.json";

/// Marker under a target's `repairs/` recording that the project-scope external
/// stub model has been rendered for THIS target at least once.
pub(crate) const ADA_EXTERNAL_RENDERED: &str = "ada_external_rendered";

/// Force-fuzz: reconstruct a COMPILABLE stub of the used subset of each missing
/// external Ada library so the target's own body compiles and the target reaches
/// `built_and_fuzzed`. Seeds each external package's API shape from the client
/// source (tree-sitter) and refines parameter/return types from GNAT's
/// `expected/found` oracle in the last build output. Renders into the shared Ada
/// stub source dir (already on the build path). Returns whether the model
/// advanced this round (so the repair loop retries).
fn refine_ada_external_stubs(
    work_dir: &Path,
    harness_id: &str,
    repairs_dir: &Path,
    errors: &[BuildErrorKind],
) -> bool {
    use crate::auto::ada_external_stub::ExternalStubModel;
    let model_path = work_dir.join(ADA_EXTERNAL_MODEL);
    let mut model = ExternalStubModel::load(&model_path);
    // Packages needing stubs: every `with`ed unit absent from the tree (from a
    // stubbed library), plus any already being modeled.
    let mut packages: std::collections::BTreeSet<String> =
        model.stubbed_packages().map(str::to_owned).collect();
    for err in errors {
        if let BuildErrorKind::MissingAdaWith { unit } = err {
            packages.insert(unit.clone());
        }
    }
    if packages.is_empty() {
        return false;
    }
    // Seed from the instrumented Ada closure (the code that USES the library).
    // Skipped outright when neither the sources nor the package set moved since
    // the last round — seeding parses every staged file, and re-parsing an
    // unchanged tree can only reach the same conclusion.
    let sources = read_ada_source_texts(&work_dir.join("src_instrumented"));
    let seeded = model.seed_from_sources_if_changed(&sources, &packages);
    // Refine the profile types from GNAT's expected/found pairs.
    let raw = std::fs::read_to_string(
        crate::auto::layout::harness_dir(work_dir, harness_id)
            .join("repairs")
            .join(ADA_BUILD_OUTPUT_LOG),
    )
    .unwrap_or_default();
    let refined = model.refine_from_build_output(&raw);
    // Entities a client CHILD unit of a stubbed package names without qualification
    // (it sees its parent's declarations directly), which the qualified-reference
    // scan above cannot see.
    let adopted = model.refine_child_unit_undefined(&raw, &sources);
    if model.is_empty() {
        return false;
    }
    // Render every round so the stubs exist for the next build. The render dir is
    // run-level, matching the model: a stable path is what lets the compiled stub
    // objects survive from one target to the next in the shared object dir.
    //
    // The older per-error `AdaPackageStub` repair writes signature-only stubs for
    // the same units into the target's own `repairs/ada_stubs`. Both dirs are on
    // Source_Dirs, and GNAT rejects a unit declared twice, so a package the model
    // owns is removed from the per-target dir — which is also the "full profile
    // supersedes the empty stub" rule that used to happen by overwriting in place.
    let external_dir = work_dir.join(crate::build::SHARED_ADA_STUBS_DIR);
    let per_target_dir = repairs_dir.join(crate::auto::repair::AUTO_ADA_STUBS_DIR);
    // A target that INHERITS a converged model learns nothing new here
    // (`seeded`/`refined`/`adopted` are all false) yet has just materialised the
    // whole stub set for the first time. That is real progress, and reporting
    // `false` would drop the loop through to body stub-out with the stubs never
    // built. It counts ONCE per target: "the render changed a file" is not usable
    // as a standing signal, because the per-error stub repair keeps rewriting the
    // same units while a unit is still missing, and the two would take turns
    // overwriting each other for as many rounds as the cap allows.
    let first_render_marker = repairs_dir.join(ADA_EXTERNAL_RENDERED);
    let first_render = !first_render_marker.exists();
    let _ = model.render(&external_dir);
    for package in model.stubbed_packages() {
        let stem = crate::auto::ada_external_stub::ada_unit_stem(package);
        let _ = std::fs::remove_file(per_target_dir.join(format!("{stem}.ads")));
        let _ = std::fs::remove_file(per_target_dir.join(format!("{stem}.adb")));
    }
    let _ = std::fs::write(&first_render_marker, "");
    let _ = model.save(&model_path);
    seeded || refined || adopted || first_render
}

/// File under a target's `repairs/` holding the unit stems whose real Ada body is
/// offline-unbuildable and replaced by a synthesized stub body.
pub(crate) const ADA_EXCLUDED_BODIES: &str = "ada_excluded_bodies.json";

/// Directory under a target's `repairs/` holding the synthesized stub bodies
/// (`<stem>.adb`) that shadow offline-unbuildable project bodies.
pub(crate) const ADA_STUB_BODIES_DIR: &str = "ada_stub_bodies";

/// Copy every synthesized stub body into `src_instrumented`, overwriting the
/// staged real body so it shadows the extended project's original source.
fn apply_stub_bodies(work_dir: &Path, harness_id: &str) {
    let stub_dir = crate::auto::layout::harness_dir(work_dir, harness_id)
        .join("repairs")
        .join(ADA_STUB_BODIES_DIR);
    let Ok(entries) = std::fs::read_dir(&stub_dir) else {
        return;
    };
    let dst = work_dir.join("src_instrumented");
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("adb"))
        {
            if let Some(name) = path.file_name() {
                let _ = std::fs::copy(&path, dst.join(name));
            }
        }
    }
}

/// True when `path` is an Ada body (`.adb`) whose lowercased file stem is in the
/// body stub-out exclusion set.
fn is_excluded_ada_body(path: &Path, excluded: &std::collections::BTreeSet<String>) -> bool {
    if excluded.is_empty() {
        return false;
    }
    let is_body = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("adb"));
    is_body
        && path
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|stem| excluded.contains(&stem.to_ascii_lowercase()))
}

/// Load the persisted body stub-out exclusion set for a harness.
fn load_excluded_bodies(repairs_dir: &Path) -> std::collections::BTreeSet<String> {
    std::fs::read_to_string(repairs_dir.join(ADA_EXCLUDED_BODIES))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Force-fuzz last resort: when external-library stubbing can no longer make the
/// build progress, replace the offline-unbuildable BODY of any project unit that
/// still has residual errors (and is not the fuzz target's own unit) with a
/// synthesized `raise Program_Error` body from its spec. This drops the body's
/// problematic `with`s (missing-generic instantiations, dot-calls on stubbed
/// types) that are dragged into the build but not on the target's call path.
/// Returns whether a new body was stubbed (so the repair loop retries).
fn stub_out_unbuildable_bodies(
    work_dir: &Path,
    harness_id: &str,
    repairs_dir: &Path,
    target_source: &Path,
    target_name: &str,
) -> bool {
    let log_path = crate::auto::layout::harness_dir(work_dir, harness_id)
        .join("repairs")
        .join(ADA_BUILD_OUTPUT_LOG);
    let Ok(log) = std::fs::read_to_string(&log_path) else {
        return false;
    };
    // Body file stems that appear in an `error:` locus.
    let mut failing: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in log.lines() {
        if !line.contains(": error:") {
            continue;
        }
        let Some(first) = line.split(':').next() else {
            continue;
        };
        let base = first.trim().rsplit('/').next().unwrap_or(first.trim());
        if let Some(stem) = base.strip_suffix(".adb") {
            failing.insert(stem.to_ascii_lowercase());
        }
    }
    if failing.is_empty() {
        return false;
    }
    let target_stem = target_source
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);
    let target_lc = target_name.to_ascii_lowercase();
    let src_dir = work_dir.join("src_instrumented");
    // Persist stub bodies in their own dir; they are copied INTO src_instrumented
    // after staging so they shadow the extended project's original source (the
    // govfuzz build extends the user .gpr, so merely deleting the staged copy
    // would un-shadow the real, unbuildable body).
    let stub_bodies_dir = crate::auto::layout::harness_dir(work_dir, harness_id)
        .join("repairs")
        .join(ADA_STUB_BODIES_DIR);
    // Synthesize under the SAME standard the build settled on (the dialect ladder
    // may have dropped below Ada 2012, where the raise-expression form is illegal).
    let standard = crate::build::read_ada_dialect_cache(&work_dir.join("build").join(harness_id))
        .unwrap_or(ada_parser::ast::AdaStandard::Ada2022);
    let mut excluded = load_excluded_bodies(repairs_dir);
    let mut changed = false;
    for stem in &failing {
        if stem == "main" || excluded.contains(stem) {
            continue;
        }
        // Synthesize the trivial body from the unit's (compilable) spec.
        let spec_path = src_dir.join(format!("{stem}.ads"));
        let Ok(spec) = std::fs::read_to_string(&spec_path) else {
            continue; // no spec staged (bodyless main / subunit) — can't stub
        };
        let Some(stub) = crate::auto::ada_body_stub::synth_stub_body(&spec, &spec_path, standard)
        else {
            continue;
        };
        // Never replace the fuzz target's OWN body with a raise: if this is the
        // target's unit AND the stub would (re)implement the target subprogram,
        // its real body is on the call path — leave it (a spec-level expression
        // function target is NOT in `implemented`, so its unit stays stubbable).
        if Some(stem) == target_stem.as_ref() && stub.implemented.contains(&target_lc) {
            continue;
        }
        if std::fs::create_dir_all(&stub_bodies_dir).is_err() {
            continue;
        }
        if std::fs::write(stub_bodies_dir.join(format!("{stem}.adb")), &stub.text).is_ok() {
            // Shadow the extended original immediately for this round too.
            let _ = std::fs::write(src_dir.join(format!("{stem}.adb")), &stub.text);
            excluded.insert(stem.clone());
            changed = true;
        }
    }
    if changed {
        let _ = std::fs::write(
            repairs_dir.join(ADA_EXCLUDED_BODIES),
            serde_json::to_string_pretty(&excluded).unwrap_or_default(),
        );
    }
    changed
}

/// Read every `.ads`/`.adb` source text directly under `dir` (non-recursive: the
/// instrumented overlay is flat).
fn read_ada_source_texts(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            path.extension()
                .is_some_and(|e| matches!(e.to_str(), Some("ads") | Some("adb")))
                .then(|| std::fs::read_to_string(&path).ok())
                .flatten()
        })
        .collect()
}

/// True if the Ada source declares its unit `Pure` or `Preelaborate` — either
/// the `pragma Pure;` / `pragma Preelaborate;` form or the `with Pure => True` /
/// `with Preelaborate => True` aspect form (SweetAda uses both heavily). Such a
/// unit cannot `with` the non-pure `AdaFuzz.Probe` runtime, so instrumenting it
/// (which injects `with AdaFuzz.Probe`) breaks the build with "pure unit cannot
/// depend on non-pure unit". Over-matching (e.g. on `pragma Pure_Function`, or a
/// stray comment) is safe: the unit is merely copied uninstrumented and still
/// builds and fuzzes via the harness's top-level exception catch.
fn ada_source_is_pure_or_preelaborate(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("pragma pure")
        || lower.contains("pragma preelaborate")
        || lower.contains("with pure")
        || lower.contains("with preelaborate")
        || lower.contains("pure => true")
        || lower.contains("preelaborate => true")
}

/// Normalize Ada code written against the pre-GNAT-13 C-time surface in
/// `GNAT.Calendar`. Newer runtimes moved `timeval` and `To_Timeval` to the
/// internal `System.C_Time` unit while retaining the rest of `GNAT.Calendar`.
///
/// Keep this deliberately surgical: only the two removed qualified names are
/// rewritten. The added context clause stays on an existing line so source-line
/// mappings produced by the instrumenter remain aligned with the upstream file.
fn rewrite_legacy_gnat_calendar_c_time(source: &mut String) -> bool {
    static OLD_TIMEVAL: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::RegexBuilder::new(r"\bgnat\s*\.\s*calendar\s*\.\s*timeval\b")
            .case_insensitive(true)
            .build()
            .expect("legacy GNAT.Calendar timeval regex")
    });
    static OLD_TO_TIMEVAL: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::RegexBuilder::new(r"\bgnat\s*\.\s*calendar\s*\.\s*to_timeval\b")
            .case_insensitive(true)
            .build()
            .expect("legacy GNAT.Calendar To_Timeval regex")
    });
    static SYSTEM_C_TIME_WITH: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::RegexBuilder::new(r"\bwith\s+system\s*\.\s*c_time\s*;")
            .case_insensitive(true)
            .build()
            .expect("System.C_Time with-clause regex")
    });
    static GNAT_CALENDAR_WITH: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::RegexBuilder::new(r"\bwith\s+gnat\s*\.\s*calendar\s*;")
            .case_insensitive(true)
            .build()
            .expect("GNAT.Calendar with-clause regex")
    });

    if !OLD_TIMEVAL.is_match(source) && !OLD_TO_TIMEVAL.is_match(source) {
        return false;
    }

    let mut rewritten = OLD_TIMEVAL
        .replace_all(source, "System.C_Time.timeval")
        .into_owned();
    rewritten = OLD_TO_TIMEVAL
        .replace_all(&rewritten, "System.C_Time.To_Timeval")
        .into_owned();

    if !SYSTEM_C_TIME_WITH.is_match(&rewritten) {
        if GNAT_CALENDAR_WITH.is_match(&rewritten) {
            rewritten = GNAT_CALENDAR_WITH
                .replace(&rewritten, "$0 with System.C_Time;")
                .into_owned();
        } else {
            // A separate unit can inherit visibility in unusual source layouts.
            // Prefix the context clause on the existing first line rather than
            // adding a line, preserving diagnostic and coverage line numbers.
            rewritten.insert_str(0, "with System.C_Time; ");
        }
    }

    *source = rewritten;
    true
}

/// Populate `<work_dir>/src_instrumented/` with instrumented copies of
/// every `.ads` / `.adb` file under the source root (`work_dir`'s
/// parent). Idempotent: if the dir already contains Ada sources the
/// function exits early, so the per-candidate retry loop in
/// `attempt()` doesn't re-instrument on every call.
///
/// A parse or instrumentation failure on a single source is logged
/// once and the file is skipped — the goal is to let the build see
/// the real GNAT diagnostic rather than masking it with an
/// instrumenter error. The build will fail loudly on a missing unit
/// in the usual way.
/// Whether `dir`'s final component names a conventional Ada source root —
/// the boundary a module subdir (`src/parser`) walks up to in order to reach its
/// sibling sources when no `.gpr` enumerates them.
fn is_source_root_name(dir: &Path) -> bool {
    dir.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase())
        .is_some_and(|n| {
            matches!(
                n.as_str(),
                "src" | "source" | "sources" | "srcs" | "ada" | "code"
            )
        })
}

/// Whether `dir` (recursively, to `depth` levels) directly contains an Ada source
/// file. Bounded so a stray deep tree can't make the sibling probe walk forever.
fn dir_tree_has_ada_sources(dir: &Path, depth: usize) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path.extension().is_some_and(|x| {
            let x = x.to_ascii_lowercase();
            x == "ads" || x == "adb"
        }) {
            return true;
        }
    }
    if depth == 0 {
        return false;
    }
    subdirs
        .iter()
        .any(|sub| dir_tree_has_ada_sources(sub, depth - 1))
}

/// The nearest ancestor of `source_root` that roots the Ada source tree (a
/// directory named like a source root — `src`/`source`/...) AND holds Ada sources
/// in a sibling of the path toward `source_root`. Returns that common root so its
/// sibling modules are pulled into the instrumented set. `None` when `source_root`
/// is not a module subdir of a recognizable source tree (so the walk never crosses
/// into an unrelated parent such as a directory of separate projects).
fn walk_to_common_src_root(source_root: &Path) -> Option<PathBuf> {
    // A checkout/source-drop root may itself live under a directory named
    // `ada` (for example `<campaign>/repos/ada/ocarina`). Crossing that boundary
    // would merge every sibling repository into one build. Module directories
    // such as `<project>/src/parser` do not carry project-root markers, so keep
    // the sibling-source fallback inside the current project boundary.
    if ada_project_root_marker(source_root) {
        return None;
    }
    let mut child = source_root.to_path_buf();
    for _ in 0..3 {
        let parent = child.parent()?.to_path_buf();
        if is_source_root_name(&parent) {
            let contains_separate_projects = std::fs::read_dir(&parent)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .any(|path| path.is_dir() && ada_project_root_marker(&path));
            if contains_separate_projects {
                return None;
            }
            let has_sibling_ada = std::fs::read_dir(&parent)
                .into_iter()
                .flatten()
                .flatten()
                .any(|entry| {
                    let path = entry.path();
                    path.is_dir() && path != child && dir_tree_has_ada_sources(&path, 4)
                });
            return has_sibling_ada.then_some(parent);
        }
        child = parent;
    }
    None
}

fn ada_project_root_marker(dir: &Path) -> bool {
    if dir.join(".git").exists() || dir.join("alire.toml").is_file() {
        return true;
    }
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            entry.path().is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("gpr"))
        })
}

fn ensure_ada_src_instrumented(
    work_dir: &Path,
    source_root: &Path,
    dep_dirs: &[PathBuf],
    dir_filter: &crate::auto::discovery::DirFilter,
    closure_target_unit: Option<&str>,
    // #91: the pre-resolved governing project (operator override / target-source
    // ownership). `None` falls back to the legacy first-`.gpr`-near-source-root
    // selection, so existing call sites are byte-identical.
    governing_gpr_override: Option<&Path>,
    // Force-fuzz: unit stems (`spat`, `spat-preconditions`) whose real body is
    // offline-unbuildable and replaced by a synthesized stub body in the harness
    // stub dir. Their `.adb` is NOT staged here (the stub provides it); the `.ads`
    // still is.
    excluded_body_stems: &std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let dst = work_dir.join("src_instrumented");
    std::fs::create_dir_all(&dst).map_err(|e| format!("create {}: {e}", dst.display()))?;

    // Force-fuzz body stub-out: drop any previously-staged real body of an
    // excluded unit up front, so a stale copy from an earlier round (or another
    // harness sharing this dir) can't shadow the synthesized stub body.
    for stem in excluded_body_stems {
        let _ = std::fs::remove_file(dst.join(format!("{stem}.adb")));
    }

    // #91: use the SAME governing project the build will use — the operator
    // override / target-source owner if one was resolved, else the legacy
    // first-`.gpr` selection near the source root.
    let governing_gpr = governing_gpr_override
        .map(Path::to_path_buf)
        .or_else(|| crate::auto::gpr_scenario::find_project_gpr(source_root));

    // Directories the project's default GPR scenario excludes — don't instrument
    // sources gprbuild wouldn't compile under the default configuration.
    let source_excluded = governing_gpr
        .as_deref()
        .map(crate::auto::gpr_scenario::scenario_excluded_dirs)
        .unwrap_or_default();

    // Collect the candidate Ada sources up front so we can (optionally) restrict
    // them to the target's with-closure (#GAP-C) instead of compiling the whole
    // tree. Each dependency dir keeps its own GPR scenario exclusions.
    let mut source_files = walk_ada_sources(source_root, work_dir, &source_excluded, dir_filter);
    // #450: a multi-directory Ada library's units live across the governing .gpr's
    // Source_Dirs (ada-util src/core + src/sys), but the scanned source_root is only
    // one subdir — so cross-package units fail `missing_ada_symbol`. Add the .gpr's
    // active (default-scenario) Source_Dirs to the instrumented set. Deduped by path
    // (source_root is usually a subdir of a listed Source_Dir); instrumentation is
    // keyed by unit filename, so any residual overlap is idempotent. No .gpr -> the
    // unchanged whole-tree behaviour.
    let preserve_project_naming = governing_gpr.is_some();
    for gpr_dir in governing_gpr
        .as_deref()
        .map(crate::auto::gpr_scenario::active_source_dirs)
        .unwrap_or_default()
    {
        if gpr_dir != source_root {
            source_files.extend(walk_ada_sources(
                &gpr_dir,
                work_dir,
                &source_excluded,
                dir_filter,
            ));
        }
    }
    // #450 increment 2(b): no governing `.gpr` to enumerate Source_Dirs, but the
    // scanned root is a module subdir of a larger source tree (`src/parser`, whose
    // dependency lives in the sibling `src/core`). Walk up to the nearest
    // source-root-like ancestor (`src`) that also roots Ada sources in a sibling
    // dir, and add its tree so the cross-package dependency is instrumented instead
    // of failing `missing_ada_symbol`. The with-closure restriction below keeps the
    // compiled set to the target's actual dependencies.
    if governing_gpr.is_none() {
        if let Some(common_root) = walk_to_common_src_root(source_root) {
            source_files.extend(walk_ada_sources(
                &common_root,
                work_dir,
                &source_excluded,
                dir_filter,
            ));
        }
    }
    // Source-root order is meaningful: the explicitly scanned root wins ties,
    // followed by the governing project's evaluated Source_Dirs order.  Within
    // each walk paths are sorted, and this second pass resolves units repeated
    // across roots by declared Ada identity rather than traversal order.
    let source_files_considered = source_files.len();
    source_files = dedup_ada_units(source_files);
    let duplicate_units_discarded = source_files_considered.saturating_sub(source_files.len());
    let selected_source_variants = source_files
        .iter()
        .filter(|path| {
            let Some(basename) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            ada_variant_dest_basename(basename).is_some_and(|canonical| canonical != basename)
        })
        .count();
    let dep_file_lists: Vec<Vec<PathBuf>> = dep_dirs
        .iter()
        .map(|dep_dir| {
            let dep_excluded = crate::auto::gpr_scenario::find_project_gpr(dep_dir)
                .map(|gpr| crate::auto::gpr_scenario::scenario_excluded_dirs(&gpr))
                .unwrap_or_default();
            walk_ada_sources(dep_dir, work_dir, &dep_excluded, dir_filter)
        })
        .collect();

    // Closure-restricted source set: only the units transitively withed from the
    // target. `None` => compile every collected source (the prior whole-tree
    // behavior), used both when no target is given and when the closure can't be
    // confidently computed.
    let closure_set: Option<std::collections::BTreeSet<PathBuf>> =
        closure_target_unit.and_then(|target| {
            let mut all = source_files.clone();
            for fs in &dep_file_lists {
                all.extend(fs.iter().cloned());
            }
            let map = build_ada_unit_file_map(&all);
            compute_ada_build_closure(target, &map)
        });
    let in_closure = |p: &Path| closure_set.as_ref().is_none_or(|c| c.contains(p));

    let mut wrote_any = false;
    for source_path in &source_files {
        if !in_closure(source_path) {
            continue;
        }
        // Force-fuzz body stub-out: don't stage the real body of a unit whose body
        // is offline-unbuildable — the harness stub dir supplies a trivial body.
        if is_excluded_ada_body(source_path, excluded_body_stems) {
            continue;
        }
        let source_path = source_path.clone();
        let mut source = match crate::source_text::read_source_text(&source_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "govfuzz auto: skipping {}: read error: {e}",
                    source_path.display()
                );
                continue;
            }
        };
        rewrite_legacy_gnat_calendar_c_time(&mut source);
        // A Pure/Preelaborate unit can't depend on the non-pure probe runtime;
        // copy it through uninstrumented so the build still sees it. The
        // categorization commonly lives in the spec, so for a body also consult
        // the sibling `.ads`.
        let mut is_pure = ada_source_is_pure_or_preelaborate(&source);
        if !is_pure
            && source_path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("adb"))
        {
            if let Ok(spec) =
                crate::source_text::read_source_text(&source_path.with_extension("ads"))
            {
                is_pure = ada_source_is_pure_or_preelaborate(&spec);
            }
        }
        if is_pure {
            if let Some(dest_name) =
                ada_staged_source_basename(&source_path, &source, preserve_project_naming)
            {
                if !dest_name.eq_ignore_ascii_case("main.adb") {
                    let dest = dst.join(&dest_name);
                    if std::fs::write(&dest, source.as_bytes()).is_ok() {
                        wrote_any = true;
                    }
                }
            }
            continue;
        }
        let ast = match ada_parser::reconcile::build_structural_ast(&source, None, &source_path) {
            Ok(ast) => ast,
            Err(e) => {
                eprintln!(
                    "govfuzz auto: skipping {}: parse error: {e}",
                    source_path.display()
                );
                continue;
            }
        };
        let instrumented = match instrumenter::instrument_unit(instrumenter::InstrumentArgs {
            source: &source,
            ast: &ast,
            source_path: &source_path,
        }) {
            Ok(out) => out,
            Err(e) => {
                eprintln!(
                    "govfuzz auto: skipping {}: instrumenter: {e}",
                    source_path.display()
                );
                continue;
            }
        };
        // The generated harness is always `main.adb` (`procedure Main`), and
        // the build project (`govfuzz_build.gpr`) compiles src_instrumented +
        // generated_harnesses together. A source-tree `main.adb` (example /
        // test driver — ada-toml ships six under tests/) would land here too,
        // collide with the harness main, and gprbuild would compile the
        // *source* main instead — so the binary runs the example, not the
        // harness, and never fuzzes (ada-toml's example does
        // `Load_File("example.toml").Value`, raising a discriminant check on
        // the missing file). A standalone `main` is never a fuzz target, so
        // drop it.
        let Some(dest_name) =
            ada_staged_source_basename(&source_path, &source, preserve_project_naming)
        else {
            continue;
        };
        if dest_name.eq_ignore_ascii_case("main.adb") {
            continue;
        }
        let dest = dst.join(&dest_name);
        if let Err(e) = std::fs::write(&dest, &instrumented.rewritten_source) {
            return Err(format!("write {}: {e}", dest.display()));
        }
        // Sidecar mapping instrumented lines back to the original source, so the
        // reporter can rewrite `<file>:<line>` in runtime exception messages to
        // the developer's own line numbers (instrumentation shifts them).
        if let Ok(sidecar) = instrumenter::line_map_sidecar_json(
            &source_path.to_string_lossy(),
            &instrumented.line_map,
        ) {
            let sidecar_path = dst.join(format!("{dest_name}.govfuzz-lines.json"));
            let _ = std::fs::write(&sidecar_path, sidecar);
        }
        wrote_any = true;
    }

    // Locally-available dependency sources (vendored / Alire cache): copy them
    // in *uninstrumented* so the harness can link against external library
    // units (e.g. ada-util's `Util.Encoders`) without us rewriting third-party
    // code (which only needs to compile, not emit runtrace). A dependency unit
    // never shadows a target unit of the same name (target was written first).
    for dep_files in &dep_file_lists {
        for dep_path in dep_files {
            // Honor the target with-closure for dependency units too: a vendored
            // crate the target never withs (Alire pulls many) is not compiled.
            if !in_closure(dep_path) {
                continue;
            }
            // Same rule as the source-tree walk above: a dependency's own
            // `main.adb` (e.g. SweetAda's `core/main.adb`, which does
            // `BSP.Setup; Application.Run;`) must NOT land in src_instrumented,
            // or it shadows the generated harness `main.adb` and gprbuild builds
            // the *project's* main instead of the harness — surfacing as
            // `"Setup" not declared in "bsp"` and never fuzzing.
            let mut dependency_source = crate::source_text::read_source_text(dep_path).ok();
            let dest_name = dependency_source
                .as_deref()
                .and_then(|source| ada_source_dest_basename(dep_path, source))
                .or_else(|| {
                    dep_path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(ada_variant_dest_basename)
                });
            let Some(dest_name) = dest_name else {
                continue;
            };
            if dest_name.eq_ignore_ascii_case("main.adb") {
                continue;
            }
            let dest = dst.join(&dest_name);
            if dest.exists() {
                continue;
            }
            if dependency_source
                .as_mut()
                .is_some_and(rewrite_legacy_gnat_calendar_c_time)
            {
                let _ = std::fs::write(&dest, dependency_source.unwrap().as_bytes());
            } else if let Ok(bytes) = std::fs::read(dep_path) {
                // Keep the original bytes when no textual compatibility rewrite
                // was needed (the source reader may have decoded a legacy file).
                let _ = std::fs::write(&dest, bytes);
            }
        }
    }

    // Copy the C/C++ glue real Ada libraries bind to (gnatcoll's
    // `gnatcoll_support.c` / `libc-wrappers.c`, GMP/zlib thin bindings, …) into
    // src_instrumented *uninstrumented*. Without it the Ada link fails on the
    // bound C symbols (`gnatcoll_mmap`, `__gnatcoll_open`); the generated project
    // declares the C language (see build::prepare_layout / project_synth) so
    // gprbuild compiles + links them. Walk the source root and every dep dir;
    // first writer wins (never overwrite a target/dep copy), never instrument
    // third-party C.
    let closure_c_imports = closure_set.as_ref().map(ada_c_import_symbols);
    for c_root in std::iter::once(source_root).chain(dep_dirs.iter().map(PathBuf::as_path)) {
        for c_path in walk_c_glue_sources(c_root, work_dir, dir_filter) {
            let Some(basename) = c_path.file_name() else {
                continue;
            };
            let is_c_source = c_path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("c"));
            if is_c_source
                && closure_c_imports
                    .as_ref()
                    .is_some_and(|imports| !c_source_matches_ada_import(&c_path, imports))
            {
                continue;
            }
            let dest = dst.join(basename);
            if dest.exists() {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&c_path) {
                let _ = std::fs::write(&dest, bytes);
            }
        }
    }

    // Generate the Alire "configuration" package (`<crate>_config.ads`) that
    // `alr` would materialize from each crate's `alire.toml`
    // `[configuration.variables]`. Source that `with`s it (usb_embedded's
    // `Usb_Embedded_Config.Control_Buffer_Size`) can't compile without it, and
    // it doesn't exist until `alr build` runs. Generate a faithful copy from the
    // declared defaults for the project and every resolved dependency — skipping
    // any a real build already produced (a tree/dep copy wins).
    let config_roots = std::iter::once(source_root.to_path_buf())
        .chain(dep_dirs.iter().cloned())
        .collect::<Vec<_>>();
    for root in &config_roots {
        let Some(alire_toml) = find_alire_manifest(root) else {
            continue;
        };
        if let Some(pkg) = crate::auto::alire_config::generate_config_package(&alire_toml) {
            let dest = dst.join(&pkg.file_name);
            if !dest.exists() {
                let _ = std::fs::write(&dest, &pkg.source);
            }
        }
    }

    if !wrote_any {
        return Err(format!(
            "no Ada sources found under {}; cannot prepare {}",
            source_root.display(),
            dst.display()
        ));
    }
    let staging_report = serde_json::json!({
        "schema_version": 1,
        "source_files_considered": source_files_considered,
        "duplicate_units_discarded": duplicate_units_discarded,
        "selected_source_variants": selected_source_variants,
        "staged_ada_files": std::fs::read_dir(&dst)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("ads") || ext.eq_ignore_ascii_case("adb")))
            .count(),
    });
    if let Ok(bytes) = serde_json::to_vec(&staging_report) {
        let _ = crate::auto::report::atomic_write(
            &work_dir.join("auto/ada-staging-report.json"),
            &bytes,
        );
    }
    Ok(())
}

/// External C names referenced by the Ada units in a target's static closure.
/// Both classic `pragma Import (C, Entity, "external")` and aspect-style
/// `External_Name => "external"` declarations occur in legacy projects.
fn ada_c_import_symbols(
    closure: &std::collections::BTreeSet<PathBuf>,
) -> std::collections::BTreeSet<String> {
    let external_name =
        regex::Regex::new(r#"(?i)(?:external_name|link_name)\s*=>\s*"([A-Za-z_][A-Za-z0-9_@$]*)""#)
            .expect("valid Ada external-name regex");
    let pragma_import = regex::Regex::new(
        r"(?i)pragma\s+import\s*\(\s*(?:c|cpp|c_plus_plus|stdcall)\s*,\s*([A-Za-z][A-Za-z0-9_]*)",
    )
    .expect("valid Ada import regex");
    let pragma_external =
        regex::Regex::new(r#"(?i)pragma\s+import\s*\([^;]*?"([A-Za-z_][A-Za-z0-9_@$]*)""#)
            .expect("valid Ada pragma external-name regex");
    let mut symbols = std::collections::BTreeSet::new();
    for path in closure {
        let Ok(source) = crate::source_text::read_source_text(path) else {
            continue;
        };
        for captures in external_name.captures_iter(&source) {
            symbols.insert(captures[1].to_owned());
        }
        for captures in pragma_external.captures_iter(&source) {
            symbols.insert(captures[1].to_owned());
        }
        // Without an explicit External_Name, Convention C uses the Ada entity
        // name. Keeping that identifier is conservative; a false-positive C TU
        // costs compilation time but does not hide a dependency.
        for captures in pragma_import.captures_iter(&source) {
            symbols.insert(captures[1].to_owned());
        }
    }
    symbols
}

fn c_source_matches_ada_import(
    source_path: &Path,
    imports: &std::collections::BTreeSet<String>,
) -> bool {
    if imports.is_empty() {
        return false;
    }
    let Ok(source) = crate::source_text::read_source_text(source_path) else {
        return false;
    };
    imports.iter().any(|symbol| source.contains(symbol))
}

/// Mirror `<work_dir>/harnesses/<harness_id>/` into
/// `<work_dir>/generated_harnesses/<harness_id>/` (file-by-file copy)
/// so `crate::build::select_harness` finds it where the Ada build
/// pipeline expects. We copy rather than symlink so the build
/// pipeline's `select_harness` doesn't get tripped up by symlink
/// metadata checks on hosts with stricter file-type filters.
fn mirror_harness_into_generated_harnesses(
    work_dir: &Path,
    harness_id: &str,
) -> Result<(), String> {
    let src = crate::auto::layout::harness_dir(work_dir, harness_id);
    if !src.is_dir() {
        return Err(format!(
            "harness dir missing: {}; generate_harness step did not run",
            src.display()
        ));
    }
    let dst = work_dir.join("generated_harnesses").join(harness_id);
    std::fs::create_dir_all(&dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    for entry in std::fs::read_dir(&src).map_err(|e| format!("read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("read entry under {}: {e}", src.display()))?;
        let from = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let to = dst.join(entry.file_name());
        // The stable harness id intentionally survives a generator upgrade or a
        // corrected overload selection. Always atomically refresh the owned build
        // copy; keeping an existing file made the Ada build execute stale `main.adb`
        // even though generation had produced the fixed call in `harnesses/`.
        let bytes =
            std::fs::read(&from).map_err(|e| format!("read harness {}: {e}", from.display()))?;
        crate::auto::report::atomic_write(&to, &bytes)
            .map_err(|e| format!("mirror {} -> {}: {e}", from.display(), to.display()))?;
    }
    Ok(())
}

/// Recursively yield Ada source paths under `root`, skipping anything
/// inside the govfuzz_work directory itself (so we don't pick up
/// generated harnesses or stale instrumented copies).
/// Find the `alire.toml` crate manifest governing `start` — in `start` itself,
/// else walking up to 8 parents (the scan path may be a subdir of the crate
/// root). Returns `None` when there is no manifest.
fn find_alire_manifest(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start.to_path_buf());
    for _ in 0..8 {
        let current = dir?;
        let candidate = current.join("alire.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = current.parent().map(Path::to_path_buf);
    }
    None
}

fn walk_ada_sources(
    root: &Path,
    work_dir: &Path,
    excluded_dirs: &[PathBuf],
    dir_filter: &crate::auto::discovery::DirFilter,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if dir == work_dir {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                // Skip per-OS variant dirs for platforms other than the build
                // host. Multi-platform Ada projects (e.g. ada-util's
                // src/base/os-windows, os-macos64, os-linux64) hold the same
                // units under each, so compiling them all collides ("duplicate
                // unit"). Keep only the host's.
                let keep = entry
                    .file_name()
                    .to_str()
                    // Skip non-library dirs (tests/testsuite/examples/benchmarks/
                    // fuzz) with the SAME filter discovery uses, so the build
                    // source set matches the discovered target set. Without it a
                    // tree's `testsuite/` fixtures leak into src_instrumented —
                    // gnatcoll's `foo.adb`+`foo.c` then collide on one object name
                    // and fail every harness build. `--include-dir` restores a dir.
                    .map(|name| !ada_dir_is_foreign_platform(name) && !dir_filter.skips(name))
                    .unwrap_or(true);
                // Skip directories the project's default GPR scenario excludes
                // (libkeccak's SIMD `src/x86_64/AVX2`, a dep's bare-metal variant
                // body) — gprbuild wouldn't compile them, and the host can't.
                let scenario_excluded = !excluded_dirs.is_empty()
                    && path
                        .canonicalize()
                        .ok()
                        .is_some_and(|canon| excluded_dirs.iter().any(|ex| canon.starts_with(ex)));
                if keep && !scenario_excluded {
                    stack.push(path);
                }
            } else if ft.is_file() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                // Skip foreign-platform GNAT variant bodies (`unit__win32.adb`
                // on a non-Windows host); the host variant is kept and renamed
                // to the canonical unit at copy time (see ada_variant_dest_basename).
                if (s.ends_with(".ads") || s.ends_with(".adb"))
                    && ada_variant_dest_basename(&s).is_some()
                {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    dedup_ada_units(out)
}

/// Collect C/C++ glue sources (`.c`/`.h`) under `root` — the binding code a real
/// Ada library compiles alongside its Ada (gnatcoll's `gnatcoll_support.c`,
/// `libc-wrappers.c`, GMP/zlib shims). Mirrors [`walk_ada_sources`]'s traversal
/// (skips the work dir and foreign-platform variant dirs) but keeps C/header
/// files so they can be copied in and compiled by the C-enabled project.
fn walk_c_glue_sources(
    root: &Path,
    work_dir: &Path,
    dir_filter: &crate::auto::discovery::DirFilter,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if dir == work_dir {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let keep = entry
                    .file_name()
                    .to_str()
                    // Same non-library dir skip as walk_ada_sources: a `testsuite/`
                    // C fixture (gnatcoll's `foo.c`) must not be compiled into the
                    // harness, or it collides with a sibling `foo.adb` on object name.
                    .map(|name| !ada_dir_is_foreign_platform(name) && !dir_filter.skips(name))
                    .unwrap_or(true);
                if keep {
                    stack.push(path);
                }
            } else if ft.is_file() {
                let name = entry.file_name();
                let lower = name.to_string_lossy().to_ascii_lowercase();
                // Skip foreign-platform C glue by FILENAME too (gnatcoll ships
                // `win32-wrappers.c` next to `libc-wrappers.c`): a flattened dep
                // tree loses the per-OS dir the dir-skip keys on, so a Windows
                // shim would reach the compiler and fail on `windows.h`.
                let stem = lower
                    .rsplit_once('.')
                    .map(|(s, _)| s)
                    .unwrap_or(lower.as_str());
                if (lower.ends_with(".c") || lower.ends_with(".h"))
                    && !ada_dir_is_foreign_platform(&lower)
                    && !c_file_is_simd_backend(stem)
                {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Resolve a GNAT per-platform body/spec variant filename to the unit's
/// canonical source name. AdaCore projects ship `unit__<platform>.ad[sb]`
/// (gnatcoll's `gnatcoll-io-native-codec__unix.adb`,
/// `gnatcoll-os-stat-fstat__unix.adb`) selected by a project Naming scheme we
/// don't synthesize, so GNAT's default naming can't find the unit and the build
/// fails with "missing Ada unit". Returns:
///   - `None`       => a FOREIGN-platform variant; skip it (won't compile here).
///   - `Some(name)` => the canonical basename to write under src_instrumented:
///     the `__<host>` suffix stripped (so default naming resolves the unit), or
///     the name unchanged when it carries no platform-variant suffix.
pub(super) fn ada_variant_dest_basename(basename: &str) -> Option<String> {
    let (stem, ext) = match basename.rsplit_once('.') {
        Some((s, e)) if e.eq_ignore_ascii_case("ads") || e.eq_ignore_ascii_case("adb") => (s, e),
        _ => return Some(basename.to_owned()),
    };
    let Some((base, tok)) = stem.rsplit_once("__") else {
        return Some(basename.to_owned());
    };
    // Only a known platform token is a variant suffix; a unit that merely
    // contains `__` for another reason is left untouched.
    const PLATFORM_TOKENS: &[&str] = &[
        "unix",
        "posix",
        "default",
        "linux",
        "gnu",
        "win32",
        "win64",
        "windows",
        "nt",
        "mingw",
        "msvc",
        "osx",
        "darwin",
        "macos",
        "bsd",
        "freebsd",
        "netbsd",
        "openbsd",
        "dragonfly",
        "aix",
        "solaris",
        "vxworks",
        "rtems",
    ];
    let tok_l = tok.to_ascii_lowercase();
    if !PLATFORM_TOKENS.contains(&tok_l.as_str()) {
        return Some(basename.to_owned());
    }
    if ada_dir_is_foreign_platform(&tok_l) {
        None
    } else {
        Some(format!("{base}.{ext}"))
    }
}

/// True when a C/C++ source file is a CPU-SIMD backend specialization the
/// default `-g`-only C build cannot compile: a foreign-CPU-arch intrinsic file
/// (`blake3_neon.c` needs `arm_neon.h`, absent on x86) or an x86 vector backend
/// (`blake3_avx2.c`, `blake3_sse41.c`) that needs a per-file `-mavx2`/`-msse4.1`
/// flag we do not synthesize. The library's portable fallback (`*_portable.c`)
/// plus its runtime dispatcher give a buildable path, and the specialized
/// backend is only LINKED when the target actually uses the SIMD library (never
/// our parser targets) — so skipping its compilation unblocks the harness build
/// without affecting the fuzzed code. Matched on the trailing `_<simd>` filename
/// segment (the universal convention) to avoid false positives.
fn c_file_is_simd_backend(file_stem_lower: &str) -> bool {
    const SIMD_TOKENS: &[&str] = &[
        "neon", "sve", "avx", "avx2", "avx512", "avx512f", "sse", "sse2", "sse3", "ssse3", "sse41",
        "sse42", "aarch64", "armv7", "armv8", "altivec", "vsx",
    ];
    file_stem_lower
        .rsplit(['_', '-'])
        .next()
        .is_some_and(|seg| SIMD_TOKENS.contains(&seg))
}

/// Canonical Ada unit key from a source filename: `gnatcoll-json.ads` ->
/// `gnatcoll.json`, `gnatcoll-json-utility.adb` -> `gnatcoll.json.utility`. A GNAT
/// `__<platform>` variant suffix is stripped first (a host variant maps to the
/// base unit; a foreign variant yields `None`). Lowercased. `None` for non-Ada.
fn ada_unit_key_from_filename(basename: &str) -> Option<String> {
    let canonical = ada_variant_dest_basename(basename)?;
    let stem = canonical
        .strip_suffix(".ads")
        .or_else(|| canonical.strip_suffix(".adb"))?;
    Some(stem.replace('-', ".").to_ascii_lowercase())
}

/// Declared Ada compilation-unit name, independent of GNAT's default filename
/// convention.  Project files may map an arbitrary basename to a unit; parsing
/// the declaration lets the flattened overlay preserve that mapping by writing
/// the source under a canonical GNAT basename.
fn ada_declared_unit_name(source: &str, path: &Path) -> Option<String> {
    let ast = ada_parser::reconcile::build_structural_ast(source, None, path).ok()?;
    if let Some(package) = ast.packages.first() {
        return Some(package.name.to_ascii_lowercase());
    }
    ast.subprograms
        .iter()
        .find(|subprogram| {
            matches!(
                subprogram.owner,
                ada_parser::ast::SubprogramOwner::LibraryLevel
            )
        })
        .map(|subprogram| subprogram.name.to_ascii_lowercase())
}

fn ada_source_unit_name(path: &Path) -> Option<String> {
    crate::source_text::read_source_text(path)
        .ok()
        .and_then(|source| ada_declared_unit_name(&source, path))
        .or_else(|| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(ada_unit_key_from_filename)
        })
}

/// Destination basename for a source staged under GNAT's default naming.  A
/// successfully parsed declaration is authoritative; the source basename is a
/// compatibility fallback for compiler runtime units the structural parser
/// cannot parse.  Platform variants are still screened before renaming.
pub(super) fn ada_source_dest_basename(path: &Path, source: &str) -> Option<String> {
    let basename = path.file_name()?.to_str()?;
    let variant_name = ada_variant_dest_basename(basename)?;
    let extension = path.extension()?.to_str()?;
    if !extension.eq_ignore_ascii_case("ads") && !extension.eq_ignore_ascii_case("adb") {
        return Some(variant_name);
    }
    ada_declared_unit_name(source, path)
        .map(|name| {
            format!(
                "{}.{}",
                name.replace('.', "-"),
                extension.to_ascii_lowercase()
            )
        })
        .or(Some(variant_name))
}

fn ada_staged_source_basename(
    path: &Path,
    source: &str,
    preserve_project_naming: bool,
) -> Option<String> {
    let basename = path.file_name()?.to_str()?;
    // Screening the variant is still necessary, but when the governing project
    // is inherited its Naming package expects the original selected basename.
    let _ = ada_variant_dest_basename(basename)?;
    if preserve_project_naming {
        Some(basename.to_owned())
    } else {
        ada_source_dest_basename(path, source)
    }
}

/// Ancestor unit names of `unit` (`a.b.c` -> [`a.b`, `a`]). A child unit's
/// closure must include its parents.
fn ada_unit_ancestors(unit_lower: &str) -> Vec<String> {
    let parts: Vec<&str> = unit_lower.split('.').collect();
    (1..parts.len())
        .rev()
        .map(|n| parts[..n].join("."))
        .collect()
}

/// Lowercased names of units withed by an Ada source (via the structural AST).
/// `None` on a parse failure. The caller keeps the units it can prove reachable;
/// compiler diagnostics and the repair loop add any missed real unit later.
fn ada_source_withs(source: &str, path: &Path) -> Option<Vec<String>> {
    let ast = ada_parser::reconcile::build_structural_ast(source, None, path).ok()?;
    Some(
        ast.units
            .iter()
            .flat_map(|u| u.withs.iter())
            .map(|w| w.name.to_ascii_lowercase())
            .collect(),
    )
}

/// Parent unit of an Ada `separate` subunit body, lowercased: a subunit begins
/// (after optional context clauses) with `separate (Parent.Unit)`. `None` when
/// the source is not a subunit. Subunits are not `with`ed but are required to
/// complete the parent unit (gnatcoll's per-OS `GNATCOLL.OS.Stat.Stat` body).
fn ada_subunit_parent(source: &str) -> Option<String> {
    for raw in source.lines() {
        // Strip a trailing line comment (a `--` inside a string at the top of a
        // subunit is vanishingly rare); ignore blank/comment lines.
        let line = raw.split("--").next().unwrap_or(raw);
        let trimmed = line.trim_start();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("separate") {
            let after = rest.trim_start();
            if let Some(inner) = after.strip_prefix('(') {
                if let Some(end) = inner.find(')') {
                    let name = inner[..end].trim();
                    if !name.is_empty() {
                        return Some(name.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    None
}

/// Map every Ada source file under consideration to its unit key (spec + body
/// share a key), for closure resolution.
fn build_ada_unit_file_map(files: &[PathBuf]) -> std::collections::BTreeMap<String, Vec<PathBuf>> {
    let mut map: std::collections::BTreeMap<String, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    for f in files {
        let mut keys = Vec::new();
        if let Some(key) = f
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(ada_unit_key_from_filename)
        {
            keys.push(key);
        }
        // GNAT's predefined-unit filenames use compressed historical spellings
        // (`s-valint.adb` declares `System.Val_Int`, `s-forlit.ads` declares
        // `System.Formatting.Literals`). Index the declared name as an alias so
        // with-closure traversal can connect those units without hardcoding the
        // compiler's filename table. Keep the filename key for ordinary units and
        // for parser fallbacks.
        if let Some(unit) = ada_source_unit_name(f) {
            keys.push(unit);
        }
        keys.sort();
        keys.dedup();
        for key in keys {
            let paths = map.entry(key).or_default();
            if !paths.contains(f) {
                paths.push(f.clone());
            }
        }
    }
    map
}

/// Transitive `with`-closure of `target_unit` over the Ada sources in
/// `unit_files` (source tree + dependency dirs): the set of source files that
/// must be compiled to build the target. An unresolved external unit is left out
/// of the static closure so the compiler can report it and the repair loop can
/// resolve or classify it. Expanding to the whole tree here compiles unrelated
/// platform backends and optional SDK bindings, obscuring the target's actual
/// dependency. `None` is reserved for a target unit absent from the source map.
fn compute_ada_build_closure(
    target_unit: &str,
    unit_files: &std::collections::BTreeMap<String, Vec<PathBuf>>,
) -> Option<std::collections::BTreeSet<PathBuf>> {
    use std::collections::{BTreeSet, VecDeque};
    let mut closure: BTreeSet<PathBuf> = BTreeSet::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let seed = target_unit.to_ascii_lowercase();
    if !unit_files.contains_key(&seed) {
        return None;
    }
    queue.push_back(seed.clone());
    queue.extend(ada_unit_ancestors(&seed));
    while let Some(unit) = queue.pop_front() {
        if !visited.insert(unit.clone()) {
            continue;
        }
        let Some(files) = unit_files.get(&unit) else {
            // External/generated/runtime unit. Keep the known closure; the
            // compiler's missing-unit diagnostic is more precise than compiling
            // every unrelated source in the repository. Runtime-named units that
            // ARE present in the map must not be skipped: alternate runtime trees
            // such as Drake intentionally provide their own System.* dependency
            // closure and require those exact sources to build the selected target.
            continue;
        };
        for f in files {
            if !closure.insert(f.clone()) {
                continue;
            }
            let Ok(source) = crate::source_text::read_source_text(f) else {
                continue;
            };
            let Some(withs) = ada_source_withs(&source, f) else {
                continue;
            };
            for w in withs {
                queue.extend(ada_unit_ancestors(&w));
                queue.push_back(w);
            }
        }
        // Pull in `separate` subunit bodies of this unit (direct child units whose
        // body begins `separate (...)`). They are never `with`ed but are required
        // to complete the parent — e.g. gnatcoll's per-OS GNATCOLL.OS.Stat.Stat /
        // .Fstat bodies, which the with-closure alone misses.
        let prefix = format!("{unit}.");
        let subunit_keys: Vec<String> = unit_files
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .filter(|(k, _)| !visited.contains(k.as_str()))
            .filter(|(_, kfiles)| {
                kfiles.iter().any(|kf| {
                    kf.extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("adb"))
                        && crate::source_text::read_source_text(kf)
                            .ok()
                            .and_then(|s| ada_subunit_parent(&s))
                            .is_some()
                })
            })
            .map(|(k, _)| k.clone())
            .collect();
        queue.extend(subunit_keys);
    }
    Some(closure)
}

/// True when a directory name is a per-OS source variant for a platform other
/// than the build host (so it would collide with the host's units). Token
/// match is conservative — only well-known platform spellings.
fn ada_dir_is_foreign_platform(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let host_linux = cfg!(target_os = "linux");
    let host_macos = cfg!(target_os = "macos");
    let host_windows = cfg!(target_os = "windows");
    const WINDOWS: &[&str] = &["windows", "win32", "win64", "mingw", "msvc"];
    const UNIX: &[&str] = &["unix", "posix"];
    const MACOS: &[&str] = &["macos", "darwin", "osx"];
    const BSD: &[&str] = &["freebsd", "netbsd", "openbsd", "dragonfly"];
    let foreign = |tokens: &[&str]| tokens.iter().any(|t| n.contains(t));
    // A dir is foreign if it names a platform that is not the host.
    (!host_windows && foreign(WINDOWS))
        || (host_windows && foreign(UNIX))
        || (!host_macos && foreign(MACOS))
        || (foreign(BSD)
            && !cfg!(any(
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd"
            )))
        || (!host_linux && n.contains("linux") && !n.contains("clinux"))
}

/// Drop duplicate Ada compilation units.  Identity comes from the declaration,
/// not the basename, and spec/body are distinct.  Input order expresses source
/// directory precedence; host affinity overrides it only for an explicit host
/// platform variant.  Lexically sorted directory walks make every remaining tie
/// deterministic.
fn dedup_ada_units(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    use std::collections::HashMap;
    let mut best: HashMap<String, PathBuf> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for path in paths {
        let Some(unit) = ada_source_unit_name(&path) else {
            continue;
        };
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let key = format!("{unit}:{extension}");
        match best.get(&key) {
            None => {
                order.push(key.clone());
                best.insert(key, path);
            }
            Some(existing) => {
                if ada_host_affinity(&path) > ada_host_affinity(existing) {
                    best.insert(key, path);
                }
            }
        }
    }
    order.into_iter().filter_map(|b| best.remove(&b)).collect()
}

/// Heuristic score: higher when a path's directory tokens match the build
/// host, used to pick among duplicate-unit candidates.
fn ada_host_affinity(path: &Path) -> i32 {
    let p = path.to_string_lossy().to_ascii_lowercase();
    let mut score = 0;
    if cfg!(target_os = "linux") && p.contains("linux") {
        score += 2;
    }
    if (p.contains("unix") || p.contains("posix")) && !cfg!(target_os = "windows") {
        score += 1;
    }
    if cfg!(target_pointer_width = "64") && p.contains("64") {
        score += 1;
    }
    if cfg!(target_pointer_width = "32") && p.contains("32") {
        score += 1;
    }
    score
}

fn env_injections_from_events(
    events: &[crate::auto::runtrace::RuntraceEvent],
) -> Vec<(String, String)> {
    let mut seen = std::collections::HashSet::new();
    events
        .iter()
        .filter_map(|event| match event {
            crate::auto::runtrace::RuntraceEvent::EnvVarMissing { name, .. } => {
                if is_injectable_env_var_name(name)
                    && !crate::auto::runtrace::is_internal_env_name(name)
                    && seen.insert(name.clone())
                {
                    Some((name.clone(), format!("/tmp/govfuzz/fake_env/{name}")))
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect()
}

/// A real, injectable environment-variable NAME shape: an upper-case head then
/// upper-case letters / digits / underscores (`OPENSSL_CONF`, `HOME`; matches
/// `^[A-Z][A-Z0-9_]+$`). Runtime-INFRASTRUCTURE probes that run inside a crash /
/// death / panic handler — the in-process ASan / libLLVM symbolizer's
/// `getenv("bar")`, etc. — carry lowercase / non-conventional names that are never
/// the TARGET's configuration dependency. Rejecting them stops govfuzz fabricating
/// and injecting a fake value (which both perturbs the run and reads as a real
/// dependency) (#33).
fn is_injectable_env_var_name(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && name.len() >= 2
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Inject a `runtime_mode` object into a finding's `finding.json`
/// so `govfuzz replay --finding <id>` can reconstruct the exact
/// environment that produced the crash. Best-effort: a malformed
/// finding.json or I/O error logs a one-line warning and continues
/// — losing replay information for one finding shouldn't abort the
/// whole sweep.
/// The raw `input_reachability` label for a candidate's
/// `target_rank::InputReachability`, stamped into `finding.json` so the
/// actionability + confidence layers can tell an attacker-reachable public entry
/// from an internal function the harness drove directly. `None` (Ada targets,
/// ranked structurally) leaves the signal unset.
fn reachability_label(
    reachability: Option<target_rank::InputReachability>,
) -> Option<&'static str> {
    reachability.map(|reachability| match reachability {
        target_rank::InputReachability::AttackerReachable => "attacker_reachable",
        target_rank::InputReachability::OutputSerializer => "output_serializer",
        target_rank::InputReachability::ReachabilityUnproven => "reachability_unproven",
        target_rank::InputReachability::IpcChannelReachable => "ipc_channel_reachable",
    })
}

/// Did this pass's runtrace show the harness reading fuzz-driven data from a
/// virtualized IPC channel (#440/#441/#438)? The shim tags such reads `"v":1`;
/// the events arrive here as [`RuntraceEvent::Unknown`] (the auto parser has no
/// typed variant for them). A crash in a function with no untrusted-input buffer
/// parameter is still input-reachable when its data came through one of these
/// channels, so we upgrade its reachability label (see [`InputReachability`]).
fn ipc_channel_read_observed(events: &[crate::auto::runtrace::RuntraceEvent]) -> bool {
    // Reads that DELIVER fuzz bytes to the target (not writes/creates/unlinks).
    const READ_KINDS: &[&str] = &[
        "\"e\":\"shm_open\"",
        "\"e\":\"shmat\"",
        "\"e\":\"mq_receive\"",
        "\"e\":\"mq_timedreceive\"",
        "\"e\":\"mmio\"",
    ];
    events.iter().any(|event| {
        if let crate::auto::runtrace::RuntraceEvent::Unknown { raw } = event {
            raw.contains("\"v\":1") && READ_KINDS.iter().any(|k| raw.contains(k))
        } else {
            false
        }
    })
}

/// Reachability label for a finding, upgraded to `ipc_channel_reachable` when a
/// function with no untrusted-input buffer (`ReachabilityUnproven`, or unranked
/// `None`) was driven through a virtualized IPC channel this run.
fn effective_reachability_label(
    static_reachability: Option<target_rank::InputReachability>,
    ipc_channel_observed: bool,
) -> Option<&'static str> {
    let label = reachability_label(static_reachability);
    if ipc_channel_observed && matches!(label, None | Some("reachability_unproven")) {
        return Some("ipc_channel_reachable");
    }
    label
}

/// Clone `candidate`, upgrading its reachability to
/// [`InputReachability::IpcChannelReachable`] when a virtualized IPC channel drove
/// the run and the static reachability was `ReachabilityUnproven` (or `None`, the
/// Ada/unranked case). The upgraded clone feeds the report's per-target note so it
/// matches the per-finding label.
fn candidate_with_ipc_reachability(candidate: &Candidate, ipc_channel_observed: bool) -> Candidate {
    let mut upgraded = candidate.clone();
    if ipc_channel_observed
        && matches!(
            candidate.input_reachability,
            None | Some(target_rank::InputReachability::ReachabilityUnproven)
        )
    {
        upgraded.input_reachability = Some(target_rank::InputReachability::IpcChannelReachable);
    }
    upgraded
}

fn stamp_runtime_mode(
    finding_path: &std::path::Path,
    pass: crate::auto::pass::Pass,
    env_injected: &[(String, String)],
    input_reachability: Option<&str>,
) -> std::io::Result<()> {
    let bytes = std::fs::read(finding_path)?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mode = value
        .get("actionability")
        .and_then(|actionability| actionability.get("mode"))
        .cloned()
        .and_then(|mode| serde_json::from_value::<actionability::RunMode>(mode).ok())
        .unwrap_or_default();
    {
        let obj = value.as_object_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "finding.json is not a JSON object",
            )
        })?;
        let env_map: serde_json::Map<String, serde_json::Value> = env_injected
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        obj.insert(
            "runtime_mode".to_owned(),
            serde_json::json!({
                "pass": pass.as_str(),
                "env_injected": env_map,
            }),
        );
        // Persist the fuzzed entry's attacker-reachability so the recomputed
        // actionability verdict / confidence reflect whether this was a proven
        // attacker entry or a function the harness drove directly.
        if let Some(label) = input_reachability {
            obj.insert(
                "input_reachability".to_owned(),
                serde_json::Value::String(label.to_owned()),
            );
        }
        obj.remove("actionability");
    }
    let recomputed = actionability::value_for_finding(mode, &value, Some(finding_path));
    let obj = value.as_object_mut().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "finding.json is not a JSON object",
        )
    })?;
    obj.insert("actionability".to_owned(), recomputed);
    let pretty = serde_json::to_vec_pretty(&value)?;
    std::fs::write(finding_path, pretty)
}

#[cfg(test)]
mod env_injection_tests {
    use super::env_injections_from_events;
    use crate::auto::runtrace::RuntraceEvent;

    fn missing(name: &str) -> RuntraceEvent {
        RuntraceEvent::EnvVarMissing {
            api: "getenv".to_owned(),
            name: name.to_owned(),
        }
    }

    #[test]
    fn runtime_infra_getenv_probes_are_not_injected() {
        // #33: a lowercase symbolizer/ASan probe (`getenv("bar")`) and the Rust
        // panic handler's RUST_BACKTRACE must NOT be fabricated as target env deps,
        // while a genuine UPPER_SNAKE target var still is (no over-suppression).
        let events = vec![
            missing("bar"),            // symbolizer probe — wrong shape
            missing("RUST_BACKTRACE"), // panic-handler runtime infra
            missing("APP_CONFIG"),     // genuine target dependency
        ];
        let injected = env_injections_from_events(&events);
        let names: Vec<&str> = injected.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["APP_CONFIG"], "got {injected:?}");
    }
}

#[cfg(test)]
mod undefined_external_types_tests {
    use super::{undefined_external_types, undefined_external_types_for_lang};
    use crate::auto::candidate::Lang;
    use crate::auto::decl_index::DeclarationIndex;
    use build_classifier::BuildErrorKind;
    use std::collections::BTreeSet;

    #[test]
    fn placeholder_synthesized_type_is_not_an_external_type() {
        let idx = DeclarationIndex::default();
        let errors = vec![BuildErrorKind::MissingType {
            name: "widget_t".to_owned(),
        }];
        // Not synthesized => it looks like an unsupplied external type.
        assert_eq!(
            undefined_external_types(&errors, &idx, &BTreeSet::new()),
            Some(vec!["widget_t".to_owned()])
        );
        // Synthesized as a TypePlaceholder => an actionable gap, keep the manifest.
        let synthesized = BTreeSet::from(["widget_t".to_owned()]);
        assert_eq!(undefined_external_types(&errors, &idx, &synthesized), None);
    }

    #[test]
    fn incomplete_type_still_degrades_to_report_only() {
        let idx = DeclarationIndex::default();
        // A pimpl `IncompleteType` is never placeholder-synthesized, so it still
        // routes to report-only even when other types were synthesized.
        let errors = vec![BuildErrorKind::IncompleteType {
            name: "Pimpl".to_owned(),
        }];
        assert_eq!(
            undefined_external_types(&errors, &idx, &BTreeSet::from(["widget_t".to_owned()])),
            Some(vec!["Pimpl".to_owned()])
        );
    }

    #[test]
    fn incomplete_standard_type_is_not_an_external_sdk() {
        let idx = DeclarationIndex::default();
        for name in ["size_t", "pollfd", "struct pollfd"] {
            for error in [
                BuildErrorKind::MissingType {
                    name: name.to_owned(),
                },
                BuildErrorKind::IncompleteType {
                    name: name.to_owned(),
                },
            ] {
                assert_eq!(
                    undefined_external_types(&[error], &idx, &BTreeSet::new()),
                    None,
                    "{name} comes from a host system header"
                );
            }
        }
    }

    #[test]
    fn incomplete_type_defined_in_tree_but_harness_invisible_degrades() {
        // Group 7: the type IS defined somewhere in the scanned tree (a `struct` in
        // a header), so `type_defined_in_compiled_source` is true — but the harness
        // TU only sees a forward declaration and can't construct it. An
        // `IncompleteType` is never repaired, so a persistent one at the final
        // outcome is unrecoverable and must degrade to a report-only scan rather
        // than a bare failed_build.
        let mut idx = DeclarationIndex::default();
        idx.insert_source_type_name_for_test("EncryptedFile");
        assert!(idx.type_defined_in_compiled_source("EncryptedFile"));
        let errors = vec![BuildErrorKind::IncompleteType {
            name: "EncryptedFile".to_owned(),
        }];
        assert_eq!(
            undefined_external_types(&errors, &idx, &BTreeSet::new()),
            Some(vec!["EncryptedFile".to_owned()])
        );
    }

    #[test]
    fn incomplete_c_type_complete_in_tree_stays_actionable() {
        let mut idx = DeclarationIndex::default();
        idx.insert_source_type_name_for_test("inflate_state");
        let errors = vec![BuildErrorKind::IncompleteType {
            name: "inflate_state".to_owned(),
        }];
        assert_eq!(
            undefined_external_types_for_lang(&errors, &idx, &BTreeSet::new(), Lang::C),
            None,
            "an in-tree C type is a recoverable include/source problem, not an external SDK"
        );
    }

    #[test]
    fn external_class_placeholdered_as_scalar_degrades_to_report_only() {
        // Group 6: an out-of-tree class (MFC `CString`) is placeholder-synthesized
        // as an opaque scalar; the rebuild fails with generic `Other` diagnostics
        // (scalar used with method-call / construction syntax). Because we DID
        // placeholder an out-of-tree type and the tail is the class-misuse shape,
        // the target degrades to report-only naming the external type.
        let idx = DeclarationIndex::default();
        let errors = vec![BuildErrorKind::Other {
            tail: "handler.cpp:3:22: error: called object type 'unsigned long' is not a \
                   function or function pointer\nmain.cpp:65: error: cannot initialize a member \
                   subobject of type 'unsigned long' with an rvalue of type 'const char *'"
                .to_owned(),
        }];
        let synthesized = BTreeSet::from(["CString".to_owned()]);
        assert_eq!(
            undefined_external_types(&errors, &idx, &synthesized),
            Some(vec!["CString".to_owned()])
        );
    }

    #[test]
    fn class_misuse_other_without_a_placeholder_stays_failed_build() {
        // A class-misuse `Other` with NO out-of-tree placeholder behind it is a real
        // build problem (a genuine codegen bug or a link error), not an external
        // type — it must keep its failed_build so the dependency manifest surfaces
        // it. `None` == no degradation.
        let idx = DeclarationIndex::default();
        let errors = vec![BuildErrorKind::Other {
            tail: "error: called object type 'int' is not a function or function pointer"
                .to_owned(),
        }];
        assert_eq!(
            undefined_external_types(&errors, &idx, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn unrelated_other_with_a_placeholder_stays_failed_build() {
        // Even WITH an out-of-tree placeholder, an `Other` that is NOT the
        // scalar-used-as-class shape (e.g. a link error) must not be swallowed —
        // only the specific class-misuse tails degrade.
        let idx = DeclarationIndex::default();
        let errors = vec![BuildErrorKind::Other {
            tail: "ld: undefined reference to `some_other_symbol'".to_owned(),
        }];
        let synthesized = BTreeSet::from(["CString".to_owned()]);
        assert_eq!(undefined_external_types(&errors, &idx, &synthesized), None);
    }
}

#[cfg(test)]
mod pass_budget_tests {
    use super::plan_pass_budget;
    use std::time::Duration;

    #[test]
    fn per_target_time_is_total_split_across_passes() {
        // --per-target-time is the TOTAL per-target fuzz wall, split evenly across
        // the passes (was per-pass). 60s total over 3 passes => 20s each.
        let (per_pass, total) = plan_pass_budget(Duration::from_secs(60), None, 3);
        assert_eq!(per_pass, Duration::from_secs(20));
        assert_eq!(total, Duration::from_secs(60));
    }

    #[test]
    fn single_pass_gets_the_whole_per_target_budget() {
        let (per_pass, total) = plan_pass_budget(Duration::from_secs(60), None, 1);
        assert_eq!(per_pass, Duration::from_secs(60));
        assert_eq!(total, Duration::from_secs(60));
    }

    #[test]
    fn total_time_alias_overrides_per_target_time() {
        // The deprecated --total-time alias, when set, wins over --per-target-time.
        let (per_pass, total) =
            plan_pass_budget(Duration::from_secs(60), Some(Duration::from_secs(90)), 3);
        assert_eq!(per_pass, Duration::from_secs(30));
        assert_eq!(total, Duration::from_secs(90));
    }
}

#[cfg(test)]
mod engine_selection_tests {
    use super::{applicable_engines, per_engine_budget, prune_engines_for_toolchain, FuzzEngine};
    use crate::auto::candidate::Lang;
    use std::time::Duration;

    #[test]
    fn applicable_engines_gates_afl_to_c_cpp() {
        use FuzzEngine::*;
        // both requested, C target -> both apply, order preserved
        assert_eq!(
            applicable_engines(Lang::C, &[Builtin, AflPlusPlus]),
            vec![Builtin, AflPlusPlus]
        );
        assert_eq!(
            applicable_engines(Lang::Cpp, &[AflPlusPlus]),
            vec![AflPlusPlus]
        );
        // afl-only on a non-C/C++ target -> fall back to builtin (never empty)
        assert_eq!(applicable_engines(Lang::Ada, &[AflPlusPlus]), vec![Builtin]);
        assert_eq!(
            applicable_engines(Lang::Rust, &[AflPlusPlus]),
            vec![Builtin]
        );
        assert_eq!(
            applicable_engines(Lang::Java, &[AflPlusPlus]),
            vec![Builtin]
        );
        // builtin always applies
        assert_eq!(applicable_engines(Lang::Java, &[Builtin]), vec![Builtin]);
    }

    #[test]
    fn prune_unavailable_afl_drops_to_builtin() {
        use FuzzEngine::*;
        // afl unavailable: AFL dropped, builtin kept
        assert_eq!(
            prune_engines_for_toolchain(&[Builtin, AflPlusPlus], false),
            vec![Builtin]
        );
        // afl unavailable and afl-only: fall back to builtin (never empty)
        assert_eq!(
            prune_engines_for_toolchain(&[AflPlusPlus], false),
            vec![Builtin]
        );
        // afl available: unchanged
        assert_eq!(
            prune_engines_for_toolchain(&[Builtin, AflPlusPlus], true),
            vec![Builtin, AflPlusPlus]
        );
    }

    #[test]
    fn engine_budget_splits_evenly() {
        // 1 engine -> whole budget; 2 engines -> half each
        assert_eq!(
            per_engine_budget(Duration::from_secs(60), 1),
            Duration::from_secs(60)
        );
        assert_eq!(
            per_engine_budget(Duration::from_secs(60), 2),
            Duration::from_secs(30)
        );
        // never zero for a positive budget
        assert!(per_engine_budget(Duration::from_secs(1), 4) > Duration::ZERO);
        // zero in -> zero out (no target time means no slice)
        assert_eq!(per_engine_budget(Duration::ZERO, 2), Duration::ZERO);
    }
}

#[cfg(test)]
mod ipc_reachability_tests {
    use super::{effective_reachability_label, ipc_channel_read_observed, reachability_label};
    use crate::auto::runtrace::RuntraceEvent;
    use target_rank::InputReachability;

    fn raw(line: &str) -> RuntraceEvent {
        RuntraceEvent::Unknown {
            raw: line.to_owned(),
        }
    }

    #[test]
    fn detects_virtualized_ipc_reads() {
        assert!(ipc_channel_read_observed(&[raw(
            r#"{"e":"mq_receive","r":17,"v":1}"#
        )]));
        assert!(ipc_channel_read_observed(&[raw(
            r#"{"e":"shm_open","n":"/m","fd":7,"v":1}"#
        )]));
        assert!(ipc_channel_read_observed(&[raw(
            r#"{"e":"mmio","p":"/dev/mem","d":7,"v":1}"#
        )]));
    }

    #[test]
    fn ignores_writes_and_non_virtualized_events() {
        // mq_send is a write, not a fuzz-data-delivering read.
        assert!(!ipc_channel_read_observed(&[raw(
            r#"{"e":"mq_send","r":0,"v":1}"#
        )]));
        // A real (non-virtualized) shm_open carries no v:1.
        assert!(!ipc_channel_read_observed(&[raw(
            r#"{"e":"shm_open","n":"/m","fd":7}"#
        )]));
        // Unrelated event.
        assert!(!ipc_channel_read_observed(&[raw(
            r#"{"e":"open","p":"/etc/x"}"#
        )]));
        assert!(!ipc_channel_read_observed(&[]));
    }

    #[test]
    fn upgrades_unproven_to_ipc_when_channel_observed() {
        assert_eq!(
            effective_reachability_label(Some(InputReachability::ReachabilityUnproven), true),
            Some("ipc_channel_reachable")
        );
        // Ada / unranked (None) driven through a channel also upgrades.
        assert_eq!(
            effective_reachability_label(None, true),
            Some("ipc_channel_reachable")
        );
    }

    #[test]
    fn no_upgrade_without_channel_or_for_attacker_reachable() {
        assert_eq!(
            effective_reachability_label(Some(InputReachability::ReachabilityUnproven), false),
            Some("reachability_unproven")
        );
        // A proven attacker-reachable buffer param is never downgraded/relabeled.
        assert_eq!(
            effective_reachability_label(Some(InputReachability::AttackerReachable), true),
            Some("attacker_reachable")
        );
        // A serializer stays a serializer (its args are caller-controlled even if
        // the function also touches a channel).
        assert_eq!(
            effective_reachability_label(Some(InputReachability::OutputSerializer), true),
            reachability_label(Some(InputReachability::OutputSerializer))
        );
    }
}

#[cfg(test)]
mod sanitizer_override_tests {
    use super::{coverage_only_compiler_override, sanitizer_compiler_override};
    use multicore_fuzz::Sanitizer;

    fn has_flag(flags: &[String], needle: &str) -> bool {
        flags.iter().any(|f| f.contains(needle))
    }

    #[test]
    fn coverage_only_has_coverage_and_no_fsanitize() {
        // `--sanitizers none` (#434): native crash-only + coverage. The build must
        // carry the engine's coverage instrumentation but NO `-fsanitize=` group,
        // so ASan/UBSan never run and cannot false-positive.
        let ov = coverage_only_compiler_override();
        for flags in [&ov.cflags, &ov.cxxflags] {
            assert!(
                has_flag(flags, "-fsanitize-coverage=trace-pc-guard,trace-cmp"),
                "coverage instrumentation must stay: {flags:?}"
            );
            assert!(
                !flags.iter().any(|f| f.starts_with("-fsanitize=")),
                "no -fsanitize= group allowed for `none`: {flags:?}"
            );
        }
        assert_eq!(ov.cc, "clang");
        assert_eq!(ov.cxx, "clang++");
        assert!(
            ov.cxxflags
                .iter()
                .any(|f| f == "-Wno-reserved-user-defined-literal"),
            "native CXXFLAGS must retain legacy string/macro adjacency support: {:?}",
            ov.cxxflags
        );
    }

    #[test]
    fn set_override_keeps_fsanitize_and_coverage() {
        // `--sanitizers asan,ubsan` still bakes the exact -fsanitize= set plus
        // coverage, and subtracts the noisy UBSan checks.
        let ov = sanitizer_compiler_override(&[Sanitizer::Asan, Sanitizer::Ubsan]);
        assert!(
            ov.cxxflags
                .iter()
                .any(|f| f == "-Wno-reserved-user-defined-literal"),
            "native CXXFLAGS must retain legacy string/macro adjacency support: {:?}",
            ov.cxxflags
        );
        for flags in [&ov.cflags, &ov.cxxflags] {
            assert!(has_flag(flags, "-fsanitize=address,undefined"), "{flags:?}");
            assert!(
                has_flag(flags, "-fsanitize-coverage=trace-pc-guard,trace-cmp"),
                "{flags:?}"
            );
            assert!(
                has_flag(flags, "-fno-sanitize=function,vptr,alignment"),
                "UBSan noisy checks subtracted: {flags:?}"
            );
        }
    }

    #[test]
    fn set_override_without_ubsan_does_not_subtract_checks() {
        let ov = sanitizer_compiler_override(&[Sanitizer::Asan]);
        assert!(!has_flag(&ov.cflags, "-fno-sanitize="), "{:?}", ov.cflags);
    }
}

#[cfg(test)]
mod corpus_reseed_tests {
    use super::{reseed_from_corpus_queue, CORPUS_RESEED_CAP};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn reseed_from_corpus_queue_loads_deduped_capped_inputs() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let work = std::env::temp_dir().join(format!("govfuzz-reseed-{nonce}"));
        let queue = work.join("corpus").join("H-RS").join("queue");
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join("aaaa.bin"), b"coverage-input-1").unwrap();
        std::fs::write(queue.join("bbbb.bin"), b"coverage-input-2").unwrap();
        // A queue entry duplicating an existing seed must not be re-added; an
        // empty entry is skipped.
        std::fs::write(queue.join("cccc.bin"), b"existing-seed").unwrap();
        std::fs::write(queue.join("dddd.bin"), b"").unwrap();

        let mut seeds = vec![b"existing-seed".to_vec()];
        let added = reseed_from_corpus_queue(&work, "H-RS", &mut seeds, CORPUS_RESEED_CAP);

        assert_eq!(added, 2, "two fresh coverage inputs reseeded");
        assert!(seeds.contains(&b"coverage-input-1".to_vec()));
        assert!(seeds.contains(&b"coverage-input-2".to_vec()));
        assert_eq!(
            seeds
                .iter()
                .filter(|s| s.as_slice() == b"existing-seed")
                .count(),
            1,
            "no duplicate of an existing seed"
        );

        // The cap bounds how many are taken.
        let mut capped = Vec::new();
        assert_eq!(reseed_from_corpus_queue(&work, "H-RS", &mut capped, 1), 1);
    }
}

#[cfg(test)]
mod stub_execution_tests {
    use super::stub_execution_summary;
    use crate::auto::repair::Repair;
    use std::path::PathBuf;

    fn blind(sym: &str) -> Repair {
        Repair::StubBlind {
            symbol: sym.to_owned(),
        }
    }
    fn declared(sym: &str) -> Repair {
        Repair::StubDeclared {
            symbol: sym.to_owned(),
            return_type: "int".to_owned(),
            provenance: "declared".to_owned(),
        }
    }
    fn add_source(sym: &str) -> Repair {
        Repair::AddSource {
            symbol: sym.to_owned(),
            source_path: PathBuf::from(format!("/s/{sym}.c")),
        }
    }

    #[test]
    fn all_blind_no_real_is_stub_only() {
        // The #417 libyaml shape: every called symbol blind-stubbed, nothing real.
        let se = stub_execution_summary(&[
            blind("yaml_parser_initialize"),
            blind("yaml_parser_set_input_string"),
            blind("yaml_parser_parse"),
        ]);
        assert!(se.stub_only);
        assert_eq!(se.blind_stubbed_symbols, 3);
        assert_eq!(se.real_linked_symbols, 0);
        assert_eq!(se.resolved_called_symbols, 3);
        assert_eq!(se.blind_stub_fraction, 1.0);
    }

    #[test]
    fn no_repairs_is_not_stub_only() {
        // A self-contained target that needed no external resolution genuinely
        // fuzzed real code — never flag it.
        let se = stub_execution_summary(&[]);
        assert!(!se.stub_only);
        assert_eq!(se.resolved_called_symbols, 0);
        assert_eq!(se.blind_stub_fraction, 0.0);
    }

    #[test]
    fn any_real_linked_source_is_not_stub_only() {
        // Real dependency code ran, plus one blind leaf helper — NOT a false clean.
        let se = stub_execution_summary(&[add_source("real_decode"), blind("leaf_helper")]);
        assert!(!se.stub_only);
        assert_eq!(se.real_linked_symbols, 1);
        assert_eq!(se.blind_stubbed_symbols, 1);
    }

    #[test]
    fn ninety_percent_blind_boundary() {
        // 9 blind + 1 declared = 0.9 exactly -> stub_only (>= threshold), since no
        // real source was linked. The lone declared stub still has a real
        // signature but the surface is overwhelmingly blind.
        let mut repairs: Vec<Repair> = (0..9).map(|i| blind(&format!("b{i}"))).collect();
        repairs.push(declared("d0"));
        let se = stub_execution_summary(&repairs);
        assert_eq!(se.resolved_called_symbols, 10);
        assert!((se.blind_stub_fraction - 0.9).abs() < 1e-9);
        assert!(se.stub_only, "0.90 blind fraction must trip the threshold");

        // 8 blind + 2 declared = 0.8 -> below threshold, not stub_only.
        let mut below: Vec<Repair> = (0..8).map(|i| blind(&format!("b{i}"))).collect();
        below.push(declared("d0"));
        below.push(declared("d1"));
        let se = stub_execution_summary(&below);
        assert!((se.blind_stub_fraction - 0.8).abs() < 1e-9);
        assert!(
            !se.stub_only,
            "0.80 blind fraction stays below the threshold"
        );
    }

    #[test]
    fn strongest_evidence_wins_dedup() {
        // A symbol that was AddSource'd (real) AND later appears blind across
        // retries counts as REAL, never blind — so stubbing is not overstated.
        let se = stub_execution_summary(&[add_source("f"), blind("f"), declared("f")]);
        assert_eq!(se.real_linked_symbols, 1);
        assert_eq!(se.blind_stubbed_symbols, 0);
        assert_eq!(se.declared_stubbed_symbols, 0);
        assert_eq!(se.resolved_called_symbols, 1);
        assert!(!se.stub_only);
    }
}

#[cfg(test)]
mod throughput_tests {
    use super::{
        aggregate_executions_per_sec, entry_miss_classification, harness_emits_target_entry_proof,
        Outcome, PassRun,
    };
    use crate::auto::pass::Pass;

    #[test]
    fn passrun_carries_engine_label() {
        let pr = PassRun {
            pass: Pass::FuzzDriven,
            engine: "afl++".to_owned(),
            executions: 10,
            target_entry_observed: false,
            coverage_edges: 0,
            elapsed_secs: 1.0,
            executions_per_sec: 10.0,
            findings: vec![],
        };
        let json = serde_json::to_string(&pr).unwrap();
        assert!(json.contains("\"engine\":\"afl++\""));
    }

    fn pass(executions: usize, elapsed_secs: f64) -> PassRun {
        PassRun {
            pass: Pass::Rng,
            engine: "builtin".to_owned(),
            executions,
            target_entry_observed: false,
            coverage_edges: 0,
            elapsed_secs,
            executions_per_sec: if elapsed_secs > 0.0 {
                executions as f64 / elapsed_secs
            } else {
                0.0
            },
            findings: vec![],
        }
    }

    fn pass_entered(executions: usize) -> PassRun {
        let mut p = pass(executions, 1.0);
        p.target_entry_observed = true;
        p
    }

    // #95 -------------------------------------------------------------------
    #[test]
    fn entry_miss_native_no_entry_is_demoted_with_named_reason() {
        use crate::auto::candidate::Lang;
        // A C cascade whose builtin pass ran (execs > 0) but never observed the
        // target-entry checkpoint must be classified as built_not_entered, not a
        // fuzz success. This is the core #95 invariant.
        let passes = vec![pass(500, 1.0)];
        let miss = entry_miss_classification(Lang::C, &passes, false)
            .expect("native no-entry cascade must be demoted");
        assert_eq!(miss.0, "decode_or_bailout");
        assert!(
            miss.1
                .contains("no pass reached the target-entry checkpoint"),
            "{}",
            miss.1
        );
    }

    #[test]
    fn entry_miss_native_with_entry_stays_a_fuzz_success() {
        use crate::auto::candidate::Lang;
        // At least one pass observed entry -> genuine built_and_fuzzed, no demotion.
        for lang in [Lang::C, Lang::Cpp, Lang::Ada] {
            assert!(
                entry_miss_classification(lang, &[pass(10, 1.0), pass_entered(490)], false)
                    .is_none(),
                "{lang:?} with an observed entry must NOT be demoted"
            );
        }
    }

    #[test]
    fn entry_miss_stub_only_and_no_execution_are_named_distinctly() {
        use crate::auto::candidate::Lang;
        // stub-only: every external symbol was a blind stub.
        let (kind, reason) = entry_miss_classification(Lang::Cpp, &[pass(10, 1.0)], true).unwrap();
        assert_eq!(kind, "stub_only");
        assert!(reason.contains("blind stub"), "{reason}");
        // no execution: built but no iteration ran.
        let (kind, _) = entry_miss_classification(Lang::Ada, &[pass(0, 0.0)], false).unwrap();
        assert_eq!(kind, "no_execution");
    }

    #[test]
    fn entry_miss_never_demotes_interpreted_or_managed_lanes() {
        use crate::auto::candidate::Lang;
        // CRITICAL #95 guard: interpreted/managed lanes have NO target-entry probe,
        // so their `target_entry_observed` is always false. They must NEVER be
        // demoted — doing so would regress every Ruby/Python/JS/Go/... success to
        // built_not_entered. `harness_emits_target_entry_proof` gates this.
        let passes = vec![pass(1000, 1.0)];
        for lang in [
            Lang::Rust,
            Lang::Java,
            Lang::Python,
            Lang::Perl,
            Lang::Go,
            Lang::Cobol,
            Lang::Fortran,
            Lang::CSharp,
            Lang::Js,
            Lang::Ts,
            Lang::Ruby,
            Lang::Lua,
            Lang::Php,
        ] {
            assert!(
                entry_miss_classification(lang, &passes, false).is_none(),
                "{lang:?} is not entry-instrumented and must not be demoted"
            );
            assert!(
                entry_miss_classification(lang, &passes, true).is_none(),
                "{lang:?} stub-only run must still not be demoted (no entry probe)"
            );
            assert!(!harness_emits_target_entry_proof(lang), "{lang:?}");
        }
        for lang in [Lang::C, Lang::Cpp, Lang::Ada] {
            assert!(harness_emits_target_entry_proof(lang), "{lang:?}");
        }
    }

    #[test]
    fn entry_miss_afl_only_native_cascade_is_not_demoted() {
        use crate::auto::candidate::Lang;
        // Only an afl pass ran (main_afl has no external-driver probe), so entry
        // could never be proven. Don't demote on absence of proof it can't emit.
        let mut afl = pass(1000, 1.0);
        afl.engine = "afl++".to_owned();
        assert!(entry_miss_classification(Lang::C, &[afl], false).is_none());
    }

    #[test]
    fn built_not_entered_serializes_with_stable_tag_and_round_trips() {
        let outcome = Outcome::BuiltNotEntered {
            repairs: vec![],
            retries: 0,
            passes: vec![pass(5, 0.5)],
            per_pass_budget_secs: 30,
            total_wall_budget_secs: 60,
            executions_per_sec: 10.0,
            runtrace_events: vec![],
            entry_miss: "decode_or_bailout".to_owned(),
            reason: "no entry".to_owned(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("\"outcome\":\"built_not_entered\""), "{json}");
        let back: Outcome = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Outcome::BuiltNotEntered { .. }));
        let trace = outcome.attempt_trace();
        assert_eq!(trace.terminal_stage, "target_not_reached");
        assert_eq!(trace.reason_category.as_deref(), Some("decode_or_bailout"));
        assert_eq!(trace.terminal_reason.as_deref(), Some("no entry"));
    }

    #[test]
    fn aggregate_is_time_weighted_not_mean_of_rates() {
        // 1000ex over 1s (1000/s) + 1000ex over 4s (250/s): the time-weighted
        // throughput is Σexecs/Σelapsed = 2000/5 = 400/s, NOT the 625/s mean of
        // the two per-pass rates. This is the libFuzzer `average_exec_per_sec`
        // definition and the reason a slow pass can't be hidden by a fast one.
        let passes = vec![pass(1000, 1.0), pass(1000, 4.0)];
        assert_eq!(aggregate_executions_per_sec(&passes), 400.0);
    }

    #[test]
    fn aggregate_is_zero_when_no_wall_elapsed() {
        // No measurable wall must yield 0.0, never NaN/inf from a 0 divide.
        assert_eq!(aggregate_executions_per_sec(&[pass(0, 0.0)]), 0.0);
        assert_eq!(aggregate_executions_per_sec(&[]), 0.0);
    }
}

#[cfg(test)]
mod cmplog_accumulate_tests {
    use super::append_cmplog_records;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn append_cmplog_records_accumulates_only_cmplog_lines() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-cmplog-acc-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let runtrace = dir.join("runtrace.jsonl");
        let snapshot = dir.join("cmplog.jsonl");

        // Pass 1 log: a runtrace event plus one cmplog record.
        std::fs::write(
            &runtrace,
            "{\"e\":\"getenv\",\"n\":\"FOO\"}\n\
             {\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"4141\",\"b\":\"4d41\"}\n",
        )
        .unwrap();
        append_cmplog_records(&runtrace, &snapshot);

        // Pass 2 log (runtrace is truncated/rewritten per pass): another cmplog.
        std::fs::write(
            &runtrace,
            "{\"e\":\"open\",\"p\":\"/x\",\"r\":-1}\n\
             {\"e\":\"cmplog\",\"k\":\"strcmp\",\"a\":\"6869\",\"b\":\"796f\"}\n",
        )
        .unwrap();
        append_cmplog_records(&runtrace, &snapshot);

        let acc = std::fs::read_to_string(&snapshot).unwrap();
        let lines: Vec<&str> = acc.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "should accumulate both cmplog records: {acc}"
        );
        assert!(lines.iter().all(|l| l.contains("\"e\":\"cmplog\"")));
        assert!(!acc.contains("getenv") && !acc.contains("open"));
    }
}

#[cfg(test)]
mod iteration_cap_tests {
    use super::auto_iteration_cap;

    #[test]
    fn auto_iteration_cap_is_unbounded_unless_explicit_positive() {
        // Unset or explicit-zero: time-governed (effectively unbounded).
        assert_eq!(auto_iteration_cap(None), usize::MAX);
        assert_eq!(auto_iteration_cap(Some(0)), usize::MAX);
        // Explicit positive caps the loop.
        assert_eq!(auto_iteration_cap(Some(5000)), 5000);
        // The retired hardcoded 1024 cap must no longer apply.
        assert_ne!(auto_iteration_cap(None), 1024);
    }
}

#[cfg(test)]
mod ada_source_tests {
    use super::{ada_dir_is_foreign_platform, ada_source_dest_basename, dedup_ada_units};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn foreign_platform_dirs_follow_build_host() {
        // Host variants stay eligible while variants for another OS are
        // filtered before duplicate Ada units can collide.
        assert_eq!(
            ada_dir_is_foreign_platform("os-windows"),
            !cfg!(target_os = "windows")
        );
        assert_eq!(
            ada_dir_is_foreign_platform("os-win32"),
            !cfg!(target_os = "windows")
        );
        assert!(ada_dir_is_foreign_platform("os-macos64"));
        assert!(ada_dir_is_foreign_platform("os-freebsd64"));
        // Host-matching / generic dirs are kept.
        assert_eq!(
            ada_dir_is_foreign_platform("os-linux64"),
            !cfg!(target_os = "linux")
        );
        assert_eq!(
            ada_dir_is_foreign_platform("os-unix"),
            cfg!(target_os = "windows")
        );
        assert!(!ada_dir_is_foreign_platform("encoders"));
        assert!(!ada_dir_is_foreign_platform("streams"));
    }

    #[test]
    fn dedup_keeps_one_unit_per_basename_host_preferred() {
        let paths = vec![
            PathBuf::from("/p/os-windows/util-systems-os.ads"),
            PathBuf::from("/p/os-linux64/util-systems-os.ads"),
            PathBuf::from("/p/core/util-strings.ads"),
        ];
        let kept = dedup_ada_units(paths);
        // One util-systems-os.ads (the linux64 one), plus the unique strings unit.
        assert_eq!(kept.len(), 2, "{kept:?}");
        let os = kept
            .iter()
            .find(|p| p.file_name().unwrap() == "util-systems-os.ads")
            .unwrap();
        assert!(os.to_string_lossy().contains("linux64"), "{os:?}");
    }

    #[test]
    fn declared_unit_identity_deduplicates_custom_names_deterministically() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("01-preferred-name.ads");
        let duplicate = temp.path().join("02-other-name.ads");
        let body = temp.path().join("arbitrary-body-name.adb");
        fs::write(
            &first,
            "package Parent.Child is procedure Run; end Parent.Child;",
        )
        .unwrap();
        fs::write(
            &duplicate,
            "package Parent.Child is procedure Other; end Parent.Child;",
        )
        .unwrap();
        fs::write(
            &body,
            "package body Parent.Child is procedure Run is begin null; end Run; end Parent.Child;",
        )
        .unwrap();

        let kept = dedup_ada_units(vec![first.clone(), duplicate, body.clone()]);
        assert_eq!(kept, vec![first.clone(), body.clone()]);
        let spec_source = fs::read_to_string(&first).unwrap();
        let body_source = fs::read_to_string(&body).unwrap();
        assert_eq!(
            ada_source_dest_basename(&first, &spec_source).as_deref(),
            Some("parent-child.ads")
        );
        assert_eq!(
            ada_source_dest_basename(&body, &body_source).as_deref(),
            Some("parent-child.adb")
        );
    }
}

#[cfg(test)]
mod stamp_tests {
    use super::{
        ada_subunit_parent, ada_unit_key_from_filename, ada_variant_dest_basename,
        build_ada_unit_file_map, c_file_is_simd_backend, compute_ada_build_closure,
        ensure_ada_src_instrumented, env_injections_from_events,
        mirror_harness_into_generated_harnesses, reset_repairs_dir,
        rewrite_legacy_gnat_calendar_c_time, stage_ada_c_repair_sources, stamp_runtime_mode,
        walk_to_common_src_root,
    };
    use crate::auto::pass::Pass;
    use crate::auto::runtrace::RuntraceEvent;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_finding() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("govfuzz-stamp-{n}.json"));
        fs::write(
            &p,
            r#"{"id":"F-0001-abc","exception":{"name":"ASAN_HEAP_BUFFER_OVERFLOW"}}"#,
        )
        .unwrap();
        p
    }

    fn tmpdir(prefix: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("govfuzz-attempt-{prefix}-{n}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn reset_repairs_dir_clears_stale_artifacts() {
        // A reused work-dir must not carry a prior run's repair artefacts into
        // this attempt: the inner retry loop appends to auto_stubs.c, so a stale
        // (e.g. previously-duplicated) stub file would re-break an otherwise-
        // buildable target. reset_repairs_dir wipes the regenerable repair state
        // while leaving everything outside repairs/ (the corpus) untouched.
        let root = tmpdir("reset-repairs");
        let repairs = root.join("repairs");
        fs::create_dir_all(repairs.join("auto_includes")).unwrap();
        fs::write(repairs.join("auto_stubs.c"), "stale\nduplicate defs\n").unwrap();
        fs::write(repairs.join("auto_types.h"), "stale type").unwrap();
        // A sibling of repairs/ (stands in for the persisted corpus) must survive.
        fs::create_dir_all(root.join("corpus")).unwrap();
        fs::write(root.join("corpus").join("seed"), "keep me").unwrap();

        reset_repairs_dir(&repairs).unwrap();

        assert!(repairs.is_dir(), "repairs/ must be recreated empty");
        assert!(
            !repairs.join("auto_stubs.c").exists(),
            "stale auto_stubs.c must be cleared"
        );
        assert!(
            !repairs.join("auto_types.h").exists(),
            "stale auto_types.h must be cleared"
        );
        assert!(
            !repairs.join("auto_includes").exists(),
            "stale synthesised-includes dir must be cleared"
        );
        assert!(
            root.join("corpus").join("seed").exists(),
            "the persisted corpus outside repairs/ must be preserved"
        );
    }

    #[test]
    fn ada_harness_mirror_refreshes_an_existing_stable_id() {
        let work = tmpdir("refresh-ada-mirror");
        let harness = work.join("harnesses/H-A-STABLE");
        let generated = work.join("generated_harnesses/H-A-STABLE");
        fs::create_dir_all(&harness).unwrap();
        fs::create_dir_all(&generated).unwrap();
        fs::write(
            harness.join("main.adb"),
            "procedure Main is begin New_Target; end Main;\n",
        )
        .unwrap();
        fs::write(
            generated.join("main.adb"),
            "procedure Main is begin Old_Target; end Main;\n",
        )
        .unwrap();

        mirror_harness_into_generated_harnesses(&work, "H-A-STABLE").unwrap();

        let mirrored = fs::read_to_string(generated.join("main.adb")).unwrap();
        assert!(mirrored.contains("New_Target"));
        assert!(!mirrored.contains("Old_Target"));
        fs::remove_dir_all(work).ok();
    }

    #[test]
    fn stamps_pass_and_env_injected() {
        let path = tmp_finding();
        stamp_runtime_mode(
            &path,
            Pass::Rng,
            &[(
                "ACME_HOME".to_owned(),
                "/tmp/govfuzz/fake_env/ACME_HOME".to_owned(),
            )],
            None,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed["runtime_mode"]["pass"], "rng");
        assert_eq!(
            parsed["runtime_mode"]["env_injected"]["ACME_HOME"],
            "/tmp/govfuzz/fake_env/ACME_HOME"
        );
        // Pre-existing fields untouched.
        assert_eq!(parsed["id"], "F-0001-abc");
        assert_eq!(parsed["exception"]["name"], "ASAN_HEAP_BUFFER_OVERFLOW");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_env_injected_stamps_empty_object() {
        let path = tmp_finding();
        stamp_runtime_mode(&path, Pass::Empty, &[], None).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed["runtime_mode"]["pass"], "empty");
        assert!(parsed["runtime_mode"]["env_injected"]
            .as_object()
            .unwrap()
            .is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn stamp_runtime_mode_recomputes_actionability_for_env_prosthetics() {
        let path = tmp_finding();
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": "F-0001-abc",
                "rule_id": "GF-201",
                "harness_id": "H",
                "exception": {
                    "stack": [
                        { "function": "parse", "file": "src/parse.c", "line": 12 }
                    ]
                },
                "actionability": {
                    "mode": "attacking",
                    "verdict": "likely_reachable",
                    "impact": "critical",
                    "confidence": "medium",
                    "prosthetics": { "used": false }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        stamp_runtime_mode(
            &path,
            Pass::Rng,
            &[(
                "ACME_HOME".to_owned(),
                "/tmp/govfuzz/fake_env/ACME_HOME".to_owned(),
            )],
            None,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        assert_eq!(parsed["actionability"]["mode"], "attacking");
        assert_eq!(parsed["actionability"]["verdict"], "lab_only");
        assert_eq!(parsed["actionability"]["prosthetics"]["used"], true);
        assert_eq!(
            parsed["actionability"]["prosthetics"]["items"][0]["kind"],
            "missing_env_shim"
        );
        assert_eq!(
            parsed["actionability"]["prosthetics"]["items"][0]["name"],
            "ACME_HOME"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn env_injections_deduplicate_repeated_missing_names() {
        let events = vec![
            RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "GOVFUZZ_FAKE_IDENTITY".to_owned(),
            },
            RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "GOVFUZZ_FAKE_IDENTITY".to_owned(),
            },
            RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME_HOME".to_owned(),
            },
        ];

        let injected = env_injections_from_events(&events);

        assert_eq!(
            injected,
            vec![(
                "ACME_HOME".to_owned(),
                "/tmp/govfuzz/fake_env/ACME_HOME".to_owned(),
            )]
        );
    }

    #[test]
    fn env_injections_ignore_present_env_accesses() {
        let events = vec![
            RuntraceEvent::EnvVarAccess {
                api: "getenv".to_owned(),
                name: "DB_PASSWORD".to_owned(),
            },
            RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME_HOME".to_owned(),
            },
        ];

        let injected = env_injections_from_events(&events);

        assert_eq!(
            injected,
            vec![(
                "ACME_HOME".to_owned(),
                "/tmp/govfuzz/fake_env/ACME_HOME".to_owned(),
            )]
        );
    }

    #[test]
    fn ada_instrumentation_uses_explicit_source_root_not_work_parent() {
        let root = tmpdir("source-root");
        let project = root.join("project");
        let sibling = root.join("sibling");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("target.adb"),
            "procedure Target is begin null; end Target;\n",
        )
        .unwrap();
        fs::write(
            sibling.join("leak.adb"),
            "procedure Leak is begin null; end Leak;\n",
        )
        .unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            None,
            None,
            &Default::default(),
        )
        .unwrap();

        assert!(work.join("src_instrumented/target.adb").is_file());
        assert!(
            !work.join("src_instrumented/leak.adb").exists(),
            "auto should not instrument sibling sources outside the requested sweep root"
        );
    }

    #[test]
    fn ada_instrumentation_extends_run_level_tree_for_later_target_closures() {
        // `src_instrumented` is shared by the whole auto run.  Returning merely
        // because the first target populated it left every later target with the
        // first target's dependency closure, producing widespread
        // MissingAdaSymbol failures.  Each serialized Ada attempt must extend
        // the staged union with its own closure.
        let root = tmpdir("ada-multi-target-closures");
        let project = root.join("project");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("first.ads"),
            "with Dep_First; package First is procedure Run; end First;\n",
        )
        .unwrap();
        fs::write(
            project.join("first.adb"),
            "package body First is procedure Run is begin Dep_First.Touch; end Run; end First;\n",
        )
        .unwrap();
        fs::write(
            project.join("dep_first.ads"),
            "package Dep_First is procedure Touch; end Dep_First;\n",
        )
        .unwrap();
        fs::write(
            project.join("second.ads"),
            "with Dep_Second; package Second is procedure Run; end Second;\n",
        )
        .unwrap();
        fs::write(
            project.join("second.adb"),
            "package body Second is procedure Run is begin Dep_Second.Touch; end Run; end Second;\n",
        )
        .unwrap();
        fs::write(
            project.join("dep_second.ads"),
            "package Dep_Second is procedure Touch; end Dep_Second;\n",
        )
        .unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            Some("first"),
            None,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();
        assert!(work.join("src_instrumented/dep_first.ads").is_file());
        assert!(!work.join("src_instrumented/dep_second.ads").exists());

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            Some("second"),
            None,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();
        assert!(work.join("src_instrumented/dep_first.ads").is_file());
        assert!(work.join("src_instrumented/dep_second.ads").is_file());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn ada_source_main_is_not_instrumented_into_src_instrumented() {
        // A source-tree `main.adb` (example / test driver) must not be copied
        // into src_instrumented: the build project compiles src_instrumented
        // alongside the generated harness's own `main.adb`, so a source `main`
        // would collide and gprbuild would build the *example* instead of the
        // harness — every Ada target would then run the example and never fuzz.
        let root = tmpdir("ada-main-collision");
        let project = root.join("project");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("lib.adb"),
            "package body Lib is\n   function F (X : Integer) return Integer is\n   begin\n      return X + 1;\n   end F;\nend Lib;\n",
        )
        .unwrap();
        fs::write(
            project.join("main.adb"),
            "with Lib;\nprocedure Main is\n   Y : constant Integer := Lib.F (1);\nbegin\n   null;\nend Main;\n",
        )
        .unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            None,
            None,
            &Default::default(),
        )
        .unwrap();

        assert!(
            work.join("src_instrumented/lib.adb").is_file(),
            "library sources must still be instrumented"
        );
        assert!(
            !work.join("src_instrumented/main.adb").exists(),
            "source-tree main.adb must be skipped so it doesn't shadow the harness main"
        );
    }

    #[test]
    fn ada_dependency_main_is_not_copied_into_src_instrumented() {
        // A `--ada-deps` directory's own `main.adb` (e.g. SweetAda's
        // `core/main.adb`, which does `BSP.Setup; Application.Run;`) must also be
        // skipped — it would otherwise shadow the generated harness main exactly
        // like a source-tree main, and gprbuild would build the project's main
        // (failing with `"Setup" not declared in "bsp"`) instead of fuzzing.
        let root = tmpdir("ada-dep-main-collision");
        let project = root.join("project");
        let dep = root.join("core");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&dep).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("target.adb"),
            "procedure Target is begin null; end Target;\n",
        )
        .unwrap();
        fs::write(dep.join("bits.adb"), "package body Bits is\nend Bits;\n").unwrap();
        fs::write(
            dep.join("main.adb"),
            "procedure Main is\nbegin\n   BSP.Setup;\n   Application.Run;\nend Main;\n",
        )
        .unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            std::slice::from_ref(&dep),
            &Default::default(),
            None,
            None,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();

        assert!(
            work.join("src_instrumented/bits.adb").is_file(),
            "real dependency units must still be copied for linking"
        );
        assert!(
            !work.join("src_instrumented/main.adb").exists(),
            "a dependency's own main.adb must be skipped so it doesn't shadow the harness main"
        );
    }

    #[test]
    fn ada_closure_copies_only_c_glue_for_imported_symbols() {
        let root = tmpdir("ada-c-glue-closure");
        let project = root.join("project");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("widget.ads"),
            "package Widget is\n   function Read return Integer;\nend Widget;\n",
        )
        .unwrap();
        fs::write(
            project.join("widget.adb"),
            "package body Widget is\n\
             function Native return Integer;\n\
             pragma Import (C, Native, \"needed_native\");\n\
             function Read return Integer is (Native);\n\
             end Widget;\n",
        )
        .unwrap();
        fs::write(
            project.join("needed.c"),
            "int needed_native(void) { return 7; }\n",
        )
        .unwrap();
        fs::write(
            project.join("unrelated.c"),
            "#include <missing_vendor/sdk.h>\nint unrelated(void) { return 0; }\n",
        )
        .unwrap();
        fs::write(project.join("widget.h"), "int needed_native(void);\n").unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            Some("widget"),
            None,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();

        let staged = work.join("src_instrumented");
        assert!(staged.join("needed.c").is_file());
        assert!(!staged.join("unrelated.c").exists());
        assert!(
            staged.join("widget.h").is_file(),
            "headers remain available"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn ada_build_stages_selected_c_repair_sources_on_gpr_path() {
        let root = tmpdir("ada-c-repair-source");
        let work = root.join("work");
        let source = root.join("native_helper.c");
        fs::create_dir_all(&work).unwrap();
        fs::write(&source, "int native_helper(void) { return 1; }\n").unwrap();

        stage_ada_c_repair_sources(&work, "H-A0001-TEST", &[source]).unwrap();

        assert_eq!(
            fs::read_to_string(
                work.join("harnesses/H-A0001-TEST/repairs/ada_stubs/native_helper.c")
            )
            .unwrap(),
            "int native_helper(void) { return 1; }\n"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn ada_pure_unit_is_copied_uninstrumented() {
        // A Pure/Preelaborate unit must not get `with AdaFuzz.Probe` injected, or
        // gprbuild fails with "pure unit cannot depend on non-pure unit". It is
        // copied through uninstrumented instead. The body inherits purity from
        // its spec's `with Pure => True` aspect (the form SweetAda's crc uses).
        let root = tmpdir("ada-pure-skip");
        let project = root.join("project");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("crc16.ads"),
            "package Crc16\n   with Pure => True\nis\n   function Compute (X : Integer) return Integer;\nend Crc16;\n",
        )
        .unwrap();
        // Exception handler => the instrumenter would otherwise inject
        // `with AdaFuzz.Probe`, which is exactly what breaks a Pure unit.
        fs::write(
            project.join("crc16.adb"),
            "package body Crc16 is\n   function Compute (X : Integer) return Integer is\n      Y : Integer := X;\n   begin\n      Y := Y + 1;\n      return Y;\n   exception\n      when others => return 0;\n   end Compute;\nend Crc16;\n",
        )
        .unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            None,
            None,
            &Default::default(),
        )
        .unwrap();

        let body = fs::read_to_string(work.join("src_instrumented/crc16.adb")).unwrap();
        assert!(
            !body.contains("AdaFuzz.Probe"),
            "a Pure unit's body must be copied uninstrumented (no probe with-clause): {body}"
        );
    }

    #[test]
    fn legacy_gnat_calendar_c_time_is_rewritten_without_shifting_lines() {
        let mut source = "-- old GNAT runtime client\nwith Ada.Calendar;\nWITH GNAT.Calendar;\nprocedure Wait is\n   T : GNAT.Calendar.TIMEVAL := GNAT.Calendar.timeval'Null_Parameter;\nbegin\n   T := Gnat . Calendar . To_Timeval (1.0);\nend Wait;\n".to_owned();
        let original_lines = source.lines().count();

        assert!(rewrite_legacy_gnat_calendar_c_time(&mut source));
        assert_eq!(source.lines().count(), original_lines);
        assert!(source.contains("WITH GNAT.Calendar; with System.C_Time;"));
        assert!(source.contains("System.C_Time.timeval"));
        assert!(source.contains("System.C_Time.To_Timeval"));
        assert!(!source
            .to_ascii_lowercase()
            .contains("gnat.calendar.timeval"));
        assert!(!source
            .to_ascii_lowercase()
            .contains("gnat . calendar . to_timeval"));
    }

    #[test]
    fn modern_gnat_calendar_apis_are_not_rewritten() {
        let mut source = "with GNAT.Calendar.Time_IO;\npackage body Clock is\n   D : constant GNAT.Calendar.Day_Name := GNAT.Calendar.Monday;\nend Clock;\n".to_owned();
        let original = source.clone();

        assert!(!rewrite_legacy_gnat_calendar_c_time(&mut source));
        assert_eq!(source, original);
    }

    #[test]
    fn legacy_gnat_calendar_rewrite_applies_to_dependency_copies() {
        let root = tmpdir("ada-legacy-calendar-dep");
        let project = root.join("project");
        let dep = root.join("dep");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&dep).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("target.adb"),
            "procedure Target is begin null; end Target;\n",
        )
        .unwrap();
        fs::write(
            dep.join("legacy.ads"),
            "with GNAT.Calendar;\npackage Legacy is\n   T : GNAT.Calendar.timeval;\nend Legacy;\n",
        )
        .unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            std::slice::from_ref(&dep),
            &Default::default(),
            None,
            None,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();

        let copied = fs::read_to_string(work.join("src_instrumented/legacy.ads")).unwrap();
        assert!(copied.contains("with System.C_Time;"));
        assert!(copied.contains("System.C_Time.timeval"));
    }

    #[test]
    fn ada_dependency_dirs_are_copied_uninstrumented() {
        let root = tmpdir("ada-deps");
        let project = root.join("project");
        let dep = root.join("vendor/ada-util/src");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&dep).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(
            project.join("target.adb"),
            "procedure Target is begin null; end Target;\n",
        )
        .unwrap();
        let dep_body = "package body Util.Encoders is\nbegin\n   null;\nend Util.Encoders;\n";
        fs::write(dep.join("util-encoders.adb"), dep_body).unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            std::slice::from_ref(&dep),
            &Default::default(),
            None,
            None,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();

        // The dependency unit is present so the harness can link against it.
        let copied = work.join("src_instrumented/util-encoders.adb");
        assert!(copied.is_file(), "dependency source should be copied in");
        // ...and copied verbatim (uninstrumented — no AdaFuzz.Probe rewrites).
        let got = fs::read_to_string(&copied).unwrap();
        assert_eq!(got, dep_body, "dependency must not be instrumented");
    }

    // A library unit shaped like the proven `crc16` fixture above: a Pure package
    // (spec + body), copied verbatim into src_instrumented regardless of the
    // instrumenter. The bug under test lives in the directory WALK (which dirs are
    // traversed), upstream of the pure/instrument decision, so a Pure anchor is a
    // faithful, deterministic stand-in for "a library source that must be built".
    fn lib_unit(dir: &std::path::Path, unit: &str) {
        fs::create_dir_all(dir).unwrap();
        // GNAT crunches unit names to lowercase file names (gnatcoll-email.ads).
        let fname = unit.to_ascii_lowercase();
        fs::write(
            dir.join(format!("{fname}.ads")),
            format!("package {unit}\n   with Pure => True\nis\n   function Compute (X : Integer) return Integer;\nend {unit};\n"),
        )
        .unwrap();
        fs::write(
            dir.join(format!("{fname}.adb")),
            format!("package body {unit} is\n   function Compute (X : Integer) return Integer is\n      Y : Integer := X;\n   begin\n      Y := Y + 1;\n      return Y;\n   exception\n      when others => return 0;\n   end Compute;\nend {unit};\n"),
        )
        .unwrap();
    }

    #[test]
    fn ada_testsuite_fixtures_excluded_from_build_sources() {
        // A real Ada+C tree (gnatcoll) ships test fixtures under `testsuite/` —
        // including a `foo.adb` AND a `foo.c`. If both land in src_instrumented the
        // C-enabled build project would emit one `foo.o` for two sources and
        // gprbuild fails ("same object file name"), breaking EVERY harness build.
        // The build source walk must drop non-library dirs with the same filter
        // discovery uses (regression for the gnatcoll-core email-parser campaign).
        let root = tmpdir("ada-testsuite-skip");
        let project = root.join("project");
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();
        lib_unit(&project.join("core/src"), "Widget");
        let fixtures = project.join("testsuite/projects/tests");
        fs::create_dir_all(&fixtures).unwrap();
        fs::write(
            fixtures.join("foo.adb"),
            "procedure Foo is begin null; end Foo;\n",
        )
        .unwrap();
        fs::write(fixtures.join("foo.c"), "int foo(void){return 0;}\n").unwrap();

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            None,
            None,
            &Default::default(),
        )
        .unwrap();

        let si = work.join("src_instrumented");
        assert!(
            si.join("widget.adb").is_file(),
            "real library unit must be built into src_instrumented"
        );
        assert!(
            !si.join("foo.adb").exists(),
            "testsuite Ada fixture must NOT leak into the build source set"
        );
        assert!(
            !si.join("foo.c").exists(),
            "testsuite C fixture must NOT leak into the build source set (object-name collision)"
        );
    }

    #[test]
    fn ada_include_dir_restores_testsuite_into_build_sources() {
        // `--include-dir testsuite` opts a non-library dir back in for BOTH
        // discovery and the build source walk, so a project whose fuzzable code
        // legitimately lives under an otherwise-excluded name still builds.
        let root = tmpdir("ada-testsuite-keep");
        let project = root.join("project");
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();
        lib_unit(&project, "Anchor"); // top-level so the call always succeeds
        lib_unit(&project.join("testsuite"), "Kept");

        let keep_testsuite = crate::auto::discovery::DirFilter::new(&[], &["testsuite".into()]);
        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &keep_testsuite,
            None,
            None,
            &Default::default(),
        )
        .unwrap();

        assert!(
            work.join("src_instrumented/kept.adb").is_file(),
            "--include-dir testsuite must restore the dir into the build source set"
        );
    }

    #[test]
    fn ada_platform_variant_basename_resolution() {
        // Plain (non-variant) names pass through unchanged.
        assert_eq!(
            ada_variant_dest_basename("gnatcoll-json.adb").as_deref(),
            Some("gnatcoll-json.adb")
        );
        assert_eq!(
            ada_variant_dest_basename("widget.ads").as_deref(),
            Some("widget.ads")
        );
        // `__` that is not a platform token is not a variant suffix.
        assert_eq!(
            ada_variant_dest_basename("foo__bar.adb").as_deref(),
            Some("foo__bar.adb")
        );
        // Non-Ada files pass through (the C-glue walk relies on this).
        assert_eq!(
            ada_variant_dest_basename("shim.c").as_deref(),
            Some("shim.c")
        );
        // Of a host/foreign platform pair, exactly one resolves to the canonical
        // unit and the other is skipped (host-agnostic assertion).
        let unix = ada_variant_dest_basename("gnatcoll-os-stat-fstat__unix.adb");
        let win = ada_variant_dest_basename("gnatcoll-os-stat-fstat__win32.adb");
        assert!(
            (unix.as_deref() == Some("gnatcoll-os-stat-fstat.adb") && win.is_none())
                || (win.as_deref() == Some("gnatcoll-os-stat-fstat.adb") && unix.is_none()),
            "one platform variant must resolve to the unit, the other skipped: unix={unix:?} win={win:?}"
        );
    }

    #[test]
    fn ada_platform_variant_written_under_canonical_unit_name() {
        // gnatcoll ships `gnatcoll-io-native-codec__unix.adb` + `__win32.adb`;
        // GNAT default naming only finds `gnatcoll-io-native-codec.adb`, so the
        // host variant must be renamed to that and the foreign one dropped.
        let root = tmpdir("ada-plat-variant");
        let project = root.join("project");
        let work = root.join("work");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&work).unwrap();
        let pure_spec = "package Plat\n   with Pure => True\nis\nend Plat;\n";
        let body = "package body Plat is\nend Plat;\n";
        for variant in ["unix", "win32"] {
            fs::write(project.join(format!("plat__{variant}.ads")), pure_spec).unwrap();
            fs::write(project.join(format!("plat__{variant}.adb")), body).unwrap();
        }

        ensure_ada_src_instrumented(
            &work,
            &project,
            &[],
            &Default::default(),
            None,
            None,
            &Default::default(),
        )
        .unwrap();

        let si = work.join("src_instrumented");
        // The host variant is written under the canonical (suffix-stripped) name.
        assert!(
            si.join("plat.ads").is_file() || si.join("plat.adb").is_file(),
            "host platform variant must be written under the canonical unit name"
        );
        // The suffixed variant filenames must NOT survive (they wouldn't resolve).
        for variant in ["unix", "win32"] {
            assert!(
                !si.join(format!("plat__{variant}.ads")).exists()
                    && !si.join(format!("plat__{variant}.adb")).exists(),
                "platform-variant suffix must not survive into src_instrumented ({variant})"
            );
        }
    }

    #[test]
    fn c_simd_backend_files_are_skipped_from_glue() {
        // blake3's per-CPU backends can't compile under the default `-g` build, so
        // they are dropped from the C glue (gnatcoll's `blake3_neon.c` failed on
        // `arm_neon.h`, blocking every Ada harness on the tree).
        for stem in [
            "blake3_neon",
            "blake3_avx2",
            "blake3_avx512",
            "blake3_sse41",
            "blake3_sse2",
        ] {
            assert!(
                c_file_is_simd_backend(stem),
                "{stem} must be treated as a SIMD backend"
            );
        }
        // ...but the portable path, dispatcher, and ordinary glue are kept.
        for stem in [
            "blake3",
            "blake3_portable",
            "blake3_dispatch",
            "gnatcoll_support",
            "libc-wrappers",
        ] {
            assert!(
                !c_file_is_simd_backend(stem),
                "{stem} must NOT be treated as a SIMD backend"
            );
        }
    }

    #[test]
    fn ada_unit_key_from_filename_maps_gnat_convention() {
        assert_eq!(
            ada_unit_key_from_filename("gnatcoll-json.ads").as_deref(),
            Some("gnatcoll.json")
        );
        assert_eq!(
            ada_unit_key_from_filename("gnatcoll-json-utility.adb").as_deref(),
            Some("gnatcoll.json.utility")
        );
        assert_eq!(
            ada_unit_key_from_filename("widget.ads").as_deref(),
            Some("widget")
        );
        assert_eq!(ada_unit_key_from_filename("shim.c"), None);
        // A host platform variant maps to the base unit (unix is host on
        // linux/macos CI); the suffix is stripped.
        assert_eq!(
            ada_unit_key_from_filename("gnatcoll-os-stat-fstat__unix.adb").as_deref(),
            Some("gnatcoll.os.stat.fstat")
        );
    }

    #[test]
    fn ada_build_closure_includes_only_withed_units() {
        let root = tmpdir("ada-closure");
        fs::create_dir_all(&root).unwrap();
        // App withs Lib (in-tree) and Ada.Text_IO (runtime). Unrelated is never
        // withed and must be excluded; the closure is the target + Lib spec/body.
        let app = root.join("app.adb");
        fs::write(
            &app,
            "with Lib;\nwith Ada.Text_IO;\nprocedure App is\nbegin\n   null;\nend App;\n",
        )
        .unwrap();
        let lib_ads = root.join("lib.ads");
        fs::write(&lib_ads, "package Lib is\n   procedure Go;\nend Lib;\n").unwrap();
        let lib_adb = root.join("lib.adb");
        fs::write(
            &lib_adb,
            "package body Lib is\n   procedure Go is\n   begin\n      null;\n   end Go;\nend Lib;\n",
        )
        .unwrap();
        let unrelated = root.join("unrelated.adb");
        fs::write(
            &unrelated,
            "procedure Unrelated is\nbegin\n   null;\nend Unrelated;\n",
        )
        .unwrap();

        let files = vec![
            app.clone(),
            lib_ads.clone(),
            lib_adb.clone(),
            unrelated.clone(),
        ];
        let map = build_ada_unit_file_map(&files);
        let closure = compute_ada_build_closure("app", &map)
            .expect("closure computable when every with resolves");
        assert!(closure.contains(&app), "target unit included");
        assert!(
            closure.contains(&lib_ads) && closure.contains(&lib_adb),
            "withed Lib spec + body included"
        );
        assert!(
            !closure.contains(&unrelated),
            "un-withed unit excluded from the closure"
        );

        // An unresolved external unit stays outside the known closure. The build
        // then reports that exact dependency instead of compiling unrelated units.
        let needs_ext = root.join("needsext.adb");
        fs::write(
            &needs_ext,
            "with Some_External_Lib;\nprocedure Needsext is\nbegin\n   null;\nend Needsext;\n",
        )
        .unwrap();
        let map2 = build_ada_unit_file_map(std::slice::from_ref(&needs_ext));
        let partial = compute_ada_build_closure("needsext", &map2)
            .expect("the known target closure remains usable");
        assert_eq!(partial, std::collections::BTreeSet::from([needs_ext]));
    }

    #[test]
    fn ada_build_closure_keeps_in_tree_runtime_units() {
        let root = tmpdir("ada-runtime-closure");
        fs::create_dir_all(&root).unwrap();
        let target_ads = root.join("s-valint.ads");
        let target_adb = root.join("s-valint.adb");
        let dependency_ads = root.join("s-forlit.ads");
        fs::write(
            &target_ads,
            "package System.Val_Int is\n   function Value_Integer (S : String) return Integer;\nend System.Val_Int;\n",
        )
        .unwrap();
        fs::write(
            &target_adb,
            "with System.Formatting.Literals;\npackage body System.Val_Int is\n   function Value_Integer (S : String) return Integer is (S'Length);\nend System.Val_Int;\n",
        )
        .unwrap();
        fs::write(
            &dependency_ads,
            "package System.Formatting.Literals is\nend System.Formatting.Literals;\n",
        )
        .unwrap();

        let map = build_ada_unit_file_map(&[
            target_ads.clone(),
            target_adb.clone(),
            dependency_ads.clone(),
        ]);
        let closure = compute_ada_build_closure("s.valint", &map).unwrap();
        assert!(closure.contains(&target_ads));
        assert!(closure.contains(&target_adb));
        assert!(closure.contains(&dependency_ads));
    }

    #[test]
    fn ada_subunit_parent_detects_separate_clause() {
        assert_eq!(
            ada_subunit_parent("separate (GNATCOLL.OS.Stat)\nfunction Stat return Integer is\nbegin\n   return 0;\nend Stat;\n").as_deref(),
            Some("gnatcoll.os.stat")
        );
        // with-clauses may precede the separate clause.
        assert_eq!(
            ada_subunit_parent(
                "with Interfaces.C;\nseparate (Pkg.Child)\nprocedure P is begin null; end P;\n"
            )
            .as_deref(),
            Some("pkg.child")
        );
        // A normal library unit is not a subunit.
        assert_eq!(ada_subunit_parent("package Lib is\nend Lib;\n"), None);
    }

    #[test]
    fn ada_build_closure_pulls_in_separate_subunits() {
        // gnatcoll's per-OS bodies (GNATCOLL.OS.Stat.Stat) are `separate` subunits
        // that nothing `with`s — the closure must still include them to build.
        let root = tmpdir("ada-closure-subunit");
        fs::create_dir_all(&root).unwrap();
        let app = root.join("app.adb");
        fs::write(
            &app,
            "with Lib;\nprocedure App is\nbegin\n   null;\nend App;\n",
        )
        .unwrap();
        let lib_ads = root.join("lib.ads");
        fs::write(&lib_ads, "package Lib is\n   procedure Go;\nend Lib;\n").unwrap();
        let lib_adb = root.join("lib.adb");
        fs::write(
            &lib_adb,
            "package body Lib is\n   procedure Helper is separate;\n   procedure Go is\n   begin\n      Helper;\n   end Go;\nend Lib;\n",
        )
        .unwrap();
        // The subunit body — not withed anywhere, only reachable as a subunit.
        let helper = root.join("lib-helper.adb");
        fs::write(
            &helper,
            "separate (Lib)\nprocedure Helper is\nbegin\n   null;\nend Helper;\n",
        )
        .unwrap();

        let files = vec![
            app.clone(),
            lib_ads.clone(),
            lib_adb.clone(),
            helper.clone(),
        ];
        let map = build_ada_unit_file_map(&files);
        let closure = compute_ada_build_closure("app", &map).expect("closure computable");
        assert!(
            closure.contains(&helper),
            "the `separate` subunit body must be pulled into the closure: {closure:?}"
        );
    }

    #[test]
    fn walk_to_common_src_root_finds_sibling_module_root() {
        // #450(2b): scanning `src/parser` (no .gpr) must walk up to `src` because a
        // sibling module `src/core` roots the dependency's Ada sources.
        let base = tmpdir("ada-common-root");
        let src = base.join("src");
        fs::create_dir_all(src.join("parser")).unwrap();
        fs::create_dir_all(src.join("core")).unwrap();
        fs::write(
            src.join("parser/parser.adb"),
            "with Core;\npackage body Parser is end Parser;\n",
        )
        .unwrap();
        fs::write(src.join("core/core.ads"), "package Core is end Core;\n").unwrap();

        let found = walk_to_common_src_root(&src.join("parser"));
        assert_eq!(
            found.as_deref(),
            Some(src.as_path()),
            "the `src` root with a sibling Ada module must be returned"
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn walk_to_common_src_root_stops_at_non_source_parent() {
        // A directory of separate projects is NOT a source root — the walk must not
        // pull a sibling project's sources.
        let base = tmpdir("ada-unrelated-projects");
        let projb = base.join("projB");
        fs::create_dir_all(projb.join("sub")).unwrap();
        fs::create_dir_all(base.join("projA")).unwrap();
        fs::write(projb.join("sub/b.adb"), "package body B is end B;\n").unwrap();
        fs::write(base.join("projA/a.ads"), "package A is end A;\n").unwrap();

        // `base` is not named like a source root, so no common root is returned.
        assert_eq!(walk_to_common_src_root(&projb), None);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn walk_to_common_src_root_does_not_merge_repositories_under_ada_dir() {
        let base = tmpdir("ada-separate-checkouts");
        let repos = base.join("repos/ada");
        let first = repos.join("first");
        let second = repos.join("second");
        fs::create_dir_all(first.join(".git")).unwrap();
        fs::create_dir_all(second.join(".git")).unwrap();
        fs::write(first.join("first.ads"), "package First is end First;\n").unwrap();
        fs::write(second.join("second.ads"), "package Second is end Second;\n").unwrap();

        assert_eq!(
            walk_to_common_src_root(&first),
            None,
            "an ada repository category is not a shared project source root"
        );
        fs::remove_dir_all(&base).ok();
    }
}

#[cfg(test)]
mod foreign_cross_target_tests {
    use super::*;
    use crate::auto::candidate::{Candidate, Lang};
    use crate::auto::cross_target::resolve_cross_target;

    fn foreign_candidate(lang: Lang, guard: &str) -> Candidate {
        Candidate {
            harness_id: "H-C-test".to_owned(),
            lang,
            source_path: PathBuf::from("/tmp/foreign.c"),
            line: 1,
            name: "parse".to_owned(),
            score: 0,
            is_static: false,
            foreign_guard: Some(guard.to_owned()),
            input_reachability: None,
            dialect: None,
        }
    }

    #[test]
    fn foreign_c_candidate_with_present_toolchain_is_not_skipped() {
        // The crux of (b): a foreign_guard'd candidate is no longer turned into
        // an unconditional UnsupportedParams skip. When the cross toolchain +
        // emulator are installed it resolves to a CrossTarget the attempt loop
        // proceeds to build+fuzz; otherwise the skip is ACTIONABLE (names what
        // to install), never the old generic "does not match this host" text.
        let guard = "aarch64";
        let target = resolve_cross_target(guard).expect("aarch64 maps");
        let result = resolve_foreign_candidate_target(&foreign_candidate(Lang::C, guard), guard);
        if target.available() {
            let resolved = result.expect("present toolchain must NOT skip");
            assert_eq!(resolved.triple, "aarch64-linux-gnu");
        } else {
            let reason = result.expect_err("absent toolchain skips");
            assert!(
                reason.contains("not installed on this host") && reason.contains("missing:"),
                "skip reason must be actionable: {reason}"
            );
            assert!(
                !reason.contains("does not match this host"),
                "must not use the old generic pre-skip text: {reason}"
            );
        }
    }

    #[test]
    fn foreign_candidate_unknown_guard_skips_with_mapping_reason() {
        let result =
            resolve_foreign_candidate_target(&foreign_candidate(Lang::C, "ppc64"), "ppc64");
        let reason = result.expect_err("unmapped guard skips");
        assert!(reason.contains("no cross toolchain mapping"), "{reason}");
    }

    #[test]
    fn foreign_ada_candidate_skips_naming_gnat() {
        // Even a guard we have a C/C++ cross toolchain for is skipped for Ada,
        // since cross-GNAT wiring is out of scope — but with a precise reason.
        let result =
            resolve_foreign_candidate_target(&foreign_candidate(Lang::Ada, "win32"), "win32");
        let reason = result.expect_err("Ada cross skips");
        assert!(reason.contains("GNAT cross"), "{reason}");
    }
}

#[cfg(test)]
mod single_header_impl_tests {
    use super::single_header_implementation_macros;

    #[test]
    fn detects_stb_ifdef_implementation_guard() {
        // Declarations under an include guard; bodies under the impl guard.
        let src = "#ifndef STB_IMAGE_H\n#define STB_IMAGE_H\nint stbi_load(void);\n#endif\n\
                   #ifdef STB_IMAGE_IMPLEMENTATION\nint stbi_load(void){return 0;}\n#endif\n";
        assert_eq!(
            single_header_implementation_macros(src),
            vec!["STB_IMAGE_IMPLEMENTATION".to_owned()]
        );
    }

    #[test]
    fn detects_if_defined_forms_and_dedups() {
        let src = "#if defined(CUTE_ASEPRITE_IMPLEMENTATION)\nx\n#endif\n\
                   #if defined CUTE_ASEPRITE_IMPLEMENTATION\ny\n#endif\n";
        assert_eq!(
            single_header_implementation_macros(src),
            vec!["CUTE_ASEPRITE_IMPLEMENTATION".to_owned()]
        );
    }

    #[test]
    fn picks_first_macro_in_a_compound_if() {
        let src = "#if defined(DR_WAV_IMPLEMENTATION) || defined(DR_WAV_STATIC)\nz\n#endif\n";
        assert_eq!(
            single_header_implementation_macros(src),
            vec!["DR_WAV_IMPLEMENTATION".to_owned()]
        );
    }

    #[test]
    fn ignores_ifndef_and_undef_even_with_impl_suffix() {
        // An `#ifndef`/`#undef` of an `_IMPLEMENTATION`-suffixed name must NOT be
        // defined — only positive guards that WRAP the implementation count.
        let src = "#ifndef WEIRD_IMPLEMENTATION\n#define WEIRD_IMPLEMENTATION\n#endif\n\
                   #undef OTHER_IMPLEMENTATION\n";
        assert!(single_header_implementation_macros(src).is_empty());
    }

    #[test]
    fn ignores_lowercase_and_plain_source() {
        // A lowercase `do_implementation` token and ordinary code yield nothing.
        let src = "void do_implementation(void);\nint main(void){return 0;}\n";
        assert!(single_header_implementation_macros(src).is_empty());
    }

    #[test]
    fn detects_short_impl_suffix_idiom() {
        // sokol-style `<NAME>_IMPL` (not only the long `_IMPLEMENTATION`).
        let src = "#ifdef SOKOL_IMPL\nbody\n#endif\n";
        assert_eq!(
            single_header_implementation_macros(src),
            vec!["SOKOL_IMPL".to_owned()]
        );
    }

    #[test]
    fn rejects_bare_impl_without_prefix() {
        // `_IMPL` / `_IMPLEMENTATION` with no library prefix are not impl macros.
        let src = "#ifdef _IMPL\na\n#endif\n#if defined(_IMPLEMENTATION)\nb\n#endif\n";
        assert!(single_header_implementation_macros(src).is_empty());
    }

    #[test]
    fn detects_cute_aseprite_real_guard_form() {
        // The exact shape of cute_aseprite.h: a `#define` in the usage doc (must be
        // ignored — not a guard), the real `#ifdef` impl guard, and an `#ifndef
        // ..._ONCE` re-include guard (must be ignored).
        let src = "/* usage:\n#define CUTE_ASEPRITE_IMPLEMENTATION\n*/\n\
                   #ifdef CUTE_ASEPRITE_IMPLEMENTATION\n\
                   #ifndef CUTE_ASEPRITE_IMPLEMENTATION_ONCE\n\
                   #define CUTE_ASEPRITE_IMPLEMENTATION_ONCE\nbody\n#endif\n#endif\n";
        assert_eq!(
            single_header_implementation_macros(src),
            vec!["CUTE_ASEPRITE_IMPLEMENTATION".to_owned()]
        );
    }
}

#[cfg(test)]
mod platform_stub_tests {
    use super::*;
    use crate::auto::candidate::{Candidate, Lang};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn cand(lang: Lang, guard: &str) -> Candidate {
        Candidate {
            harness_id: "H".to_owned(),
            lang,
            source_path: PathBuf::from("/tmp/x.c"),
            line: 1,
            name: "f".to_owned(),
            score: 0,
            is_static: false,
            foreign_guard: Some(guard.to_owned()),
            input_reachability: None,
            dialect: None,
        }
    }

    fn tmp(prefix: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("govfuzz-pstub-{prefix}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn windows_c_guard_prefers_cross_when_toolchain_available_else_stub_isolated() {
        // With mingw + wine present, a Windows C guard cross-compiles to a real
        // PE and fuzzes under wine (higher fidelity). Without the toolchain it
        // falls back to the reduced-fidelity native stub-isolated build.
        let result = resolve_foreign_strategy(&cand(Lang::C, "_WIN32"), "_WIN32").expect("ok");
        let available = crate::auto::cross_target::resolve_cross_target("_WIN32")
            .unwrap()
            .available();
        if available {
            assert!(
                matches!(result, ForeignStrategy::Cross(_)),
                "a Windows C guard with mingw+wine present must cross-compile to a real PE"
            );
        } else {
            match result {
                ForeignStrategy::StubIsolated(stub) => assert_eq!(stub.platform, "windows"),
                _ => panic!("without mingw+wine a Windows C guard must stub-isolate"),
            }
        }
    }

    #[test]
    fn windows_cross_override_enables_mingw_coverage_without_asan() {
        // mingw-w64 gcc supports `trace-pc` + `trace-cmp` (not `trace-pc-guard`)
        // and has no ASan runtime; the Windows driver implements the trace-pc
        // hook + a vectored exception handler for crash detection.
        let target = crate::auto::cross_target::resolve_cross_target("_WIN32").unwrap();
        let ov = cross_compiler_override(&target);
        assert_eq!(ov.cc, "x86_64-w64-mingw32-gcc");
        let cflags = ov.cflags.join(" ");
        assert!(
            cflags.contains("-fsanitize-coverage=trace-pc,trace-cmp"),
            "mingw build gets trace-pc coverage + cmplog, got: {cflags}"
        );
        assert!(
            !cflags.contains("trace-pc-guard"),
            "mingw-w64 gcc rejects trace-pc-guard"
        );
        assert!(
            !cflags.contains("-fsanitize=address"),
            "mingw has no ASan runtime"
        );
        assert!(
            cflags.contains("-static") && ov.cxxflags.join(" ").contains("-static"),
            "the wine PE must link static (no mingw DLL deps wine can't load): {cflags}"
        );
    }

    #[test]
    fn aarch64_cross_override_stays_coverage_blind() {
        // The qemu-user arch path is unchanged: plain `-O1 -g` (ASan/coverage do
        // not survive qemu-user today). Guards against accidentally arming it.
        let target = crate::auto::cross_target::resolve_cross_target("aarch64").unwrap();
        let ov = cross_compiler_override(&target);
        let cflags = ov.cflags.join(" ");
        assert!(
            !cflags.contains("fsanitize-coverage"),
            "aarch64 cross stays coverage-blind, got: {cflags}"
        );
        assert!(!cflags.contains("-fsanitize=address"));
    }

    #[test]
    fn windows_ada_guard_is_not_stub_isolated() {
        // Platform stubbing is C/C++ only; an Ada `win32` unit takes the cross
        // path, which then skips for lack of a GNAT cross toolchain.
        let result = resolve_foreign_strategy(&cand(Lang::Ada, "win32"), "win32");
        assert!(matches!(result, Err(reason) if reason.contains("GNAT cross")));
    }

    #[test]
    fn aarch64_guard_routes_to_cross_or_actionable_skip() {
        // An arch guard never platform-stubs; it cross-compiles when the toolchain
        // is present, else skips actionably.
        let result = resolve_foreign_strategy(&cand(Lang::C, "aarch64"), "aarch64");
        let available = crate::auto::cross_target::resolve_cross_target("aarch64")
            .unwrap()
            .available();
        if available {
            assert!(matches!(result, Ok(ForeignStrategy::Cross(_))));
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn apply_platform_stub_writes_header_define_and_force_include() {
        let stub = crate::auto::cross_target::foreign_platform_stub("_WIN32").unwrap();
        let root = tmp("apply");
        let harness = crate::auto::layout::harness_dir(&root, "H");
        let repairs = harness.join("repairs");
        std::fs::create_dir_all(&repairs).unwrap();
        apply_platform_stub(&stub, &harness, &repairs).unwrap();

        assert!(
            harness.join("windows.h").is_file(),
            "fake header dropped beside harness"
        );
        let defines =
            std::fs::read_to_string(repairs.join(crate::auto::repair::AUTO_DEFINES_FILE)).unwrap();
        assert!(defines.contains("#define _WIN32 1"), "{defines}");
        let includes =
            std::fs::read_to_string(repairs.join(crate::auto::repair::AUTO_CPP_INCLUDES_FILE))
                .unwrap();
        assert!(includes.contains("#include \"windows.h\""), "{includes}");

        // Idempotent: re-applying must not duplicate the define.
        apply_platform_stub(&stub, &harness, &repairs).unwrap();
        let defines2 =
            std::fs::read_to_string(repairs.join(crate::auto::repair::AUTO_DEFINES_FILE)).unwrap();
        assert_eq!(defines2.matches("#define _WIN32 1").count(), 1);
    }
}

#[cfg(test)]
mod cpp_owner_class_tests {
    use super::cpp_owner_class;

    #[test]
    fn extracts_owner_class_of_namespaced_method() {
        assert_eq!(
            cpp_owner_class("json11::JsonParser::expect"),
            Some("JsonParser")
        );
        // Overload signature suffix is ignored.
        assert_eq!(
            cpp_owner_class("json11::JsonParser::fail(string &&)"),
            Some("JsonParser")
        );
        // Multi-level namespace: owner is the last segment before the method.
        assert_eq!(cpp_owner_class("a::b::C::m"), Some("C"));
        // Non-namespaced method.
        assert_eq!(cpp_owner_class("Reader::read"), Some("Reader"));
    }

    #[test]
    fn free_functions_have_no_owner_class() {
        // A bare free function — no `::`, no owner.
        assert_eq!(cpp_owner_class("foo"), None);
        assert_eq!(cpp_owner_class("parse(const char *)"), None);
        // A namespaced FREE function: the second-to-last segment is a namespace,
        // not a class. It still returns that segment here; the skip is gated by
        // `cpp_class_defined_only_in_translation_unit`, which only matches recorded
        // CLASS names — a namespace is never one — so a free function is never
        // skipped. Documented so the gating contract is explicit.
        assert_eq!(cpp_owner_class("json11::helper"), Some("json11"));
    }
}

#[cfg(test)]
mod refused_repair_tracking_tests {
    //! Regression for the yaml-cpp self-target repair livelock: building a harness
    //! for `YAML::Emitter::Write` surfaced ~22 sibling `EmitterState::Set*` symbols
    //! whose definition source the index mis-attributes to the target's OWN
    //! `emitter.cpp` (the shortest `/src/` path wins the score tiebreak). Each was
    //! planned as a self-target `AddSource { source_path: emitter.cpp }` and refused,
    //! so the identical "refusing self-target repair" line printed dozens of times in
    //! one round while the loop ground on. The fix tracks refused repairs by their
    //! stable [`repair_key`] so an identical proposal is logged and re-processed
    //! exactly once per target, and a round whose only proposals are
    //! already-refused/applied makes no progress and stops cleanly.
    use super::*;
    use crate::auto::candidate::{Candidate, Lang};
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn emitter_candidate() -> Candidate {
        Candidate {
            harness_id: "H-X02D3".to_owned(),
            lang: Lang::Cpp,
            source_path: PathBuf::from("/src/emitter.cpp"),
            line: 1,
            name: "YAML::Emitter::Write".to_owned(),
            score: 0,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        }
    }

    /// An `AddSource` re-adding the candidate's OWN source is a self-target repair,
    /// regardless of which (sibling) symbol the index mis-attributed to it.
    #[test]
    fn self_target_addsource_is_refused_by_source_path() {
        let cand = emitter_candidate();
        let sibling_symbol = Repair::AddSource {
            symbol: "YAML::EmitterState::SetBoolFormat(YAML::EMITTER_MANIP, YAML::FmtScope::value)"
                .to_owned(),
            source_path: cand.source_path.clone(),
        };
        assert!(
            repair_replaces_candidate_target(&sibling_symbol, &cand),
            "re-adding the candidate's own source must be refused as self-target"
        );
        // A genuinely different source (a real sibling) is NOT a self-target repair.
        let real_sibling = Repair::AddSource {
            symbol: "YAML::EmitterState::SetBoolFormat(YAML::EMITTER_MANIP, YAML::FmtScope::value)"
                .to_owned(),
            source_path: PathBuf::from("/src/emitterstate.cpp"),
        };
        assert!(
            !repair_replaces_candidate_target(&real_sibling, &cand),
            "adding a real sibling source must NOT be treated as a self-target repair"
        );
    }

    /// The dozens of refused self-target proposals in one round all share ONE stable
    /// key (the candidate's source path), so `record_refused_repair` surfaces them
    /// exactly once — collapsing the dozens-of-identical-lines spam to a single line.
    #[test]
    fn identical_self_target_refusals_are_recorded_once() {
        let cand = emitter_candidate();
        let mut refused: HashSet<String> = HashSet::new();
        // ~22 distinct sibling symbols, every one mis-attributed to emitter.cpp.
        let sibling_symbols = [
            "YAML::EmitterState::SetBoolFormat(YAML::EMITTER_MANIP, YAML::FmtScope::value)",
            "YAML::EmitterState::SetNullFormat(YAML::EMITTER_MANIP, YAML::FmtScope::value)",
            "YAML::EmitterState::SetIndent(unsigned long, YAML::FmtScope::value)",
            "YAML::EmitterState::StartedScalar()",
            "YAML::EmitterState::SetLocalValue(YAML::EMITTER_MANIP)",
        ];
        let mut logged = 0usize;
        for round in 0..3 {
            for sym in sibling_symbols {
                let repair = Repair::AddSource {
                    symbol: sym.to_owned(),
                    source_path: cand.source_path.clone(),
                };
                assert!(repair_replaces_candidate_target(&repair, &cand));
                if record_refused_repair(&mut refused, &repair) {
                    logged += 1;
                }
            }
            // The same self-target key was already recorded after round 0, so later
            // rounds add nothing — the loop never re-proposes it.
            assert_eq!(
                refused.len(),
                1,
                "all self-target re-adds of {} collapse to one key (round {round})",
                cand.source_path.display()
            );
        }
        assert_eq!(
            logged, 1,
            "the identical self-target refusal must be surfaced exactly once per target"
        );
    }

    /// Genuinely-DIFFERENT refused repairs must each surface once — the dedup keys on
    /// the stable per-repair key, so multi-step repair across distinct proposals is
    /// preserved (only IDENTICAL re-proposals are suppressed).
    #[test]
    fn distinct_refused_repairs_each_surface_once() {
        let cand = emitter_candidate();
        let mut refused: HashSet<String> = HashSet::new();
        // Two DIFFERENT self-target shapes: re-add own source, and stub own symbol.
        let readd_own = Repair::AddSource {
            symbol: "YAML::Emitter::Helper()".to_owned(),
            source_path: cand.source_path.clone(),
        };
        let stub_own = Repair::StubBlind {
            symbol: cand.name.clone(),
        };
        assert!(record_refused_repair(&mut refused, &readd_own));
        assert!(record_refused_repair(&mut refused, &stub_own));
        assert_eq!(
            refused.len(),
            2,
            "distinct refused keys are tracked separately"
        );
        // Re-proposing either is suppressed.
        assert!(!record_refused_repair(&mut refused, &readd_own));
        assert!(!record_refused_repair(&mut refused, &stub_own));
    }

    /// Only the candidate's OWN symbol signals an unavailable target (the honest-skip
    /// trigger). A sibling symbol mis-attributed to the candidate's file is refused
    /// but does NOT set the blocker — its real definition is added from a sibling, so
    /// the build can still converge and must not be wrongly skipped.
    #[test]
    fn only_own_symbol_signals_unavailable_target() {
        let cand = emitter_candidate();
        let own_symbol = Repair::AddSource {
            symbol: cand.name.clone(),
            source_path: cand.source_path.clone(),
        };
        let sibling_symbol = Repair::AddSource {
            symbol: "YAML::EmitterState::SetBoolFormat(YAML::EMITTER_MANIP, YAML::FmtScope::value)"
                .to_owned(),
            source_path: cand.source_path.clone(),
        };
        assert!(
            repair_signals_unavailable_target(&own_symbol, &cand),
            "re-adding the candidate's own source for its OWN symbol means it is unavailable"
        );
        assert!(
            !repair_signals_unavailable_target(&sibling_symbol, &cand),
            "a sibling symbol mis-attributed to the candidate's file is resolvable elsewhere"
        );
    }

    #[test]
    fn own_target_forward_declaration_is_not_a_replacement_or_unavailable_signal() {
        let cand = emitter_candidate();
        let declaration = Repair::DeclareFunction {
            symbol: cand.name.clone(),
            return_type: "void".to_owned(),
            provenance: "real definition survives".to_owned(),
        };
        assert!(!repair_replaces_candidate_target(&declaration, &cand));
        assert!(!repair_signals_unavailable_target(&declaration, &cand));
    }

    #[test]
    fn refused_self_source_dependency_falls_back_to_declaration_stub() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-self-source-fallback-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("value.h"),
            "namespace Json {\n\
             class ValueIteratorBase {\n\
             public:\n\
               ValueIteratorBase();\n\
             };\n\
             }\n",
        )
        .unwrap();
        let target = root.join("target.cpp");
        fs::write(
            &target,
            "#include \"value.h\"\n\
             Json::ValueIteratorBase::ValueIteratorBase() {}\n\
             int target() { return 0; }\n",
        )
        .unwrap();

        let index = DeclarationIndex::build(&root).unwrap();
        let candidate = Candidate {
            harness_id: "H-JSONCPP".to_owned(),
            lang: Lang::Cpp,
            source_path: target.clone(),
            line: 3,
            name: "target".to_owned(),
            score: 0,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        };
        let error = BuildErrorKind::UndefinedSymbol {
            name: "Json::ValueIteratorBase::ValueIteratorBase()".to_owned(),
        };
        let manifest = RepairManifest::default();

        let initial = crate::auto::repair::plan_repair_forced_with_source_policy(
            &error, &index, &manifest, false, true,
        )
        .expect("definition-backed source repair");
        assert!(
            matches!(initial, Repair::AddSource { ref symbol, ref source_path }
                if symbol == "Json::ValueIteratorBase::ValueIteratorBase()"
                    && source_path == &target),
            "definition-backed repair should re-add the defining source: {initial:?}"
        );
        assert!(repair_replaces_candidate_target(&initial, &candidate));

        let fallback =
            dependency_fallback_after_refused_source(&error, &index, &manifest, &candidate, false)
                .expect("declaration-backed fallback");
        assert!(
            matches!(fallback, Repair::StubDeclared { ref symbol, .. }
                if symbol == "Json::ValueIteratorBase::ValueIteratorBase()"),
            "source-disabled re-plan should preserve a real declaration: {fallback:?}"
        );
        assert!(!repair_replaces_candidate_target(&fallback, &candidate));

        let target_error = BuildErrorKind::UndefinedSymbol {
            name: candidate.name.clone(),
        };
        assert!(
            dependency_fallback_after_refused_source(
                &target_error,
                &index,
                &manifest,
                &candidate,
                false,
            )
            .is_none(),
            "the selected fuzz target must never be replaced by a fallback stub"
        );

        fs::remove_dir_all(root).unwrap();
    }
}
