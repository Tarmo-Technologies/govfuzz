// SPDX-License-Identifier: Apache-2.0

//! Aggregates per-target [`AttemptResult`]s into `<work>/auto/run.md`
//! and `<work>/auto/run.json` — the human-readable summary + machine
//! ledger the `govfuzz auto` sweep emits. The `needed_for_build`
//! section deduplicates repairs and missing-library notes across
//! targets so the upstream maintainer sees one entry per missing
//! header / symbol / library with the full list of referencing
//! `harness_id`s.

use crate::auto::attempt::{
    stub_execution_summary, AttemptResult, AttemptTrace, Outcome, PassRun, StubExecution,
};
use crate::auto::candidate::{Candidate, Lang};
use crate::auto::repair::Repair;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Serialize)]
struct RunJson<'a> {
    schema_version: u32,
    started_at: String,
    finished_at: String,
    partial: bool,
    mode: actionability::RunMode,
    source_root: &'a Path,
    summary: Summary,
    needed_for_build: NeededForBuild,
    targets: Vec<TargetEntry<'a>>,
}

#[derive(Debug, Default, Serialize)]
struct Summary {
    discovered: usize,
    /// Total ranked candidates discovered BEFORE any `--max-targets` /
    /// `--campaign-time` split cap. Equals `discovered` for an uncapped run;
    /// larger when a cap dropped lower-ranked targets from the sweep (#6 — so a
    /// truncated run is never read as having discovered only the swept count).
    discovered_total: usize,
    /// Candidates dropped from the sweep by `--max-targets` / the campaign-time
    /// split (`discovered_total - discovered`). 0 for an uncapped run.
    #[serde(skip_serializing_if = "is_zero")]
    dropped_by_cap: usize,
    /// `--resume`: targets skipped this run because they already completed in a
    /// prior sweep over the same work-dir (their artifacts remain on disk). 0 when
    /// not resuming. Included in `discovered`.
    #[serde(skip_serializing_if = "is_zero")]
    resumed: usize,
    built: usize,
    built_and_fuzzed: usize,
    /// #417: of the `built_and_fuzzed` targets, how many were FALSE CLEANS —
    /// their harness fuzzed only blind stubs, never the real library (see
    /// [`StubExecution::stub_only`]). Surfaced distinctly so a sweep that
    /// "built and fuzzed N" isn't read as N real fuzz campaigns.
    fuzzed_stub_only: usize,
    /// force-fuzz Phase 2: of the swept targets, how many ran forced-and-stub-heavy
    /// (`--force` AND [`StubExecution::stub_only`]) — a forced build that fuzzed
    /// synthesized stubs. Their findings are floored to Low with a stub-artifact
    /// note, and this count is surfaced next to `built_and_fuzzed` so a forced sweep
    /// isn't read as N confirmed campaigns. 0 (omitted) for a non-force run.
    #[serde(skip_serializing_if = "is_zero")]
    forced: usize,
    /// #95: targets whose C/C++/Ada harness built and ran fuzz passes but never
    /// observed the target-entry checkpoint — the run exercised only decoding or
    /// blind stubs, so it is NOT a fuzz success (`built_and_fuzzed`). Surfaced
    /// distinctly so it can never inflate the fuzz-success headline. 0 (omitted)
    /// when every built target genuinely entered.
    #[serde(skip_serializing_if = "is_zero")]
    built_not_entered: usize,
    failed_build: usize,
    unsupported_params: usize,
    unrecoverable_link: usize,
    unrecoverable_runtime: usize,
    /// M22: targets discovered + statically analyzed but not fuzzed (legacy
    /// dialect with no lane yet, absent legacy toolchain, or unrecoverable
    /// build). Surfaced distinctly so they read as triaged, not dropped.
    #[serde(skip_serializing_if = "is_zero")]
    report_only: usize,
    findings: usize,
    /// #484: static findings (from `--static` / report-only) that a fuzz crash or
    /// oracle hit reached at the same source site — upgraded to `fuzz_confirmed`.
    /// The headline number that separates "a scanner flagged it" from "a fuzzer
    /// walked into it". 0 (omitted) when nothing was confirmed.
    #[serde(skip_serializing_if = "is_zero")]
    fuzz_confirmed: usize,
}

#[derive(Debug, Default, Serialize)]
struct NeededForBuild {
    synthesized_headers: Vec<Aggregated>,
    synthesized_types: Vec<Aggregated>,
    /// Build-config macros `#define`d to a benign value because they were used
    /// but never defined (the project's build system injects them via
    /// generated `config.h` / `-D`). The maintainer must supply real values.
    synthesized_macros: Vec<Aggregated>,
    stubbed_symbols_declared: Vec<Aggregated>,
    stubbed_symbols_blind: Vec<Aggregated>,
    stubbed_ada_units: Vec<Aggregated>,
    stubbed_ada_symbols: Vec<Aggregated>,
    missing_libraries: Vec<Aggregated>,
    missing_gpr_imports: Vec<Aggregated>,
    /// Layer-C: env vars the runtrace shim observed getenv() NULLing
    /// during fuzz. With injection on, these double with the
    /// Repair::EnvVarInjection ledger; with --no-stubs they show
    /// the would-be fakes.
    environment_variables_faked: Vec<Aggregated>,
    /// Layer-C: open/stat/access ENOENT paths.
    missing_files: Vec<Aggregated>,
    /// Layer-C: connect()/getaddrinfo() failures.
    network_endpoints: Vec<Aggregated>,
    /// Layer-C: dlopen() NULL returns.
    dlopen_failures: Vec<Aggregated>,
    /// Ada units the classifier still flagged as missing after auto
    /// repair attempts. Successful Ada stub repairs are reported in
    /// `stubbed_ada_units` / `stubbed_ada_symbols` instead.
    missing_ada_units: Vec<Aggregated>,
    /// Harness / codegen build errors (a malformed generated harness or a parser
    /// recovery artifact — "no member named", "did you mean", a bare `type`
    /// placeholder). These are NOT external dependencies, so they are recorded
    /// here for honesty instead of being framed in the missing-dependency
    /// manifest with an "acquire" hint (#5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    harness_codegen_errors: Vec<Aggregated>,
}

#[derive(Debug, Serialize)]
struct Aggregated {
    name: String,
    referenced_by_targets: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TargetEntry<'a> {
    harness_id: &'a str,
    source: &'a Path,
    name: &'a str,
    line: u32,
    score: i32,
    outcome: &'a Outcome,
    attempt_trace: AttemptTrace,
    /// #417: stub-vs-real execution summary for fuzzed targets — the field that
    /// distinguishes a real fuzz from a FALSE CLEAN over empty stubs. `None`
    /// (omitted) for outcomes that never fuzzed.
    #[serde(skip_serializing_if = "Option::is_none")]
    stub_execution: Option<StubExecution>,
    /// Whether the fuzzed parameters are an attacker-controlled input channel
    /// (C/C++ only). Surfaced so a crash on a non-attacker-reachable target
    /// (serializer / caller-controlled args) is honestly flagged, not presented
    /// as a vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    input_reachability: Option<target_rank::InputReachability>,
    /// #(c): set when the target was built STUB-ISOLATED for a foreign OS platform
    /// (its platform deps faked so it compiles natively). Names the platform so a
    /// reader knows every finding on this target is REDUCED-FIDELITY — the logic
    /// ran but the platform behavior was stubbed, not real.
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_stub: Option<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// A round-trippable persisted copy of one target's full attempt result, written
/// to `<work>/harnesses/<id>/result.json` the moment the attempt finishes. On a
/// `--resume` re-run it is loaded back into a real [`AttemptResult`] so the target
/// is fully re-integrated into the new report (its outcome bucket, repair bags,
/// findings, pass detail) without being re-attempted. `Candidate` isn't itself
/// serde-able (its `Lang`/`InputReachability` are cross-crate enums), so its
/// fields are stored as stable strings here, mirroring the discovery cache.
#[derive(Serialize, Deserialize)]
struct PersistedResult {
    harness_id: String,
    lang: String,
    source_path: String,
    line: u32,
    name: String,
    score: i32,
    is_static: bool,
    #[serde(default)]
    foreign_guard: Option<String>,
    #[serde(default)]
    input_reachability: Option<String>,
    outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_trace: Option<AttemptTrace>,
    harness_dir: String,
}

fn lang_tag(l: Lang) -> &'static str {
    match l {
        Lang::Ada => "ada",
        Lang::C => "c",
        Lang::Cpp => "cpp",
        Lang::Rust => "rust",
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Perl => "perl",
        Lang::Go => "go",
        Lang::Cobol => "cobol",
        Lang::Fortran => "fortran",
        Lang::CSharp => "csharp",
        Lang::Js => "javascript",
        Lang::Ts => "typescript",
        Lang::Ruby => "ruby",
        Lang::Lua => "lua",
        Lang::Php => "php",
    }
}
fn lang_from_tag(s: &str) -> Option<Lang> {
    Some(match s {
        "ada" => Lang::Ada,
        "c" => Lang::C,
        "cpp" => Lang::Cpp,
        "rust" => Lang::Rust,
        "java" => Lang::Java,
        "python" => Lang::Python,
        "perl" => Lang::Perl,
        "go" => Lang::Go,
        "cobol" => Lang::Cobol,
        "fortran" => Lang::Fortran,
        "csharp" => Lang::CSharp,
        "javascript" => Lang::Js,
        "typescript" => Lang::Ts,
        "ruby" => Lang::Ruby,
        "lua" => Lang::Lua,
        "php" => Lang::Php,
        _ => return None,
    })
}
fn reach_tag(r: target_rank::InputReachability) -> &'static str {
    use target_rank::InputReachability::*;
    match r {
        AttackerReachable => "attacker_reachable",
        OutputSerializer => "output_serializer",
        ReachabilityUnproven => "reachability_unproven",
        IpcChannelReachable => "ipc_channel_reachable",
    }
}
fn reach_from_tag(s: &str) -> Option<target_rank::InputReachability> {
    use target_rank::InputReachability::*;
    Some(match s {
        "attacker_reachable" => AttackerReachable,
        "output_serializer" => OutputSerializer,
        "reachability_unproven" => ReachabilityUnproven,
        "ipc_channel_reachable" => IpcChannelReachable,
        _ => return None,
    })
}

/// Persist one target's full result to `<work>/harnesses/<id>/result.json` the moment
/// its attempt finishes, so a `--resume` re-run (or one after a mid-sweep
/// interrupt) reloads it instead of re-attempting. Best-effort: a write failure
/// never aborts the run (resume is an optimization, not a correctness input).
pub fn persist_target_result(work_dir: &Path, result: &AttemptResult) {
    let dir = crate::auto::layout::harness_dir(work_dir, &result.candidate.harness_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let c = &result.candidate;
    let dto = PersistedResult {
        harness_id: c.harness_id.clone(),
        lang: lang_tag(c.lang).to_owned(),
        source_path: c.source_path.to_string_lossy().into_owned(),
        line: c.line,
        name: c.name.clone(),
        score: c.score,
        is_static: c.is_static,
        foreign_guard: c.foreign_guard.clone(),
        input_reachability: c.input_reachability.map(|r| reach_tag(r).to_owned()),
        outcome: result.outcome.clone(),
        attempt_trace: Some(result.attempt_trace()),
        harness_dir: result.harness_dir.to_string_lossy().into_owned(),
    };
    if let Ok(bytes) = serde_json::to_vec(&dto) {
        let _ = atomic_write(&dir.join("result.json"), &bytes);
    }
}

/// Replace a file through a same-directory, flushed temporary file. A kill/OOM
/// can leave an unreferenced `.tmp-*`, but never a half-written destination; the
/// next successful checkpoint removes its own temporary file via rename.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("checkpoint");
    // Remove only abandoned temporaries for this destination. Multiple govfuzz
    // processes can legitimately share a work directory, so never remove a
    // temporary owned by a process that is still alive.
    let stale_prefix = format!(".{leaf}.tmp-");
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let owner = file_name
                .strip_prefix(&stale_prefix)
                .and_then(|suffix| suffix.split_once('-'))
                .and_then(|(pid, _)| pid.parse::<u32>().ok());
            if owner.is_some_and(|pid| !checkpoint_writer_is_alive(pid)) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let temp = parent.join(format!(
        ".{leaf}.tmp-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(target_os = "linux")]
fn checkpoint_writer_is_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(not(target_os = "linux"))]
fn checkpoint_writer_is_alive(_pid: u32) -> bool {
    // Without a portable, race-free process-liveness query, preserve the file.
    // A failed write still removes its own temporary below.
    true
}

/// Whether a target already completed (has a well-formed persisted result), for
/// `--resume`'s skip decision. A missing/corrupt file means "not done" →
/// re-attempt.
pub fn target_already_complete(work_dir: &Path, harness_id: &str) -> bool {
    load_resumed_result(work_dir, harness_id).is_some()
}

/// Load a prior target's persisted result back into a real [`AttemptResult`], so
/// `--resume` re-integrates it fully into the new report. `None` if absent,
/// corrupt, or carrying an unrecognized language tag (treated as "re-attempt").
pub fn load_resumed_result(work_dir: &Path, harness_id: &str) -> Option<AttemptResult> {
    let p = [
        crate::auto::layout::harness_dir(work_dir, harness_id),
        crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id),
    ]
    .into_iter()
    .map(|dir| dir.join("result.json"))
    .find(|path| path.is_file())?;
    let text = std::fs::read_to_string(p).ok()?;
    let dto: PersistedResult = serde_json::from_str(&text).ok()?;
    Some(AttemptResult {
        candidate: Candidate {
            harness_id: dto.harness_id,
            lang: lang_from_tag(&dto.lang)?,
            source_path: PathBuf::from(dto.source_path),
            line: dto.line,
            name: dto.name,
            score: dto.score,
            is_static: dto.is_static,
            foreign_guard: dto.foreign_guard,
            input_reachability: dto.input_reachability.as_deref().and_then(reach_from_tag),
            dialect: None,
        },
        outcome: dto.outcome,
        harness_dir: PathBuf::from(dto.harness_dir),
    })
}

/// Collapse the per-target `"<kind> harness cannot initialize parameter '<p>' of
/// target '<t>' with type '<ty>': <rest>"` reason to `"<kind> harness cannot
/// initialize a parameter with type '<ty>': <rest>"`. The parameter name and
/// target name vary per row, but the underlying gap (this type has no
/// synthesizable constructor) is one issue — dropping them lets the
/// `(category, summary)` dedup fold every target sharing an unconstructible type
/// into a single `xN` row. The type is kept so genuinely different types stay
/// distinct, actionable rows.
fn collapse_uninitializable_param_reason(reason: &str) -> String {
    const MARKER: &str = " cannot initialize parameter '";
    if let Some(kind_end) = reason.find(MARKER) {
        if let Some(type_pos) = reason.find(" with type '") {
            if type_pos > kind_end {
                let kind = &reason[..kind_end]; // "<kind> harness"
                let tail = &reason[type_pos..]; // " with type '<ty>': <rest>"
                return format!("{kind} cannot initialize a parameter{tail}");
            }
        }
    }
    reason.to_owned()
}

#[allow(clippy::too_many_arguments)]
pub fn write_reports(
    source_root: &Path,
    results: &[AttemptResult],
    work_dir: &Path,
    started_at: &str,
    finished_at: &str,
    partial: bool,
    mode: actionability::RunMode,
    resumed: usize,
    discovered_total: usize,
    static_dynamic: bool,
    force: bool,
) -> Result<()> {
    let auto_dir = work_dir.join("auto");
    std::fs::create_dir_all(&auto_dir)?;

    // force-fuzz Phase 2: under `--force`, a target whose harness fuzzed only blind
    // stubs (`stub_only`) ran against synthesized bodies, so any crash is likely a
    // stub artifact. Collect those harness ids so their findings are floored to Low
    // with a stub-artifact note, and count them for the summary. Empty for a
    // non-force run — the non-force path is completely unchanged.
    let forced_harness_ids: std::collections::BTreeSet<String> = if force {
        results
            .iter()
            .filter_map(|r| match &r.outcome {
                Outcome::BuiltAndFuzzed { repairs, .. }
                    if stub_execution_summary(repairs).stub_only =>
                {
                    Some(r.candidate.harness_id.clone())
                }
                _ => None,
            })
            .collect()
    } else {
        std::collections::BTreeSet::new()
    };

    let attempted = results.len();
    // #6: `discovered_total` is the pre-cap ranked count threaded from the CLI;
    // clamp to the attempted count so a caller that passes 0 (the report tests,
    // an uncapped run) still reports `discovered_total == discovered`.
    let discovered_total = discovered_total.max(attempted);
    let mut summary = Summary {
        // `results` already includes `--resume`-reloaded targets (re-integrated
        // before the report), so they're counted in `discovered` and their outcome
        // buckets; `resumed` just surfaces how many were carried over, not re-run.
        discovered: attempted,
        discovered_total,
        dropped_by_cap: discovered_total - attempted,
        resumed,
        ..Summary::default()
    };
    let mut needed = NeededForBuild::default();
    let mut bag_headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_types: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_macros: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_declared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_blind: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_ada_stub_units: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_ada_stub_symbols: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_libs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_gpr_imports: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_env: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_endpoints: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_dlopen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_ada_units: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // #5: harness/codegen build errors, kept OUT of the missing-dependency
    // manifest so they are never framed to the user as an external dep to acquire.
    let mut bag_codegen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut failed_error_text = String::new();
    // Per-failed-target final diagnostics, so the missing-dep manifest can record
    // a still-blocking entry for EVERY unresolved build error — not just the
    // shared-lib / Ada subset the bags above capture. Without this a build that
    // dies on an unresolvable `#include` (a configure-generated header) or any
    // other non-lib error produces an opaque `failed_build` with an empty
    // manifest (#418).
    let mut failed_targets: Vec<(String, Vec<build_classifier::BuildErrorKind>)> = Vec::new();

    for r in results {
        let id = r.candidate.harness_id.clone();
        match &r.outcome {
            Outcome::Built { repairs, .. } => {
                summary.built += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
            }
            Outcome::BuiltAndFuzzed {
                repairs,
                passes,
                runtrace_events,
                ..
            } => {
                summary.built += 1;
                summary.built_and_fuzzed += 1;
                // #417: count the FALSE-CLEAN subset so a sweep that built+fuzzed
                // N targets doesn't read as N real fuzz campaigns when some only
                // exercised blind stubs.
                if stub_execution_summary(repairs).stub_only {
                    summary.fuzzed_stub_only += 1;
                    // force-fuzz Phase 2: a forced sweep's stub-only target is a
                    // forced-and-stub-heavy campaign — count it distinctly so N
                    // forced targets aren't read as N confirmed campaigns.
                    if forced_harness_ids.contains(&id) {
                        summary.forced += 1;
                    }
                }
                summary.findings += passes.iter().map(|p| p.findings.len()).sum::<usize>();
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                aggregate_runtrace(
                    runtrace_events,
                    &id,
                    &mut bag_env,
                    &mut bag_files,
                    &mut bag_endpoints,
                    &mut bag_dlopen,
                );
            }
            // #95: built + ran fuzz passes but the entry-instrumented harness
            // never observed target entry. It genuinely built (so it counts as
            // `built`), but it is NOT `built_and_fuzzed` and its passes' findings
            // do NOT count toward the headline (a crash without target entry is a
            // decode/stub artifact). Repairs + runtrace evidence are still
            // aggregated for the manifest.
            Outcome::BuiltNotEntered {
                repairs,
                runtrace_events,
                ..
            } => {
                summary.built += 1;
                summary.built_not_entered += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                aggregate_runtrace(
                    runtrace_events,
                    &id,
                    &mut bag_env,
                    &mut bag_files,
                    &mut bag_endpoints,
                    &mut bag_dlopen,
                );
            }
            Outcome::FailedBuild {
                repairs,
                last_errors,
                ..
            } => {
                summary.failed_build += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                // Accumulate the error text so a "stubbed" dep that the build still
                // fails on is reported as still-blocking, not "build continued".
                for e in last_errors {
                    failed_error_text.push_str(&format!("{e:?}\n"));
                }
                // Keep the full final diagnostic set for this target so the manifest
                // surfaces a still-blocking entry for every unresolved error (#418).
                failed_targets.push((id.clone(), last_errors.clone()));
                for e in last_errors {
                    // #5: a harness/codegen error is govfuzz's own (or a project
                    // build-config) problem, not a dependency — record it in its
                    // own bag and keep it out of the missing-dependency paths.
                    if build_classifier::is_codegen_error(e) {
                        bag_codegen
                            .entry(codegen_error_label(e))
                            .or_default()
                            .push(id.clone());
                        continue;
                    }
                    match e {
                        build_classifier::BuildErrorKind::MissingSharedLib { name } => {
                            bag_libs.entry(name.clone()).or_default().push(id.clone());
                        }
                        build_classifier::BuildErrorKind::MissingAdaWith { unit }
                        | build_classifier::BuildErrorKind::MissingAdaPackageBody { unit } => {
                            bag_ada_units
                                .entry(unit.clone())
                                .or_default()
                                .push(id.clone());
                        }
                        build_classifier::BuildErrorKind::MissingAdaSymbol { unit, symbol } => {
                            // GNAT occasionally emits the symbol with
                            // no enclosing unit (regex matched `Foo`
                            // but the unit context was on a prior
                            // line we didn't see). A bare `.Foo` row
                            // has no actionable target for the
                            // maintainer — drop it.
                            if unit.is_empty() {
                                continue;
                            }
                            let key = format!("{unit}.{symbol}");
                            bag_ada_units.entry(key).or_default().push(id.clone());
                        }
                        _ => {}
                    }
                }
            }
            Outcome::UnsupportedParams { .. } => {
                summary.unsupported_params += 1;
            }
            Outcome::UnrecoverableLink { missing, .. } => {
                summary.unrecoverable_link += 1;
                for m in missing {
                    if m.ends_with(".gpr") {
                        bag_gpr_imports
                            .entry(m.clone())
                            .or_default()
                            .push(id.clone());
                    } else {
                        bag_libs.entry(m.clone()).or_default().push(id.clone());
                    }
                }
            }
            Outcome::UnrecoverableRuntime {
                repairs,
                runtrace_events,
                ..
            } => {
                summary.unrecoverable_runtime += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                aggregate_runtrace(
                    runtrace_events,
                    &id,
                    &mut bag_env,
                    &mut bag_files,
                    &mut bag_endpoints,
                    &mut bag_dlopen,
                );
            }
            // M22: discovered + statically analyzed but not fuzzed. Counted
            // separately so a sweep that report-only'd N legacy targets does not
            // read as N failed builds or N silent drops. Its CWE-tagged static
            // findings count toward the headline findings total (campaign fix).
            Outcome::ReportOnly {
                static_findings, ..
            } => {
                summary.report_only += 1;
                summary.findings += static_findings;
            }
        }
    }
    // `--static`: whole-tree static findings are written straight to the findings
    // dir (not linked to any result), so fold their count in here alongside the
    // result-linked fuzz/report-only findings. Zero when `--static` wasn't used.
    summary.findings += tree_static_finding_ids(work_dir).len();
    // #484: how many of those static findings a fuzz/oracle hit confirmed (read
    // from disk so a `--resume` reload reports the same number the join set).
    summary.fuzz_confirmed = crate::auto::confirm::count_fuzz_confirmed(work_dir);

    needed.synthesized_headers = drain_bag(bag_headers);
    needed.synthesized_types = drain_bag(bag_types);
    needed.synthesized_macros = drain_bag(bag_macros);
    needed.stubbed_symbols_declared = drain_bag(bag_declared);
    needed.stubbed_symbols_blind = drain_bag(bag_blind);
    needed.stubbed_ada_units = drain_bag(bag_ada_stub_units);
    needed.stubbed_ada_symbols = drain_bag(bag_ada_stub_symbols);
    needed.missing_libraries = drain_bag(bag_libs);
    needed.missing_gpr_imports = drain_bag(bag_gpr_imports);
    needed.environment_variables_faked = drain_bag(bag_env);
    needed.missing_files = drain_bag(bag_files);
    needed.network_endpoints = drain_bag(bag_endpoints);
    needed.dlopen_failures = drain_bag(bag_dlopen);
    needed.missing_ada_units = drain_bag(bag_ada_units);
    needed.harness_codegen_errors = drain_bag(bag_codegen);

    let targets: Vec<TargetEntry> = results
        .iter()
        .map(|r| TargetEntry {
            harness_id: &r.candidate.harness_id,
            source: &r.candidate.source_path,
            name: &r.candidate.name,
            line: r.candidate.line,
            score: r.candidate.score,
            outcome: &r.outcome,
            attempt_trace: r.attempt_trace(),
            stub_execution: r.outcome.stub_execution(),
            input_reachability: r.candidate.input_reachability,
            platform_stub: r.outcome.platform_stub(),
        })
        .collect();

    let run_json = RunJson {
        schema_version: 1,
        started_at: started_at.to_owned(),
        finished_at: finished_at.to_owned(),
        partial,
        mode,
        source_root,
        summary,
        needed_for_build: needed,
        targets,
    };
    let json_path = auto_dir.join("run.json");
    std::fs::write(&json_path, serde_json::to_vec_pretty(&run_json)?)?;
    let md_path = auto_dir.join("run.md");
    std::fs::write(&md_path, render_md(&run_json))?;

    // Fuzz-assurance evidence ledger: an in-toto attestation of every finding's
    // tier (fuzz_confirmed / reachable / static / lab_only), self-anchored by a
    // sha256 of the evidence — an auditable, signable SLSA/CISA-workflow artifact.
    crate::auto::attestation::write_attestation(
        &auto_dir,
        work_dir,
        source_root,
        started_at,
        finished_at,
        mode.as_str(),
    );

    // govfuzz self-diagnostics: consolidate everything govfuzz could NOT fully
    // handle — internal panics caught during the sweep + codegen artifacts (its own
    // bugs) + per-target outcomes it couldn't fuzz (unsupported types, failed
    // builds, report-only) — into bug-report.{json,md}, deduplicated. Without
    // `--debug` a fully clean run writes nothing; with `--debug` a version-stamped
    // confirmation is always written. Distinct from missing-deps.txt (the user env).
    use crate::auto::bug_report::{InternalIssue, IssueCategory, IssueContext};
    fn strip_target_prefix(reason: &str) -> String {
        for pat in ["C++ target '", "C target '", "Ada target '", "target '"] {
            if let Some(rest) = reason.strip_prefix(pat) {
                if let Some((_, tail)) = rest.split_once("' ") {
                    return tail.trim().to_owned();
                }
            }
        }
        reason.to_owned()
    }
    fn build_error_summary(kind: &build_classifier::BuildErrorKind) -> String {
        use build_classifier::BuildErrorKind as E;
        match kind {
            E::MissingType { name } => format!("undefined type '{name}'"),
            E::IncompleteType { name } => format!("incomplete type '{name}'"),
            E::MissingHeader { path } => format!("missing header '{path}'"),
            E::MissingMacro { name, .. } => format!("undefined macro '{name}'"),
            E::UndefinedSymbol { name } => format!("undefined symbol '{name}'"),
            E::UndeclaredFunction { name, file, line } => {
                format!("undeclared function '{name}' at {file}:{line}")
            }
            E::MalformedFunctionDecl { file, line } => {
                format!("malformed declarator at {file}:{line}")
            }
            E::Other { tail } => first_error_line(tail),
            // Ada/library kinds (MissingSharedLib, MissingAdaWith, …): a Debug
            // rendering carries the name/unit, which is what the maintainer needs.
            other => format!("{other:?}"),
        }
    }
    let mut extra: Vec<InternalIssue> = Vec::new();
    for e in &run_json.needed_for_build.harness_codegen_errors {
        extra.push(InternalIssue {
            category: IssueCategory::CodegenDefect,
            summary: e.name.clone(),
            context: IssueContext {
                phase: "harness-codegen".to_owned(),
                target: (!e.referenced_by_targets.is_empty())
                    .then(|| e.referenced_by_targets.join(", ")),
                ..Default::default()
            },
            detail: None,
            backtrace: None,
            occurrences: e.referenced_by_targets.len().max(1),
        });
    }
    for r in results {
        let file = r
            .candidate
            .source_path
            .strip_prefix(source_root)
            .unwrap_or(&r.candidate.source_path)
            .display()
            .to_string();
        let context = |phase: &str| IssueContext {
            phase: phase.to_owned(),
            file: Some(file.clone()),
            target: Some(r.candidate.name.clone()),
            language: Some(format!("{:?}", r.candidate.lang)),
        };
        let entry = match &r.outcome {
            crate::auto::attempt::Outcome::UnsupportedParams { reason } => Some((
                IssueCategory::UnsupportedType,
                collapse_uninitializable_param_reason(&strip_target_prefix(reason)),
                context("harness-gen"),
            )),
            crate::auto::attempt::Outcome::FailedBuild { last_errors, .. } => Some((
                IssueCategory::FailedBuild,
                last_errors
                    .first()
                    .map(build_error_summary)
                    .unwrap_or_else(|| "build failed".to_owned()),
                context("build"),
            )),
            crate::auto::attempt::Outcome::ReportOnly { reason, .. } => Some((
                IssueCategory::ReportOnly,
                strip_target_prefix(reason),
                context("report-only"),
            )),
            crate::auto::attempt::Outcome::UnrecoverableLink { missing, .. } => Some((
                IssueCategory::FailedBuild,
                format!("unresolved link symbol(s): {}", missing.join(", ")),
                context("link"),
            )),
            crate::auto::attempt::Outcome::UnrecoverableRuntime { reason, .. } => Some((
                IssueCategory::FailedBuild,
                strip_target_prefix(reason),
                context("runtime"),
            )),
            // #95: built + ran but the target was never entered — a coverage gap,
            // surfaced distinctly so a maintainer can tell it apart from a build
            // failure or an unsupported type.
            crate::auto::attempt::Outcome::BuiltNotEntered { reason, .. } => Some((
                IssueCategory::TargetNotReached,
                strip_target_prefix(reason),
                context("fuzz-entry"),
            )),
            _ => None,
        };
        if let Some((category, summary, ctx)) = entry {
            extra.push(InternalIssue {
                category,
                summary,
                context: ctx,
                detail: None,
                backtrace: None,
                occurrences: 1,
            });
        }
    }
    let bug_count = crate::auto::bug_report::write(
        &auto_dir,
        finished_at,
        &extra,
        crate::auto::bug_report::debug_enabled(),
    );
    // Always point at the report under --debug (it's always written then, even
    // with zero issues), so the user sees WHERE it landed at the end of the run.
    if bug_count > 0 || crate::auto::bug_report::debug_enabled() {
        eprintln!(
            "govfuzz: bug report ({bug_count} issue(s) govfuzz couldn't fully handle) → {}",
            auto_dir.join("bug-report.md").display()
        );
    }

    // Always emit a machine-readable per-finding index alongside run.md/run.json.
    write_findings_csv(
        &auto_dir,
        work_dir,
        results,
        mode,
        static_dynamic,
        &forced_harness_ids,
    )?;

    // Consolidated missing-dependency manifest for the offline-transfer workflow:
    // every external dependency a target needed but the tree didn't provide, each
    // marked stubbed (build continued) or still-blocking, with an acquisition
    // hint. One trip instead of build-hit-copy-repeat.
    let mut manifest =
        build_dependency_manifest(&run_json.needed_for_build, source_root, &failed_error_text);
    // #418: guarantee no opaque `failed_build`. Fold every failed target's final
    // unresolved diagnostics into the manifest as still-blocking entries (with
    // remediation), and ensure each failed target contributes at least one entry.
    record_failed_build_blockers(&mut manifest, &failed_targets, source_root);
    // Targets that SKIPPED on an opaque IDL type never reached the build, so their
    // missing CORBA stub headers aren't in the ledger. Scan skipped targets'
    // sources for unresolved `*C.h`/`*S.h` includes and record the missing IDL —
    // turning a silent skip into "bring bank.idl".
    add_idl_deps_from_skipped_targets(&mut manifest, source_root, results);
    // Merge the early declaration/toolchain seed and every incrementally
    // checkpointed semantic requirement. The run-start checkpoint overwrites any
    // prior run, so this cannot resurrect stale entries from an older campaign.
    if let Some(checkpoint) = load_dependency_manifest(work_dir) {
        manifest.merge_from(&checkpoint);
    }
    add_semantic_requirements_from_results(&mut manifest, source_root, results);
    manifest.mark_checkpoint(results.len(), true);
    write_dependency_manifest_files(work_dir, &manifest)?;
    if !manifest.is_empty() {
        eprintln!(
            "govfuzz auto: {} external dependenc{} needed ({} still blocking, {} stubbed) — see {}",
            manifest.entries.len(),
            if manifest.entries.len() == 1 {
                "y"
            } else {
                "ies"
            },
            manifest.blocking_count(),
            manifest.stubbed_count(),
            auto_dir.join("missing-deps.txt").display(),
        );
    }
    Ok(())
}

/// Column header for `findings.csv`. ONE ROW PER ROOT-CAUSE ISSUE (findings are
/// grouped by `cluster_key_full`); see [`write_findings_csv`]. `count` is the
/// number of collapsed member findings and `member_finding_ids` lists them.
const FINDINGS_CSV_HEADER: &str = "id,count,harness_id,rule_id,message,exception_name,sanitizer,classification,confirmation,impact,confidence,verdict,cwe,source,data_flow,sink_file,sink_line,sink_function,entity,remediation,signature,member_finding_ids\n";

/// One parsed finding plus its backfilled actionability, ready to project into a
/// `findings.csv` row.
struct CsvFinding {
    id: String,
    /// Root-cause grouping key: `cluster_key_full` when present, else the id (so a
    /// fallback / unclustered finding stays its own issue).
    group_key: String,
    harness_id: String,
    /// The finding-rule id that fired (`GF-401` unsafe-copy, `GF-405` tainted-open,
    /// …). For a static finding this is the primary "what check flagged this" key —
    /// the analog of a fuzz finding's crash `signature`, which is blank here.
    rule_id: String,
    /// Human-readable one-line description of the defect ("Command execution with a
    /// non-literal argument"). Without it a static row carried only a CWE number,
    /// which doesn't say what the issue actually is.
    message: String,
    exception_name: String,
    sanitizer: String,
    classification: String,
    /// #484: provenance of the finding — `static` (scanner-only), `fuzz` (a
    /// runtime crash / oracle hit), or `fuzz_confirmed` (a static finding a fuzz
    /// input reached at the same site). The column that lets a reader trust a
    /// static row: `fuzz_confirmed` is not a maybe.
    confirmation: String,
    impact: actionability::Impact,
    confidence: actionability::ActionabilityConfidence,
    verdict: actionability::Verdict,
    cwe: Vec<String>,
    /// Taint SOURCE `file:line` when the finding carries a source→sink flow
    /// (interprocedural taint rules like GF-405/419); empty for a pattern rule
    /// (e.g. GF-401 unsafe-copy) that flags a call site without tracing an origin.
    source: String,
    /// #1: the full source→sink taint path, each step `path:line` joined by
    /// ` -> ` (Coverity-style). Empty for a pattern rule with no trace.
    data_flow: String,
    sink_file: String,
    sink_line: String,
    sink_function: String,
    /// #6: the tainted variable / sink expression this finding is about (the
    /// "entity" commercial SAST tables show). Empty when the rule resolved no
    /// sink expression or tainted parameter.
    entity: String,
    /// Actionable one-line fix for the rule (not a location) — see
    /// [`static_analysis::remediation_for`].
    remediation: String,
    signature: String,
    /// force-fuzz Phase 2: this finding belongs to a forced-and-stub-heavy target
    /// (`--force` + a stub-only build). Its `confidence` has been floored to `Low`
    /// and `note` carries the stub-artifact caveat. `false` for every non-forced
    /// finding (the default path).
    forced: bool,
    /// Provenance note surfaced in the report. Currently only the forced/stub
    /// caveat ([`confidence_model::FORCED_STUB_NOTE`]); empty otherwise.
    note: String,
}

/// Provenance strength for an issue row's `confirmation` column (higher wins):
/// a fuzz-confirmed static finding outranks a plain fuzz crash, which outranks a
/// scanner-only static hit.
fn confirmation_rank(confirmation: &str) -> u8 {
    match confirmation {
        // Dynamically confirmed: a static finding a fuzz/oracle hit reached
        // (#484), or an oracle hit that graduated a static candidate at runtime
        // (#422). Both mean "observed", not "flagged".
        "fuzz_confirmed" | "runtime" => 3,
        "fuzz" | "oracle" => 2,
        _ => 1, // "static" and anything unrecognized.
    }
}

/// Severity rank for picking an issue's representative + its max severity (lower
/// is more severe), mirroring `actionability`'s internal impact ordering.
fn csv_impact_rank(impact: actionability::Impact) -> u8 {
    match impact {
        actionability::Impact::Critical => 0,
        actionability::Impact::High => 1,
        actionability::Impact::Medium => 2,
        actionability::Impact::Low => 3,
        actionability::Impact::Info => 4,
        actionability::Impact::Unknown => 5,
    }
}

/// Always emit `<work>/auto/findings.csv` — a machine-readable, ROOT-CAUSE-grouped
/// issue index next to run.md / run.json. Findings are grouped by
/// `cluster_key_full` (one row per issue, not one per crashing input), so the auto
/// path matches the report crate's `render_csv_report` instead of inflating the
/// CSV with the cascade's per-pass duplicates. Each row projects the issue's
/// most-severe (representative) member, with `count` + `member_finding_ids`
/// preserving the collapsed set and `cwe` the union across members. (There is
/// deliberately no `source` column: it only ever named the synthetic govfuzz
/// harness entry — the sink columns carry the real defect location.) When the run
/// produced no findings the file is written header-only.
/// Finding ids from a `--static` whole-tree scan (`F-STATIC-*`). These are
/// written straight into the findings dir rather than linked to a per-target
/// result, so the report reads them from disk to fold them in alongside the
/// result-linked fuzz/report-only findings. Empty when `--static` wasn't used
/// (no such dirs exist).
pub(crate) fn tree_static_finding_ids(work_dir: &Path) -> Vec<String> {
    let dir = work_dir.join("findings");
    let mut ids: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| {
                // Disk-written findings not linked to a per-target result: the
                // `--static` whole-tree scan (`F-STATIC-*`), the MSan corpus replay
                // (`F-MSAN-*`), and fuzz-driven capability profiling (`F-CAP-*`).
                // All are folded into the report from disk.
                (name.starts_with("F-STATIC-")
                    || name.starts_with("F-MSAN-")
                    || name.starts_with("F-CAP-"))
                    && dir.join(name).join("finding.json").is_file()
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    ids.sort();
    ids
}

fn write_findings_csv(
    auto_dir: &Path,
    work_dir: &Path,
    results: &[AttemptResult],
    mode: actionability::RunMode,
    static_dynamic: bool,
    forced_harness_ids: &std::collections::BTreeSet<String>,
) -> Result<()> {
    let findings_root = work_dir.join("findings");
    // Both extra columns are appended at the END so existing column indices are
    // unchanged when the flags are off: `--static-dynamic` adds `scan_type`, and
    // `--force` adds a `forced` note column (present only when any target ran
    // forced-and-stub-heavy).
    let force = !forced_harness_ids.is_empty();
    let mut out = String::from(FINDINGS_CSV_HEADER.trim_end());
    if static_dynamic {
        out.push_str(",scan_type");
    }
    if force {
        out.push_str(",forced");
    }
    out.push('\n');

    // Collect unique finding ids in result order.
    let mut seen = std::collections::BTreeSet::new();
    let mut fids: Vec<String> = Vec::new();
    for result in results {
        // M22 (campaign fix): report-only static findings (F-RO-*) carry a CWE and
        // must appear in findings.csv like any other finding. Collect fuzz pass
        // findings AND the report-only finding ids.
        let result_fids: Vec<&String> = match &result.outcome {
            Outcome::BuiltAndFuzzed { passes, .. } => {
                passes.iter().flat_map(|p| &p.findings).collect()
            }
            Outcome::ReportOnly { finding_ids, .. } => finding_ids.iter().collect(),
            _ => Vec::new(),
        };
        for fid in result_fids {
            if seen.insert(fid.clone()) {
                fids.push(fid.clone());
            }
        }
    }
    // `--static` whole-tree findings aren't linked to a result — pull them from
    // disk so they render as rows too (deduped against the result-linked set).
    for fid in tree_static_finding_ids(work_dir) {
        if seen.insert(fid.clone()) {
            fids.push(fid);
        }
    }

    // Group by root-cause key, preserving first-seen order.
    let mut groups: Vec<Vec<CsvFinding>> = Vec::new();
    let mut index_by_key: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for fid in &fids {
        let finding_path = findings_root.join(fid).join("finding.json");
        let Some(finding) = load_csv_finding(&finding_path, fid, mode, forced_harness_ids) else {
            continue;
        };
        match index_by_key.get(&finding.group_key) {
            Some(&idx) => groups[idx].push(finding),
            None => {
                index_by_key.insert(finding.group_key.clone(), groups.len());
                groups.push(vec![finding]);
            }
        }
    }

    for group in &groups {
        out.push_str(&render_issue_row(group, static_dynamic, force));
    }
    std::fs::write(auto_dir.join("findings.csv"), out)?;
    Ok(())
}

/// Load + backfill one finding into a [`CsvFinding`]. Returns `None` when the file
/// is missing or unparseable (the finding is still counted in the run summary; a
/// malformed sidecar must not abort the whole report).
fn load_csv_finding(
    path: &Path,
    fid: &str,
    mode: actionability::RunMode,
    forced_harness_ids: &std::collections::BTreeSet<String>,
) -> Option<CsvFinding> {
    let raw: serde_json::Value = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())?;
    // Reuse / backfill so source / sink / verdict / fix_location are populated
    // even for findings whose on-disk actionability predates those fields.
    let action = actionability::existing_actionability_or_backfill(mode, &raw, Some(path));

    let id = raw
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(fid)
        .to_owned();
    let group_key = raw
        .get("cluster_key_full")
        .and_then(serde_json::Value::as_str)
        .filter(|key| !key.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| id.clone());
    let (sink_file, sink_line, sink_function) = match &action.sink {
        Some(sink) => (
            sink.file.clone().unwrap_or_default(),
            sink.line.map(|line| line.to_string()).unwrap_or_default(),
            sink.function.clone(),
        ),
        None => (String::new(), String::new(), String::new()),
    };
    // #1: the taint SOURCE `file:line`, when the finding recorded a source→sink
    // flow. Interprocedural taint rules carry `exception.source_file`/`source_line`;
    // a pure pattern rule (GF-401 unsafe-copy) has none, so this stays empty rather
    // than duplicating the sink.
    let source = {
        let file = json_str(&raw, &["exception", "source_file"]);
        let line = json_str(&raw, &["exception", "source_line"]);
        match (file.is_empty(), line.is_empty()) {
            (false, false) => format!("{file}:{line}"),
            (false, true) => file,
            _ => String::new(),
        }
    };

    let classification = json_str(&raw, &["classification"]);
    let is_static = classification == "static_scan";
    // #484: provenance. An explicit `confirmation` (set by the join, or "static"
    // on a static finding) wins; a finding without one is a runtime hit, so
    // default it to "fuzz".
    let confirmation = match json_str(&raw, &["confirmation"]).as_str() {
        "" if is_static => "static".to_owned(),
        "" => "fuzz".to_owned(),
        other => other.to_owned(),
    };
    // A static finding has no harness — its `harness_id` is the sentinel
    // "static-scan", which merely duplicates the `classification` column. Blank it
    // so the column carries a real harness id only when one exists (fuzz findings).
    let harness_id = if is_static {
        String::new()
    } else {
        json_str(&raw, &["harness_id"])
    };
    // Prefer the confidence the finding was EMITTED with (persisted in its
    // `actionability` record) over the report-time backfill, which recomputes a
    // generic value and flattens an emit-time `high` (e.g. an unsafe-copy sink) to
    // `medium`. Fall back to the backfilled value for records that predate it.
    let confidence = json_str(&raw, &["actionability", "confidence"]);
    let mut confidence = actionability::ActionabilityConfidence::from_label(&confidence)
        .unwrap_or(action.confidence);

    // force-fuzz Phase 2: a finding whose target ran forced-and-stub-heavy is
    // low-confidence by construction — the forced build fuzzed synthesized stubs,
    // so a crash may be a stub artifact. Floor its confidence to `Low` (the label
    // floor, matching `confidence_model::forced_floor`) and attach the caveat note.
    // Keyed off the finding's real (raw) harness id so the static-scan blanking of
    // `harness_id` below doesn't hide the match.
    let raw_harness_id = json_str(&raw, &["harness_id"]);
    let forced = forced_harness_ids.contains(&raw_harness_id);
    if forced {
        confidence = actionability::ActionabilityConfidence::Low;
    }
    let note = if forced {
        confidence_model::FORCED_STUB_NOTE.to_owned()
    } else {
        String::new()
    };

    Some(CsvFinding {
        id,
        group_key,
        harness_id,
        rule_id: json_str(&raw, &["rule_id"]),
        message: json_str(&raw, &["exception", "message"]),
        exception_name: json_str(&raw, &["exception", "name"]),
        sanitizer: json_str(&raw, &["exception", "sanitizer"]),
        classification,
        confirmation,
        impact: action.impact,
        confidence,
        verdict: action.verdict,
        // #8: bare CWE numbers — strip the `CWE-` prefix so the column is `120`,
        // not `CWE-120`.
        cwe: action
            .cwe
            .iter()
            .map(|id| id.strip_prefix("CWE-").unwrap_or(id).to_owned())
            .collect(),
        source,
        data_flow: json_str(&raw, &["data_flow"]),
        sink_file,
        sink_line,
        sink_function,
        entity: json_str(&raw, &["entity"]),
        remediation: static_analysis::remediation_for(&json_str(&raw, &["rule_id"])).to_owned(),
        signature: json_str(&raw, &["signature"]),
        forced,
        note,
    })
}

/// Render one `findings.csv` row for a root-cause group: the most-severe member is
/// the representative whose columns are projected; `count` + `member_finding_ids`
/// preserve the collapsed set; `cwe` is the union across members (representative
/// first). `group` is non-empty by construction.
fn render_issue_row(group: &[CsvFinding], static_dynamic: bool, force: bool) -> String {
    let representative = group
        .iter()
        .min_by_key(|f| csv_impact_rank(f.impact))
        .unwrap_or(&group[0]);
    // Union the CWEs (representative first, then any genuinely different member CWE).
    let mut cwe: Vec<String> = Vec::new();
    for member in std::iter::once(representative).chain(group.iter()) {
        for id in &member.cwe {
            if !cwe.contains(id) {
                cwe.push(id.clone());
            }
        }
    }
    // #4: `id` is the representative; `member_finding_ids` lists the collapsed set.
    // They differ only when a group collapsed >1 finding — leave the column blank
    // for a singleton so it doesn't just echo `id`.
    let member_ids = if group.len() > 1 {
        group
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>()
            .join(";")
    } else {
        String::new()
    };
    // Confirmation is orthogonal to severity, so a group's row shows its STRONGEST
    // provenance (fuzz_confirmed > fuzz > static), not just the representative's.
    let confirmation = group
        .iter()
        .map(|f| f.confirmation.as_str())
        .max_by_key(|c| confirmation_rank(c))
        .unwrap_or("static")
        .to_owned();

    // force-fuzz Phase 2: a group is forced when ANY member ran forced-and-stub-heavy
    // (findings share a root-cause key; a forced member pins the whole issue Low with
    // the stub-artifact note).
    let group_forced = group.iter().any(|f| f.forced);
    let confidence = if group_forced {
        actionability::ActionabilityConfidence::Low
    } else {
        representative.confidence
    };
    let forced_note = group
        .iter()
        .find(|f| f.forced)
        .map(|f| f.note.clone())
        .unwrap_or_default();

    let fields = [
        representative.id.clone(),
        group.len().to_string(),
        representative.harness_id.clone(),
        representative.rule_id.clone(),
        representative.message.clone(),
        representative.exception_name.clone(),
        representative.sanitizer.clone(),
        representative.classification.clone(),
        confirmation,
        representative.impact.as_str().to_owned(),
        confidence.as_str().to_owned(),
        representative.verdict.as_str().to_owned(),
        cwe.join(";"),
        representative.source.clone(),
        representative.data_flow.clone(),
        representative.sink_file.clone(),
        representative.sink_line.clone(),
        representative.sink_function.clone(),
        representative.entity.clone(),
        representative.remediation.clone(),
        representative.signature.clone(),
        member_ids,
    ];
    let mut row = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            row.push(',');
        }
        row.push_str(&csv_field(field));
    }
    if static_dynamic {
        // scan_type: `static-dynamic` when ANY member of the root-cause group is a
        // static-scan finding (govfuzz's static + fuzz-confirmation pipeline — this
        // covers a static finding a fuzz input confirmed, where the crash is the
        // cluster representative), else `dynamic` for a purely fuzzed result.
        let scan_type = if group.iter().any(|f| f.classification == "static_scan") {
            "static-dynamic"
        } else {
            "dynamic"
        };
        row.push(',');
        row.push_str(scan_type);
    }
    if force {
        // force-fuzz Phase 2: `forced` column carries the stub-artifact caveat note
        // for a forced-and-stub-heavy issue (empty for a genuinely-built one).
        row.push(',');
        row.push_str(&csv_field(&forced_note));
    }
    row.push('\n');
    row
}

/// Read a nested string field, returning an empty string when absent / non-string.
fn json_str(value: &serde_json::Value, path: &[&str]) -> String {
    let mut current = value;
    for component in path {
        match current.get(*component) {
            Some(next) => current = next,
            None => return String::new(),
        }
    }
    current.as_str().unwrap_or_default().to_owned()
}

/// RFC-4180 CSV field escaping: quote when the value contains a comma, quote,
/// CR, or LF, doubling any embedded quotes.
fn csv_field(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

/// Fold the per-category `NeededForBuild` ledger into the one flat dependency
/// manifest, tagging each entry's kind and whether govfuzz stubbed it (build
/// continued) or it is still blocking (the user must supply the real thing).
fn build_dependency_manifest(
    needed: &NeededForBuild,
    source_root: &Path,
    failed_error_text: &str,
) -> crate::auto::dep_manifest::DependencyManifest {
    use crate::auto::dep_manifest::{DepKind, DependencyManifest};
    let mut m = DependencyManifest::new();
    // A dependency we "stubbed" is only honestly "build continued" if the build
    // didn't keep failing on it. When a stubbed type/symbol name still appears in
    // a FailedBuild target's errors, the stub did NOT unblock it — report it as
    // STILL BLOCKING, not stubbed (ctre `utf8_iterator`).
    let still_blocks = |name: &str| !name.is_empty() && failed_error_text.contains(name);
    let add = |kind: DepKind, items: &[Aggregated], stubbed: bool, m: &mut DependencyManifest| {
        for a in items {
            let stubbed = stubbed && !still_blocks(&a.name);
            m.push(
                kind,
                a.name.clone(),
                a.referenced_by_targets.clone(),
                stubbed,
            );
        }
    };
    // Still-blocking first (insertion order is preserved; render sorts blocking
    // ahead anyway, but this keeps the JSON readable too).
    add(
        DepKind::SharedLibrary,
        &needed.missing_libraries,
        false,
        &mut m,
    );
    add(
        DepKind::GprImport,
        &needed.missing_gpr_imports,
        false,
        &mut m,
    );
    add(DepKind::AdaUnit, &needed.missing_ada_units, false, &mut m);
    // A missing filesystem path is classified more precisely so the user knows
    // what to recreate: a dangling symlink, a path on a network mount (NFS/SMB),
    // or a plain file/dir.
    for a in &needed.missing_files {
        // An llvm-debuginfod client cache file (`~/.cache/llvm-debuginfod/...`) is
        // a transient lookup artifact, not a real build input — the build/fuzz
        // completes without it. Mark it non-blocking (stubbed) so the manifest
        // doesn't mislabel it "still blocking".
        m.push(
            classify_missing_path(&a.name),
            a.name.clone(),
            a.referenced_by_targets.clone(),
            is_debuginfod_cache(&a.name),
        );
    }
    // Build-time env vars the project's GPR requires via `external("VAR")` with
    // no default (gprbuild errors without them) — recorded so they travel with
    // the rest of the missing-dependency set.
    for var in required_gpr_externals(source_root) {
        m.push(
            DepKind::EnvVar,
            var,
            vec!["build (project.gpr external)".to_owned()],
            false,
        );
    }
    // Stubbed (build continued against a fake).
    // A stubbed header that matches the CORBA/IDL generated-stub naming
    // (`bankC.h`/`bankS.h`) is reported as the missing IDL interface (`bank.idl`)
    // — what the user actually needs to bring/regenerate — not a generic header.
    for a in &needed.synthesized_headers {
        let stubbed = !still_blocks(&a.name);
        match crate::auto::dep_manifest::corba_generated_idl(&a.name) {
            Some(idl) => m.push_merge(
                DepKind::IdlInterface,
                idl,
                a.referenced_by_targets.clone(),
                stubbed,
            ),
            // A header govfuzz stubbed: if a `.in`/`.dist`/`.cmake` template sits
            // beside it in the tree it's configure-generated, so name that template
            // and the configure step instead of a dead-end apt-file hint. When no
            // template is found, push_merge_with_hint falls back to the per-kind
            // default (which still special-cases generated-header *names*).
            None => {
                let hint = configure_template_hint(source_root, &a.name);
                let kind = if hint.is_some()
                    || crate::auto::dep_manifest::is_configure_generated_header(&a.name)
                {
                    DepKind::GeneratedSource
                } else {
                    DepKind::Header
                };
                m.push_merge_with_hint(
                    kind,
                    a.name.clone(),
                    a.referenced_by_targets.clone(),
                    stubbed,
                    hint,
                );
            }
        }
    }
    // ConfigTypeAlias entries are generated-source requirements and are added
    // from the structured Repair ledger below. Do not also mislabel the
    // human-formatted width assumption as an ordinary missing C type.
    let ordinary_types: Vec<Aggregated> = needed
        .synthesized_types
        .iter()
        .filter(|entry| !entry.name.contains("(synthesised config default"))
        .map(|entry| Aggregated {
            name: entry.name.clone(),
            referenced_by_targets: entry.referenced_by_targets.clone(),
        })
        .collect();
    add(DepKind::CType, &ordinary_types, true, &mut m);
    add(DepKind::Macro, &needed.synthesized_macros, true, &mut m);
    add(
        DepKind::Symbol,
        &needed.stubbed_symbols_declared,
        true,
        &mut m,
    );
    add(DepKind::Symbol, &needed.stubbed_symbols_blind, true, &mut m);
    add(DepKind::AdaUnit, &needed.stubbed_ada_units, true, &mut m);
    add(
        DepKind::EnvVar,
        &needed.environment_variables_faked,
        true,
        &mut m,
    );
    add(
        DepKind::NetworkEndpoint,
        &needed.network_endpoints,
        true,
        &mut m,
    );
    add(
        DepKind::DlopenLibrary,
        &needed.dlopen_failures,
        true,
        &mut m,
    );
    m
}

/// Fold every failed target's FINAL unresolved diagnostics into the manifest as
/// still-blocking entries, and guarantee each failed target contributes at least
/// one actionable entry (#418). The per-category `needed_for_build` bags only
/// capture stubbed repairs plus the shared-lib / GPR / Ada subset of unresolved
/// errors, so a build that dies on an unresolvable `#include` (a configure-
/// generated header like c-ares' `ares_build.h`), an undefined type/symbol, or
/// any `Other` diagnostic would otherwise leave an opaque `failed_build` behind
/// an empty manifest. This makes the manifest the single honest record of WHY a
/// target could not be built.
fn record_failed_build_blockers(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    failed_targets: &[(String, Vec<build_classifier::BuildErrorKind>)],
    source_root: &Path,
) {
    use crate::auto::dep_manifest::DepKind;
    use build_classifier::BuildErrorKind as E;
    for (id, errors) in failed_targets {
        // #5: a target whose only unresolved errors are harness/codegen errors
        // is explained by the `harness_codegen_errors` ledger — it must NOT get a
        // generic "build failed → acquire dependency" manifest blocker.
        let mut had_codegen = false;
        for err in errors {
            if build_classifier::is_codegen_error(err) {
                had_codegen = true;
                continue;
            }
            match err {
                E::MissingHeader { path } => {
                    // A configure/cmake-generated header has no distro package; if a
                    // `.in`/`.dist`/`.cmake` template sits in the tree, name it and
                    // point at the configure step. Otherwise the default per-kind
                    // hint (which already special-cases generated-header names)
                    // applies.
                    let hint = configure_template_hint(source_root, path);
                    let kind = if hint.is_some()
                        || crate::auto::dep_manifest::is_configure_generated_header(path)
                    {
                        DepKind::GeneratedSource
                    } else {
                        DepKind::Header
                    };
                    manifest.push_merge_with_hint(
                        kind,
                        path.clone(),
                        vec![id.clone()],
                        false,
                        hint,
                    );
                }
                E::MissingType { name } => manifest.push_merge_with_hint(
                    DepKind::CType,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is undefined in the scanned tree — supply the header/source that \
                         declares it (often a configure-generated or out-of-tree definition)"
                    )),
                ),
                E::IncompleteType { name } => manifest.push_merge_with_hint(
                    DepKind::CType,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is forward-declared but never defined in the scanned tree (a pimpl / \
                         private implementation) — supply the source that defines it"
                    )),
                ),
                E::MissingMacro { name, .. } => manifest.push_merge_with_hint(
                    DepKind::Macro,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is injected by the project's build config (generated config.h / \
                         -D flags) — supply its real definition"
                    )),
                ),
                E::UndefinedSymbol { name } => manifest.push_merge_with_hint(
                    DepKind::Symbol,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is undefined — link the library/object that defines it, or supply \
                         its source"
                    )),
                ),
                E::UndeclaredFunction { name, file, line } => manifest.push_merge_with_hint(
                    DepKind::Symbol,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' has no declaration visible at {file}:{line} — restore the damaged \
                         header macro/declaration or supply the header that declares it"
                    )),
                ),
                E::MalformedFunctionDecl { file, line } => manifest.push_merge_with_hint(
                    DepKind::Other,
                    format!("{file}:{line} (body-less function declarator from a macro/codegen expansion)"),
                    vec![id.clone()],
                    false,
                    Some(
                        "supply the project's real macro/IDL-codegen definitions for this line, or \
                         run the codegen step (--probe-build)"
                            .to_owned(),
                    ),
                ),
                E::Other { tail } => manifest.push_merge_with_hint(
                    DepKind::Other,
                    first_error_line(tail),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "unrecognised build error for target {id} — see auto/run.json (this \
                         target's outcome.last_errors) for the full diagnostic"
                    )),
                ),
                // Shared libs / GPR imports / Ada units are already folded into the
                // manifest from the `needed_for_build` bags (and already reference
                // this target), so skip them here to avoid a second, hint-poorer
                // entry.
                E::MissingSharedLib { .. }
                | E::MissingGprImport { .. }
                | E::MissingAdaWith { .. }
                | E::MissingAdaPackageBody { .. }
                | E::MissingAdaSymbol { .. }
                | E::UncompilableAdaBody { .. } => {}
            }
        }
        // AC2 safety net: every failed target MUST leave at least one actionable
        // record. If it still has no manifest entry — all errors were folded
        // elsewhere and none referenced this target (e.g. a bare empty-unit
        // Ada-symbol row the bag dropped, or an error-less classification) —
        // record a generic blocker so the failure is never silent. A target whose
        // only errors were harness/codegen ones is already recorded in the
        // `harness_codegen_errors` ledger, so it is not framed as a dependency.
        if manifest_reference_count(manifest, id) == 0 && !had_codegen {
            manifest.push_merge_with_hint(
                DepKind::Other,
                format!("build failed for target {id}"),
                vec![id.clone()],
                false,
                Some(
                    "see auto/run.json (this target's outcome.last_errors) for the compiler \
                     diagnostic"
                        .to_owned(),
                ),
            );
        }
    }
}

/// Number of manifest entries that list `id` among their referencing targets.
/// Used to detect whether a failed target contributed any actionable entry.
fn manifest_reference_count(
    manifest: &crate::auto::dep_manifest::DependencyManifest,
    id: &str,
) -> usize {
    manifest
        .entries
        .iter()
        .filter(|e| e.referenced_by.iter().any(|r| r == id))
        .count()
}

/// A stable display label for a harness/codegen build error (#5), used as the
/// `harness_codegen_errors` bag key. A recovery-artifact `MissingType` names the
/// artifact; an `Other` tail is summarised to its first error line.
fn codegen_error_label(err: &build_classifier::BuildErrorKind) -> String {
    use build_classifier::BuildErrorKind as E;
    match err {
        E::MissingType { name } => {
            format!("codegen: unresolved '{name}' (parser recovery artifact)")
        }
        E::Other { tail } => first_error_line(tail),
        // is_codegen_error only flags the two shapes above; anything else is a
        // defensive fallback that should not occur.
        other => format!("{other:?}"),
    }
}

/// The first non-empty, trimmed line of a multi-line `Other` diagnostic tail,
/// capped so a runaway line can't bloat the manifest. Falls back to a stable
/// label when the tail is empty.
fn first_error_line(tail: &str) -> String {
    let line = tail
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("unclassified build error");
    if line.len() > 200 {
        // Truncate on a UTF-8 char boundary: compiler diagnostics are not ASCII
        // (GCC/G++ quote identifiers with U+2018/U+2019), so a fixed `[..200]`
        // can split a multi-byte char and panic.
        let mut end = 200;
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &line[..end])
    } else {
        line.to_owned()
    }
}

/// When a missing configure/cmake-generated header has a generation template in
/// the tree (`<name>.in`, `<name>.dist`, `<name>.cmake`, `<name>.cmake.in`),
/// return a remediation naming that template and the configure step. `None` when
/// no template is found — the caller then falls back to the per-kind default
/// hint (which still special-cases generated-header *names*).
fn configure_template_hint(source_root: &Path, header: &str) -> Option<String> {
    let leaf = header.rsplit(['/', '\\']).next().unwrap_or(header);
    let template = find_generation_template(source_root, leaf)?;
    Some(format!(
        "configure-generated: run the project's configure step (`./configure` / `cmake` / \
         `autoreconf -i && ./configure`) to produce '{leaf}' from '{}', then re-run govfuzz with \
         --probe-build / --consent-build; or copy the generated '{leaf}' into the tree",
        template.display()
    ))
}

/// Bounded walk for a generation template named after `leaf` (`<leaf>.in`,
/// `<leaf>.dist`, `<leaf>.cmake`, `<leaf>.cmake.in`). Returns the first match
/// relative to `root` when possible.
fn find_generation_template(root: &Path, leaf: &str) -> Option<std::path::PathBuf> {
    let candidates = [
        format!("{leaf}.in"),
        format!("{leaf}.dist"),
        format!("{leaf}.cmake"),
        format!("{leaf}.cmake.in"),
    ];
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 200_000 {
                return None;
            }
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if candidates.iter().any(|c| c == name) {
                    return Some(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
                }
            }
        }
    }
    None
}

/// Record missing IDL interfaces for targets that were SKIPPED (e.g. an opaque
/// CORBA type parameter the harness can't construct) — these never reached the
/// build, so their unresolved generated-stub includes (`bankC.h`) aren't in the
/// ledger. Scan each skipped target's source for `#include`s of CORBA-generated
/// headers whose file is absent from the tree, and record the source `.idl` as a
/// still-blocking dependency. A header that IS present (a constructibility issue,
/// not a missing IDL) is not flagged.
fn add_idl_deps_from_skipped_targets(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    results: &[AttemptResult],
) {
    use crate::auto::dep_manifest::{corba_generated_idl, DepKind};
    let present = header_basenames_present(source_root);
    let mut ordered: Vec<&AttemptResult> = results.iter().collect();
    ordered.sort_by(|a, b| a.candidate.harness_id.cmp(&b.candidate.harness_id));
    for r in ordered {
        if !matches!(r.outcome, Outcome::UnsupportedParams { .. }) {
            continue;
        }
        let Ok(text) = crate::source_text::read_source_text(&r.candidate.source_path) else {
            continue;
        };
        for include in scan_include_targets(&text) {
            let leaf = include.rsplit(['/', '\\']).next().unwrap_or(&include);
            if present.contains(leaf) {
                continue; // header is in the tree — not a missing-IDL case
            }
            if let Some(idl) = corba_generated_idl(leaf) {
                manifest.push_merge(
                    DepKind::IdlInterface,
                    idl,
                    vec![r.candidate.harness_id.clone()],
                    false,
                );
            }
        }
    }
}

/// Atomically persist an in-progress dependency manifest after completed target
/// attempts. `seed` is the pre-target declaration/toolchain scan. Rebuilding the
/// small manifest from completed results makes the checkpoint deterministic and
/// avoids keeping mutable dependency state in worker threads.
pub fn write_dependency_checkpoint(
    source_root: &Path,
    work_dir: &Path,
    seed: &crate::auto::dep_manifest::DependencyManifest,
    results: &[AttemptResult],
) -> Result<crate::auto::dep_manifest::DependencyManifest> {
    let mut manifest = seed.clone();
    manifest.complete = false;
    let mut ordered: Vec<&AttemptResult> = results.iter().collect();
    ordered.sort_by(|a, b| a.candidate.harness_id.cmp(&b.candidate.harness_id));
    for result in ordered {
        add_checkpoint_result(&mut manifest, source_root, result);
    }
    add_idl_deps_from_skipped_targets(&mut manifest, source_root, results);
    manifest.mark_checkpoint(results.len(), false);
    write_dependency_manifest_files(work_dir, &manifest)?;
    Ok(manifest)
}

/// Extend an existing durable checkpoint with one newly completed target. This
/// is the hot sweep path: it avoids rescanning every prior result after each
/// target while preserving the same merge semantics as a reconstructed resume
/// checkpoint.
pub fn checkpoint_dependency_result(
    source_root: &Path,
    work_dir: &Path,
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    result: &AttemptResult,
) -> Result<()> {
    add_checkpoint_result(manifest, source_root, result);
    add_idl_deps_from_skipped_targets(manifest, source_root, std::slice::from_ref(result));
    manifest.mark_checkpoint(manifest.completed_targets.saturating_add(1), false);
    write_dependency_manifest_files(work_dir, manifest)
}

/// Write both human and machine manifests through atomic replacement. The human
/// handoff list is committed first because that is the file printed to the
/// operator; if the process dies between renames, both files remain valid and
/// the text list is the newest checkpoint.
fn write_dependency_manifest_files(
    work_dir: &Path,
    manifest: &crate::auto::dep_manifest::DependencyManifest,
) -> Result<()> {
    let auto_dir = work_dir.join("auto");
    std::fs::create_dir_all(&auto_dir)?;
    atomic_write(
        &auto_dir.join("missing-deps.txt"),
        manifest.render_text().as_bytes(),
    )?;
    atomic_write(
        &auto_dir.join("missing-deps.json"),
        manifest.to_json().as_bytes(),
    )?;
    Ok(())
}

pub fn load_dependency_manifest(
    work_dir: &Path,
) -> Option<crate::auto::dep_manifest::DependencyManifest> {
    std::fs::read_to_string(work_dir.join("auto/missing-deps.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

/// One stable terminal/summary line. Always names the human file, even when a
/// filesystem error made the JSON count unavailable.
pub fn dependency_manifest_pointer(work_dir: &Path) -> String {
    let path = work_dir.join("auto/missing-deps.txt");
    match load_dependency_manifest(work_dir) {
        Some(manifest) => format!(
            "{} ({} blocking, {} substituted; {} target checkpoint{})",
            path.display(),
            manifest.blocking_count(),
            manifest.stubbed_count(),
            manifest.completed_targets,
            if manifest.complete {
                ", final"
            } else {
                ", in progress"
            }
        ),
        None => format!("{} (manifest unavailable)", path.display()),
    }
}

fn add_checkpoint_result(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    result: &AttemptResult,
) {
    use crate::auto::dep_manifest::{DepKind, RequirementBasis};
    use crate::auto::repair::Repair;
    let id = result.candidate.harness_id.clone();
    let repairs: &[Repair] = match &result.outcome {
        Outcome::BuiltAndFuzzed { repairs, .. }
        | Outcome::BuiltNotEntered { repairs, .. }
        | Outcome::Built { repairs, .. }
        | Outcome::FailedBuild { repairs, .. }
        | Outcome::UnrecoverableLink { repairs, .. }
        | Outcome::UnrecoverableRuntime { repairs, .. } => repairs,
        Outcome::UnsupportedParams { .. } | Outcome::ReportOnly { .. } => &[],
    };
    for repair in repairs {
        match repair {
            Repair::HeaderPlaceholder { virtual_path } => {
                add_missing_header_requirement(manifest, source_root, virtual_path, &id, true)
            }
            Repair::ConfigHeaderSynth { virtual_path } => manifest.push_merge_detailed(
                DepKind::GeneratedSource,
                virtual_path.clone(),
                vec![id.clone()],
                true,
                configure_template_hint(source_root, virtual_path),
                RequirementBasis::Observed,
                Some("GovFuzz synthesized a minimal configuration header".to_owned()),
            ),
            Repair::TypePlaceholder { type_name } => {
                if !build_classifier::is_recovery_artifact(type_name)
                    && !crate::auto::repair::is_synthesized_type_report_noise(type_name)
                {
                    manifest.push_merge(
                        DepKind::CType,
                        type_name.clone(),
                        vec![id.clone()],
                        true,
                    );
                }
            }
            Repair::TypeAlias { type_name, .. } => manifest.push_merge(
                DepKind::CType,
                type_name.clone(),
                vec![id.clone()],
                true,
            ),
            Repair::ConfigTypeAlias {
                type_name,
                underlying,
                header_path,
            } => {
                let name = header_path
                    .clone()
                    .unwrap_or_else(|| format!("generated definition for {type_name}"));
                manifest.push_merge_detailed(
                    DepKind::GeneratedSource,
                    name,
                    vec![id.clone()],
                    true,
                    Some(format!(
                        "supply the project's generated definition for '{type_name}' instead of GovFuzz's assumed '{underlying}' default"
                    )),
                    RequirementBasis::Inferred,
                    Some(format!(
                        "GovFuzz substituted default type '{underlying}' for '{type_name}'"
                    )),
                );
            }
            Repair::MacroDefine { name, .. } => manifest.push_merge(
                DepKind::Macro,
                name.clone(),
                vec![id.clone()],
                true,
            ),
            Repair::IncludeStdHeader { symbol, header } => manifest.push_merge(
                DepKind::Macro,
                format!("{symbol} -> <{header}>"),
                vec![id.clone()],
                true,
            ),
            Repair::StubDeclared { symbol, .. } | Repair::StubBlind { symbol } => manifest
                .push_merge(
                    DepKind::Symbol,
                    symbol.clone(),
                    vec![id.clone()],
                    true,
                ),
            Repair::AdaPackageStub { unit, .. } | Repair::AdaPackageBodyStub { unit, .. } => {
                manifest.push_merge(
                    DepKind::AdaUnit,
                    unit.clone(),
                    vec![id.clone()],
                    true,
                )
            }
            Repair::OverrideAdaBodyStub { source, unit, .. } => manifest.push_merge_detailed(
                DepKind::Runtime,
                format!("target-compatible Ada runtime/body for {unit}"),
                vec![id.clone()],
                true,
                Some(format!(
                    "stage the GNAT runtime/toolchain matching '{}' or supply a host-compatible implementation of {}",
                    source.display(),
                    source.display()
                )),
                RequirementBasis::Observed,
                Some(format!(
                    "the host assembler/compiler rejected '{}'; GovFuzz neutralized that body",
                    source.display()
                )),
            ),
            Repair::PlatformStub { platform } => manifest.push_merge_detailed(
                DepKind::Runtime,
                format!("{platform} SDK/runtime"),
                vec![id.clone()],
                true,
                Some(format!(
                    "stage the compatible {platform} SDK/runtime and a runnable target environment to exercise real platform behavior"
                )),
                RequirementBasis::Observed,
                Some("the target built with GovFuzz's platform stub".to_owned()),
            ),
            Repair::HeaderForward { .. }
            | Repair::AddIncludeDir { .. }
            | Repair::IncludeTypeHeader { .. }
            | Repair::DeclareFunction { .. }
            | Repair::AddSource { .. }
            | Repair::EnvVarInjection { .. }
            | Repair::AddAdaSource { .. }
            | Repair::Win32Pack => {}
        }
    }

    match &result.outcome {
        Outcome::FailedBuild { last_errors, .. } => {
            for error in last_errors {
                match error {
                    build_classifier::BuildErrorKind::MissingSharedLib { name } => manifest
                        .push_merge(
                            DepKind::SharedLibrary,
                            name.clone(),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::MissingGprImport { path } => manifest
                        .push_merge(
                            DepKind::GprImport,
                            path.clone(),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::MissingAdaWith { unit }
                    | build_classifier::BuildErrorKind::MissingAdaPackageBody { unit } => manifest
                        .push_merge(
                            DepKind::AdaUnit,
                            unit.clone(),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::MissingAdaSymbol { unit, symbol }
                        if !unit.is_empty() => manifest.push_merge(
                            DepKind::AdaUnit,
                            format!("{unit}.{symbol}"),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::UncompilableAdaBody { source } => manifest
                        .push_merge_detailed(
                            DepKind::Runtime,
                            format!("target-compatible Ada runtime/body for {source}"),
                            vec![id.clone()],
                            false,
                            Some(format!(
                                "stage the matching GNAT target runtime/toolchain or a compatible implementation of '{source}'"
                            )),
                            RequirementBasis::Observed,
                            Some("compiler/assembler rejected target-specific Ada body".to_owned()),
                        ),
                    _ => {}
                }
            }
            record_failed_build_blockers(
                manifest,
                &[(id.clone(), last_errors.clone())],
                source_root,
            );
        }
        Outcome::UnrecoverableLink { missing, .. } => {
            for name in missing {
                let kind = if name.ends_with(".gpr") {
                    DepKind::GprImport
                } else {
                    DepKind::SharedLibrary
                };
                manifest.push_merge(kind, name.clone(), vec![id.clone()], false);
            }
        }
        Outcome::BuiltAndFuzzed {
            runtrace_events, ..
        }
        | Outcome::BuiltNotEntered {
            runtrace_events, ..
        }
        | Outcome::UnrecoverableRuntime {
            runtrace_events, ..
        } => add_runtrace_requirements(manifest, &id, runtrace_events),
        Outcome::ReportOnly { reason, .. } => {
            if reason.contains("external SDK/framework") {
                manifest.push_merge_detailed(
                    DepKind::VendorSource,
                    format!("external SDK/framework source required by {id}"),
                    vec![id],
                    false,
                    Some(
                        "identify the owner of the named unresolved types in the target reason and transfer that SDK's headers and semantic source"
                            .to_owned(),
                    ),
                    RequirementBasis::Inferred,
                    Some(reason.clone()),
                );
            }
        }
        Outcome::Built { .. } | Outcome::UnsupportedParams { .. } => {}
    }
}

fn add_missing_header_requirement(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    header: &str,
    id: &str,
    stubbed: bool,
) {
    use crate::auto::dep_manifest::{
        corba_generated_idl, is_configure_generated_header, DepKind, RequirementBasis,
    };
    if let Some(idl) = corba_generated_idl(header) {
        manifest.push_merge_detailed(
            DepKind::IdlInterface,
            idl,
            vec![id.to_owned()],
            stubbed,
            None,
            RequirementBasis::Inferred,
            Some(format!("missing generated CORBA header '{header}'")),
        );
        return;
    }
    let generated_hint = configure_template_hint(source_root, header);
    if generated_hint.is_some() || is_configure_generated_header(header) {
        manifest.push_merge_detailed(
            DepKind::GeneratedSource,
            header.to_owned(),
            vec![id.to_owned()],
            stubbed,
            generated_hint,
            RequirementBasis::Observed,
            Some(format!(
                "compiler reported generated/config header '{header}' missing"
            )),
        );
    } else {
        manifest.push_merge(
            DepKind::Header,
            header.to_owned(),
            vec![id.to_owned()],
            stubbed,
        );
    }
}

fn add_runtrace_requirements(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    id: &str,
    events: &[crate::auto::runtrace::RuntraceEvent],
) {
    use crate::auto::dep_manifest::DepKind;
    use crate::auto::runtrace::RuntraceEvent;
    for event in events {
        match event {
            RuntraceEvent::EnvVarMissing { name, .. } => {
                manifest.push_merge(DepKind::EnvVar, name.clone(), vec![id.to_owned()], true)
            }
            RuntraceEvent::FileMissing { path, .. } => manifest.push_merge(
                classify_missing_path(path),
                path.clone(),
                vec![id.to_owned()],
                is_debuginfod_cache(path),
            ),
            RuntraceEvent::NetworkUnreachable { address, .. } if !address.is_empty() => manifest
                .push_merge(
                    DepKind::NetworkEndpoint,
                    address.clone(),
                    vec![id.to_owned()],
                    true,
                ),
            RuntraceEvent::DlopenFailed { library } => manifest.push_merge(
                DepKind::DlopenLibrary,
                library.clone(),
                vec![id.to_owned()],
                true,
            ),
            _ => {}
        }
    }
}

/// Add semantic substitutions that the aggregate `NeededForBuild` ledger cannot
/// represent precisely (target runtimes, generated type definitions, and
/// platform SDK substitutions). Safe to call more than once because entries
/// merge by kind+name.
fn add_semantic_requirements_from_results(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    results: &[AttemptResult],
) {
    for result in results {
        add_checkpoint_result(manifest, source_root, result);
    }
}

/// Set of header file basenames present anywhere under `root` (bounded walk).
fn header_basenames_present(root: &Path) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 200_000 {
                return out;
            }
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".h") || name.ends_with(".hpp") || name.ends_with(".hxx") {
                    out.insert(name.to_owned());
                }
            }
        }
    }
    out
}

/// Extract the targets of `#include "x"` / `#include <x>` directives from C/C++
/// source text.
fn scan_include_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("#include") else {
            continue;
        };
        let rest = rest.trim_start();
        let close = match rest.chars().next() {
            Some('"') => '"',
            Some('<') => '>',
            _ => continue,
        };
        if let Some(end) = rest[1..].find(close) {
            let inc = &rest[1..1 + end];
            if !inc.is_empty() {
                out.push(inc.to_owned());
            }
        }
    }
    out
}

/// True for an llvm-debuginfod client cache path (`~/.cache/llvm-debuginfod/...`).
/// These are transient symbol-lookup artifacts touched by the linked binary, not
/// real build inputs — the build/fuzz completes without them, so they should be
/// reported as non-blocking rather than "still blocking".
fn is_debuginfod_cache(path: &str) -> bool {
    path.contains(".cache/llvm-debuginfod")
        || (path.contains(".cache") && path.contains("debuginfod"))
}

/// Classify a missing filesystem path the build/runtime needed. A path that
/// `lstat`s as a symlink but doesn't resolve is a dangling Symlink; one under a
/// network-mount prefix (UNC `//host/share`, or `/mnt`/`/net`/`/media`/`/smb`/
/// `/nfs`) is a NetworkShare; anything else is a plain FilePath.
fn classify_missing_path(path: &str) -> crate::auto::dep_manifest::DepKind {
    use crate::auto::dep_manifest::DepKind;
    if path.starts_with("//") {
        return DepKind::NetworkShare;
    }
    let network_prefixes = ["/mnt/", "/net/", "/media/", "/smb/", "/nfs/", "/cifs/"];
    if network_prefixes.iter().any(|p| path.starts_with(p)) {
        return DepKind::NetworkShare;
    }
    // A dangling symlink: the link node exists, its target doesn't.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() && std::fs::metadata(path).is_err() {
            return DepKind::Symlink;
        }
    }
    DepKind::FilePath
}

/// Scan the project's GPR file(s) under `source_root` for `external("VAR")`
/// scenario references that have NO default — gprbuild errors ("undefined
/// external") without them, so they are genuinely-needed env vars. References
/// with a default (`external("VAR", "x")`) are fine and not reported. Best-effort
/// + bounded; returns deduped variable names.
fn required_gpr_externals(source_root: &Path) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(source_root) else {
        return Vec::new();
    };
    for entry in entries.flatten().take(256) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("gpr") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lower = text.to_ascii_lowercase();
        let mut from = 0;
        while let Some(rel) = lower[from..].find("external") {
            let at = from + rel;
            from = at + "external".len();
            let rest = text[from..].trim_start();
            // Must be the `external (...)` function form (not `external_as_list`,
            // not an identifier ending in "external").
            let Some(args) = rest.strip_prefix('(') else {
                continue;
            };
            let Some(close) = args.find(')') else {
                continue;
            };
            let inside = &args[..close];
            // First quoted token is the variable name; a comma after it means a
            // default is supplied (not needed).
            let Some(name) = first_quoted(inside) else {
                continue;
            };
            if !inside[inside
                .find('"')
                .map(|i| i + 1 + name.len() + 1)
                .unwrap_or(inside.len())..]
                .trim_start()
                .starts_with(',')
            {
                out.insert(name);
            }
        }
    }
    out.into_iter().collect()
}

/// The first `"..."` token in `s`, or None.
fn first_quoted(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let end = s[start + 1..].find('"')?;
    Some(s[start + 1..start + 1 + end].to_owned())
}

#[allow(clippy::too_many_arguments)]
fn aggregate_repairs(
    repairs: &[Repair],
    id: &str,
    headers: &mut BTreeMap<String, Vec<String>>,
    types: &mut BTreeMap<String, Vec<String>>,
    declared: &mut BTreeMap<String, Vec<String>>,
    blind: &mut BTreeMap<String, Vec<String>>,
    ada_units: &mut BTreeMap<String, Vec<String>>,
    ada_symbols: &mut BTreeMap<String, Vec<String>>,
    macros: &mut BTreeMap<String, Vec<String>>,
) {
    for r in repairs {
        match r {
            Repair::HeaderPlaceholder { virtual_path } => headers
                .entry(virtual_path.clone())
                .or_default()
                .push(id.to_owned()),
            // A forwarding header references a real in-tree header. It is a
            // build-layout adjustment, not a missing dependency or stub.
            Repair::HeaderForward { .. } => {}
            Repair::IncludeTypeHeader { .. } => {}
            // The manifest classifies this as generated source from the
            // structured repair. Keep the run ledger's original path so it can
            // merge without a second, human-label-suffixed entry.
            Repair::ConfigHeaderSynth { virtual_path } => headers
                .entry(virtual_path.clone())
                .or_default()
                .push(id.to_owned()),
            Repair::MacroDefine { name, .. } => {
                macros.entry(name.clone()).or_default().push(id.to_owned())
            }
            // A force-included standard header for an undefined standard symbol —
            // report alongside build-config macros (a build adjustment, not a
            // maintainer-must-ship artifact).
            Repair::IncludeStdHeader { symbol, header } => macros
                .entry(format!("{symbol} -> <{header}>"))
                .or_default()
                .push(id.to_owned()),
            // Prototype-only visibility repair: the real project definition is
            // still linked and executed, so this is not a synthesized dependency
            // or a stub inventory entry.
            Repair::DeclareFunction { .. } => {}
            Repair::TypePlaceholder { type_name } => {
                // A clang recovery-artifact placeholder (`type`/`expression`) is not
                // a real missing type the maintainer must ship — never report it as a
                // synthesized_type dependency (#48). Defense in depth: the planner
                // now refuses to synthesize one, but an older on-disk repair record
                // may still carry it.
                if build_classifier::is_recovery_artifact(type_name) {
                    continue;
                }
                // Skip cross-platform Win32 typedef placeholders on
                // non-Windows hosts — they're harmless internally
                // (lets the `#ifdef _WIN32` branch parse) but they're
                // not a "the maintainer must ship WCHAR" finding.
                if crate::auto::repair::is_synthesized_type_report_noise(type_name) {
                    continue;
                }
                types
                    .entry(type_name.clone())
                    .or_default()
                    .push(id.to_owned());
            }
            Repair::TypeAlias { type_name, .. } => {
                // A real typedef synthesised from the tree-wide index (e.g. an
                // arch-gated `word_t`); report it like a synthesised type.
                types
                    .entry(type_name.clone())
                    .or_default()
                    .push(id.to_owned());
            }
            Repair::ConfigTypeAlias {
                type_name,
                underlying,
                ..
            } => {
                // A DEFAULT-width config alias (the real width is set by absent
                // codegen a non-default deployment can override). Surface it as a
                // synthesised type with an explicit LOWER-CONFIDENCE width
                // annotation so a reviewer sees exactly which widths were assumed
                // and can supply the real *AliasAc.h before promoting any finding.
                types
                    .entry(format!(
                        "{type_name} -> {underlying} (synthesised config default, LOWER-CONFIDENCE width)"
                    ))
                    .or_default()
                    .push(id.to_owned());
            }
            Repair::StubDeclared { symbol, .. } => declared
                .entry(symbol.clone())
                .or_default()
                .push(id.to_owned()),
            Repair::StubBlind { symbol } => {
                blind.entry(symbol.clone()).or_default().push(id.to_owned())
            }
            Repair::AddSource { .. } => {}
            // A build-path adjustment (real in-tree header dir / Ada unit source),
            // not a synthesised artifact the maintainer must ship.
            Repair::AddIncludeDir { .. } => {}
            Repair::AddAdaSource { .. } => {}
            // Layer-C env-var injections are aggregated separately by
            // the runtrace-event aggregator (Batch B5 / Task 12). No-op
            // here to keep the existing four-bag signature stable.
            Repair::EnvVarInjection { .. } => {}
            Repair::AdaPackageStub { unit, decls, .. } => {
                push_unique_reference(ada_units, unit.clone(), id);
                for decl in decls {
                    push_unique_reference(ada_symbols, format!("{unit}.{decl}"), id);
                }
            }
            Repair::OverrideAdaBodyStub { unit, .. } => {
                push_unique_reference(ada_units, unit.clone(), id);
            }
            Repair::AdaPackageBodyStub { unit, ops, .. } => {
                push_unique_reference(ada_units, unit.clone(), id);
                for op in ops {
                    push_unique_reference(ada_symbols, format!("{unit}.{}", op.name), id);
                }
            }
            // Reduced-fidelity label, surfaced per-target via `platform_stub`
            // (not a missing dependency the maintainer must ship).
            Repair::PlatformStub { .. } => {}
            // Synthesized Win32/MFC platform headers for a stray Win32/MFC name —
            // a build adjustment (real underlying types), not a maintainer-must-
            // ship dependency.
            Repair::Win32Pack => {}
        }
    }
}

fn aggregate_runtrace(
    events: &[crate::auto::runtrace::RuntraceEvent],
    id: &str,
    env: &mut BTreeMap<String, Vec<String>>,
    files: &mut BTreeMap<String, Vec<String>>,
    endpoints: &mut BTreeMap<String, Vec<String>>,
    dlopen: &mut BTreeMap<String, Vec<String>>,
) {
    use crate::auto::runtrace::RuntraceEvent;
    for ev in events {
        match ev {
            RuntraceEvent::EnvVarMissing { name, .. } => {
                push_unique_reference(env, name.clone(), id);
            }
            RuntraceEvent::EnvVarAccess { .. } => {}
            RuntraceEvent::FileMissing { path, .. } => {
                push_unique_reference(files, path.clone(), id);
            }
            RuntraceEvent::NetworkUnreachable { address, .. } => {
                if !address.is_empty() {
                    push_unique_reference(endpoints, address.clone(), id);
                }
            }
            RuntraceEvent::DlopenFailed { library } => {
                push_unique_reference(dlopen, library.clone(), id);
            }
            // The taint-sink events are always emitted (tainted or not, so the
            // cross-execution tracker can suppress constants) and are consumed
            // by the sink oracles, not this missing-dependency aggregation.
            RuntraceEvent::FileOpened { .. }
            | RuntraceEvent::FileClosed { .. }
            | RuntraceEvent::FileDeleted { .. }
            | RuntraceEvent::PathChecked { .. }
            | RuntraceEvent::InsecurePermissions { .. }
            | RuntraceEvent::InsecureTempFile { .. }
            | RuntraceEvent::CommandExecuted { .. }
            | RuntraceEvent::ProcessExec { .. }
            | RuntraceEvent::NetworkEgress { .. }
            | RuntraceEvent::LibraryLoad { .. }
            | RuntraceEvent::SqlQuery { .. }
            | RuntraceEvent::DestructiveFsOp { .. }
            | RuntraceEvent::FormatString { .. }
            | RuntraceEvent::RuntimeCheck { .. }
            | RuntraceEvent::Unknown { .. } => {}
        }
    }
}

fn push_unique_reference(bag: &mut BTreeMap<String, Vec<String>>, name: String, id: &str) {
    let refs = bag.entry(name).or_default();
    if !refs.iter().any(|existing| existing == id) {
        refs.push(id.to_owned());
    }
}

fn drain_bag(bag: BTreeMap<String, Vec<String>>) -> Vec<Aggregated> {
    bag.into_iter()
        .map(|(name, referenced_by_targets)| Aggregated {
            name,
            referenced_by_targets,
        })
        .collect()
}

fn render_md(r: &RunJson<'_>) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "# GovFuzz auto run — {}", r.finished_at);
    let _ = writeln!(s, "Source: {}", r.source_root.display());
    let _ = writeln!(s, "Mode: {}", r.mode.as_str());
    let _ = writeln!(s);
    let _ = writeln!(s, "Discovered: {}", r.summary.discovered);
    if r.summary.dropped_by_cap > 0 {
        let _ = writeln!(
            s,
            "  (of {} ranked; {} dropped by --max-targets/--campaign-time cap)",
            r.summary.discovered_total, r.summary.dropped_by_cap
        );
    }
    let _ = writeln!(s, "Built:      {}", r.summary.built);
    let _ = writeln!(s, "Failed:     {}", r.summary.failed_build);
    let _ = writeln!(
        s,
        "Skipped (could not auto-harness): {}",
        r.summary.unsupported_params
    );
    let _ = writeln!(s, "Unrecoverable link: {}", r.summary.unrecoverable_link);
    let _ = writeln!(
        s,
        "Unrecoverable runtime: {}",
        r.summary.unrecoverable_runtime
    );
    let _ = writeln!(s, "Findings:   {}", r.summary.findings);
    // force-fuzz Phase 2: a forced sweep that fuzzed synthesized stubs must not read
    // as N confirmed campaigns — surface the forced-and-stub-heavy count distinctly,
    // right next to the fuzzed total, and note the findings are floored to Low.
    if r.summary.forced > 0 {
        let _ = writeln!(
            s,
            "Forced (stub-heavy): {} of {} fuzzed — findings floored to Low (crash may be a stub artifact)",
            r.summary.forced, r.summary.built_and_fuzzed
        );
    }
    // #417: never let a false clean hide. If any fuzzed target only exercised
    // blind stubs, lead with a loud, structured warning naming every such target
    // so a 0-finding run over millions of stub executions is not read as clean.
    if r.summary.fuzzed_stub_only > 0 {
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "## ⚠ STUB-ONLY (FALSE CLEAN) — {} of {} fuzzed target(s)",
            r.summary.fuzzed_stub_only, r.summary.built_and_fuzzed
        );
        let _ = writeln!(
            s,
            "These targets fuzzed only blind stubs (invented empty bodies); no real \
             dependency code was linked, so their results do NOT reflect the real library. \
             Provide the missing dependency sources (see Upstream delta / missing-deps) and re-run."
        );
        for t in &r.targets {
            if let Some(se) = &t.stub_execution {
                if se.stub_only {
                    let _ = writeln!(
                        s,
                        "  - {} {} — {}/{} called symbols blind-stubbed ({:.0}%)",
                        t.harness_id,
                        t.name,
                        se.blind_stubbed_symbols,
                        se.resolved_called_symbols,
                        se.blind_stub_fraction * 100.0
                    );
                }
            }
        }
    }
    let _ = writeln!(s);
    // Per-target rows. Each built+fuzzed target prints one segment
    // per pass so the maintainer can see which pass surfaced which
    // findings (e.g. `empty=4123execs/1000exec_s/0f
    // rng=3811execs/2000exec_s/1f fuzz_driven=2901execs/500exec_s/2f`).
    if !r.targets.is_empty() {
        let _ = writeln!(s, "## Targets");
        for t in &r.targets {
            let line = render_target_md_line(t);
            let _ = writeln!(s, "  - {line}");
        }
        let _ = writeln!(s);
    }
    let any_delta = !r.needed_for_build.synthesized_headers.is_empty()
        || !r.needed_for_build.synthesized_types.is_empty()
        || !r.needed_for_build.synthesized_macros.is_empty()
        || !r.needed_for_build.stubbed_symbols_declared.is_empty()
        || !r.needed_for_build.stubbed_symbols_blind.is_empty()
        || !r.needed_for_build.stubbed_ada_units.is_empty()
        || !r.needed_for_build.stubbed_ada_symbols.is_empty()
        || !r.needed_for_build.missing_libraries.is_empty()
        || !r.needed_for_build.missing_gpr_imports.is_empty()
        || !r.needed_for_build.missing_ada_units.is_empty();
    let any_delta_c = !r.needed_for_build.environment_variables_faked.is_empty()
        || !r.needed_for_build.missing_files.is_empty()
        || !r.needed_for_build.network_endpoints.is_empty()
        || !r.needed_for_build.dlopen_failures.is_empty();
    if any_delta || any_delta_c {
        let _ = writeln!(s, "## Upstream delta");
        md_section(
            &mut s,
            "Synthesised headers",
            &r.needed_for_build.synthesized_headers,
        );
        md_section(
            &mut s,
            "Synthesised types",
            &r.needed_for_build.synthesized_types,
        );
        md_section(
            &mut s,
            "Synthesised build-config macros (supply real values)",
            &r.needed_for_build.synthesized_macros,
        );
        md_section(
            &mut s,
            "Stubbed symbols (declared)",
            &r.needed_for_build.stubbed_symbols_declared,
        );
        md_section(
            &mut s,
            "Stubbed symbols (blind)",
            &r.needed_for_build.stubbed_symbols_blind,
        );
        md_section(
            &mut s,
            "Stubbed Ada units",
            &r.needed_for_build.stubbed_ada_units,
        );
        md_section(
            &mut s,
            "Stubbed Ada symbols",
            &r.needed_for_build.stubbed_ada_symbols,
        );
        md_section(
            &mut s,
            "Missing libraries (NOT auto-stubbed)",
            &r.needed_for_build.missing_libraries,
        );
        md_section(
            &mut s,
            "Missing GPR imports (NOT auto-synthesised)",
            &r.needed_for_build.missing_gpr_imports,
        );
        md_section(
            &mut s,
            "Missing Ada units (NOT auto-stubbed)",
            &r.needed_for_build.missing_ada_units,
        );
        if any_delta_c {
            let _ = writeln!(s, "\n### Runtime resources observed during fuzzing");
            md_section(
                &mut s,
                "Environment variables (auto-injected)",
                &r.needed_for_build.environment_variables_faked,
            );
            md_section(&mut s, "Missing files", &r.needed_for_build.missing_files);
            md_section(
                &mut s,
                "Network endpoints unreachable",
                &r.needed_for_build.network_endpoints,
            );
            md_section(
                &mut s,
                "dlopen failures",
                &r.needed_for_build.dlopen_failures,
            );
        }
    }
    // #5: harness/codegen build errors are a distinct category — govfuzz's own
    // codegen or the project's build config, NOT an external dependency. Rendered
    // separately so they are never read as "bring this dependency".
    if !r.needed_for_build.harness_codegen_errors.is_empty() {
        let _ = writeln!(
            s,
            "\n## Harness / codegen build errors\nThese are malformed generated harnesses or \
             parser recovery artifacts (govfuzz codegen / the project's own build config) — NOT \
             missing dependencies. Do not acquire a package for them."
        );
        md_section(
            &mut s,
            "Harness/codegen errors",
            &r.needed_for_build.harness_codegen_errors,
        );
    }
    s
}

/// Per-target one-liner for `run.md`. Looks like:
///
/// ```text
/// H-C0042 parse_packet              built+fuzzed  empty=4123execs/1000exec_s/0f rng=3811execs/2000exec_s/1f fuzz_driven=2901execs/500exec_s/2f
/// ```
///
/// For non-fuzzed outcomes the trailing pass segment is empty and
/// only the outcome label is shown. The label is the same one the live
/// progress line prints (`crate::auto::cli::outcome_label`) so the human
/// terminal output and the report never use different words for the same
/// outcome; the machine `run.json` `outcome` tag is unaffected.
fn render_target_md_line(t: &TargetEntry<'_>) -> String {
    let outcome_label = crate::auto::cli::outcome_label(t.outcome);
    // #95: `BuiltNotEntered` carries the same pass metrics as `BuiltAndFuzzed`
    // (it ran, it just never entered the target), so show them too.
    let (passes_line, finding_count) = match t.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } | Outcome::BuiltNotEntered { passes, .. } => (
            passes_summary(passes),
            passes.iter().map(|p| p.findings.len()).sum::<usize>(),
        ),
        _ => (String::new(), 0),
    };
    let mut line = if passes_line.is_empty() {
        format!("{} {} {}", t.harness_id, t.name, outcome_label)
    } else {
        format!(
            "{} {} {} {}",
            t.harness_id, t.name, outcome_label, passes_line
        )
    };
    if passes_line.is_empty() {
        line.push_str(&format!(
            "  [stage={} repairs_attempted={} fallback={}]",
            t.attempt_trace.terminal_stage,
            t.attempt_trace.repairs_attempted,
            t.attempt_trace.fallback_chain.join("->")
        ));
    }
    // #417: mark a false-clean target inline so the per-target row itself carries
    // the warning, not just the header block — the outcome_label already reads
    // "built+fuzzed (STUB-ONLY)" but spell out the symbol ratio here too.
    if let Some(se) = &t.stub_execution {
        if se.stub_only {
            line.push_str(&format!(
                "  [!] STUB-ONLY: {}/{} called symbols blind-stubbed — not a real fuzz",
                se.blind_stubbed_symbols, se.resolved_called_symbols
            ));
        }
    }
    // When a target produced findings but its fuzzed parameters are NOT an
    // attacker-controlled input channel, flag every finding as reachability-
    // unproven so an artifact (a serializer overrun, a caller-controlled arg)
    // is never mistaken for a vulnerability.
    if finding_count > 0 {
        if let Some(reach) = t.input_reachability {
            if !reach.is_attacker_reachable() {
                line.push_str(&format!("  [!] {}", reach.report_note()));
            }
        }
    }
    line
}

/// Format a `Vec<PassRun>` as space-separated `pass=Nexecs/Rexec_s/Mf`
/// segments, in the order the cascade ran them. The `Rexec_s` throughput
/// figure (#405) is the measured per-pass executions/sec, for parity with
/// libFuzzer/AFL output.
fn passes_summary(passes: &[PassRun]) -> String {
    let parts: Vec<String> = passes
        .iter()
        .map(|pr| {
            format!(
                "{}={}execs/{:.0}exec_s/{}f",
                pr.pass.as_str(),
                pr.executions,
                pr.executions_per_sec,
                pr.findings.len()
            )
        })
        .collect();
    let mut line = parts.join(" ");
    // Edge coverage accumulates across passes, so the last/largest value is the
    // total the target reached (#385). Only shown when a coverage runtime ran.
    let cov = passes.iter().map(|p| p.coverage_edges).max().unwrap_or(0);
    if cov > 0 {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&format!("cov={cov}edges"));
    }
    line
}

fn md_section(s: &mut String, title: &str, bag: &[Aggregated]) {
    use std::fmt::Write;
    if bag.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n### {title}");
    for entry in bag {
        let _ = writeln!(
            s,
            "  - {}    used by {} target(s)",
            entry.name,
            entry.referenced_by_targets.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::candidate::{Candidate, Lang};
    use crate::auto::dep_manifest::DepKind;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn tree_static_finding_ids_lists_only_f_static_dirs() {
        let tmp = std::env::temp_dir().join(format!(
            "govfuzz-tsf-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let findings = tmp.join("findings");
        for id in [
            "F-STATIC-0000",
            "F-STATIC-0001",
            "F-MSAN-0000",
            "F-CAP-0000",
            "F-0000-abcd",
            "F-RO-H1-000",
        ] {
            std::fs::create_dir_all(findings.join(id)).unwrap();
            std::fs::write(findings.join(id).join("finding.json"), b"{}").unwrap();
        }
        // A F-STATIC dir with no finding.json must be ignored (incomplete write).
        std::fs::create_dir_all(findings.join("F-STATIC-9999")).unwrap();

        // Disk-folded finding families: --static (F-STATIC-*), MSan replay
        // (F-MSAN-*), and capability profiling (F-CAP-*). Result-linked fuzz
        // (F-0000-*) and report-only (F-RO-*) rows are NOT re-read here.
        let ids = tree_static_finding_ids(&tmp);
        assert_eq!(
            ids,
            vec![
                "F-CAP-0000",
                "F-MSAN-0000",
                "F-STATIC-0000",
                "F-STATIC-0001"
            ]
        );
        // No findings dir at all -> empty, not a panic.
        assert!(tree_static_finding_ids(tmp.parent().unwrap().join("nope").as_path()).is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stubbed_dep_still_in_failed_build_errors_is_reported_blocking() {
        // ctre: `utf8_iterator` was "stubbed" but 22 builds still failed on it —
        // it must be reported STILL BLOCKING, not "stubbed (build continued)".
        let needed = NeededForBuild {
            synthesized_types: vec![
                Aggregated {
                    name: "utf8_iterator".to_owned(),
                    referenced_by_targets: vec!["H-X".to_owned()],
                },
                Aggregated {
                    name: "harmless_t".to_owned(),
                    referenced_by_targets: vec!["H-Y".to_owned()],
                },
            ],
            ..Default::default()
        };
        let failed = "MissingType { name: \"utf8_iterator\" }\n";
        let m = build_dependency_manifest(&needed, &PathBuf::from("/tmp"), failed);
        let entry = |n: &str| m.entries.iter().find(|e| e.name == n).unwrap();
        assert!(
            !entry("utf8_iterator").stubbed,
            "a stubbed type the build still fails on is STILL BLOCKING"
        );
        assert!(
            entry("harmless_t").stubbed,
            "a stubbed type absent from the errors stays stubbed (build continued)"
        );
    }

    #[test]
    fn failed_build_records_unresolved_configure_header_with_remediation() {
        // #418: a c-ares-style failure on a configure-generated header that has no
        // source in the tree must surface in the manifest as a STILL-BLOCKING
        // header with a configure-oriented remediation — not vanish behind an
        // opaque `failed_build`.
        use build_classifier::BuildErrorKind;
        let needed = NeededForBuild::default();
        let mut m = build_dependency_manifest(&needed, &PathBuf::from("/tmp"), "");
        let failed = vec![(
            "H-CARES".to_owned(),
            vec![BuildErrorKind::MissingHeader {
                path: "ares_build.h".to_owned(),
            }],
        )];
        record_failed_build_blockers(&mut m, &failed, &PathBuf::from("/tmp"));
        let e = m
            .entries
            .iter()
            .find(|e| e.name == "ares_build.h")
            .expect("ares_build.h must be recorded");
        assert_eq!(e.kind, DepKind::GeneratedSource);
        assert!(!e.stubbed, "an unresolved header is STILL BLOCKING");
        assert!(e.referenced_by.contains(&"H-CARES".to_owned()));
        let hint = e.acquisition_hint.as_deref().unwrap_or("");
        assert!(
            hint.contains("configure"),
            "remediation names configure: {hint}"
        );
        assert!(!hint.contains("apt-file"), "no dead-end apt hint: {hint}");
        assert!(!m.is_empty());
        assert_eq!(m.blocking_count(), 1);
    }

    #[test]
    fn every_failed_build_yields_at_least_one_manifest_entry() {
        // #418 AC2 (the general guard): a failed_build must never be opaque — even
        // when the diagnostic is NOT a missing header. An `Other` compiler error,
        // an undefined symbol, and an (edge-case) error-less target each leave a
        // referencing manifest entry.
        use build_classifier::BuildErrorKind;
        // A shared-lib blocker is folded by build_dependency_manifest from the
        // `missing_libraries` bag, so the lib-only failed target below is already
        // covered and must NOT also get a redundant generic "build failed" entry.
        let needed = NeededForBuild {
            missing_libraries: vec![Aggregated {
                name: "hiredis".to_owned(),
                referenced_by_targets: vec!["H-LIB".to_owned()],
            }],
            ..Default::default()
        };
        let mut m = build_dependency_manifest(&needed, &PathBuf::from("/tmp"), "");
        let failed = vec![
            (
                "H-OTHER".to_owned(),
                vec![BuildErrorKind::Other {
                    tail: "t.c:9:1: error: something the classifier does not know\nmore noise"
                        .to_owned(),
                }],
            ),
            (
                "H-SYM".to_owned(),
                vec![BuildErrorKind::UndefinedSymbol {
                    name: "vendor_decode".to_owned(),
                }],
            ),
            // Already covered by the missing_libraries fold — no extra entry.
            (
                "H-LIB".to_owned(),
                vec![BuildErrorKind::MissingSharedLib {
                    name: "hiredis".to_owned(),
                }],
            ),
            // Defensive: a target that somehow surfaced no classified error at all
            // still must not be silent.
            ("H-EMPTY".to_owned(), vec![]),
        ];
        record_failed_build_blockers(&mut m, &failed, &PathBuf::from("/tmp"));
        for id in ["H-OTHER", "H-SYM", "H-LIB", "H-EMPTY"] {
            assert!(
                manifest_reference_count(&m, id) >= 1,
                "failed target {id} must contribute >= 1 manifest entry; manifest: {}",
                m.render_text()
            );
        }
        // The Other tail is summarised to its first error line, not dropped.
        assert!(
            m.entries
                .iter()
                .any(|e| e.name.contains("something the classifier does not know")),
            "Other diagnostic must surface: {}",
            m.render_text()
        );
        // The undefined symbol is named with link/supply remediation.
        let sym = m
            .entries
            .iter()
            .find(|e| e.name == "vendor_decode")
            .unwrap();
        assert_eq!(sym.kind, DepKind::Symbol);
        assert!(!sym.stubbed);
        // H-LIB is covered by its shared-library entry only — no redundant generic
        // "build failed for target" row.
        assert_eq!(
            manifest_reference_count(&m, "H-LIB"),
            1,
            "lib-only failure must not get a duplicate generic entry: {}",
            m.render_text()
        );
        assert!(
            !m.entries
                .iter()
                .any(|e| e.name == "build failed for target H-LIB"),
            "no redundant safety-net entry for a lib-only failure"
        );
    }

    #[test]
    fn codegen_only_failure_is_not_framed_as_a_missing_dependency() {
        // #5: a target whose only unresolved error is a harness/codegen error
        // ("no member named" / a bare `type` recovery artifact) must NOT appear in
        // the missing-dependency manifest with an acquire hint.
        use build_classifier::BuildErrorKind;
        let needed = NeededForBuild::default();
        let mut m = build_dependency_manifest(&needed, &PathBuf::from("/tmp"), "");
        let failed = vec![
            (
                "H-YAML".to_owned(),
                vec![BuildErrorKind::Other {
                    tail: "n.cpp:9:7: error: no member named 'as' in 'YAML::Node'".to_owned(),
                }],
            ),
            (
                "H-ADAURL".to_owned(),
                vec![BuildErrorKind::MissingType {
                    name: "type".to_owned(),
                }],
            ),
        ];
        record_failed_build_blockers(&mut m, &failed, &PathBuf::from("/tmp"));
        assert_eq!(
            manifest_reference_count(&m, "H-YAML"),
            0,
            "codegen-only failure must not be a dependency: {}",
            m.render_text()
        );
        assert_eq!(
            manifest_reference_count(&m, "H-ADAURL"),
            0,
            "recovery-artifact failure must not be a dependency: {}",
            m.render_text()
        );
        assert!(
            !m.entries.iter().any(|e| e.name == "type"),
            "the bare 'type' recovery artifact must not be a CType dep"
        );
    }

    #[test]
    fn uninitializable_param_reasons_collapse_by_type_not_target() {
        // Two different targets/params sharing one unconstructible type must
        // normalize to the SAME summary so the bug-report dedups them to one row.
        let a = "direct-call harness cannot initialize parameter 'Command' of \
                 target 'Proc_A' with type 'Sys.Bounded_9.Bounded_String': named type \
                 Sys.Bounded_9.Bounded_String is not declared in the parsed source set \
                 and has no synthesizable constructor. Add a public constructor.";
        let b = "direct-call harness cannot initialize parameter 'Arg' of \
                 target 'Proc_B' with type 'Sys.Bounded_9.Bounded_String': named type \
                 Sys.Bounded_9.Bounded_String is not declared in the parsed source set \
                 and has no synthesizable constructor. Add a public constructor.";
        let na = collapse_uninitializable_param_reason(a);
        assert_eq!(na, collapse_uninitializable_param_reason(b));
        assert!(na.starts_with("direct-call harness cannot initialize a parameter with type "));
        assert!(na.contains("Sys.Bounded_9.Bounded_String"));
        assert!(!na.contains("Proc_A") && !na.contains("'Command'"));
        // A different type stays a distinct row.
        let c = a.replace("Bounded_9", "Bounded_42");
        assert_ne!(na, collapse_uninitializable_param_reason(&c));
        // A reason not of this shape passes through unchanged.
        let other = "C++ parameter 'x' of type 'BOOL' has no byte-buffer decoder";
        assert_eq!(collapse_uninitializable_param_reason(other), other);
    }

    #[test]
    fn first_error_line_picks_first_nonempty_and_caps() {
        assert_eq!(
            first_error_line("\n\n  real error here \nmore"),
            "real error here"
        );
        assert_eq!(first_error_line(""), "unclassified build error");
        let long = "x".repeat(500);
        assert!(first_error_line(&long).ends_with('…'));
        assert!(first_error_line(&long).chars().count() <= 201);
        // A non-ASCII diagnostic (GCC/G++ quote with U+2018/U+2019) whose
        // multi-byte char straddles the 200-byte cap must truncate on a char
        // boundary, not panic. Pad with 198 ASCII bytes so the 2-byte 'é' spans
        // bytes 198-199 and the cut at 200 would otherwise split a later char.
        let unicode = format!("{}{}", "a".repeat(198), "é".repeat(50));
        let capped = first_error_line(&unicode); // must not panic
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn configure_template_hint_names_in_tree_template() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-tmpl-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ares_build.h.in"), "/* template */\n").unwrap();
        let hint = configure_template_hint(&dir, "ares_build.h").expect("template found");
        assert!(hint.contains("ares_build.h.in"), "{hint}");
        assert!(hint.contains("configure"), "{hint}");
        // No template -> fall back to the per-kind default (None here).
        assert!(configure_template_hint(&dir, "totally_unrelated.h").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debuginfod_cache_paths_are_non_blocking() {
        assert!(is_debuginfod_cache(
            "/home/user/.cache/llvm-debuginfod/client/abc123"
        ));
        assert!(is_debuginfod_cache(
            "/root/.cache/debuginfod_client/deadbeef"
        ));
        // A real missing build input is NOT a debuginfod cache file.
        assert!(!is_debuginfod_cache("/usr/include/zlib.h"));
        assert!(!is_debuginfod_cache("/tmp/proj/libfoo.so"));
    }

    #[test]
    fn classify_missing_path_distinguishes_network_share_and_symlink() {
        assert_eq!(
            classify_missing_path("//fileserver/share/x.h"),
            DepKind::NetworkShare
        );
        assert_eq!(
            classify_missing_path("/mnt/nfs/proj/lib.a"),
            DepKind::NetworkShare
        );
        assert_eq!(
            classify_missing_path("/net/host/inc/foo.h"),
            DepKind::NetworkShare
        );
        assert_eq!(
            classify_missing_path("/usr/include/missing.h"),
            DepKind::FilePath
        );

        // A real dangling symlink classifies as Symlink.
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-symtest-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("dangling.h");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("nonexistent-target.h"), &link).unwrap();
        #[cfg(unix)]
        assert_eq!(
            classify_missing_path(link.to_str().unwrap()),
            DepKind::Symlink
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn required_gpr_externals_reports_only_no_default_vars() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-gprext-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("p.gpr"),
            "project P is\n\
             \x20  Arch : T := external (\"ARCH\", \"generic\");\n\
             \x20  Root : String := external (\"ACE_ROOT\");\n\
             end P;\n",
        )
        .unwrap();
        let vars = required_gpr_externals(&dir);
        assert!(
            vars.contains(&"ACE_ROOT".to_owned()),
            "no-default external is needed: {vars:?}"
        );
        assert!(
            !vars.contains(&"ARCH".to_owned()),
            "defaulted external is not needed: {vars:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cand(id: &str) -> Candidate {
        Candidate {
            harness_id: id.to_owned(),
            lang: Lang::C,
            source_path: PathBuf::from("/tmp/a.c"),
            line: 1,
            name: "f".to_owned(),
            score: 60,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        }
    }

    #[test]
    fn dependency_checkpoint_survives_before_final_report_and_is_atomic() {
        let work = std::env::temp_dir().join(format!(
            "govfuzz-dep-checkpoint-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = work.join("src");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("generated.h.in"), "#define X 1\n").unwrap();

        let mut seed = crate::auto::dep_manifest::DependencyManifest::new();
        seed.push(
            DepKind::Toolchain,
            "missing-cc",
            vec!["preflight: C".to_owned()],
            false,
        );
        let mut durable = write_dependency_checkpoint(&source, &work, &seed, &[]).unwrap();
        let initial = load_dependency_manifest(&work).expect("initial checkpoint");
        assert_eq!(initial.completed_targets, 0);
        assert!(!initial.complete);

        let result = AttemptResult {
            candidate: cand("H-C-CHECKPOINT"),
            outcome: Outcome::Built {
                repairs: vec![Repair::HeaderPlaceholder {
                    virtual_path: "generated.h".to_owned(),
                }],
                retries: 1,
            },
            harness_dir: work.join("harnesses/H-C-CHECKPOINT"),
        };
        checkpoint_dependency_result(&source, &work, &mut durable, &result).unwrap();
        let checkpoint = load_dependency_manifest(&work).expect("target checkpoint");
        assert_eq!(checkpoint.completed_targets, 1);
        assert!(
            !checkpoint.complete,
            "only final reporting marks it complete"
        );
        assert!(checkpoint.has(DepKind::Toolchain, "missing-cc"));
        assert!(checkpoint.has(DepKind::GeneratedSource, "generated.h"));
        let text = std::fs::read_to_string(work.join("auto/missing-deps.txt")).unwrap();
        assert!(text.contains("run still in progress"), "{text}");
        assert!(text.contains("Required toolchains"), "{text}");
        assert!(std::fs::read_dir(work.join("auto"))
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp-")));
        let _ = std::fs::remove_dir_all(work);
    }

    #[test]
    fn atomic_write_preserves_another_live_writers_temporary() {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-atomic-writer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("missing-deps.txt");
        let live_temp = dir.join(format!(
            ".missing-deps.txt.tmp-{}-999999",
            std::process::id()
        ));
        std::fs::write(&live_temp, b"other writer").unwrap();

        atomic_write(&destination, b"checkpoint").unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"checkpoint");
        assert_eq!(std::fs::read(&live_temp).unwrap(), b"other writer");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resume_result_round_trips_full_outcome_for_reintegration() {
        let work = std::env::temp_dir().join(format!(
            "govfuzz-resume-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();

        // Before any attempt: not complete, nothing to reload.
        assert!(!target_already_complete(&work, "H-C0009"));
        assert!(load_resumed_result(&work, "H-C0009").is_none());

        // Persist a full result (with repairs + reachability, so the round-trip
        // carries the detail the report aggregates — not just an outcome tag).
        let result = AttemptResult {
            candidate: Candidate {
                input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                ..cand("H-C0009")
            },
            outcome: Outcome::FailedBuild {
                repairs: vec![Repair::StubBlind {
                    symbol: "foo".into(),
                }],
                retries: 2,
                last_errors: vec![],
            },
            harness_dir: PathBuf::from("/work/harnesses/H-C0009"),
        };
        persist_target_result(&work, &result);
        assert!(target_already_complete(&work, "H-C0009"));
        let persisted: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.join("harnesses/H-C0009/result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted["attempt_trace"]["terminal_stage"], "build");
        assert_eq!(persisted["attempt_trace"]["repairs_attempted"], true);
        assert_eq!(persisted["attempt_trace"]["repair_count"], 1);

        // Reload reconstructs a real AttemptResult, full fidelity.
        let back = load_resumed_result(&work, "H-C0009").expect("reload");
        assert_eq!(back.candidate.harness_id, "H-C0009");
        assert_eq!(back.candidate.lang, Lang::C);
        assert_eq!(
            back.candidate.input_reachability,
            Some(target_rank::InputReachability::AttackerReachable)
        );
        match back.outcome {
            Outcome::FailedBuild {
                retries, repairs, ..
            } => {
                assert_eq!(retries, 2);
                assert_eq!(repairs.len(), 1);
            }
            other => panic!("outcome not round-tripped: {other:?}"),
        }

        // Unrelated target unaffected; a corrupt file reads as not-complete.
        assert!(!target_already_complete(&work, "H-C0010"));
        std::fs::write(work.join("harnesses/H-C0009/result.json"), b"{ not json").unwrap();
        assert!(!target_already_complete(&work, "H-C0009"));

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn aggregates_repairs_across_targets() {
        let r1 = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![
                    Repair::HeaderPlaceholder {
                        virtual_path: "x.h".into(),
                    },
                    Repair::StubBlind {
                        symbol: "foo".into(),
                    },
                ],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let r2 = AttemptResult {
            candidate: cand("H-C0002"),
            outcome: Outcome::Built {
                repairs: vec![Repair::HeaderPlaceholder {
                    virtual_path: "x.h".into(),
                }],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            &[r1, r2],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let headers = &json["needed_for_build"]["synthesized_headers"];
        assert_eq!(headers[0]["name"], "x.h");
        assert_eq!(
            headers[0]["referenced_by_targets"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(json["summary"]["built"], 2);
    }

    #[test]
    fn capped_run_reports_discovered_total_and_dropped_by_cap() {
        // #6: a --max-targets / campaign cap drops lower-ranked targets from the
        // sweep. The report must surface the pre-cap total and the dropped delta
        // instead of silently reporting only the swept count.
        let r1 = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![],
                retries: 0,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let r2 = AttemptResult {
            candidate: cand("H-C0002"),
            outcome: Outcome::Built {
                repairs: vec![],
                retries: 0,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-cap-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        // 5 ranked discovered, only 2 swept.
        write_reports(
            std::path::Path::new("/tmp"),
            &[r1, r2],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            5,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        assert_eq!(json["summary"]["discovered"], 2);
        assert_eq!(json["summary"]["discovered_total"], 5);
        assert_eq!(json["summary"]["dropped_by_cap"], 3);
        assert!(
            json["summary"]["discovered_total"].as_u64().unwrap()
                > json["summary"]["discovered"].as_u64().unwrap()
        );
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(md.contains("dropped by --max-targets"), "{md}");
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn missing_ada_symbol_with_empty_unit_is_dropped() {
        // GNAT occasionally emits the symbol with no enclosing unit
        // context (regex captured "Harness" alone). The aggregator
        // used to join those as `.Harness` — useless to the upstream
        // maintainer. Today they're dropped; real `Pkg.Foo` rows
        // still land in the bag.
        let r1 = AttemptResult {
            candidate: cand("H-A0001"),
            outcome: Outcome::FailedBuild {
                repairs: vec![],
                retries: 0,
                last_errors: vec![
                    build_classifier::BuildErrorKind::MissingAdaSymbol {
                        unit: String::new(),
                        symbol: "Harness".into(),
                    },
                    build_classifier::BuildErrorKind::MissingAdaSymbol {
                        unit: "Aux_Pkg".into(),
                        symbol: "Frob".into(),
                    },
                ],
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-ada-bare-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&r1),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let units = json["needed_for_build"]["missing_ada_units"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = units.iter().filter_map(|u| u["name"].as_str()).collect();
        assert!(
            !names.iter().any(|n| n.starts_with('.')),
            "leading-dot entries should be filtered: {names:?}"
        );
        assert!(
            names.contains(&"Aux_Pkg.Frob"),
            "qualified entries should still surface: {names:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn win32_type_placeholders_are_hidden_from_synthesized_types_on_linux() {
        // The miniz fixture references WCHAR inside a #ifdef _WIN32
        // block. On non-Windows hosts we still synthesise the typedef
        // so the preprocessor branch parses, but the report row is
        // noise — a Linux maintainer shouldn't be asked to ship WCHAR.
        let r1 = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![
                    Repair::TypePlaceholder {
                        type_name: "WCHAR".into(),
                    },
                    Repair::TypePlaceholder {
                        type_name: "my_widget_t".into(),
                    },
                ],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-win32-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&r1),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let types = json["needed_for_build"]["synthesized_types"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = types.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(
            !names.contains(&"WCHAR"),
            "WCHAR should be filtered on non-Windows hosts: {names:?}"
        );
        assert!(
            names.contains(&"my_widget_t"),
            "real placeholder should still surface: {names:?}"
        );
    }

    #[test]
    fn aggregates_ada_stub_repairs_separately_from_missing_ada_units() {
        let r1 = AttemptResult {
            candidate: cand("H-A0002"),
            outcome: Outcome::Built {
                repairs: vec![
                    Repair::AdaPackageStub {
                        unit: "Aux_Pkg".into(),
                        decls: vec!["Score".into()],
                        ops: Vec::new(),
                        synthesize_body: true,
                        provenance: "test".into(),
                    },
                    Repair::AdaPackageBodyStub {
                        unit: "Aux_Pkg".into(),
                        ops: vec![stub_gen::StubOp {
                            name: "Score".into(),
                            kind: stub_gen::StubOpKind::Function,
                            return_type: Some("Integer".into()),
                            params: Vec::new(),
                        }],
                        provenance: "test".into(),
                    },
                ],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-ada-stubs-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&r1),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let units = json["needed_for_build"]["stubbed_ada_units"]
            .as_array()
            .expect("stubbed_ada_units should be an array");
        let symbols = json["needed_for_build"]["stubbed_ada_symbols"]
            .as_array()
            .expect("stubbed_ada_symbols should be an array");
        assert_eq!(units[0]["name"], "Aux_Pkg");
        assert_eq!(symbols[0]["name"], "Aux_Pkg.Score");
        assert!(
            json["needed_for_build"]["missing_ada_units"]
                .as_array()
                .unwrap()
                .is_empty(),
            "repaired Ada stubs should not also surface as missing units"
        );
    }

    #[test]
    fn aggregates_runtrace_events_across_targets() {
        use crate::auto::runtrace::RuntraceEvent;
        let mut env = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        let mut dlopen = BTreeMap::new();
        aggregate_runtrace(
            &[
                RuntraceEvent::EnvVarMissing {
                    api: "getenv".to_owned(),
                    name: "ACME".to_owned(),
                },
                RuntraceEvent::EnvVarMissing {
                    api: "getenv".to_owned(),
                    name: "ACME".to_owned(),
                },
                RuntraceEvent::FileMissing {
                    syscall: "open".to_owned(),
                    path: "/etc/x.conf".to_owned(),
                    taint_offset: None,
                },
            ],
            "H-C0001",
            &mut env,
            &mut files,
            &mut endpoints,
            &mut dlopen,
        );
        aggregate_runtrace(
            &[RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME".to_owned(),
            }],
            "H-C0002",
            &mut env,
            &mut files,
            &mut endpoints,
            &mut dlopen,
        );
        assert_eq!(
            env.get("ACME").unwrap(),
            &vec!["H-C0001".to_owned(), "H-C0002".to_owned()]
        );
        assert_eq!(files.get("/etc/x.conf").unwrap().len(), 1);
    }

    #[test]
    fn markdown_renders_runtime_resources_section_when_layer_c_non_empty() {
        let needed = NeededForBuild {
            environment_variables_faked: vec![Aggregated {
                name: "ACME_CONFIG".to_owned(),
                referenced_by_targets: vec!["H-C0001".to_owned()],
            }],
            ..NeededForBuild::default()
        };
        let r = RunJson {
            schema_version: 1,
            started_at: "T0".to_owned(),
            finished_at: "T1".to_owned(),
            partial: false,
            mode: actionability::RunMode::Reporting,
            source_root: std::path::Path::new("/x"),
            summary: Summary::default(),
            needed_for_build: needed,
            targets: vec![],
        };
        let md = render_md(&r);
        assert!(md.contains("## Upstream delta"), "md: {md}");
        assert!(
            md.contains("### Runtime resources observed during fuzzing"),
            "md: {md}"
        );
        assert!(
            md.contains("Environment variables (auto-injected)"),
            "md: {md}"
        );
        assert!(md.contains("ACME_CONFIG"), "md: {md}");
    }

    #[test]
    fn markdown_skips_runtime_resources_when_layer_c_empty() {
        let r = RunJson {
            schema_version: 1,
            started_at: "T0".to_owned(),
            finished_at: "T1".to_owned(),
            partial: false,
            mode: actionability::RunMode::Reporting,
            source_root: std::path::Path::new("/x"),
            summary: Summary::default(),
            needed_for_build: NeededForBuild::default(),
            targets: vec![],
        };
        let md = render_md(&r);
        assert!(
            !md.contains("Runtime resources observed during fuzzing"),
            "md: {md}"
        );
        assert!(!md.contains("## Upstream delta"), "md: {md}");
    }

    #[test]
    fn target_entry_renders_passes_array() {
        use crate::auto::attempt::PassRun;
        use crate::auto::pass::Pass;
        // #405: per-pass elapsed/throughput chosen so each rate is exact
        // (executions / elapsed_secs lands on a round number) — empty 1000/s,
        // rng 2000/s, fuzz_driven 500/s — keeping the run.md assertion stable.
        let passes = vec![
            PassRun {
                pass: Pass::Empty,
                engine: "builtin".to_owned(),
                executions: 4123,
                target_entry_observed: false,
                coverage_edges: 180,
                elapsed_secs: 4.123,
                executions_per_sec: 1000.0,
                findings: vec![],
            },
            PassRun {
                pass: Pass::Rng,
                engine: "builtin".to_owned(),
                executions: 3811,
                target_entry_observed: false,
                coverage_edges: 240,
                elapsed_secs: 1.9055,
                executions_per_sec: 2000.0,
                findings: vec!["F-0001".to_owned()],
            },
            PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 2901,
                target_entry_observed: false,
                coverage_edges: 252,
                elapsed_secs: 5.802,
                executions_per_sec: 500.0,
                findings: vec!["F-0002".to_owned(), "F-0003".to_owned()],
            },
        ];
        let executions_per_sec = crate::auto::attempt::aggregate_executions_per_sec(&passes);
        let result = AttemptResult {
            candidate: cand("H-C0042"),
            outcome: Outcome::BuiltAndFuzzed {
                repairs: vec![],
                retries: 0,
                per_pass_budget_secs: 60,
                total_wall_budget_secs: 180,
                passes,
                executions_per_sec,
                runtrace_events: vec![],
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-passes-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&result),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let target = &json["targets"][0];
        assert_eq!(target["harness_id"], "H-C0042");
        let passes = target["outcome"]["passes"]
            .as_array()
            .expect("passes array");
        let names: Vec<&str> = passes.iter().filter_map(|p| p["pass"].as_str()).collect();
        assert_eq!(names, vec!["empty", "rng", "fuzz_driven"]);
        assert_eq!(passes[0]["executions"], 4123);
        assert_eq!(passes[1]["findings"][0], "F-0001");
        assert_eq!(passes[2]["findings"].as_array().unwrap().len(), 2);

        // #405: per-pass throughput surfaces in run.json (additive — the
        // existing `executions` field above is unchanged).
        assert_eq!(passes[0]["executions_per_sec"], 1000.0);
        assert_eq!(passes[1]["executions_per_sec"], 2000.0);
        assert_eq!(passes[0]["elapsed_secs"], 4.123);
        // ...and the target-level aggregate (Σexecs / Σelapsed, time-weighted).
        let agg = target["outcome"]["executions_per_sec"].as_f64().unwrap();
        let expect_agg = (4123.0 + 3811.0 + 2901.0) / (4.123 + 1.9055 + 5.802);
        assert!(
            (agg - expect_agg).abs() < 1e-6,
            "aggregate exec/s {agg} != {expect_agg}"
        );

        // Summary totals = sum across passes.
        assert_eq!(json["summary"]["findings"], 3);
        assert_eq!(json["summary"]["built_and_fuzzed"], 1);

        // run.md surfaces a per-target row with one segment per pass, now
        // including the measured exec/s (#405).
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(md.contains("## Targets"), "md: {md}");
        assert!(
            md.contains(
                "empty=4123execs/1000exec_s/0f rng=3811execs/2000exec_s/1f \
                 fuzz_driven=2901execs/500exec_s/2f"
            ),
            "md: {md}"
        );
    }

    #[test]
    fn write_reports_emits_findings_csv_with_populated_row() {
        use crate::auto::attempt::PassRun;
        use crate::auto::pass::Pass;

        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-csv-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let fid = "F-0000-1028b5d3";
        let finding_dir = work.join("findings").join(fid);
        std::fs::create_dir_all(&finding_dir).unwrap();
        // A real C LeakSanitizer finding shape, written WITHOUT an actionability
        // block so the CSV writer exercises the backfill path.
        std::fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": fid,
                "signature": "1028b5d3e132c794",
                "rule_id": "GF-208",
                "classification": "unhandled",
                "harness_id": "H-X0C65-56DA8C32",
                "dialect": "unknown",
                "paths": { "testcase": "testcase.bin" },
                "exception": {
                    "name": "LSAN_MEMORY_LEAK",
                    "message": "==1==ERROR: LeakSanitizer: detected memory leaks",
                    "sanitizer": "lsan",
                    "stack": [
                        { "function": "malloc" },
                        { "function": "nsvg__createParser()", "file": "/src/nanosvg.h", "line": 646 },
                        { "function": "nsvgParse", "file": "/src/nanosvg.h", "line": 3178 },
                        { "function": "govfuzz_run_one(unsigned char const*, unsigned long)", "file": "/work/auto/H/main.cpp", "line": 39 }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = AttemptResult {
            candidate: cand("H-X0C65-56DA8C32"),
            outcome: Outcome::BuiltAndFuzzed {
                repairs: vec![],
                retries: 0,
                per_pass_budget_secs: 60,
                total_wall_budget_secs: 180,
                passes: vec![PassRun {
                    pass: Pass::Rng,
                    engine: "builtin".to_owned(),
                    executions: 10,
                    target_entry_observed: false,
                    coverage_edges: 1,
                    elapsed_secs: 1.0,
                    executions_per_sec: 10.0,
                    findings: vec![fid.to_owned()],
                }],
                executions_per_sec: 10.0,
                runtrace_events: vec![],
            },
            harness_dir: PathBuf::from("/tmp"),
        };

        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&result),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();

        let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap();
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "id,count,harness_id,rule_id,message,exception_name,sanitizer,classification,confirmation,impact,confidence,verdict,cwe,source,data_flow,sink_file,sink_line,sink_function,entity,remediation,signature,member_finding_ids"
        );
        let row = lines.next().expect("one finding row");
        assert!(
            lines.next().is_none(),
            "exactly one finding row, got: {csv}"
        );
        let cells: Vec<&str> = row.split(',').collect();
        assert_eq!(cells[0], fid);
        assert_eq!(cells[1], "1", "count for a single-finding issue");
        assert_eq!(cells[2], "H-X0C65-56DA8C32");
        // rule_id + message (cells[3..5]): a fuzz crash carries no finding-rule id;
        // the message is the crash label. Both may be empty for a bare LSAN leak.
        assert_eq!(cells[5], "LSAN_MEMORY_LEAK");
        assert_eq!(cells[6], "lsan");
        assert_eq!(cells[7], "unhandled");
        // #484: a runtime crash with no static counterpart is provenance "fuzz".
        assert_eq!(cells[8], "fuzz");
        // verdict column populated.
        assert!(!cells[11].is_empty(), "verdict empty in row: {row}");
        // cwe: bare number, no `CWE-` prefix (lsan leak -> 401).
        assert_eq!(cells[12], "401");
        // source (13): empty for a fuzz crash with no taint source→sink flow.
        assert_eq!(cells[13], "");
        // data_flow (14): empty too — no taint trace on a fuzz crash.
        assert_eq!(cells[14], "");
        // sink = top resolved project frame (allocator + harness skipped).
        assert_eq!(cells[15], "/src/nanosvg.h");
        assert_eq!(cells[16], "646");
        assert_eq!(cells[17], "nsvg__createParser");
        // entity (18): a fuzz crash has no tainted-variable/sink expression.
        assert_eq!(cells[18], "");
        // remediation (19): a one-line fix; a rule-less crash gets the fallback.
        assert!(!cells[19].is_empty(), "remediation empty in row: {row}");
        assert!(
            !cells[19].contains("finding.json"),
            "remediation is guidance, not a path: {}",
            cells[19]
        );
        assert_eq!(cells[20], "1028b5d3e132c794");
        // #4: member_finding_ids is BLANK for a singleton issue (it would only echo id).
        assert_eq!(cells[21], "");

        std::fs::remove_dir_all(&work).ok();
    }

    #[test]
    fn write_reports_groups_findings_csv_by_cluster_key_full() {
        // #36: two findings that share a cluster_key_full (the cascade re-emitting
        // the same root cause across passes) must collapse to ONE issue row with
        // count=2 and both member ids — matching the report crate's grouped CSV,
        // not one row per finding.
        use crate::auto::attempt::PassRun;
        use crate::auto::pass::Pass;

        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-csv-group-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cluster = "ab".repeat(32);
        let ids = ["F-0001-aaaa", "F-0002-bbbb"];
        for fid in ids {
            let dir = work.join("findings").join(fid);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "id": fid,
                    "signature": fid,
                    "cluster_key_full": cluster,
                    "rule_id": "GF-201",
                    "classification": "unhandled",
                    "harness_id": "H-DUP",
                    "exception": {
                        "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                        "sanitizer": "asan",
                        "stack": [ { "function": "parse_rec", "file": "/src/p.c", "line": 12 } ]
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        }

        let result = AttemptResult {
            candidate: cand("H-DUP"),
            outcome: Outcome::BuiltAndFuzzed {
                repairs: vec![],
                retries: 0,
                per_pass_budget_secs: 60,
                total_wall_budget_secs: 180,
                passes: vec![
                    PassRun {
                        pass: Pass::Empty,
                        engine: "builtin".to_owned(),
                        executions: 1,
                        target_entry_observed: false,
                        coverage_edges: 1,
                        elapsed_secs: 1.0,
                        executions_per_sec: 1.0,
                        findings: vec![ids[0].to_owned()],
                    },
                    PassRun {
                        pass: Pass::Rng,
                        engine: "builtin".to_owned(),
                        executions: 1,
                        target_entry_observed: false,
                        coverage_edges: 1,
                        elapsed_secs: 1.0,
                        executions_per_sec: 1.0,
                        findings: vec![ids[1].to_owned()],
                    },
                ],
                executions_per_sec: 1.0,
                runtrace_events: vec![],
            },
            harness_dir: PathBuf::from("/tmp"),
        };

        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&result),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();

        let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap();
        let rows: Vec<&str> = csv.lines().skip(1).collect();
        assert_eq!(rows.len(), 1, "two findings, one cluster -> one row: {csv}");
        let cells: Vec<&str> = rows[0].split(',').collect();
        assert_eq!(cells[1], "2", "count collapses both members");
        assert_eq!(cells[21], "F-0001-aaaa;F-0002-bbbb", "member ids preserved");

        std::fs::remove_dir_all(&work).ok();
    }

    #[test]
    fn write_reports_emits_header_only_findings_csv_when_no_findings() {
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-csv-empty-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            &[],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();
        let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap();
        assert_eq!(csv, FINDINGS_CSV_HEADER);
        std::fs::remove_dir_all(&work).ok();
    }

    /// #484: a `--static` finding that the fuzz-confirmation join upgraded to
    /// `fuzz_confirmed` on disk must render its provenance in the findings.csv
    /// `confirmation` column and count in the run.json `fuzz_confirmed` summary.
    /// A sibling static finding with no runtime match stays `static`.
    #[test]
    fn write_reports_surfaces_fuzz_confirmed_static_finding() {
        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-confirm-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // A confirmed static finding (as the join would have rewritten it) and a
        // plain static finding, both written straight to the findings dir the way
        // `emit_tree_static_findings` does (picked up via `tree_static_finding_ids`).
        let confirmed = serde_json::json!({
            "id": "F-STATIC-0000",
            "rule_id": "GF-420",
            "classification": "static_scan",
            "confirmation": "fuzz_confirmed",
            "confirmed_by": ["F-0000-abcd"],
            "harness_id": "static-scan",
            "target": { "name": "cmd.c", "source_path": "/p/cmd.c", "line": 8,
                        "location": { "path": "/p/cmd.c", "line": 8 } },
            "oracle": { "evidence": [ { "key": "source", "value": "/p/cmd.c:8" } ] },
            "exception": { "message": "code injection" },
            "actionability": { "mode": "reporting", "verdict": "likely_reachable",
                               "impact": "high", "confidence": "high",
                               "prosthetics": { "used": false }, "cwe": ["CWE-94"] },
        });
        let plain = serde_json::json!({
            "id": "F-STATIC-0001",
            "rule_id": "GF-420",
            "classification": "static_scan",
            "confirmation": "static",
            "harness_id": "static-scan",
            "target": { "name": "util.c", "source_path": "/p/util.c", "line": 3,
                        "location": { "path": "/p/util.c", "line": 3 } },
            "oracle": { "evidence": [ { "key": "source", "value": "/p/util.c:3" } ] },
            "exception": { "message": "code injection" },
            "actionability": { "cwe": ["CWE-94"], "verdict": "static_only", "confidence": "medium" },
        });
        for f in [&confirmed, &plain] {
            let id = f["id"].as_str().unwrap();
            let dir = work.join("findings").join(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(f).unwrap(),
            )
            .unwrap();
        }

        write_reports(
            std::path::Path::new("/p"),
            &[],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();

        let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap();
        let confirmation_col = |id: &str| -> String {
            csv.lines()
                .find(|l| l.starts_with(&format!("{id},")))
                .map(|l| l.split(',').nth(8).unwrap_or("").to_owned())
                .unwrap_or_default()
        };
        assert_eq!(
            confirmation_col("F-STATIC-0000"),
            "fuzz_confirmed",
            "csv: {csv}"
        );
        assert_eq!(confirmation_col("F-STATIC-0001"), "static", "csv: {csv}");

        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(work.join("auto/run.json")).unwrap())
                .unwrap();
        assert_eq!(json["summary"]["fuzz_confirmed"], 1);
        assert_eq!(json["summary"]["findings"], 2);

        std::fs::remove_dir_all(&work).ok();
    }

    /// #417 regression — the FALSE-CLEAN bug. A harness whose every external
    /// called symbol was satisfied by a *blind* stub (an invented empty body),
    /// with no real dependency source linked, must NOT be reported as a plain
    /// clean `built_and_fuzzed`: run.json must carry a `stub_execution` field
    /// flagging `stub_only`, the summary must count it under `fuzzed_stub_only`,
    /// and run.md must surface a STUB-ONLY warning. Otherwise a 0-finding result
    /// over millions of executions of empty stubs reads as "library is clean".
    #[test]
    fn stub_only_run_is_flagged_not_reported_as_plain_clean() {
        use crate::auto::attempt::{Outcome, PassRun};
        use crate::auto::pass::Pass;
        use crate::auto::repair::Repair;

        // libyaml-shaped: every entry point the harness calls is blind-stubbed,
        // zero findings over ~8M execs, harness-only coverage.
        let blind_all = Outcome::BuiltAndFuzzed {
            repairs: vec![
                Repair::StubBlind {
                    symbol: "yaml_parser_initialize".to_owned(),
                },
                Repair::StubBlind {
                    symbol: "yaml_parser_set_input_string".to_owned(),
                },
                Repair::StubBlind {
                    symbol: "yaml_parser_parse".to_owned(),
                },
                Repair::StubBlind {
                    symbol: "yaml_parser_delete".to_owned(),
                },
            ],
            retries: 2,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 180,
            executions_per_sec: 800_000.0,
            passes: vec![PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 8_000_000,
                target_entry_observed: false,
                coverage_edges: 16,
                elapsed_secs: 10.0,
                executions_per_sec: 800_000.0,
                findings: vec![],
            }],
            runtrace_events: vec![],
        };
        // Contrast: a genuine fuzz that linked real dependency source. Even with
        // one blind-stubbed leaf helper it is NOT stub-only — real code ran.
        let real_linked = Outcome::BuiltAndFuzzed {
            repairs: vec![
                Repair::AddSource {
                    symbol: "real_decode".to_owned(),
                    source_path: PathBuf::from("/s/decode.c"),
                },
                Repair::StubBlind {
                    symbol: "leaf_helper".to_owned(),
                },
            ],
            retries: 1,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 180,
            executions_per_sec: 1000.0,
            passes: vec![PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 1000,
                target_entry_observed: true,
                coverage_edges: 1400,
                elapsed_secs: 1.0,
                executions_per_sec: 1000.0,
                findings: vec![],
            }],
            runtrace_events: vec![],
        };

        let results = vec![
            AttemptResult {
                candidate: cand("H-STUB"),
                outcome: blind_all,
                harness_dir: PathBuf::from("/tmp"),
            },
            AttemptResult {
                candidate: cand("H-REAL"),
                outcome: real_linked,
                harness_dir: PathBuf::from("/tmp"),
            },
        ];

        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-stubonly-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            &results,
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();

        // AC2: per-target field distinguishing real vs blind-stubbed execution.
        let stub = &json["targets"][0]["stub_execution"];
        assert_eq!(stub["stub_only"], serde_json::Value::Bool(true), "{json}");
        assert_eq!(stub["blind_stubbed_symbols"], 4);
        assert_eq!(stub["real_linked_symbols"], 0);
        assert_eq!(stub["resolved_called_symbols"], 4);
        assert_eq!(stub["blind_stub_fraction"], 1.0);

        // The real-linked target is NOT flagged stub-only.
        let real = &json["targets"][1]["stub_execution"];
        assert_eq!(real["stub_only"], serde_json::Value::Bool(false), "{json}");
        assert_eq!(real["real_linked_symbols"], 1);

        // AC1: the summary counts the false-clean target distinctly; it is NOT
        // silently folded into a plain clean built_and_fuzzed total.
        assert_eq!(json["summary"]["fuzzed_stub_only"], 1, "{json}");
        assert_eq!(json["summary"]["built_and_fuzzed"], 2);

        // AC1: run.md loudly surfaces the stub-only target.
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(
            md.contains("STUB-ONLY"),
            "md missing stub-only warning: {md}"
        );
        assert!(md.contains("H-STUB"), "md: {md}");
    }

    /// force-fuzz Phase 2: a finding from a target that ran forced-and-stub-heavy
    /// (`--force` + a stub-only build) must be honestly LOW confidence: the summary
    /// counts it under `forced`, run.md surfaces the forced/stub caveat, and its
    /// findings.csv row shows `low` confidence with the stub-artifact note in the
    /// trailing `forced` column — so a forced crash is never read as a confirmed bug.
    #[test]
    fn forced_stub_heavy_target_floors_findings_to_low_and_counts_forced() {
        use crate::auto::attempt::{Outcome, PassRun};
        use crate::auto::pass::Pass;
        use crate::auto::repair::Repair;

        let work = std::env::temp_dir().join(format!(
            "govfuzz-report-forced-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let fid = "F-FORCED-0001";
        let finding_dir = work.join("findings").join(fid);
        std::fs::create_dir_all(&finding_dir).unwrap();
        // A finding whose EMITTED confidence is high — the forced flooring must
        // override it, not merely leave a low value alone.
        std::fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": fid,
                "signature": "deadbeefcafef00d",
                "rule_id": "GF-208",
                "classification": "unhandled",
                "harness_id": "H-FORCED",
                "exception": {
                    "name": "SEGV",
                    "message": "AddressSanitizer: SEGV on unknown address",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "opaque_target", "file": "/src/opaque.c", "line": 12 }
                    ]
                },
                "actionability": { "confidence": "high", "impact": "high" }
            }))
            .unwrap(),
        )
        .unwrap();

        // Blind-stubbed BuiltAndFuzzed → stub_only, so under --force it is
        // forced-and-stub-heavy.
        let outcome = Outcome::BuiltAndFuzzed {
            repairs: vec![Repair::StubBlind {
                symbol: "opaque_dep".to_owned(),
            }],
            retries: 0,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 180,
            executions_per_sec: 1000.0,
            passes: vec![PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 1000,
                target_entry_observed: false,
                coverage_edges: 4,
                elapsed_secs: 1.0,
                executions_per_sec: 1000.0,
                findings: vec![fid.to_owned()],
            }],
            runtrace_events: vec![],
        };
        let result = AttemptResult {
            candidate: cand("H-FORCED"),
            outcome,
            harness_dir: PathBuf::from("/tmp"),
        };

        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&result),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            true, // force
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        // Summary counts the forced-and-stub-heavy target.
        assert_eq!(json["summary"]["forced"], 1, "{json}");
        assert_eq!(json["summary"]["fuzzed_stub_only"], 1, "{json}");
        assert_eq!(json["summary"]["built_and_fuzzed"], 1);

        // run.md surfaces the forced/stub caveat distinctly.
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(
            md.contains("Forced (stub-heavy)"),
            "md missing forced summary: {md}"
        );

        // findings.csv: `low` confidence + the trailing `forced` note column.
        let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap();
        let header = csv.lines().next().unwrap();
        assert!(header.ends_with(",forced"), "header: {header}");
        let confidence_idx = header.split(',').position(|c| c == "confidence").unwrap();
        let row = csv.lines().nth(1).expect("one finding row");
        let cells: Vec<&str> = row.split(',').collect();
        assert_eq!(cells[confidence_idx], "low", "row: {row}");
        assert!(
            row.contains("stub artifact"),
            "forced note missing in row: {row}"
        );

        std::fs::remove_dir_all(&work).ok();
    }
}
