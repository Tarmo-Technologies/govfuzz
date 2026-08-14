// SPDX-License-Identifier: Apache-2.0

//! C/C++ line coverage for negative fuzz-confirmation.
//!
//! The interpreted lanes get executed-line sets for free from their tracers; the
//! compiled lanes don't. This builds a source-based-coverage variant of the harness
//! (`make cov` — clang `-fprofile-instr-generate -fcoverage-mapping`), replays the
//! fuzz corpus through it (each input a fresh process, so the profile flushes on
//! exit), merges the profiles with `llvm-profdata`, and exports the covered
//! `(file, line)` set with `llvm-cov`. The set is written to the harness's
//! `covered-lines.txt` — the SAME sidecar the interpreted lanes write — so
//! `confirm::mark_fuzz_exercised_findings` marks a C/C++ static finding whose line
//! the campaign PROVABLY executed (yet never crashed) as `fuzz_exercised`.
//!
//! Best-effort: a missing `llvm-cov`/`llvm-profdata`, a failed coverage build, or an
//! empty corpus all skip cleanly. Never fatal.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const MAX_INPUTS: usize = 2000;
const REPLAY_BUDGET: Duration = Duration::from_secs(30);
const BUILD_RECIPE_FILE: &str = "coverage-build-recipe.json";
const COVERAGE_DIAGNOSTIC_FILE: &str = "coverage-replay-diagnostic.txt";
const EXPERT_ORACLE_FILE: &str = "expert-oracle.json";
const EXPERT_HARNESS_ENV: &str = "GOVFUZZ_EXPERT_HARNESS";
const EXPERT_COVERAGE_ENV: &str = "GOVFUZZ_EXPERT_COVERED_LINES";

/// The exact recovered inputs that made the primary C/C++ harness link. Repair
/// sources and include roots otherwise live only in the attempt loop's memory;
/// invoking a naked `make cov` later silently drops them and either fails or,
/// worse, measures a smaller/stub-different program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoverageBuildRecipe {
    schema_version: u32,
    native: bool,
    extra_sources: Vec<PathBuf>,
    extra_includes: Vec<PathBuf>,
    standard: Option<String>,
}

/// Checkpoint the successful build closure while the repair loop still owns it.
/// Coverage replay consumes this recipe through the same make/build-context path
/// as the primary build, changing only the instrumentation lane to `cov`.
pub(crate) fn persist_build_recipe(
    harness_dir: &Path,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    standard: Option<String>,
    native: bool,
) {
    let recipe = CoverageBuildRecipe {
        schema_version: 1,
        native,
        extra_sources: extra_sources.to_vec(),
        extra_includes: extra_includes.to_vec(),
        standard,
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&recipe) {
        let _ = crate::auto::report::atomic_write(&harness_dir.join(BUILD_RECIPE_FILE), &bytes);
    }
}

pub(crate) fn clear_build_recipe(harness_dir: &Path) {
    let _ = std::fs::remove_file(harness_dir.join(BUILD_RECIPE_FILE));
}

fn read_build_recipe(harness_dir: &Path) -> Option<CoverageBuildRecipe> {
    let bytes = std::fs::read(harness_dir.join(BUILD_RECIPE_FILE)).ok()?;
    let recipe: CoverageBuildRecipe = serde_json::from_slice(&bytes).ok()?;
    (recipe.schema_version == 1 && recipe.native).then_some(recipe)
}

fn write_coverage_diagnostic(hdir: &Path, message: &str) {
    let _ =
        crate::auto::report::atomic_write(&hdir.join(COVERAGE_DIAGNOSTIC_FILE), message.as_bytes());
}

fn diagnostic_tail(bytes: &[u8]) -> String {
    const MAX_BYTES: usize = 16 * 1024;
    let start = bytes.len().saturating_sub(MAX_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// Aggregate coverage across the harnesses a replay measured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageTotals {
    pub harnesses: usize,
    pub covered_lines: usize,
    pub instrumented_lines: usize,
    pub expert_oracles: usize,
    pub expert_parity_or_better: usize,
    pub expert_marginal_gaps: usize,
    pub expert_build_unavailable: usize,
}

impl CoverageTotals {
    /// Fraction of instrumented lines the campaign executed, or `None` when
    /// nothing was instrumented — which is a different statement from 0%, and
    /// must not be reported as one.
    pub fn fraction(&self) -> Option<f64> {
        (self.instrumented_lines > 0)
            .then(|| self.covered_lines as f64 / self.instrumented_lines as f64)
    }
}

/// Build + replay every C/C++ harness's corpus under source coverage, writing each
/// harness's executed `(file:line)` set to `<harness>/covered-lines.txt` and its
/// covered/instrumented counts to `coverage-summary.json`. Returns the totals.
pub fn run_coverage_replay(work_dir: &Path) -> CoverageTotals {
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return CoverageTotals::default();
    };
    // Native replay needs LLVM's coverage tools. An interpreted harness can
    // already own `covered-lines.txt`, however, and a caller can supply an
    // expert covered-line sidecar for any language. Do not make that portable
    // oracle disappear merely because llvm-cov is unavailable.
    let llvm_tools = llvm_tool("llvm-profdata").zip(llvm_tool("llvm-cov"));
    let mut totals = CoverageTotals::default();
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        if let Some((covered, instrumented)) = llvm_tools
            .as_ref()
            .and_then(|(profdata, cov)| replay_one(work_dir, &hdir, &harness_id, profdata, cov))
        {
            totals.harnesses += 1;
            totals.covered_lines += covered;
            totals.instrumented_lines += instrumented;
        }
        if let Some(expert_coverage) = explicit_expert_coverage(&harness_id) {
            run_external_expert_coverage_oracle(&hdir, &harness_id, &expert_coverage);
        }
        if let Some(verdict) = read_expert_oracle_verdict(&hdir) {
            totals.expert_oracles += 1;
            match verdict.as_str() {
                "expert_parity" | "generated_exceeds_expert" => {
                    totals.expert_parity_or_better += 1;
                }
                "expert_has_marginal_coverage" => totals.expert_marginal_gaps += 1,
                "expert_build_unavailable" => totals.expert_build_unavailable += 1,
                _ => {}
            }
        }
    }
    totals
}

fn read_expert_oracle_verdict(hdir: &Path) -> Option<String> {
    let bytes = std::fs::read(hdir.join(EXPERT_ORACLE_FILE)).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("verdict")?.as_str().map(ToOwned::to_owned)
}

fn replay_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    profdata: &str,
    cov: &str,
) -> Option<(usize, usize)> {
    if !hdir.join("Makefile").is_file() {
        return None;
    }
    // Don't clobber a covered-lines set an interpreted lane already wrote.
    if hdir.join("covered-lines.txt").is_file() {
        return None;
    }
    // No recipe means no proof that coverage is built from the program that was
    // fuzzed. Report no measurement instead of producing a plausible but wrong
    // percentage. Cross-compiled recipes are rejected by `read_build_recipe`:
    // a host clang coverage build is not the target-platform program.
    let recipe = read_build_recipe(hdir)?;
    let _ = std::fs::remove_file(hdir.join(COVERAGE_DIAGNOSTIC_FILE));
    // Check for replay work before compiling a potentially large project-level
    // coverage archive. In particular, `--deps-only` writes a successful build
    // recipe but intentionally creates no corpus.
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let inputs: Vec<PathBuf> = std::fs::read_dir(&queue)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .take(MAX_INPUTS)
        .collect();
    if inputs.is_empty() {
        return None;
    }

    // A probe-built archive carries the primary fuzz lane's sanitizers and edge
    // instrumentation. Substitute the separately built source-coverage CMake
    // archive; passing the primary archive unchanged either fails on unresolved
    // sanitizer runtime symbols or silently omits the library from the coverage
    // denominator.
    let mut coverage_sources = recipe.extra_sources.clone();
    for source in &mut coverage_sources {
        if crate::auto::build_probe::is_probe_static_library(source) {
            let primary = source.clone();
            let Some(coverage) =
                crate::auto::build_probe::coverage_variant_for_probe_archive(&primary)
            else {
                write_coverage_diagnostic(
                    hdir,
                    &format!(
                        "could not recover the source-coverage counterpart of probe archive {}\n",
                        primary.display()
                    ),
                );
                return None;
            };
            *source = coverage;
        }
    }
    let bin = hdir.join("main_cov");
    // AUTO_EXTRA_SOURCES is not a Make prerequisite, so an old main_cov can look
    // up-to-date after the repair closure changes. Force this generated lane to
    // relink from the checkpointed recipe.
    let _ = std::fs::remove_file(&bin);
    let build_output = crate::build::try_run_c_make_build_with_target_and_ldflags(
        work_dir,
        harness_id,
        &coverage_sources,
        &recipe.extra_includes,
        None,
        Some("cov"),
        recipe.standard.as_deref(),
        Some("-lm -ldl -lpthread"),
    );
    if !build_output.status.success() || !bin.is_file() {
        write_coverage_diagnostic(
            hdir,
            &format!(
                "coverage harness build failed (status {}):\nstdout:\n{}\nstderr:\n{}\n",
                build_output.status,
                diagnostic_tail(&build_output.stdout),
                diagnostic_tail(&build_output.stderr)
            ),
        );
        return None;
    }
    let deadline = Instant::now() + REPLAY_BUDGET;
    let prof_dir = hdir.join("cov_profraw");
    let _ = std::fs::remove_dir_all(&prof_dir);
    if std::fs::create_dir_all(&prof_dir).is_err() {
        return None;
    }
    let mut replayed = 0usize;
    for (i, path) in inputs.into_iter().enumerate() {
        if replayed >= MAX_INPUTS || Instant::now() >= deadline {
            break;
        }
        replayed += 1;
        // Fresh process per input (argv[1]) so the profile flushes at exit.
        let completed = crate::command_output::output_with_timeout(
            replay_command(&bin).arg(path).env(
                "LLVM_PROFILE_FILE",
                prof_dir.join(format!("cov-{i}.profraw")),
            ),
            Duration::from_secs(15),
        )
        .map(|output| !matches!(output.status.code(), Some(124 | 137)))
        .unwrap_or(false);
        if !completed {
            return None;
        }
    }
    if replayed == 0 {
        return None;
    }

    // Merge the raw profiles, then export covered lines.
    let merged = hdir.join("cov.profdata");
    let raws: Vec<std::path::PathBuf> = std::fs::read_dir(&prof_dir)
        .map(|d| {
            d.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "profraw"))
                .collect()
        })
        .unwrap_or_default();
    if raws.is_empty() {
        return None;
    }
    let merge_ok = crate::command_output::output_with_timeout(
        Command::new(profdata)
            .arg("merge")
            .arg("-sparse")
            .args(&raws)
            .arg("-o")
            .arg(&merged),
        Duration::from_secs(300),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    if !merge_ok {
        return None;
    }
    let Ok(export) = crate::command_output::output_with_timeout(
        Command::new(cov)
            .args(["export", "--format=lcov"])
            .arg(format!("-instr-profile={}", merged.display()))
            .arg(&bin),
        Duration::from_secs(300),
    ) else {
        return None;
    };
    if !export.status.success() {
        return None;
    }
    let export_text = String::from_utf8_lossy(&export.stdout);
    if export_text.contains("[govfuzz: subprocess output truncated]") {
        gfeprintln!(
            "govfuzz: llvm-cov output for {harness_id} exceeded the bounded capture; \
             negative-confirmation coverage is partial"
        );
    }
    let measurement = parse_lcov_detailed(&export_text);
    let covered = measurement.covered;
    let instrumented = measurement.instrumented;
    let _ = std::fs::remove_dir_all(&prof_dir);
    if covered.is_empty() {
        return None;
    }
    // The denominator, next to the covered set. `1,400 lines covered` says
    // nothing without knowing whether the target has 2,000 or 200,000; the
    // zero-hit `DA:` records that carry it are dropped from the covered set, so
    // the count is recorded here, at the only place that sees them.
    let _ = std::fs::write(
        hdir.join("coverage-summary.json"),
        format!(
            "{{\n  \"harness_id\": \"{harness_id}\",\n  \"covered_lines\": {},\n  \
             \"instrumented_lines\": {instrumented}\n}}\n",
            covered.len()
        ),
    );
    if std::fs::write(hdir.join("covered-lines.txt"), covered.join("\n")).is_err() {
        return None;
    }
    run_expert_harness_oracle(
        hdir,
        harness_id,
        &recipe,
        &covered,
        instrumented,
        &measurement.instrumented_files,
        profdata,
        cov,
    );
    Some((covered.len(), instrumented))
}

#[derive(Debug, Serialize)]
struct ExpertOracleMeasurement {
    source: PathBuf,
    built: bool,
    covered_lines: usize,
    total_covered_lines: usize,
    instrumented_lines: usize,
    overlap_with_generated: usize,
    expert_only_lines: usize,
    generated_only_lines: usize,
    diagnostic: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExpertOracleReport {
    schema_version: u32,
    harness_id: String,
    target: String,
    generated_covered_lines: usize,
    generated_total_covered_lines: usize,
    generated_instrumented_lines: usize,
    best_expert: Option<PathBuf>,
    expert_covered_lines: usize,
    expert_total_covered_lines: usize,
    common_instrumented_files: usize,
    overlap_lines: usize,
    expert_only_lines: usize,
    generated_only_lines: usize,
    generated_to_expert_ratio: Option<f64>,
    verdict: String,
    semantic_merge_enabled: bool,
    expert_only_sample: Vec<String>,
    measurements: Vec<ExpertOracleMeasurement>,
}

#[allow(clippy::too_many_arguments)]
fn run_expert_harness_oracle(
    hdir: &Path,
    harness_id: &str,
    recipe: &CoverageBuildRecipe,
    generated_covered: &[String],
    generated_instrumented: usize,
    generated_instrumented_files: &std::collections::BTreeSet<String>,
    profdata: &str,
    cov: &str,
) {
    let Some((source_path, target)) = read_harness_target(hdir) else {
        return;
    };
    let Some(root) = coverage_project_root_of(&source_path) else {
        return;
    };
    let expert_sources = explicit_expert_harnesses()
        .unwrap_or_else(|| crate::auto::discovery::existing_harness_sources(&root));
    if expert_sources.is_empty() {
        return;
    }
    let generated = generated_covered
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let queue = hdir
        .parent()
        .and_then(Path::parent)
        .map(|work| work.join("corpus").join(harness_id).join("queue"));
    let Some(queue) = queue.filter(|path| path.is_dir()) else {
        return;
    };
    let mut measurements = Vec::new();
    let mut best_lines = std::collections::BTreeSet::new();
    let mut best_generated = std::collections::BTreeSet::new();
    let mut best_total_covered = 0usize;
    let mut best_common_files = 0usize;
    let mut best_source = None;
    for (index, expert) in expert_sources
        .into_iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .map(|text| expert_source_mentions_target(&text, &target))
                .unwrap_or(false)
        })
        .take(4)
        .enumerate()
    {
        match build_and_replay_expert(hdir, &expert, index, recipe, &root, &queue, profdata, cov) {
            Ok(expert_measurement) => {
                let total_covered = expert_measurement.covered.len();
                let mut common_files = expert_measurement
                    .instrumented_files
                    .intersection(generated_instrumented_files)
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
                // The repair closure is linked into both binaries, so generated
                // stubs can otherwise masquerade as comparable library code.
                // The oracle is about the project implementation, not govfuzz's
                // glue translation units.
                common_files.retain(|file| Path::new(file).starts_with(&root));
                // Prefer implementation translation units when both binaries
                // contain them. Header lines frequently belong to helper code
                // compiled into the expert harness itself (Expat's siphash.h),
                // not the library under test. Header-only C++ libraries have no
                // such common implementation file, so they retain header lines.
                let translation_units = common_files
                    .iter()
                    .filter(|file| is_native_translation_unit(file))
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
                if !translation_units.is_empty() {
                    common_files = translation_units;
                }
                let covered = expert_measurement
                    .covered
                    .into_iter()
                    .filter(|line| {
                        lcov_line_file(line).is_some_and(|file| common_files.contains(file))
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                let comparable_generated = generated
                    .iter()
                    .filter(|line| {
                        lcov_line_file(line).is_some_and(|file| common_files.contains(file))
                    })
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
                let overlap = covered.intersection(&comparable_generated).count();
                let expert_only = covered.difference(&comparable_generated).count();
                let generated_only = comparable_generated.difference(&covered).count();
                measurements.push(ExpertOracleMeasurement {
                    source: expert.clone(),
                    built: true,
                    covered_lines: covered.len(),
                    total_covered_lines: total_covered,
                    instrumented_lines: expert_measurement.instrumented,
                    overlap_with_generated: overlap,
                    expert_only_lines: expert_only,
                    generated_only_lines: generated_only,
                    diagnostic: None,
                });
                if covered.len() > best_lines.len() {
                    best_lines = covered;
                    best_generated = comparable_generated;
                    best_total_covered = total_covered;
                    best_common_files = common_files.len();
                    best_source = Some(expert);
                }
            }
            Err(diagnostic) => measurements.push(ExpertOracleMeasurement {
                source: expert,
                built: false,
                covered_lines: 0,
                total_covered_lines: 0,
                instrumented_lines: 0,
                overlap_with_generated: 0,
                expert_only_lines: 0,
                generated_only_lines: generated.len(),
                diagnostic: Some(diagnostic),
            }),
        }
    }
    if best_source.is_none() {
        best_generated = generated.clone();
        best_common_files = generated_instrumented_files.len();
    }
    let overlap = best_lines.intersection(&best_generated).count();
    let expert_only = best_lines.difference(&best_generated).count();
    let generated_only = best_generated.difference(&best_lines).count();
    let ratio =
        (!best_lines.is_empty()).then(|| best_generated.len() as f64 / best_lines.len() as f64);
    let verdict = if best_source.is_none() {
        "expert_build_unavailable"
    } else if expert_only == 0 && generated_only > 0 {
        "generated_exceeds_expert"
    } else if expert_only == 0 {
        "expert_parity"
    } else {
        "expert_has_marginal_coverage"
    };
    let report = ExpertOracleReport {
        schema_version: 1,
        harness_id: harness_id.to_owned(),
        target,
        generated_covered_lines: best_generated.len(),
        generated_total_covered_lines: generated.len(),
        generated_instrumented_lines: generated_instrumented,
        best_expert: best_source,
        expert_covered_lines: best_lines.len(),
        expert_total_covered_lines: best_total_covered,
        common_instrumented_files: best_common_files,
        overlap_lines: overlap,
        expert_only_lines: expert_only,
        generated_only_lines: generated_only,
        generated_to_expert_ratio: ratio,
        verdict: verdict.to_owned(),
        semantic_merge_enabled: true,
        expert_only_sample: best_lines
            .difference(&best_generated)
            .take(64)
            .cloned()
            .collect(),
        measurements,
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&report) {
        let _ = crate::auto::report::atomic_write(&hdir.join(EXPERT_ORACLE_FILE), &bytes);
    }
}

/// A benchmark may name the exact expert harness to compare against. This
/// avoids picking an incidental upstream fuzzer and lets a pinned suite keep
/// its human baseline outside the source tree, where recipe mining cannot see
/// it. Multiple native harnesses use the platform path-list separator.
fn explicit_expert_harnesses() -> Option<Vec<PathBuf>> {
    let value = std::env::var_os(EXPERT_HARNESS_ENV)?;
    let paths = std::env::split_paths(&value)
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    Some(paths)
}

/// Language-independent expert oracle input. A benchmark that already knows
/// how to execute its maintained harness (Atheris, Jazzer, go-fuzz, a Ruby
/// driver, and so on) can provide the resulting `<source>:<line>` set instead
/// of forcing this module to understand every ecosystem's build runner.
///
/// The environment value may be one file for a single-target run, or a
/// directory containing `<harness-id>.txt`/`<harness-id>/covered-lines.txt` for
/// a multi-target sweep. The portable sidecar deliberately has precedence over
/// the native compiler oracle because it is an explicit benchmark input.
fn explicit_expert_coverage(harness_id: &str) -> Option<PathBuf> {
    let configured = PathBuf::from(std::env::var_os(EXPERT_COVERAGE_ENV)?);
    if configured.is_file() {
        return Some(configured);
    }
    if !configured.is_dir() {
        return None;
    }
    [
        configured.join(format!("{harness_id}.txt")),
        configured.join(harness_id).join("covered-lines.txt"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn covered_line_set(path: &Path) -> Option<std::collections::BTreeSet<String>> {
    let lines = std::fs::read_to_string(path)
        .ok()?
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.rsplit_once(':')
                .is_some_and(|(file, number)| !file.is_empty() && number.parse::<u64>().is_ok())
        })
        .map(ToOwned::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    (!lines.is_empty()).then_some(lines)
}

fn covered_line_files(
    lines: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    lines
        .iter()
        .filter_map(|line| lcov_line_file(line).map(ToOwned::to_owned))
        .collect()
}

fn run_external_expert_coverage_oracle(hdir: &Path, harness_id: &str, expert_path: &Path) {
    let Some(generated) = covered_line_set(&hdir.join("covered-lines.txt")) else {
        return;
    };
    let Some(expert) = covered_line_set(expert_path) else {
        return;
    };
    let generated_files = covered_line_files(&generated);
    let expert_files = covered_line_files(&expert);
    let mut common_files = generated_files
        .intersection(&expert_files)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if let Some((source_path, _)) = read_harness_target(hdir) {
        if let Some(root) = coverage_project_root_of(&source_path) {
            common_files.retain(|file| Path::new(file).starts_with(&root));
        }
    }
    let translation_units = common_files
        .iter()
        .filter(|file| is_native_translation_unit(file))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if !translation_units.is_empty() {
        common_files = translation_units;
    }
    // No common file means the coordinate systems are incompatible, not that
    // both harnesses covered zero lines. Refuse a false parity result.
    if common_files.is_empty() {
        return;
    }
    let comparable_generated = generated
        .iter()
        .filter(|line| lcov_line_file(line).is_some_and(|file| common_files.contains(file)))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let comparable_expert = expert
        .iter()
        .filter(|line| lcov_line_file(line).is_some_and(|file| common_files.contains(file)))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if comparable_expert.is_empty() {
        return;
    }
    let overlap = comparable_expert
        .intersection(&comparable_generated)
        .count();
    let expert_only = comparable_expert.difference(&comparable_generated).count();
    let generated_only = comparable_generated.difference(&comparable_expert).count();
    let verdict = if expert_only == 0 && generated_only > 0 {
        "generated_exceeds_expert"
    } else if expert_only == 0 {
        "expert_parity"
    } else {
        "expert_has_marginal_coverage"
    };
    let generated_instrumented = std::fs::read(hdir.join("coverage-summary.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.get("instrumented_lines")?.as_u64())
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    let target = read_harness_target(hdir)
        .map(|(_, target)| target)
        .unwrap_or_default();
    let report = ExpertOracleReport {
        schema_version: 1,
        harness_id: harness_id.to_owned(),
        target,
        generated_covered_lines: comparable_generated.len(),
        generated_total_covered_lines: generated.len(),
        generated_instrumented_lines: generated_instrumented,
        best_expert: Some(expert_path.to_path_buf()),
        expert_covered_lines: comparable_expert.len(),
        expert_total_covered_lines: expert.len(),
        common_instrumented_files: common_files.len(),
        overlap_lines: overlap,
        expert_only_lines: expert_only,
        generated_only_lines: generated_only,
        generated_to_expert_ratio: Some(
            comparable_generated.len() as f64 / comparable_expert.len() as f64,
        ),
        verdict: verdict.to_owned(),
        semantic_merge_enabled: true,
        expert_only_sample: comparable_expert
            .difference(&comparable_generated)
            .take(64)
            .cloned()
            .collect(),
        measurements: vec![ExpertOracleMeasurement {
            source: expert_path.to_path_buf(),
            built: true,
            covered_lines: comparable_expert.len(),
            total_covered_lines: expert.len(),
            // A covered-only sidecar has no instrumentation denominator. Zero
            // means unknown here; it is never used as a 0% measurement.
            instrumented_lines: 0,
            overlap_with_generated: overlap,
            expert_only_lines: expert_only,
            generated_only_lines: generated_only,
            diagnostic: None,
        }],
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&report) {
        let _ = crate::auto::report::atomic_write(&hdir.join(EXPERT_ORACLE_FILE), &bytes);
    }
}

fn expert_source_mentions_target(source: &str, target: &str) -> bool {
    if source.contains(target) {
        return true;
    }
    let unqualified = target.split('(').next().unwrap_or(target).trim();
    let leaf = unqualified.rsplit("::").next().unwrap_or(unqualified);
    if leaf.is_empty() {
        return false;
    }
    let qualifier_leaf = unqualified
        .rsplit_once("::")
        .and_then(|(qualifier, _)| qualifier.rsplit("::").next());
    if qualifier_leaf.is_some_and(|class| !source.contains(class)) {
        return false;
    }
    source.match_indices(leaf).any(|(start, _)| {
        let before = source[..start].chars().next_back();
        let after = source[start + leaf.len()..].chars().next();
        let identifier_boundaries = !before
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        identifier_boundaries && source[start + leaf.len()..].trim_start().starts_with('(')
    })
}

fn read_harness_target(hdir: &Path) -> Option<(PathBuf, String)> {
    let bytes = std::fs::read(hdir.join("result.json")).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some((
        PathBuf::from(value.get("source_path")?.as_str()?),
        value.get("name")?.as_str()?.to_owned(),
    ))
}

/// Find the compilation/comparison root for a coverage oracle.
///
/// Recipe mining intentionally stops at the nearest `testing`/`fuzzing`
/// directory. That is useful for finding examples, but it is too narrow for an
/// expert harness's include path: RE2's source lives in `<repo>/re2/parse.cc`
/// beside `<repo>/re2/testing`, while `#include "re2/regexp.h"` requires the
/// repository root itself. Prefer the enclosing VCS boundary and otherwise the
/// nearest build manifest; retain the recipe root as a final fallback for
/// source snapshots without either marker.
fn coverage_project_root_of(source_path: &Path) -> Option<PathBuf> {
    let mut current = source_path.parent()?;
    let mut nearest_manifest = None;
    for _ in 0..16 {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        if nearest_manifest.is_none()
            && [
                "CMakeLists.txt",
                "meson.build",
                "configure.ac",
                "configure.in",
                "Cargo.toml",
                "go.mod",
                "pyproject.toml",
            ]
            .iter()
            .any(|marker| current.join(marker).is_file())
        {
            nearest_manifest = Some(current.to_path_buf());
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    nearest_manifest.or_else(|| crate::auto::recipe_mining::project_root_of(source_path))
}

/// Include roots from the exact generated C/C++ build context. The compact
/// coverage recipe persists repair inputs, while compile-database and inferred
/// include paths live in the generated Makefile. Expert harnesses must see both
/// or a transitive header tree (RE2's sibling Abseil checkout) can compile in
/// the generated lane and fail only in the comparison lane.
fn harness_context_include_dirs(hdir: &Path) -> Vec<PathBuf> {
    let Ok(makefile) = std::fs::read_to_string(hdir.join("Makefile")) else {
        return Vec::new();
    };
    let mut flags = Vec::new();
    for line in makefile.lines() {
        let value = line
            .strip_prefix("INCLUDES = ")
            .or_else(|| line.strip_prefix("COMPILE_DB_FLAGS = "));
        if let Some(value) = value {
            flags.extend(crate::generate_harness::split_compile_command(value));
        }
    }
    crate::generate_harness::include_dirs_from_compile_flags(&flags)
}

/// Project translation units compiled directly by the generated coverage
/// recipe. These are distinct from repair-time `extra_sources`: build-context
/// inference can put a whole source closure straight into the Makefile (Snappy
/// needs snappy-sinksource.cc and snappy-stubs-internal.cc beside snappy.cc).
/// The expert oracle must compile that same closure or it is measuring a build
/// failure rather than a harness-semantic difference.
fn harness_context_sources(hdir: &Path, project_root: &Path) -> Vec<PathBuf> {
    let Ok(makefile) = std::fs::read_to_string(hdir.join("Makefile")) else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    for line in makefile.lines().filter(|line| line.starts_with('\t')) {
        for token in crate::generate_harness::split_compile_command(line.trim()) {
            let path = PathBuf::from(&token);
            let native_source = path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| matches!(extension, "c" | "cc" | "cpp" | "cxx"));
            if native_source
                && path.is_absolute()
                && path.is_file()
                && path.starts_with(project_root)
                && !sources.contains(&path)
            {
                sources.push(path);
            }
        }
    }
    sources
}

#[allow(clippy::too_many_arguments)]
fn build_and_replay_expert(
    hdir: &Path,
    expert: &Path,
    index: usize,
    recipe: &CoverageBuildRecipe,
    project_root: &Path,
    queue: &Path,
    profdata: &str,
    cov: &str,
) -> Result<LcovMeasurement, String> {
    let extension = expert
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let cpp = matches!(extension, "cc" | "cpp" | "cxx");
    if !cpp && extension != "c" {
        return Err("expert oracle currently compiles native C/C++ harnesses".to_owned());
    }
    let source =
        std::fs::read_to_string(expert).map_err(|error| format!("read expert source: {error}"))?;
    let oracle_dir = hdir.join(format!("expert_oracle_{index}"));
    let _ = std::fs::remove_dir_all(&oracle_dir);
    std::fs::create_dir_all(&oracle_dir)
        .map_err(|error| format!("create expert oracle directory: {error}"))?;
    let driver = oracle_dir.join(if cpp { "driver.cc" } else { "driver.c" });
    let driver_source = if cpp {
        expert_driver_source(true)
    } else {
        expert_driver_source(false)
    };
    std::fs::write(&driver, driver_source)
        .map_err(|error| format!("write expert driver: {error}"))?;
    let binary = oracle_dir.join("expert_cov");
    let compiler = if cpp { "clang++" } else { "clang" };
    let mut command = Command::new(compiler);
    command.args([
        "-O0",
        "-g",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
        "-Wno-error",
    ]);
    if let Some(standard) = recipe.standard.as_deref() {
        command.arg(format!("-std={standard}"));
    }
    if cpp {
        for flag in crate::build::detect_cpp_stdlib_include_flags_for(compiler, &[]) {
            command.arg(flag);
        }
        if let Some(search_path) = crate::build::detect_libstdcxx_search_path() {
            command.arg(format!("-L{search_path}"));
        }
    }
    for definition in required_expert_definitions(&source) {
        command.arg(definition);
    }
    let mut includes = vec![project_root.to_path_buf()];
    if let Some(parent) = expert.parent() {
        includes.push(parent.to_path_buf());
    }
    for conventional in [
        project_root.join("include"),
        project_root.join("lib"),
        project_root.join("src"),
        project_root.join(".govfuzz-build"),
        project_root.join(".govfuzz-build-cov"),
        project_root.join(".govfuzz-build/include"),
        project_root.join(".govfuzz-build-cov/include"),
    ] {
        if conventional.is_dir() {
            includes.push(conventional);
        }
    }
    includes.extend(recipe.extra_includes.iter().cloned());
    includes.extend(harness_context_include_dirs(hdir));
    let mut seen_includes = std::collections::HashSet::new();
    includes.retain(|include| seen_includes.insert(include.clone()));
    for include in includes {
        command.arg("-I").arg(include);
    }
    command.arg(expert).arg(&driver);
    for support in expert_support_sources(expert) {
        command.arg(support);
    }
    // Without a probe archive, the generated Makefile compiles the selected
    // target translation unit directly. The expert build must do the same;
    // `recipe.extra_sources` contains only repaired/additional closure sources,
    // not that primary file (TinyXML2 otherwise fails with undefined methods).
    let primary_target_source = (!recipe
        .extra_sources
        .iter()
        .any(|source| crate::auto::build_probe::is_probe_static_library(source)))
    .then(|| read_harness_target(hdir).map(|(source, _)| source))
    .flatten();
    if let Some(target_source) = primary_target_source.as_ref() {
        if target_source.is_file()
            && target_source != expert
            && target_source
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| matches!(extension, "c" | "cc" | "cpp" | "cxx"))
        {
            command.arg(target_source);
        }
    }
    for source in harness_context_sources(hdir, project_root) {
        if source != expert
            && primary_target_source.as_ref() != Some(&source)
            && !recipe.extra_sources.contains(&source)
        {
            command.arg(source);
        }
    }
    for source in &recipe.extra_sources {
        let source = if crate::auto::build_probe::is_probe_static_library(source) {
            crate::auto::build_probe::coverage_variant_for_probe_archive(source)
                .ok_or_else(|| format!("no coverage variant for {}", source.display()))?
        } else {
            source.clone()
        };
        command.arg(source);
    }
    command
        .args(["-lm", "-ldl", "-lpthread", "-o"])
        .arg(&binary);
    let output = crate::command_output::output_with_timeout(&mut command, Duration::from_secs(300))
        .map_err(|error| format!("run expert compiler: {error}"))?;
    if !output.status.success() || !binary.is_file() {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "expert build failed: {}",
            diagnostic.chars().take(2000).collect::<String>()
        ));
    }
    replay_expert_coverage(hdir, &oracle_dir, &binary, queue, profdata, cov)
}

fn expert_driver_source(cpp: bool) -> String {
    let linkage = if cpp { "extern \"C\" " } else { "" };
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n\
         {linkage}int LLVMFuzzerTestOneInput(const uint8_t *, size_t);\n\
         int main(int argc, char **argv) {{\n\
           if (argc < 2) return 0; FILE *f = fopen(argv[1], \"rb\"); if (!f) return 1;\n\
           if (fseek(f, 0, SEEK_END)) return 1; long n = ftell(f); rewind(f);\n\
           if (n < 0) return 1; uint8_t *p = (uint8_t *)malloc((size_t)n + 1); if (!p) return 1;\n\
           size_t got = fread(p, 1, (size_t)n, f); fclose(f); p[got] = 0;\n\
           int rc = LLVMFuzzerTestOneInput(p, got); free(p); return rc;\n\
         }}\n"
    )
}

fn required_expert_definitions(source: &str) -> Vec<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut definitions = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim().trim_start_matches('#').trim();
        let Some(name) = trimmed.strip_prefix("ifndef ").map(str::trim) else {
            continue;
        };
        if !lines.iter().skip(index + 1).take(4).any(|next| {
            next.trim_start()
                .strip_prefix('#')
                .is_some_and(|directive| directive.trim_start().starts_with("error"))
        }) || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            continue;
        }
        let value = if name.to_ascii_uppercase().contains("ENCODING") {
            "UTF-8"
        } else {
            "1"
        };
        definitions.push(format!("-D{name}={value}"));
    }
    definitions
}

fn expert_support_sources(expert: &Path) -> Vec<PathBuf> {
    let Some(parent) = expert.parent() else {
        return Vec::new();
    };
    let mut sources = std::fs::read_dir(parent)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path != expert)
                .filter(|path| {
                    !path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.to_ascii_lowercase().contains("fuzz"))
                })
                .filter(|path| {
                    path.extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|extension| matches!(extension, "c" | "cc" | "cpp" | "cxx"))
                })
                .filter(|path| {
                    std::fs::read_to_string(path)
                        .map(|text| {
                            !text.contains("LLVMFuzzerTestOneInput")
                                && !text.contains("int main(")
                                && !text.contains("int\nmain(")
                        })
                        .unwrap_or(false)
                })
                .take(32)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    sources.sort();
    sources
}

fn replay_expert_coverage(
    hdir: &Path,
    oracle_dir: &Path,
    binary: &Path,
    queue: &Path,
    profdata: &str,
    cov: &str,
) -> Result<LcovMeasurement, String> {
    let input_dir = oracle_dir.join("inputs");
    let profile_dir = oracle_dir.join("profraw");
    std::fs::create_dir_all(&input_dir).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&profile_dir).map_err(|error| error.to_string())?;
    let control_len = sequence_control_len(hdir);
    let inputs = std::fs::read_dir(queue)
        .map_err(|error| format!("read corpus queue: {error}"))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .take(MAX_INPUTS)
        .collect::<Vec<_>>();
    let deadline = Instant::now() + REPLAY_BUDGET;
    let mut replayed = 0usize;
    for (index, input) in inputs.iter().enumerate() {
        if Instant::now() >= deadline {
            break;
        }
        let mut bytes = std::fs::read(input).map_err(|error| error.to_string())?;
        if control_len > 0 && bytes.len() >= control_len {
            bytes.truncate(bytes.len() - control_len);
        }
        let normalized = input_dir.join(format!("input-{index}"));
        std::fs::write(&normalized, bytes).map_err(|error| error.to_string())?;
        let output = crate::command_output::output_with_timeout(
            replay_command(binary).arg(&normalized).env(
                "LLVM_PROFILE_FILE",
                profile_dir.join(format!("expert-{index}.profraw")),
            ),
            Duration::from_secs(15),
        )
        .map_err(|error| format!("replay expert harness: {error}"))?;
        if matches!(output.status.code(), Some(124 | 137)) {
            return Err("expert harness timed out during corpus replay".to_owned());
        }
        replayed += 1;
    }
    if replayed == 0 {
        return Err("no corpus inputs replayed through expert harness".to_owned());
    }
    let raws = std::fs::read_dir(&profile_dir)
        .map_err(|error| error.to_string())?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|value| value == "profraw"))
        .collect::<Vec<_>>();
    if raws.is_empty() {
        return Err("expert replay produced no profiles".to_owned());
    }
    let merged = oracle_dir.join("expert.profdata");
    let merge = crate::command_output::output_with_timeout(
        Command::new(profdata)
            .arg("merge")
            .arg("-sparse")
            .args(&raws)
            .arg("-o")
            .arg(&merged),
        Duration::from_secs(300),
    )
    .map_err(|error| error.to_string())?;
    if !merge.status.success() {
        return Err("failed to merge expert coverage profiles".to_owned());
    }
    let export = crate::command_output::output_with_timeout(
        Command::new(cov)
            .args(["export", "--format=lcov"])
            .arg(format!("-instr-profile={}", merged.display()))
            .arg(binary),
        Duration::from_secs(300),
    )
    .map_err(|error| error.to_string())?;
    if !export.status.success() {
        return Err("failed to export expert coverage".to_owned());
    }
    Ok(parse_lcov_detailed(&String::from_utf8_lossy(
        &export.stdout,
    )))
}

fn sequence_control_len(hdir: &Path) -> usize {
    std::fs::read(hdir.join("sequence-layout.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.get("control_len")?.as_u64())
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0)
}

/// Coverage is a best-effort post-pass. Bound every replay so a target that hangs
/// after consuming its input cannot hold the complete auto campaign open.
fn replay_command(bin: &Path) -> Command {
    if which::which("timeout").is_ok() {
        let mut command = Command::new("timeout");
        command.arg("-s").arg("KILL").arg("10").arg(bin);
        command
    } else {
        Command::new(bin)
    }
}

/// Parse an LCOV export into the covered `<file>:<line>` set plus the number of
/// lines INSTRUMENTED — every `DA:` record, hit or not.
///
/// LCOV: `SF:<file>` opens a file section, `DA:<line>,<count>` is a line record.
///
/// Without the second number a coverage figure has no denominator: "1,400 lines"
/// is uninterpretable without knowing whether the target has 2,000 or 200,000.
/// The zero-hit records that carry it are exactly the ones the covered set
/// drops, so they are counted here, at the only place that sees them.
#[derive(Debug)]
struct LcovMeasurement {
    covered: Vec<String>,
    instrumented: usize,
    instrumented_files: std::collections::BTreeSet<String>,
}

#[cfg(test)]
fn parse_lcov(lcov: &str) -> (Vec<String>, usize) {
    let measurement = parse_lcov_detailed(lcov);
    (measurement.covered, measurement.instrumented)
}

fn parse_lcov_detailed(lcov: &str) -> LcovMeasurement {
    let mut out = Vec::new();
    let mut instrumented = 0usize;
    let mut instrumented_files = std::collections::BTreeSet::new();
    let mut file = String::new();
    for line in lcov.lines() {
        if line.contains("[govfuzz: subprocess output truncated]") {
            file.clear();
        } else if let Some(rest) = line.strip_prefix("SF:") {
            file = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("DA:") {
            let mut parts = rest.split(',');
            let (Some(line_no), Some(count)) = (parts.next(), parts.next()) else {
                continue;
            };
            if file.is_empty() {
                continue;
            }
            instrumented += 1;
            instrumented_files.insert(file.clone());
            let hit = count.trim().parse::<u64>().unwrap_or(0);
            if hit > 0 {
                out.push(format!("{file}:{}", line_no.trim()));
            }
        }
    }
    LcovMeasurement {
        covered: out,
        instrumented,
        instrumented_files,
    }
}

fn lcov_line_file(line: &str) -> Option<&str> {
    line.rsplit_once(':').map(|(file, _)| file)
}

fn is_native_translation_unit(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "c" | "cc" | "cpp" | "cxx" | "C"))
}

/// Resolve an llvm tool, preferring the versioned name available in this image
/// (`llvm-cov-18`) and falling back to the unversioned one.
fn llvm_tool(base: &str) -> Option<String> {
    [format!("{base}-18"), base.to_owned()]
        .into_iter()
        .find(|name| which::which(name).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcov_export_yields_only_executed_lines() {
        let lcov = "\
TN:\n\
SF:/proj/parse.c\n\
DA:4,0\n\
DA:5,12\n\
DA:6,3\n\
end_of_record\n\
SF:/proj/other.c\n\
DA:1,0\n\
end_of_record\n";
        let (covered, instrumented) = parse_lcov(lcov);
        assert_eq!(covered, vec!["/proj/parse.c:5", "/proj/parse.c:6"]);
        // The denominator counts every instrumented line, including the zero-hit
        // records the covered set drops. Without it, "2 lines covered" cannot be
        // turned into a coverage figure.
        assert_eq!(
            instrumented, 4,
            "all four DA records are instrumented lines, hit or not"
        );
    }

    #[test]
    fn a_wholly_unexecuted_file_still_contributes_to_the_denominator() {
        // The pathological case the old covered-only parse hid: a target whose
        // corpus reached nothing at all reported an empty set and no scale, so
        // "0 lines" and "no coverage build" were indistinguishable.
        let lcov = "\
TN:\n\
SF:/proj/never.c\n\
DA:1,0\n\
DA:2,0\n\
DA:3,0\n\
end_of_record\n";
        let (covered, instrumented) = parse_lcov(lcov);
        assert!(covered.is_empty());
        assert_eq!(instrumented, 3);
    }

    #[test]
    fn successful_repair_build_recipe_round_trips_exact_inputs() {
        let root = tempfile::tempdir().unwrap();
        let harness = root.path().join("harness");
        std::fs::create_dir_all(&harness).unwrap();
        let sources = vec![
            PathBuf::from("/project/parser.c"),
            PathBuf::from("/repair/stub.c"),
        ];
        let includes = vec![
            PathBuf::from("/project/include"),
            PathBuf::from("/repair/include"),
        ];

        persist_build_recipe(
            &harness,
            &sources,
            &includes,
            Some("gnu11".to_owned()),
            true,
        );
        let recipe = read_build_recipe(&harness).expect("native recipe");

        assert_eq!(recipe.extra_sources, sources);
        assert_eq!(recipe.extra_includes, includes);
        assert_eq!(recipe.standard.as_deref(), Some("gnu11"));
    }

    #[test]
    fn cross_build_recipe_is_not_replayed_as_host_coverage() {
        let root = tempfile::tempdir().unwrap();
        persist_build_recipe(root.path(), &[], &[], None, false);
        assert!(read_build_recipe(root.path()).is_none());
    }

    #[test]
    fn coverage_oracle_uses_repo_root_above_nested_testing_directory() {
        let fixture = tempfile::tempdir().unwrap();
        let repo = fixture.path().join("re2");
        let source = repo.join("re2/parse.cc");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("re2/testing")).unwrap();
        std::fs::write(&source, "// parse\n").unwrap();

        assert_eq!(
            coverage_project_root_of(&source).as_deref(),
            Some(repo.as_path())
        );
    }

    #[test]
    fn expert_oracle_recovers_generated_compile_context_include_roots() {
        let harness = tempfile::tempdir().unwrap();
        std::fs::write(
            harness.path().join("Makefile"),
            "INCLUDES = -I . -iquote /project/re2 -idirafter /project/re2\n\
             COMPILE_DB_FLAGS = -I /project -I /deps/abseil -fPIC\n",
        )
        .unwrap();

        assert_eq!(
            harness_context_include_dirs(harness.path()),
            vec![
                PathBuf::from("."),
                PathBuf::from("/project/re2"),
                PathBuf::from("/project"),
                PathBuf::from("/deps/abseil"),
            ]
        );
    }

    #[test]
    fn expert_oracle_recovers_direct_source_closure_from_makefile() {
        let project = tempfile::tempdir().unwrap();
        let harness = tempfile::tempdir().unwrap();
        let primary = project.path().join("snappy.cc");
        let support = project.path().join("snappy-sinksource.cc");
        std::fs::write(&primary, "// primary\n").unwrap();
        std::fs::write(&support, "// support\n").unwrap();
        std::fs::write(
            harness.path().join("Makefile"),
            format!(
                "main_cov:\n\t$(COV_CXX) -o $@ main.cpp {} {} $(AUTO_EXTRA_SOURCES)\n",
                primary.display(),
                support.display()
            ),
        )
        .unwrap();

        assert_eq!(
            harness_context_sources(harness.path(), project.path()),
            vec![primary, support]
        );
    }

    #[test]
    fn a_fraction_needs_a_denominator() {
        // "0%" and "nothing was instrumented" are different statements, and
        // reporting the second as the first is how a broken coverage build gets
        // mistaken for a target the fuzzer failed to reach.
        let nothing = CoverageTotals::default();
        assert_eq!(nothing.fraction(), None);

        let measured = CoverageTotals {
            harnesses: 2,
            covered_lines: 589,
            instrumented_lines: 2458,
            ..CoverageTotals::default()
        };
        let fraction = measured.fraction().expect("instrumented lines present");
        assert!((fraction - 0.2396).abs() < 0.001, "got {fraction}");
    }

    #[test]
    fn expert_required_macro_and_sequence_tail_are_normalized() {
        let definitions = required_expert_definitions(
            "#ifndef ENCODING_FOR_FUZZING\n#  error required\n#endif\n",
        );
        assert_eq!(definitions, ["-DENCODING_FOR_FUZZING=UTF-8"]);

        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("sequence-layout.json"),
            r#"{"control_len":42,"portfolio_lanes":4}"#,
        )
        .unwrap();
        assert_eq!(sequence_control_len(root.path()), 42);
    }

    #[test]
    fn cpp_expert_harness_matches_a_qualified_signature_by_class_and_call() {
        let expert = r#"
            #include "tinyxml2.h"
            int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
                tinyxml2::XMLDocument document;
                return document.Parse(reinterpret_cast<const char *>(data), size);
            }
        "#;
        assert!(expert_source_mentions_target(
            expert,
            "tinyxml2::XMLDocument::Parse(const char *, size_t)"
        ));
        assert!(!expert_source_mentions_target(
            "OtherDocument document; document.Parse(data);",
            "tinyxml2::XMLDocument::Parse(const char *, size_t)"
        ));
    }

    #[test]
    fn portable_expert_coverage_compares_interpreted_line_sidecars() {
        let root = tempfile::tempdir().unwrap();
        let harness = root.path().join("H-PY001-00000001");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(
            harness.join("result.json"),
            r#"{"source_path":"/project/parser.py","name":"parse"}"#,
        )
        .unwrap();
        std::fs::write(
            harness.join("covered-lines.txt"),
            "/project/parser.py:10\n/project/parser.py:11\n/project/parser.py:13\n",
        )
        .unwrap();
        let expert = root.path().join("expert-covered-lines.txt");
        std::fs::write(
            &expert,
            "/project/parser.py:10\n/project/parser.py:11\n/project/parser.py:12\n",
        )
        .unwrap();

        run_external_expert_coverage_oracle(&harness, "H-PY001-00000001", &expert);

        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(harness.join(EXPERT_ORACLE_FILE)).unwrap())
                .unwrap();
        assert_eq!(report["target"], "parse");
        assert_eq!(report["verdict"], "expert_has_marginal_coverage");
        assert_eq!(report["overlap_lines"], 2);
        assert_eq!(report["expert_only_lines"], 1);
        assert_eq!(report["generated_only_lines"], 1);
        assert_eq!(report["common_instrumented_files"], 1);
        assert_eq!(report["generated_instrumented_lines"], 0);
    }

    #[test]
    fn portable_expert_coverage_refuses_disjoint_file_coordinates() {
        let root = tempfile::tempdir().unwrap();
        let harness = root.path().join("H-PY002-00000002");
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(harness.join("covered-lines.txt"), "/auto/parser.py:10\n").unwrap();
        let expert = root.path().join("expert-covered-lines.txt");
        std::fs::write(&expert, "/expert/parser.py:10\n").unwrap();

        run_external_expert_coverage_oracle(&harness, "H-PY002-00000002", &expert);

        assert!(!harness.join(EXPERT_ORACLE_FILE).exists());
    }
}
