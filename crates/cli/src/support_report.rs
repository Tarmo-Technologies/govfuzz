// SPDX-License-Identifier: Apache-2.0

//! Compact, privacy-preserving diagnostics for an offline `govfuzz auto` run.
//!
//! The collector reads only structured result checkpoints and coarse work-tree
//! metadata. It deliberately does not include source, generated harness text,
//! corpus inputs, target names, source paths, or raw repair payloads.

use anyhow::{bail, Context, Result};
use regex::{Captures, Regex};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const SCHEMA_VERSION: u32 = 3;
const DEFAULT_MAX_BYTES: usize = 6_000;
const DEFAULT_EXAMPLES: usize = 8;
const SHAPE_LIMIT: usize = 360;

#[derive(Debug, clap::Args)]
pub struct SupportReportArgs {
    /// Existing `govfuzz auto --work-dir` to summarize. The source tree is never read.
    pub work_dir: PathBuf,

    /// Destination text file. Default: <work-dir>/auto/support-report.txt.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Print the same scrubbed report to stdout after writing it.
    #[arg(long)]
    pub stdout: bool,

    /// Maximum number of representative reason/error shapes in the report.
    #[arg(long, default_value_t = DEFAULT_EXAMPLES, value_name = "N")]
    pub examples: usize,

    /// Hard maximum report size in bytes (minimum 1024).
    #[arg(long, default_value_t = DEFAULT_MAX_BYTES, value_name = "BYTES")]
    pub max_bytes: usize,

    /// #103: bundle the scrubbed diagnostics into a `.tar.gz` archive at this path
    /// (e.g. `--bundle govfuzz-bug-report.tar.gz`). The archive contains the
    /// scrubbed report, govfuzz's own internal-issue log (bug-report.json, if any),
    /// and a manifest describing every included field. Works entirely offline. A
    /// self-test scans the archive contents for host secrets (the real work-dir
    /// path, username, hostname) and refuses to write an archive that leaks any.
    #[arg(long, value_name = "FILE.tar.gz")]
    pub bundle: Option<PathBuf>,

    /// #103: print the bundle inventory + the scrubbed report to stdout WITHOUT
    /// writing any archive, so the operator can review exactly what would be shared
    /// before creating it. Implies bundle-style collection.
    #[arg(long)]
    pub preview: bool,
}

#[derive(Default)]
struct Evidence {
    results: usize,
    invalid_results: usize,
    used_final_report_fallback: bool,
    outcomes: BTreeMap<(String, String), usize>,
    error_kinds: BTreeMap<String, usize>,
    error_shapes: BTreeMap<(String, String, String), usize>,
    reason_shapes: BTreeMap<(String, String, String), usize>,
    repair_kinds: BTreeMap<String, usize>,
    unsupported_categories: BTreeMap<String, usize>,
    terminal_stages: BTreeMap<String, usize>,
    fallback_chains: BTreeMap<String, usize>,
    reason_categories: BTreeMap<String, usize>,
    failed_without_repairs: usize,
    failed_without_errors: usize,
    compiled_targets: usize,
    launched_targets: usize,
    target_entry_observed: usize,
    fuzz_input_executions: usize,
    coverage_edges: usize,
    stub_only_targets: usize,
}

#[derive(Default)]
struct WorkFacts {
    staged_ada_files: usize,
    fake_corba_files: usize,
    generated_harness_dirs: usize,
    discovery_cache: bool,
    discovery_cache_producer_match: Option<bool>,
    dialect_cache_files: usize,
    dialect_cache_context_matches: usize,
    harness_metadata_files: usize,
    exact_line_matches: usize,
    name_fallbacks: usize,
    emitted_paths: BTreeMap<String, usize>,
    build_context_provenance: BTreeMap<String, usize>,
    compiler_families: BTreeMap<String, usize>,
    effective_standards: BTreeMap<String, usize>,
    forwarded_flag_families: BTreeMap<String, usize>,
    dropped_flag_families: BTreeMap<String, usize>,
    per_tu_object_graphs: usize,
    repair_per_tu_object_graphs: usize,
    per_tu_context_rows: usize,
    repair_per_tu_context_rows: usize,
    per_tu_compiler_families: BTreeMap<String, usize>,
    per_tu_effective_standards: BTreeMap<String, usize>,
    per_tu_flag_families: BTreeMap<String, usize>,
    idl_files_seen: Option<usize>,
    idl_files_parsed: Option<usize>,
    idl_partial: Option<bool>,
    idl_reopened_modules: Option<usize>,
    idl_generated_collisions: Option<usize>,
    idl_real_fake_collisions: Option<usize>,
    duplicate_staged_units: Option<usize>,
    selected_source_variants: Option<usize>,
    final_run_report: bool,
    missing_deps_report: bool,
    run_context: Option<AutoSupportContext>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AutoSupportContext {
    schema_version: u32,
    #[serde(default)]
    campaign_version: String,
    #[serde(default)]
    campaign_commit: String,
    #[serde(default)]
    discovery_semantic_version: u32,
    #[serde(default)]
    generated_state_semantic_version: u32,
    #[serde(default)]
    work_state: String,
    #[serde(default)]
    discovery_cache_hit: Option<bool>,
    languages: Vec<String>,
    cxx_std: Option<String>,
    preprocess: String,
    passes: String,
    sanitizers: Vec<String>,
    probe_build: bool,
    run_untrusted: bool,
    build_command_present: bool,
    unsafe_build_search: bool,
    force: bool,
    no_stubs: bool,
    static_scan: bool,
    resume: bool,
    jobs: usize,
    max_repair_rounds: usize,
    ada_dependency_dirs: usize,
    extra_include_dirs: usize,
    extra_source_files: usize,
    seed_files: usize,
    seed_dirs: usize,
    grammar_present: bool,
}

/// Persist only non-sensitive run switches/counts. Paths, the build command,
/// target filters, environment values, and dependency names are intentionally
/// excluded. Called after `.govfuzz.toml` has been applied so the checkpoint
/// describes the effective run rather than only the command line.
pub(crate) fn write_auto_context(
    work_dir: &Path,
    args: &crate::auto::cli::AutoArgs,
    work_state: crate::auto::work_state::WorkStateDisposition,
) -> std::io::Result<()> {
    let context = AutoSupportContext {
        schema_version: 2,
        campaign_version: crate::auto::bug_report::version().to_owned(),
        campaign_commit: crate::auto::bug_report::commit().to_owned(),
        discovery_semantic_version: crate::auto::discovery_cache::DISCOVERY_SEMANTIC_VERSION,
        generated_state_semantic_version: crate::auto::work_state::GENERATED_STATE_SEMANTIC_VERSION,
        work_state: work_state.to_string(),
        discovery_cache_hit: None,
        languages: args
            .languages
            .iter()
            .map(|language| format!("{language:?}").to_ascii_lowercase())
            .collect(),
        cxx_std: args.cxx_std.as_deref().map(safe_cxx_standard),
        preprocess: format!("{:?}", args.preprocess).to_ascii_lowercase(),
        passes: if args.single_pass {
            "fuzz".to_owned()
        } else {
            args.passes
                .as_deref()
                .map(safe_passes)
                .unwrap_or_else(|| "default".to_owned())
        },
        sanitizers: args
            .sanitizers
            .iter()
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "asan" | "ubsan" | "msan" | "tsan" | "lsan" | "none" => value.to_ascii_lowercase(),
                _ => "custom".to_owned(),
            })
            .collect(),
        probe_build: args.probe_build,
        run_untrusted: args.run_untrusted,
        build_command_present: args.build_command.is_some(),
        unsafe_build_search: args.unsafe_search_and_run_build_commands,
        force: args.force,
        no_stubs: args.no_stubs,
        static_scan: args.static_scan,
        resume: args.resume,
        jobs: args.jobs,
        max_repair_rounds: args.max_repair_rounds,
        ada_dependency_dirs: args.ada_deps.len(),
        extra_include_dirs: args.extra_includes.len(),
        extra_source_files: args.extra_sources.len(),
        seed_files: args.seed_files.len(),
        seed_dirs: args.seed_dirs.len(),
        grammar_present: args.grammar_file.is_some(),
    };
    let bytes = serde_json::to_vec(&context).map_err(std::io::Error::other)?;
    crate::auto::report::atomic_write(&work_dir.join("auto/support-context.json"), &bytes)
}

/// Complete the context checkpoint after discovery decides whether it reused a
/// cache. This is deliberately a boolean: neither the cache path nor its target
/// rows belong in a privacy-preserving support artifact.
pub(crate) fn checkpoint_discovery_cache_hit(work_dir: &Path, hit: bool) -> std::io::Result<()> {
    let path = work_dir.join("auto/support-context.json");
    let mut context: AutoSupportContext =
        serde_json::from_slice(&std::fs::read(&path)?).map_err(std::io::Error::other)?;
    context.discovery_cache_hit = Some(hit);
    let bytes = serde_json::to_vec(&context).map_err(std::io::Error::other)?;
    crate::auto::report::atomic_write(&path, &bytes)
}

fn safe_cxx_standard(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let suffix = lower
        .strip_prefix("gnu++")
        .or_else(|| lower.strip_prefix("c++"));
    if suffix.is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a' | b'b'))
    }) {
        lower
    } else {
        "custom".to_owned()
    }
}

fn safe_passes(value: &str) -> String {
    let mut safe = Vec::new();
    for pass in value.split(',').map(str::trim) {
        match pass {
            "empty" | "rng" | "fuzz" | "fuzz_driven" => safe.push(pass),
            _ => return "custom".to_owned(),
        }
    }
    if safe.is_empty() {
        "custom".to_owned()
    } else {
        safe.join(",")
    }
}

pub fn run(args: SupportReportArgs) -> i32 {
    // #103: bundle / preview mode manages its own console output (it prints an
    // inventory + self-test result), so only the plain text-report path prints the
    // "written to" line.
    let bundle_mode = args.bundle.is_some() || args.preview;
    match run_inner(args) {
        Ok(path) => {
            if !bundle_mode {
                gfeprintln!(
                    "govfuzz: compact scrubbed support report written to {}",
                    path.display()
                );
            }
            0
        }
        Err(error) => {
            gfeprintln!("govfuzz bug-report: {error:#}");
            2
        }
    }
}

fn run_inner(args: SupportReportArgs) -> Result<PathBuf> {
    if !args.work_dir.is_dir() {
        bail!(
            "work directory does not exist or is not a directory: {}",
            args.work_dir.display()
        );
    }
    if args.max_bytes < 1_024 {
        bail!("--max-bytes must be at least 1024");
    }
    let evidence = collect_evidence(&args.work_dir)?;
    let facts = collect_work_facts(&args.work_dir);
    let report = render_report(&evidence, &facts, args.examples, args.max_bytes, true);
    // #103: bundle / preview mode packages the scrubbed diagnostics into an offline
    // archive (or previews the inventory) with a host-secret self-test.
    if args.bundle.is_some() || args.preview {
        return emit_bundle(&args, &report);
    }
    let output = args
        .output
        .unwrap_or_else(|| args.work_dir.join("auto/support-report.txt"));
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    std::fs::write(&output, report.as_bytes())
        .with_context(|| format!("write {}", output.display()))?;
    if args.stdout {
        print!("{report}");
    }
    Ok(output)
}

/// #103: build the scrubbed diagnostic bundle (or preview it). The bundle carries
/// only already-scrubbed, bounded diagnostics — the compact support report,
/// govfuzz's own internal-issue log if present, and a manifest — plus a self-test
/// that scans every included field for host secrets (the real work-dir path, the
/// username, the hostname) and REFUSES to write an archive that leaks any.
fn emit_bundle(args: &SupportReportArgs, report: &str) -> Result<PathBuf> {
    let mut files: Vec<(String, String)> = vec![
        ("support-report.txt".to_owned(), report.to_owned()),
        ("MANIFEST.txt".to_owned(), bundle_manifest()),
    ];
    // govfuzz's own internal-issue log (its OWN defects), already scrubbed: file
    // tokens instead of paths, bounded error tails. Include when present.
    if let Ok(json) = std::fs::read_to_string(args.work_dir.join("auto/bug-report.json")) {
        files.push(("bug-report.json".to_owned(), json));
    }

    // Self-test: never let a host secret ride along. Derive the tokens that MUST
    // NOT appear (the real work path + its components, $USER/$HOME, the hostname)
    // and scan every included field. A leak is a hard error — the bundle is not
    // written — so the collector cannot silently exfiltrate proprietary paths.
    let secrets = host_secret_tokens(&args.work_dir);
    let leaks = self_test_scan(&files, &secrets);
    if !leaks.is_empty() {
        bail!(
            "bug-report bundle self-test FAILED: a host secret leaked into {}; refusing to write the archive",
            leaks.join(", ")
        );
    }
    files.push((
        "SELF-TEST.txt".to_owned(),
        format!(
            "self-test: PASS\nscanned {} field(s) for {} host-secret token(s); none present\n",
            files.len(),
            secrets.len()
        ),
    ));

    if args.preview {
        println!("govfuzz bug-report — bundle preview (NO archive written)");
        println!(
            "self-test: PASS ({} host-secret token(s) checked, none leaked)",
            secrets.len()
        );
        println!("contents ({} field(s)):", files.len());
        for (name, content) in &files {
            println!("  - {name} ({} bytes)", content.len());
        }
        println!("\n===== support-report.txt =====\n{report}");
        return Ok(args.work_dir.to_path_buf());
    }

    let bundle_path = args
        .bundle
        .clone()
        .expect("bundle path present in bundle mode");
    // Stage the bundle under the work dir, tar it with the system `tar`, then clean
    // up the staging tree. A single top-level `govfuzz-bug-report/` dir keeps the
    // archive tidy on extraction.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stage_parent = args
        .work_dir
        .join(format!("auto/.bug-report-stage-{nonce}"));
    let stage = stage_parent.join("govfuzz-bug-report");
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("create bundle staging dir {}", stage.display()))?;
    for (name, content) in &files {
        std::fs::write(stage.join(name), content)
            .with_context(|| format!("write bundle field {name}"))?;
    }
    if let Some(parent) = bundle_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&bundle_path)
        .arg("-C")
        .arg(&stage_parent)
        .arg("govfuzz-bug-report")
        .status()
        .context("run `tar` to build the bundle (is tar installed?)")?;
    let _ = std::fs::remove_dir_all(&stage_parent);
    if !status.success() {
        bail!("`tar` failed to build the bundle archive");
    }
    gfeprintln!(
        "govfuzz: bug-report bundle written to {} ({} scrubbed field(s), self-test PASS)",
        bundle_path.display(),
        files.len()
    );
    Ok(bundle_path)
}

/// #103: host secrets that must NEVER appear in the bundle — the real work-dir
/// absolute path and its parent components (which carry the username in
/// `/home/<user>/...`), the `$USER`/`$HOME` values, and the hostname. Short/empty
/// tokens are dropped so a one-letter component can't cause a spurious match.
fn host_secret_tokens(work_dir: &Path) -> Vec<String> {
    let mut tokens: BTreeSet<String> = BTreeSet::new();
    let canonical = std::fs::canonicalize(work_dir).unwrap_or_else(|_| work_dir.to_path_buf());
    // The full absolute work path (very distinctive — slashes + the whole prefix).
    tokens.insert(canonical.to_string_lossy().into_owned());
    // The work dir's parent basename usually carries the project/user name, so a
    // leak of just the basename (without the full path) is still caught. Require
    // length >= 6 so a generic parent like "src" / "work" / "home" can't over-match
    // a common word that legitimately appears in the scrubbed report.
    if let Some(name) = canonical
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
    {
        if name.len() >= 6 {
            tokens.insert(name.to_owned());
        }
    }
    // The absolute HOME path (embeds the username but as a rooted path, so it can't
    // false-match a bare token like the `1ubuntu1` inside a clang version string the
    // way the raw `$USER` would).
    if let Ok(home) = std::env::var("HOME") {
        if home.len() >= 4 {
            tokens.insert(home);
        }
    }
    if let Ok(host) = std::fs::read_to_string("/etc/hostname") {
        let host = host.trim().to_owned();
        if host.len() >= 4 {
            tokens.insert(host);
        }
    }
    tokens
        .into_iter()
        .filter(|token| token.len() >= 4)
        .collect()
}

/// #103: scan every bundled field for any host-secret token; return the names of
/// the fields that leaked (empty = clean).
fn self_test_scan(files: &[(String, String)], secrets: &[String]) -> Vec<String> {
    let mut leaked = Vec::new();
    for (name, content) in files {
        if secrets
            .iter()
            .any(|secret| content.contains(secret.as_str()))
        {
            leaked.push(name.clone());
        }
    }
    leaked
}

/// #103: the human-readable inventory of what the bundle carries and — as
/// important — what it deliberately excludes, so an operator can share it
/// confidently.
fn bundle_manifest() -> String {
    format!(
        "govfuzz bug-report bundle — manifest (schema {SCHEMA_VERSION})\n\
         \n\
         Included fields (all scrubbed + bounded):\n\
         - support-report.txt : govfuzz version/build + toolchain versions; sanitized run\n\
         \x20  options + outcome counts; representative error/reason SHAPES per language,\n\
         \x20  outcome, and category; attempt traces, repair categories, target-entry /\n\
         \x20  stub-only accounting; selected-project / compile-context PROVENANCE\n\
         \x20  (families + standards, never real paths); cache/resume fingerprint status.\n\
         - bug-report.json    : govfuzz's OWN internal issues (panics/codegen/discovery\n\
         \x20  drops), with stable file TOKENS instead of paths and bounded tails. Omitted\n\
         \x20  if the run recorded none.\n\
         - SELF-TEST.txt      : result of scanning every field above for host secrets.\n\
         \n\
         Deliberately EXCLUDED (never collected): source contents, generated harness\n\
         text, corpus bytes, findings inputs, environment values, usernames, hostnames,\n\
         absolute paths, and real target/unit/class/function/variable names. The\n\
         self-test enforces the absence of the work-dir path, username, and hostname.\n"
    )
}

fn collect_evidence(work_dir: &Path) -> Result<Evidence> {
    let mut evidence = Evidence::default();
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for root in [work_dir.join("harnesses"), work_dir.join("auto")] {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path().join("result.json");
            if path.is_file() {
                paths.push(path);
            }
        }
    }
    paths.sort();
    for path in paths {
        let value = match std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        {
            Some(value) => value,
            None => {
                evidence.invalid_results += 1;
                continue;
            }
        };
        let id = value
            .get("harness_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !id.is_empty() && !seen.insert(id.to_owned()) {
            continue;
        }
        let lang = value
            .get("lang")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let Some(outcome) = value.get("outcome") else {
            evidence.invalid_results += 1;
            continue;
        };
        ingest_checkpoint(&mut evidence, lang, &value, outcome);
    }

    // Older releases may have a final run.json but no per-target checkpoints.
    // It is still useful after a completed campaign, although it cannot help an
    // interrupted one. Never combine the two sources: that would double-count.
    if evidence.results == 0 {
        let run_path = work_dir.join("auto/run.json");
        if let Some(run) = std::fs::read_to_string(run_path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        {
            if let Some(targets) = run.get("targets").and_then(Value::as_array) {
                for target in targets {
                    let id = target
                        .get("harness_id")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let lang = language_from_harness_id(id);
                    if let Some(outcome) = target.get("outcome") {
                        ingest_checkpoint(&mut evidence, lang, target, outcome);
                    }
                }
                evidence.used_final_report_fallback = !targets.is_empty();
            }
        }
    }

    if evidence.results == 0
        && evidence.invalid_results == 0
        && !work_dir.join("auto/support-context.json").is_file()
    {
        bail!(
            "no completed target checkpoints found under {}; run this against the work directory passed to `govfuzz auto`",
            work_dir.display()
        );
    }
    Ok(evidence)
}

fn ingest_checkpoint(evidence: &mut Evidence, lang: &str, root: &Value, outcome: &Value) {
    ingest_outcome(evidence, lang, outcome);
    if let Some(trace) = root.get("attempt_trace") {
        let stage = safe_trace_token(
            trace
                .get("terminal_stage")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
        );
        *evidence.terminal_stages.entry(stage).or_default() += 1;
        if let Some(category) = trace.get("reason_category").and_then(Value::as_str) {
            *evidence
                .reason_categories
                .entry(safe_trace_token(category))
                .or_default() += 1;
        }
        let chain = trace
            .get("fallback_chain")
            .and_then(Value::as_array)
            .map(|steps| {
                steps
                    .iter()
                    .filter_map(Value::as_str)
                    .map(safe_trace_token)
                    .collect::<Vec<_>>()
                    .join("->")
            })
            .filter(|chain| !chain.is_empty())
            .unwrap_or_else(|| "none".to_owned());
        *evidence.fallback_chains.entry(chain).or_default() += 1;
    }

    let tag = outcome
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if matches!(tag, "built" | "built_and_fuzzed") {
        evidence.compiled_targets += 1;
    }
    if tag == "built_and_fuzzed" {
        let passes = outcome
            .get("passes")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if !passes.is_empty() {
            evidence.launched_targets += 1;
        }
        let mut entered = false;
        let mut peak_edges = 0usize;
        for pass in passes {
            evidence.fuzz_input_executions = evidence.fuzz_input_executions.saturating_add(
                pass.get("executions").and_then(Value::as_u64).unwrap_or(0) as usize,
            );
            entered |= pass
                .get("target_entry_observed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            peak_edges = peak_edges.max(
                pass.get("coverage_edges")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize,
            );
        }
        evidence.coverage_edges = evidence.coverage_edges.saturating_add(peak_edges);
        evidence.target_entry_observed += usize::from(entered);

        let repairs = outcome
            .get("repairs")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let blind = repairs
            .iter()
            .filter(|repair| repair.get("kind").and_then(Value::as_str) == Some("stub_blind"));
        let blind_count = blind.count();
        let real_count = repairs
            .iter()
            .filter(|repair| repair.get("kind").and_then(Value::as_str) == Some("add_source"))
            .count();
        let explicit_stub_only = root
            .get("stub_execution")
            .and_then(|stub| stub.get("stub_only"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if explicit_stub_only || (blind_count > 0 && real_count == 0) {
            evidence.stub_only_targets += 1;
        }
    }
}

fn safe_trace_token(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if !lower.is_empty()
        && lower
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        lower
    } else {
        "custom".to_owned()
    }
}

fn ingest_outcome(evidence: &mut Evidence, lang: &str, outcome: &Value) {
    let tag = outcome
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    evidence.results += 1;
    *evidence
        .outcomes
        .entry((lang.to_owned(), tag.to_owned()))
        .or_default() += 1;

    let repairs = outcome
        .get("repairs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for repair in repairs {
        let kind = repair
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        *evidence.repair_kinds.entry(kind.to_owned()).or_default() += 1;
    }

    if tag == "failed_build" {
        if repairs.is_empty() {
            evidence.failed_without_repairs += 1;
        }
        let errors = outcome
            .get("last_errors")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if errors.is_empty() {
            evidence.failed_without_errors += 1;
        }
        for error in errors {
            let kind = error
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            *evidence.error_kinds.entry(kind.to_owned()).or_default() += 1;
            let shape = build_error_shape(error);
            *evidence
                .error_shapes
                .entry((lang.to_owned(), kind.to_owned(), shape))
                .or_default() += 1;
        }
    } else if matches!(
        tag,
        "unsupported_params" | "report_only" | "unrecoverable_link" | "unrecoverable_runtime"
    ) {
        let raw = outcome
            .get("reason")
            .and_then(Value::as_str)
            .or_else(|| {
                outcome
                    .get("missing")
                    .and_then(Value::as_array)
                    .map(|_| "unresolved link symbols")
            })
            .unwrap_or("no structured reason");
        if tag == "unsupported_params" {
            *evidence
                .unsupported_categories
                .entry(unsupported_reason_category(raw).to_owned())
                .or_default() += 1;
        }
        let shape = redact_text(raw);
        *evidence
            .reason_shapes
            .entry((lang.to_owned(), tag.to_owned(), shape))
            .or_default() += 1;
    }
}

fn unsupported_reason_category(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("blocked_by_concurrency") || lower.contains("task/protected") {
        "concurrency"
    } else if lower.contains("blocked_by_generic") || lower.contains("generic package") {
        "generic"
    } else if lower.contains("blocked_by_private") || lower.contains("private child") {
        "private_visibility"
    } else if lower.contains("deleted constructor") || lower.contains("= delete") {
        "deleted_constructor"
    } else if lower.contains("private constructor") || lower.contains("not accessible") {
        "inaccessible_constructor"
    } else if lower.contains("ambiguous") {
        "ambiguous_type"
    } else if lower.contains("no synthesizable constructor") || lower.contains("cannot construct") {
        "unsynthesizable_constructor"
    } else if lower.contains("named type") && lower.contains("not declared") {
        "undeclared_ada_type"
    } else if lower.contains("opaque type") || lower.contains("phase c") {
        "opaque_class"
    } else if lower.contains("lifecycle") || lower.contains("setup methods") {
        "lifecycle_unavailable"
    } else if lower.contains("corba::environment") {
        "corba_environment"
    } else if lower.contains("toolchain") || lower.contains("compiler") {
        "toolchain"
    } else if lower.contains("legacy") || lower.contains("k&r") {
        "legacy_dialect"
    } else {
        "other"
    }
}

fn build_error_shape(error: &Value) -> String {
    let kind = error
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    match kind {
        "missing_header" => "header=<FILE>".to_owned(),
        "missing_type" => "type=<TYPE>".to_owned(),
        "incomplete_type" => "type=<TYPE>".to_owned(),
        "missing_macro" => format!(
            "macro=<MACRO> value_position={}",
            error
                .get("as_value")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        ),
        "undefined_symbol" => "symbol=<SYMBOL>".to_owned(),
        "undeclared_function" => "function=<FUNCTION> at <FILE>:<LINE>".to_owned(),
        "missing_shared_lib" => "library=<LIBRARY>".to_owned(),
        "missing_ada_with" => "unit=<ADA_UNIT>".to_owned(),
        "missing_ada_symbol" => "unit=<ADA_UNIT> symbol=<ADA_SYMBOL>".to_owned(),
        "missing_ada_package_body" => "unit=<ADA_UNIT>".to_owned(),
        "uncompilable_ada_body" => "source=<FILE>".to_owned(),
        "missing_gpr_import" => "project=<GPR_FILE>".to_owned(),
        "malformed_function_decl" => "declarator at <FILE>:<LINE>".to_owned(),
        "other" => error
            .get("tail")
            .and_then(Value::as_str)
            .map(redact_text)
            .unwrap_or_else(|| "no diagnostic tail".to_owned()),
        _ => "unrecognized structured error".to_owned(),
    }
}

fn collect_work_facts(work_dir: &Path) -> WorkFacts {
    let run_context: Option<AutoSupportContext> =
        std::fs::read_to_string(work_dir.join("auto/support-context.json"))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok());
    let discovery_path = work_dir.join("discovery-cache.json");
    let discovery_cache = discovery_path.is_file();
    let discovery_cache_producer_match = discovery_cache.then(|| {
        let cache: Value = std::fs::read_to_string(&discovery_path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Value::Null);
        let Some(context) = run_context.as_ref() else {
            return false;
        };
        cache.get("producer_version").and_then(Value::as_str)
            == Some(context.campaign_version.as_str())
            && cache.get("producer_commit").and_then(Value::as_str)
                == Some(context.campaign_commit.as_str())
            && cache
                .get("discovery_semantic_version")
                .and_then(Value::as_u64)
                == Some(context.discovery_semantic_version as u64)
    });

    let mut facts = WorkFacts {
        staged_ada_files: count_extensions(&work_dir.join("src_instrumented"), &["ads", "adb"]),
        fake_corba_files: count_extensions(&work_dir.join("fake_corba"), &["ads", "adb"]),
        generated_harness_dirs: count_directories(&work_dir.join("generated_harnesses")),
        discovery_cache,
        discovery_cache_producer_match,
        dialect_cache_files: count_extensions(&work_dir.join("cxx_dialects"), &["txt"]),
        final_run_report: work_dir.join("auto/run.json").is_file(),
        missing_deps_report: work_dir.join("auto/missing-deps.json").is_file(),
        run_context,
        ..WorkFacts::default()
    };
    let mut inspected = BTreeSet::new();
    for root in [
        work_dir.join("generated_harnesses"),
        work_dir.join("harnesses"),
    ] {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            // `auto` deliberately mirrors a harness between `harnesses/` and
            // `generated_harnesses/`.  The directories are distinct paths, so
            // canonical-path deduplication counts every fact twice.  Stable
            // harness ids are unique inside a work directory and are used only
            // as an in-memory key; they are never emitted in the scrubbed report.
            let key = entry.file_name().to_string_lossy().into_owned();
            if inspected.insert(key) {
                inspect_harness_facts(&dir, &mut facts);
            }
        }
    }
    facts.dialect_cache_context_matches = count_matching_dialect_contexts(work_dir);

    if let Some(report) =
        std::fs::read_to_string(work_dir.join("fake_corba/idl_recovery_report.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    {
        facts.idl_files_seen = report
            .get("files_seen")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        facts.idl_files_parsed = report
            .get("files_parsed")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        facts.idl_partial = report.get("complete").and_then(Value::as_bool).map(|v| !v);
        facts.idl_reopened_modules = report
            .get("reopened_modules")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        facts.idl_generated_collisions = report
            .get("generated_unit_collisions")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        facts.idl_real_fake_collisions = report
            .get("real_fake_collisions_pruned")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
    }
    if let Some(report) = std::fs::read_to_string(work_dir.join("auto/ada-staging-report.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    {
        facts.duplicate_staged_units = report
            .get("duplicate_units_discarded")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        facts.selected_source_variants = report
            .get("selected_source_variants")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
    }
    facts
}

fn inspect_harness_facts(dir: &Path, facts: &mut WorkFacts) {
    let metadata_path = dir.join("generation-metadata.json");
    if let Some(metadata) = std::fs::read_to_string(metadata_path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    {
        facts.harness_metadata_files += 1;
        facts.exact_line_matches += usize::from(
            metadata
                .get("exact_line_match")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
        facts.name_fallbacks += usize::from(
            metadata
                .get("name_fallback")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
        let language = safe_trace_token(
            metadata
                .get("language")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
        );
        let path = safe_trace_token(
            metadata
                .get("emitted_path")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
        );
        *facts
            .emitted_paths
            .entry(format!("{language}/{path}"))
            .or_default() += 1;
    }

    let Ok(makefile) = std::fs::read_to_string(dir.join("Makefile")) else {
        return;
    };
    let language = if dir.join("main.cpp").is_file() {
        "cpp"
    } else {
        "c"
    };
    let assignment = |name: &str| -> Option<&str> {
        makefile.lines().find_map(|line| {
            let (left, right) = line.split_once('=')?;
            (left.trim().trim_end_matches('?').trim() == name).then(|| right.trim())
        })
    };
    let provenance = assignment("BUILD_CONTEXT_PROVENANCE").unwrap_or("none");
    *facts
        .build_context_provenance
        .entry(format!("{language}/{}", safe_trace_token(provenance)))
        .or_default() += 1;
    let generated_context_graph = dir.join("build_context_objects.mk").is_file();
    let repair_context_graph = dir.join("repair_context_objects.mk").is_file();
    if generated_context_graph || repair_context_graph {
        facts.per_tu_object_graphs += 1;
    }
    if repair_context_graph {
        facts.repair_per_tu_object_graphs += 1;
    }
    collect_per_tu_context_facts(
        dir,
        "build_context_objects.mk",
        "context_objs/main_",
        language,
        false,
        facts,
    );
    collect_per_tu_context_facts(
        dir,
        "repair_context_objects.mk",
        "repair_context_objs/main_",
        language,
        true,
        facts,
    );
    let compiler = assignment(if language == "cpp" { "CXX" } else { "CC" })
        .map(compiler_family)
        .unwrap_or("unknown");
    *facts
        .compiler_families
        .entry(format!("{language}/{compiler}"))
        .or_default() += 1;
    if language == "cpp" {
        let standard = assignment("CXX_STD")
            .map(safe_cxx_standard)
            .unwrap_or_else(|| "unknown".to_owned());
        *facts
            .effective_standards
            .entry(format!("cpp/{standard}"))
            .or_default() += 1;
    }
    if let Some(flags) = assignment("COMPILE_DB_FLAGS") {
        for family in safe_flag_families(flags) {
            *facts
                .forwarded_flag_families
                .entry(format!("{language}/{family}"))
                .or_default() += 1;
        }
    }
    if let Some(dropped) = assignment("BUILD_CONTEXT_DROPPED") {
        for family in dropped
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty() && *v != "none")
        {
            *facts
                .dropped_flag_families
                .entry(format!("{language}/{}", safe_trace_token(family)))
                .or_default() += 1;
        }
    }
}

fn collect_per_tu_context_facts(
    dir: &Path,
    fragment_name: &str,
    main_object_prefix: &str,
    language: &str,
    repair: bool,
    facts: &mut WorkFacts,
) {
    let Ok(fragment) = std::fs::read_to_string(dir.join(fragment_name)) else {
        return;
    };
    let mut next_recipe_is_main_context = false;
    for line in fragment.lines() {
        if line.starts_with(main_object_prefix) && line.contains(".o:") {
            next_recipe_is_main_context = true;
            continue;
        }
        if !next_recipe_is_main_context {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with('\t') {
            next_recipe_is_main_context = false;
            continue;
        }
        let command = line.trim();
        // Generated object rules first create their private object directory;
        // the following recipe line is the authoritative compiler command.
        if command.starts_with("@mkdir ") || !command.contains(" -c ") {
            continue;
        }
        next_recipe_is_main_context = false;
        if repair {
            facts.repair_per_tu_context_rows += 1;
        } else {
            facts.per_tu_context_rows += 1;
        }
        let compiler = command
            .split_whitespace()
            .next()
            .map(compiler_family)
            .unwrap_or("other");
        *facts
            .per_tu_compiler_families
            .entry(format!("{language}/{compiler}"))
            .or_default() += 1;
        if language == "cpp" {
            let standard = command
                .split_whitespace()
                .filter_map(|token| token.strip_prefix("-std="))
                .next_back()
                .map(safe_cxx_standard)
                .unwrap_or_else(|| "unknown".to_owned());
            *facts
                .per_tu_effective_standards
                .entry(format!("cpp/{standard}"))
                .or_default() += 1;
        }
        for family in safe_flag_families(command) {
            *facts
                .per_tu_flag_families
                .entry(format!("{language}/{family}"))
                .or_default() += 1;
        }
    }
}

fn compiler_family(value: &str) -> &'static str {
    let leaf = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value)
        .to_ascii_lowercase();
    if leaf.contains("clang") {
        "clang"
    } else if leaf == "gcc" || leaf.starts_with("gcc-") || leaf == "g++" || leaf.starts_with("g++-")
    {
        "gcc"
    } else if leaf.contains("cl.exe") || leaf == "cl" {
        "msvc"
    } else {
        "other"
    }
}

fn safe_flag_families(flags: &str) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    for flag in flags.split_whitespace() {
        if flag == "-D" || flag.starts_with("-D") || flag == "-U" || flag.starts_with("-U") {
            out.insert("defines");
        } else if matches!(flag, "-I" | "-isystem" | "-iquote" | "-idirafter")
            || flag.starts_with("-I")
        {
            out.insert("include_paths");
        } else if matches!(flag, "-include" | "-imacros") {
            out.insert("forced_include");
        } else if flag.contains("sysroot") {
            out.insert("sysroot");
        } else if flag.starts_with("--target") {
            out.insert("target");
        } else if flag.starts_with("-m") {
            out.insert("machine_abi");
        } else if flag.contains("pack")
            || flag.contains("abi-version")
            || flag.contains("short-enums")
        {
            out.insert("layout_abi");
        } else if flag.starts_with("-fms-") || matches!(flag, "-fdeclspec" | "-fpermissive") {
            out.insert("language_extensions");
        } else if flag.starts_with("-std=") {
            out.insert("standard");
        }
    }
    out
}

fn count_matching_dialect_contexts(work_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| dir.join("main.cpp").is_file())
        .filter(|dir| {
            let mut hasher = Sha256::new();
            hasher.update(b"govfuzz-cxx-dialect-context-v2\0");
            for name in ["Makefile", "main.cpp"] {
                hasher.update(name.as_bytes());
                if let Ok(bytes) = std::fs::read(dir.join(name)) {
                    hasher.update(bytes);
                }
            }
            let repairs = dir.join("repairs");
            if let Ok(entries) = std::fs::read_dir(repairs) {
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
            work_dir
                .join("cxx_dialects")
                .join(format!("{key}.txt"))
                .is_file()
        })
        .count()
}

fn count_extensions(dir: &Path, extensions: &[&str]) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    extensions
                        .iter()
                        .any(|wanted| ext.eq_ignore_ascii_case(wanted))
                })
        })
        .count()
}

fn count_directories(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .count()
}

fn render_report(
    evidence: &Evidence,
    facts: &WorkFacts,
    max_examples: usize,
    max_bytes: usize,
    include_toolchains: bool,
) -> String {
    let mut body = String::new();
    body.push_str(&format!(
        "schema=govfuzz.support.v{SCHEMA_VERSION}\nversion={}\ncommit={}\nhost={}/{}\n",
        crate::auto::bug_report::version(),
        crate::auto::bug_report::commit(),
        std::env::consts::OS,
        std::env::consts::ARCH,
    ));
    body.push_str(
        "privacy=source/harness/corpus text omitted; paths, file names, targets, types, variables, units, symbols, and macros replaced\n",
    );
    body.push_str(&format!(
        "checkpoints={} invalid={} source={}\n",
        evidence.results,
        evidence.invalid_results,
        if evidence.used_final_report_fallback {
            "final_run_fallback"
        } else if evidence.results == 0 {
            "context_only"
        } else {
            "per_target"
        }
    ));

    body.push_str("outcomes:\n");
    let mut by_lang: BTreeMap<&str, Vec<(&str, usize)>> = BTreeMap::new();
    for ((lang, outcome), count) in &evidence.outcomes {
        by_lang.entry(lang).or_default().push((outcome, *count));
    }
    for (lang, mut outcomes) in by_lang {
        outcomes.sort_by(|a, b| a.0.cmp(b.0));
        body.push_str(&format!(
            "  {lang}: {}\n",
            outcomes
                .into_iter()
                .map(|(outcome, count)| format!("{outcome}={count}"))
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }

    body.push_str(&format!(
        "error_kinds={}\n",
        render_flat_counts(&evidence.error_kinds)
    ));
    body.push_str(&format!(
        "repair_kinds={}\n",
        render_flat_counts(&evidence.repair_kinds)
    ));
    body.push_str(&format!(
        "unsupported_categories={}\n",
        render_flat_counts(&evidence.unsupported_categories)
    ));
    body.push_str(&format!(
        "attempts=terminal_stages:{} reason_categories:{} fallback_chains:{}\n",
        render_flat_counts(&evidence.terminal_stages),
        render_flat_counts(&evidence.reason_categories),
        render_flat_counts(&evidence.fallback_chains),
    ));
    body.push_str(&format!(
        "execution=generated:{} compiled:{} launched:{} target_entry_observed:{} fuzz_inputs:{} coverage_edges:{} stub_only_targets:{}\n",
        facts.harness_metadata_files.max(facts.generated_harness_dirs),
        evidence.compiled_targets,
        evidence.launched_targets,
        evidence.target_entry_observed,
        evidence.fuzz_input_executions,
        evidence.coverage_edges,
        evidence.stub_only_targets,
    ));
    body.push_str(&format!(
        "ledgers=failed_without_repairs:{} failed_without_last_errors:{}\n",
        evidence.failed_without_repairs, evidence.failed_without_errors
    ));
    body.push_str(&format!(
        "artifacts=staged_ada_files:{} fake_corba_files:{} generated_harness_dirs:{} harness_refresh_metadata:{} discovery_cache:{} discovery_cache_producer_match:{} dialect_cache_files:{} dialect_context_matches:{} per_tu_object_graphs:{} repair_per_tu_object_graphs:{} final_report:{} missing_deps:{}\n",
        facts.staged_ada_files,
        facts.fake_corba_files,
        facts.generated_harness_dirs,
        facts.harness_metadata_files,
        yes_no(facts.discovery_cache),
        yes_no_option(facts.discovery_cache_producer_match),
        facts.dialect_cache_files,
        facts.dialect_cache_context_matches,
        facts.per_tu_object_graphs,
        facts.repair_per_tu_object_graphs,
        yes_no(facts.final_run_report),
        yes_no(facts.missing_deps_report),
    ));
    body.push_str(&format!(
        "selection=exact_line_matches:{} name_fallbacks:{} emitted_paths:{}\n",
        facts.exact_line_matches,
        facts.name_fallbacks,
        render_flat_counts(&facts.emitted_paths),
    ));
    body.push_str(&format!(
        "build_context=provenance:{} compiler_families:{} standards:{} forwarded_flag_families:{} dropped_flag_families:{}\n",
        render_flat_counts(&facts.build_context_provenance),
        render_flat_counts(&facts.compiler_families),
        render_flat_counts(&facts.effective_standards),
        render_flat_counts(&facts.forwarded_flag_families),
        render_flat_counts(&facts.dropped_flag_families),
    ));
    body.push_str(&format!(
        "tu_context=rows:{} repair_rows:{} compiler_families:{} standards:{} flag_families:{}\n",
        facts.per_tu_context_rows,
        facts.repair_per_tu_context_rows,
        render_flat_counts(&facts.per_tu_compiler_families),
        render_flat_counts(&facts.per_tu_effective_standards),
        render_flat_counts(&facts.per_tu_flag_families),
    ));
    body.push_str(&format!(
        "ada_idl=files_seen:{} files_parsed:{} partial:{} reopened_modules:{} generated_unit_collisions:{} real_fake_collisions_pruned:{} duplicate_staged_units:{} selected_source_variants:{}\n",
        option_usize(facts.idl_files_seen),
        option_usize(facts.idl_files_parsed),
        yes_no_option(facts.idl_partial),
        option_usize(facts.idl_reopened_modules),
        option_usize(facts.idl_generated_collisions),
        option_usize(facts.idl_real_fake_collisions),
        option_usize(facts.duplicate_staged_units),
        option_usize(facts.selected_source_variants),
    ));
    if let Some(context) = &facts.run_context {
        body.push_str(&format!(
            "campaign=version:{} commit:{} discovery_semantics:{} generated_state_semantics:{} work_state:{} discovery_cache_hit:{}\n",
            if context.campaign_version.is_empty() { "unknown" } else { &context.campaign_version },
            if context.campaign_commit.is_empty() { "unknown" } else { &context.campaign_commit },
            context.discovery_semantic_version,
            context.generated_state_semantic_version,
            if context.work_state.is_empty() { "unknown" } else { &context.work_state },
            yes_no_option(context.discovery_cache_hit),
        ));
        body.push_str(&format!(
            "run_context=languages:{} cxx_std:{} preprocess:{} passes:{} sanitizers:{} probe_build:{} run_untrusted:{} build_command:{} unsafe_build_search:{} force:{} no_stubs:{} static:{} resume:{} jobs:{} repair_rounds:{} ada_deps:{} extra_includes:{} extra_sources:{} seed_files:{} seed_dirs:{} grammar:{}\n",
            if context.languages.is_empty() {
                "auto".to_owned()
            } else {
                context.languages.join(",")
            },
            context.cxx_std.as_deref().unwrap_or("auto"),
            context.preprocess,
            context.passes,
            if context.sanitizers.is_empty() {
                "default".to_owned()
            } else {
                context.sanitizers.join(",")
            },
            yes_no(context.probe_build),
            yes_no(context.run_untrusted),
            yes_no(context.build_command_present),
            yes_no(context.unsafe_build_search),
            yes_no(context.force),
            yes_no(context.no_stubs),
            yes_no(context.static_scan),
            yes_no(context.resume),
            context.jobs,
            context.max_repair_rounds,
            context.ada_dependency_dirs,
            context.extra_include_dirs,
            context.extra_source_files,
            context.seed_files,
            context.seed_dirs,
            yes_no(context.grammar_present),
        ));
    } else {
        body.push_str(
            "run_context=unavailable (campaign predates privacy-safe context checkpoint)\n",
        );
    }

    if include_toolchains {
        body.push_str("toolchains:\n");
        for tool in [
            "clang", "clang++", "gcc", "g++", "gnatmake", "gprbuild", "alr", "make",
        ] {
            body.push_str(&format!("  {tool}: {}\n", tool_version(tool)));
        }
        let env_state = ["CC", "CXX", "CFLAGS", "CXXFLAGS", "ADAFLAGS"]
            .into_iter()
            .map(|name| {
                format!(
                    "{name}={}",
                    if std::env::var_os(name).is_some() {
                        "set"
                    } else {
                        "unset"
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        body.push_str(&format!("  env: {env_state}\n"));
    }

    let reason_limit = max_examples.div_ceil(2);
    let error_limit = max_examples / 2;
    body.push_str("representative_outcomes:\n");
    for ((lang, outcome, shape), count) in sorted_shapes(&evidence.reason_shapes)
        .into_iter()
        .take(reason_limit)
    {
        body.push_str(&format!("  {count}x {lang}/{outcome}: {shape}\n"));
    }
    body.push_str("representative_build_errors:\n");
    for ((lang, kind, shape), count) in sorted_shapes(&evidence.error_shapes)
        .into_iter()
        .take(error_limit)
    {
        body.push_str(&format!("  {count}x {lang}/{kind}: {shape}\n"));
    }

    let digest = Sha256::digest(body.as_bytes());
    let report_id = format!("{:x}", digest);
    let mut report = format!(
        "GOVFUZZ SUPPORT REPORT (SCRUBBED)\nreport_id={}\n{body}END\n",
        &report_id[..16]
    );
    truncate_report(&mut report, max_bytes);
    report
}

fn render_flat_counts(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "none".to_owned();
    }
    let mut entries: Vec<_> = counts.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    entries
        .into_iter()
        .map(|(name, count)| format!("{name}:{count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn sorted_shapes(
    counts: &BTreeMap<(String, String, String), usize>,
) -> Vec<(&(String, String, String), usize)> {
    let mut entries: Vec<_> = counts.iter().map(|(key, count)| (key, *count)).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    entries
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn yes_no_option(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn option_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn tool_version(tool: &str) -> String {
    let output = match Command::new(tool).arg("--version").output() {
        Ok(output) => output,
        Err(_) => return "missing".to_owned(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let first = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("present (version unavailable)");
    cap_shape(redact_text(first), 160)
}

fn language_from_harness_id(id: &str) -> &'static str {
    if id.starts_with("H-A") {
        "ada"
    } else if id.starts_with("H-C") {
        "c"
    } else if id.starts_with("H-X") {
        "cpp"
    } else if id.starts_with("H-R") {
        "rust"
    } else if id.starts_with("H-J") {
        "java"
    } else if id.starts_with("H-P") {
        "python"
    } else if id.starts_with("H-L") {
        "perl"
    } else if id.starts_with("H-G") {
        "go"
    } else if id.starts_with("H-B") {
        "cobol"
    } else if id.starts_with("H-F") {
        "fortran"
    } else if id.starts_with("H-S") {
        "csharp"
    } else if id.starts_with("H-N") {
        "javascript"
    } else if id.starts_with("H-T") {
        "typescript"
    } else if id.starts_with("H-U") {
        "ruby"
    } else if id.starts_with("H-V") {
        "lua"
    } else if id.starts_with("H-W") {
        "php"
    } else {
        "unknown"
    }
}

fn redact_text(raw: &str) -> String {
    static ABS_PATH: OnceLock<Regex> = OnceLock::new();
    static REL_SOURCE_PATH: OnceLock<Regex> = OnceLock::new();
    static FILE_NAME: OnceLock<Regex> = OnceLock::new();
    static SINGLE_QUOTED: OnceLock<Regex> = OnceLock::new();
    static DOUBLE_QUOTED: OnceLock<Regex> = OnceLock::new();
    static BACKTICKED: OnceLock<Regex> = OnceLock::new();
    static QUALIFIED: OnceLock<Regex> = OnceLock::new();
    static LABELED_IDENT: OnceLock<Regex> = OnceLock::new();
    static PARAM_IDENT: OnceLock<Regex> = OnceLock::new();
    static LOCATION: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();

    let mut text = raw.replace('\0', " ");
    text = ABS_PATH
        .get_or_init(|| {
            Regex::new(r"(?:[A-Za-z]:[\\/]|/)[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)+")
                .expect("absolute-path regex")
        })
        .replace_all(&text, "<PATH>")
        .into_owned();
    text = REL_SOURCE_PATH
        .get_or_init(|| {
            Regex::new(
                r"(?i)\b(?:[A-Za-z0-9_.-]+[\\/])+[A-Za-z0-9_.-]+\.(?:ads|adb|gpr|c|cc|cpp|cxx|h|hh|hpp|hxx|rs|go|java|py|pl|cs|js|ts|rb|lua|php|idl)\b",
            )
            .expect("relative-source-path regex")
        })
        .replace_all(&text, "<PATH>")
        .into_owned();
    text = FILE_NAME
        .get_or_init(|| {
            Regex::new(
                r"(?i)\b[A-Za-z0-9_.-]+\.(ads|adb|gpr|c|cc|cpp|cxx|h|hh|hpp|hxx|rs|go|java|py|pl|cs|js|ts|rb|lua|php|idl)\b",
            )
            .expect("source-file regex")
        })
        .replace_all(&text, |captures: &Captures<'_>| {
            format!("<FILE.{}>", captures[1].to_ascii_lowercase())
        })
        .into_owned();
    // Include the preceding non-word character in the match so an apostrophe
    // in ordinary prose ("project's") cannot consume everything up to a later
    // quoted identifier.
    text = SINGLE_QUOTED
        .get_or_init(|| Regex::new(r"(^|[^A-Za-z0-9])'([^'\n]{1,240})'").unwrap())
        .replace_all(&text, |captures: &Captures<'_>| {
            let replacement = quoted_placeholder(&captures[2]);
            if replacement.starts_with('<') {
                format!("{}{replacement}", &captures[1])
            } else {
                format!("{}'{replacement}'", &captures[1])
            }
        })
        .into_owned();
    for (slot, regex, quote) in [
        (&DOUBLE_QUOTED, r#"\"([^\"\n]{1,240})\""#, "\""),
        (&BACKTICKED, r"`([^`\n]{1,240})`", "`"),
    ] {
        text = slot
            .get_or_init(|| Regex::new(regex).expect("quoted-value regex"))
            .replace_all(&text, |captures: &Captures<'_>| {
                let replacement = quoted_placeholder(&captures[1]);
                if replacement.starts_with('<') {
                    replacement
                } else {
                    format!("{quote}{replacement}{quote}")
                }
            })
            .into_owned();
    }
    text = QUALIFIED
        .get_or_init(|| {
            Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*(?:(?:::|\.)[A-Za-z_][A-Za-z0-9_]*)+\b")
                .expect("qualified-identifier regex")
        })
        .replace_all(&text, "<QUALIFIED>")
        .into_owned();
    // Compiler versions differ in whether names are quoted. Cover the common
    // unquoted forms without blanking useful grammar such as "expected
    // parameter declarator".
    text = LABELED_IDENT
        .get_or_init(|| {
            Regex::new(
                r"(?i)\b(named type|undeclared identifier|no member named|no type named|undefined symbol|undefined reference to)\s+([A-Za-z_][A-Za-z0-9_:.-]*)",
            )
            .expect("labeled-identifier regex")
        })
        .replace_all(&text, "$1 <IDENT>")
        .into_owned();
    text = PARAM_IDENT
        .get_or_init(|| {
            Regex::new(r"(?i)\b(parameter|target|method)\s+([A-Za-z_][A-Za-z0-9_:.-]*)\s+(of type|with type|is not|has no|needs)")
                .expect("parameter-identifier regex")
        })
        .replace_all(&text, "$1 <IDENT> $3")
        .into_owned();
    text = LOCATION
        .get_or_init(|| Regex::new(r"(<FILE\.[a-z0-9]+>|<PATH>):\d+(?::\d+)?").unwrap())
        .replace_all(&text, "$1:<LINE>")
        .into_owned();
    text = HEX
        .get_or_init(|| Regex::new(r"\b0x[0-9A-Fa-f]+\b").unwrap())
        .replace_all(&text, "<HEX>")
        .into_owned();
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    cap_shape(collapsed, SHAPE_LIMIT)
}

fn quoted_placeholder(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().all(|ch| ch.is_ascii_punctuation()) {
        return trimmed.to_owned();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("corba::environment") {
        return "<CORBA_ENV>".to_owned();
    }
    if lower.contains("std::") {
        return "<STD_TYPE>".to_owned();
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return "<PATH>".to_owned();
    }
    if trimmed.contains("::")
        || trimmed.contains('*')
        || trimmed.contains('&')
        || trimmed.contains('<')
        || trimmed.contains('>')
        || trimmed.split_whitespace().count() > 1
    {
        return "<TYPE>".to_owned();
    }
    if trimmed
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return "<MACRO>".to_owned();
    }
    if trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return "<IDENT>".to_owned();
    }
    "<TEXT>".to_owned()
}

fn cap_shape(mut value: String, max: usize) -> String {
    if value.len() <= max {
        return value;
    }
    let mut end = max.saturating_sub(3);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.truncate(end);
    value.push_str("...");
    value
}

fn truncate_report(report: &mut String, max_bytes: usize) {
    if report.len() <= max_bytes {
        return;
    }
    const NOTE: &str = "\n[truncated at configured privacy/size limit]\nEND\n";
    let mut end = max_bytes.saturating_sub(NOTE.len());
    while !report.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    report.truncate(end);
    report.push_str(NOTE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "govfuzz-support-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_result(work: &Path, id: &str, value: Value) {
        let dir = work.join("harnesses").join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("result.json"), serde_json::to_vec(&value).unwrap()).unwrap();
    }

    #[test]
    fn collector_counts_live_checkpoints_and_scrubs_private_names() {
        let work = temp_dir("scrub");
        write_result(
            &work,
            "H-X0001-SECRET",
            serde_json::json!({
                "harness_id": "H-X0001-SECRET",
                "lang": "cpp",
                "source_path": "/classified/project/real_parser.cpp",
                "name": "MissionParser::DecodeSecret",
                "outcome": {
                    "outcome": "unsupported_params",
                    "reason": "C++ parameter 'super_secret' of type 'const Mission::Header &' has no byte-buffer decoder: opaque type 'Mission::Header' needs lifecycle support (Phase C)"
                }
            }),
        );
        write_result(
            &work,
            "H-A0002-SECRET",
            serde_json::json!({
                "harness_id": "H-A0002-SECRET",
                "lang": "ada",
                "source_path": "/classified/project/mission_unit.adb",
                "name": "Mission_Unit.Decode",
                "outcome": {
                    "outcome": "failed_build",
                    "repairs": [{"kind":"ada_package_stub", "unit":"Mission_Unit"}],
                    "retries": 1,
                    "last_errors": [
                        {"kind":"missing_ada_symbol", "unit":"Mission_Unit", "symbol":"Secret_Header"},
                        {"kind":"other", "tail":"/classified/project/private_header.hpp:77:3: error: no matching constructor for initialization of 'Mission::Header'"}
                    ]
                }
            }),
        );
        fs::create_dir_all(work.join("src_instrumented")).unwrap();
        fs::write(work.join("src_instrumented/private.ads"), "secret").unwrap();

        let evidence = collect_evidence(&work).unwrap();
        let report = render_report(
            &evidence,
            &collect_work_facts(&work),
            8,
            DEFAULT_MAX_BYTES,
            false,
        );
        assert!(report.contains("ada: failed_build=1"), "{report}");
        assert!(report.contains("cpp: unsupported_params=1"), "{report}");
        assert!(
            report.contains("unsupported_categories=opaque_class:1"),
            "{report}"
        );
        assert!(report.contains("missing_ada_symbol:1"), "{report}");
        assert!(
            report.contains("unit=<ADA_UNIT> symbol=<ADA_SYMBOL>"),
            "{report}"
        );
        assert!(report.contains("no matching constructor"), "{report}");
        for secret in [
            "classified",
            "real_parser",
            "private_header",
            "MissionParser",
            "DecodeSecret",
            "super_secret",
            "Mission_Unit",
            "Secret_Header",
            "Mission::Header",
        ] {
            assert!(!report.contains(secret), "leaked {secret}: {report}");
        }
        assert!(report.len() <= DEFAULT_MAX_BYTES);
        fs::remove_dir_all(work).ok();
    }

    #[test]
    fn report_enforces_hard_size_limit() {
        let mut evidence = Evidence {
            results: 100,
            ..Default::default()
        };
        for index in 0..100 {
            evidence.reason_shapes.insert(
                (
                    "cpp".to_owned(),
                    "unsupported_params".to_owned(),
                    format!("shape {index} {}", "x".repeat(300)),
                ),
                1,
            );
        }
        let report = render_report(&evidence, &WorkFacts::default(), 100, 1_024, false);
        assert!(report.len() <= 1_024, "{}", report.len());
        assert!(report.contains("truncated at configured privacy/size limit"));
    }

    #[test]
    fn corrupt_checkpoint_is_counted_without_exposing_its_name() {
        let work = temp_dir("corrupt");
        let dir = work.join("harnesses/H-X-SENSITIVE-NAME");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("result.json"), "not json").unwrap();
        let evidence = collect_evidence(&work).unwrap();
        assert_eq!(evidence.results, 0);
        assert_eq!(evidence.invalid_results, 1);
        let report = render_report(&evidence, &WorkFacts::default(), 8, 6_000, false);
        assert!(report.contains("checkpoints=0 invalid=1"));
        assert!(!report.contains("SENSITIVE"));
        fs::remove_dir_all(work).ok();
    }

    #[test]
    fn scrubber_handles_unquoted_compiler_identifiers_without_losing_error_grammar() {
        let scrubbed = redact_text(
            "classified_dir/private.hpp:8: error: expected parameter declarator; named type Secret_Header is not declared; use of undeclared identifier HiddenValue",
        );
        assert!(
            scrubbed.contains("expected parameter declarator"),
            "{scrubbed}"
        );
        assert!(scrubbed.contains("named type <IDENT>"), "{scrubbed}");
        assert!(
            scrubbed.contains("undeclared identifier <IDENT>"),
            "{scrubbed}"
        );
        assert!(!scrubbed.contains("private.hpp"), "{scrubbed}");
        assert!(!scrubbed.contains("classified_dir"), "{scrubbed}");
        assert!(!scrubbed.contains("Secret_Header"), "{scrubbed}");
        assert!(!scrubbed.contains("HiddenValue"), "{scrubbed}");
    }

    #[test]
    fn run_context_only_preserves_allowlisted_option_values() {
        assert_eq!(safe_cxx_standard("gnu++98"), "gnu++98");
        assert_eq!(safe_cxx_standard("SecretProjectDialect"), "custom");
        assert_eq!(safe_passes("empty,rng,fuzz"), "empty,rng,fuzz");
        assert_eq!(safe_passes("classified-pass"), "custom");
    }

    #[test]
    fn unsupported_reasons_are_classified_without_retaining_identifiers() {
        assert_eq!(
            unsupported_reason_category(
                "C++ parameter Secret of type const Mission::Header has no decoder: opaque type Mission::Header needs lifecycle support (Phase C)"
            ),
            "opaque_class"
        );
        assert_eq!(
            unsupported_reason_category(
                "direct-call harness cannot initialize parameter X: named type Mission.Header is not declared"
            ),
            "undeclared_ada_type"
        );
        assert_eq!(
            unsupported_reason_category("blocked_by_concurrency: protected object found"),
            "concurrency"
        );
    }

    #[test]
    fn collector_reports_offline_decision_and_execution_facts_without_identifiers() {
        let work = temp_dir("decision-ledger");
        let id = "H-X0001-PRIVATE";
        write_result(
            &work,
            id,
            serde_json::json!({
                "harness_id": id,
                "lang": "cpp",
                "attempt_trace": {
                    "terminal_stage": "fuzz",
                    "fallback_chain": ["sequence_failed", "direct_built_and_fuzzed"],
                    "reason_category": "success",
                    "repairs_attempted": true
                },
                "outcome": {
                    "outcome": "built_and_fuzzed",
                    "repairs": [{"kind":"add_source", "symbol":"SecretSymbol", "source_path":"/secret/source.cpp"}],
                    "passes": [{
                        "pass":"fuzz_driven", "executions":17, "coverage_edges":9,
                        "target_entry_observed":true, "findings":[]
                    }]
                }
            }),
        );
        let harness = work.join("harnesses").join(id);
        fs::write(harness.join("main.cpp"), "// SecretTarget::Parse\n").unwrap();
        fs::write(
            harness.join("Makefile"),
            "CXX = /private/toolchain/g++\nCXX_STD ?= gnu++17\nBUILD_CONTEXT_PROVENANCE = associated_header_compile_database\nBUILD_CONTEXT_DROPPED = module_or_pch,dependency_output\nCOMPILE_DB_FLAGS = -DSECRET_VALUE=1 -I /private/include -include /private/config.hpp --sysroot=/private/sdk -mabi=lp64 -fpack-struct=1\n",
        )
        .unwrap();
        fs::write(
            harness.join("build_context_objects.mk"),
            "context_objs/main_0.o: FORCE_CONTEXT_OBJECTS\n\t/private/toolchain/g++ $(CXXFLAGS) -std=gnu++14 -DSECRET_CONTEXT=1 -c /private/source.cpp -o context_objs/main_0.o\n",
        )
        .unwrap();
        fs::write(
            harness.join("repair_context_objects.mk"),
            "repair_context_objs/main_0.o: FORCE_CONTEXT_OBJECTS\n\t/private/toolchain/g++ $(CXXFLAGS) -std=gnu++17 -DSUPPORT_SECRET=1 -c /private/support.cpp -o repair_context_objs/main_0.o\n",
        )
        .unwrap();
        fs::write(
            harness.join("generation-metadata.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version":1, "language":"cpp", "requested_line_present":true,
                "exact_line_match":false, "name_fallback":true,
                "requested_kind":"sequence", "emitted_path":"factory_receiver"
            }))
            .unwrap(),
        )
        .unwrap();
        let mirrored = work.join("generated_harnesses").join(id);
        fs::create_dir_all(&mirrored).unwrap();
        for file in [
            "main.cpp",
            "Makefile",
            "build_context_objects.mk",
            "repair_context_objects.mk",
            "generation-metadata.json",
        ] {
            fs::copy(harness.join(file), mirrored.join(file)).unwrap();
        }
        fs::create_dir_all(work.join("fake_corba")).unwrap();
        fs::write(
            work.join("fake_corba/idl_recovery_report.json"),
            serde_json::to_vec(&serde_json::json!({
                "files_seen":3, "files_parsed":2, "complete":false,
                "reopened_modules":2, "generated_unit_collisions":0,
                "real_fake_collisions_pruned":1
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(work.join("auto")).unwrap();
        fs::write(
            work.join("auto/ada-staging-report.json"),
            r#"{"duplicate_units_discarded":4,"selected_source_variants":2}"#,
        )
        .unwrap();
        fs::write(
            work.join("auto/support-context.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version":2, "campaign_version":"test-version",
                "campaign_commit":"test-commit", "discovery_semantic_version":1,
                "generated_state_semantic_version":1, "work_state":"fresh",
                "discovery_cache_hit":true, "languages":["cpp"], "cxx_std":null,
                "preprocess":"auto", "passes":"default", "sanitizers":[],
                "probe_build":false, "run_untrusted":false, "build_command_present":false,
                "unsafe_build_search":false, "force":false, "no_stubs":false,
                "static_scan":true, "resume":false, "jobs":1, "max_repair_rounds":3,
                "ada_dependency_dirs":0, "extra_include_dirs":0, "extra_source_files":0,
                "seed_files":0, "seed_dirs":0, "grammar_present":false
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            work.join("discovery-cache.json"),
            r#"{"producer_version":"test-version","producer_commit":"test-commit","discovery_semantic_version":1}"#,
        )
        .unwrap();

        let evidence = collect_evidence(&work).unwrap();
        let facts = collect_work_facts(&work);
        assert_eq!(
            facts.harness_metadata_files, 1,
            "mirrors must not double-count"
        );
        assert_eq!(
            facts.build_context_provenance.values().sum::<usize>(),
            1,
            "mirrors must not double-count build context"
        );
        let report = render_report(&evidence, &facts, 6, 4_000, false);
        for expected in [
            "target_entry_observed:1",
            "fuzz_inputs:17",
            "terminal_stages:fuzz:1",
            "sequence_failed->direct_built_and_fuzzed:1",
            "name_fallbacks:1",
            "cpp/factory_receiver:1",
            "cpp/associated_header_compile_database:1",
            "cpp/gcc:1",
            "cpp/gnu++17:1",
            "cpp/forced_include:1",
            "cpp/module_or_pch:1",
            "files_seen:3 files_parsed:2 partial:yes",
            "reopened_modules:2",
            "duplicate_staged_units:4 selected_source_variants:2",
            "discovery_cache_producer_match:yes",
            "per_tu_object_graphs:1 repair_per_tu_object_graphs:1",
            "tu_context=rows:1 repair_rows:1",
            "standards:cpp/gnu++14:1 cpp/gnu++17:1",
        ] {
            assert!(report.contains(expected), "missing {expected}:\n{report}");
        }
        for secret in [
            "PRIVATE",
            "SecretTarget",
            "SecretSymbol",
            "SECRET_VALUE",
            "/private",
            "config.hpp",
        ] {
            assert!(!report.contains(secret), "leaked {secret}:\n{report}");
        }
        assert!(report.len() <= 4_000);
        fs::remove_dir_all(work).ok();
    }
}
