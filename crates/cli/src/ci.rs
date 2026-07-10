// SPDX-License-Identifier: Apache-2.0

//! `govfuzz ci` subcommand — wraps `govfuzz auto`, walks the
//! findings directory after the run, optionally writes a Markdown
//! summary to `$GITHUB_STEP_SUMMARY` (or `--summary-file`), and
//! exits non-zero based on a configurable severity threshold.

use crate::auto::cli::{run as run_auto, AutoArgs};
use anyhow::Context;
use clap::ValueEnum;
use finding_rules::Severity;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct CiArgs {
    /// Source root to sweep.
    pub path: PathBuf,

    /// Work directory. Default ./govfuzz_work.
    #[arg(long, default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Per-target TOTAL fuzz wall-clock budget in seconds (split across the
    /// passes). Forwarded to `govfuzz auto`.
    #[arg(long, default_value_t = 60)]
    pub per_target_time: u64,

    /// Stop a target once it has produced N distinct findings (crash
    /// signatures), or when its per-target time is spent — whichever first.
    /// `1` ≈ libFuzzer stop-on-first-crash. Forwarded to `govfuzz auto`.
    #[arg(long = "per-target-finding-count", value_name = "N")]
    pub per_target_finding_count: Option<usize>,

    /// Whole-run wall-clock budget across all targets (seconds); with
    /// `--min-target-time` it splits the budget across targets instead.
    /// Forwarded to `govfuzz auto`.
    #[arg(long = "campaign-time", value_name = "SECS")]
    pub campaign_time: Option<u64>,

    /// SPLIT-mode floor (seconds), used only with `--campaign-time`: each
    /// attempted target gets at least this much fuzz time. Forwarded to
    /// `govfuzz auto`.
    #[arg(
        long = "min-target-time",
        value_name = "SECS",
        requires = "campaign_time"
    )]
    pub min_target_time: Option<u64>,

    /// Skip auto-stubbing entirely (diagnostics-only).
    #[arg(long)]
    pub no_stubs: bool,

    /// Path to append a Markdown summary to. Defaults to the
    /// `GITHUB_STEP_SUMMARY` env var when unset.
    #[arg(long, value_name = "PATH")]
    pub summary_file: Option<PathBuf>,

    /// Severity threshold that triggers a non-zero exit.
    #[arg(long, value_enum, default_value_t = FailOn::Any)]
    pub fail_on: FailOn,

    /// Run mode forwarded to govfuzz auto.
    #[arg(long, default_value_t = actionability::RunMode::Reporting)]
    pub mode: actionability::RunMode,

    /// Restrict the sweep to a comma-separated subset of source languages
    /// (`ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`; common
    /// spellings like `c++`/`rs`/`py` accepted). Forwarded to `govfuzz auto`.
    /// Unset (default) = fuzz every language found.
    #[arg(
        long = "languages",
        visible_alias = "lang",
        value_enum,
        value_delimiter = ',',
        ignore_case = true,
        value_name = "LIST"
    )]
    pub languages: Vec<crate::auto::candidate::LangSelector>,

    /// Actionability threshold that triggers a non-zero exit. When unset, CI keeps the existing severity gate.
    #[arg(long, value_enum)]
    pub fail_on_actionability: Option<FailOnActionability>,

    /// Minimum actionability confidence for --fail-on-actionability.
    #[arg(long, value_enum, default_value_t = MinActionabilityConfidence::Low)]
    pub min_actionability_confidence: MinActionabilityConfidence,

    /// Optional policy file used to enrich CI gate and dashboard decisions.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Optional runner assignment plan used to enrich CI budget governance evidence.
    #[arg(long)]
    pub runner_plan: Option<PathBuf>,

    /// Write dashboard-friendly CI JSON to this path.
    #[arg(long)]
    pub dashboard_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    Any,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOnActionability {
    Real,
    Likely,
    Lab,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinActionabilityConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ActionabilityBuckets {
    pub by_verdict: BTreeMap<String, usize>,
    pub by_verdict_and_confidence: BTreeMap<(String, String), usize>,
}

impl FailOn {
    fn rank(self) -> u8 {
        match self {
            FailOn::Any => 0,
            FailOn::Low => 1,
            FailOn::Medium => 2,
            FailOn::High => 3,
            FailOn::Critical => 4,
        }
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Build the `auto` argument set that `govfuzz ci` drives. Extracted so flag
/// forwarding (notably the budget knobs `--per-target-time` /
/// `--per-target-finding-count` / `--campaign-time` / `--min-target-time`) is
/// unit-testable without running the whole pipeline.
fn auto_args_from_ci(args: &CiArgs) -> AutoArgs {
    AutoArgs {
        path: args.path.clone(),
        work_dir: args.work_dir.clone(),
        discovery_cache: None,
        config: None,
        grammar_file: None,
        max_len: "auto".to_owned(),
        timeout: None,
        cxx_std: None,
        unsafe_search_and_run_build_commands: false,
        dry_run: false,
        per_target_time: args.per_target_time,
        total_time: None,
        per_target_finding_count: args.per_target_finding_count,
        campaign_time: args.campaign_time,
        min_target_time: args.min_target_time,
        max_targets: None,
        max_repair_rounds: crate::auto::attempt::DEFAULT_MAX_REPAIR_ROUNDS,
        passes: None,
        single_pass: false,
        jobs: 1,
        reuse_discovery: false,
        no_discovery_cache: false,
        fresh_discovery: false,
        resume: false,
        iterations: None,
        rss_limit_mb: 2048,
        no_stubs: args.no_stubs,
        list_fakes: false,
        targets: Vec::new(),
        harness_ids: Vec::new(),
        target_files: Vec::new(),
        exclude_paths: Vec::new(),
        exclude: Vec::new(),
        languages: args.languages.clone(),
        ada_deps: Vec::new(),
        seed_files: Vec::new(),
        seed_dirs: Vec::new(),
        mode: args.mode,
        engine: "builtin".to_owned(),
        verbose: false,
        probe_build: false,
        deps_only: false,
        list_targets: false,
        exclude_dir: Vec::new(),
        include_dir: Vec::new(),
        preprocess: crate::auto::discovery::PreprocessMode::Auto,
        install_deps: false,
        run_untrusted: false,
        build_command: None,
        extra_includes: Vec::new(),
        extra_sources: Vec::new(),
        comparison_progress: false,
        sanitizers: Default::default(),
        sbom: false,
        static_scan: false,
        external_tools: false,
        sloc: None,
        static_dynamic: false,
        decoder_limits: Default::default(),
        force: false,
    }
}

pub fn run(args: CiArgs) -> i32 {
    let work_dir = args.work_dir.clone();
    let auto_args = auto_args_from_ci(&args);
    // auto::cli::run returns 0 for success, 2 when no candidates,
    // 1 for hard errors. We treat 1 here as failure regardless of
    // findings; 0/2 mean the auto loop completed normally.
    let auto_exit = run_auto(auto_args);
    if auto_exit != 0 && auto_exit != 2 {
        return auto_exit;
    }

    // Fail closed: if the findings directory cannot be enumerated, the
    // gate must error out (exit 1), never report zero findings and pass.
    let findings = match bucket_findings(&work_dir) {
        Ok(findings) => findings,
        Err(error) => {
            eprintln!("error: CI gate could not read findings: {error:#}");
            return 1;
        }
    };
    let total: usize = findings.values().sum();

    let summary_target = summary_path_resolution(args.summary_file.as_deref());
    if let Some(path) = summary_target {
        let markdown = render_summary(&work_dir, total, &findings);
        if let Err(error) = append_summary(&path, &markdown) {
            eprintln!(
                "warning: could not write CI summary to {}: {error}",
                path.display()
            );
        }
    }

    let mut exit_code = if let Some(fail_on_actionability) = args.fail_on_actionability {
        let actionability = match bucket_actionability(&work_dir) {
            Ok(actionability) => actionability,
            Err(error) => {
                eprintln!("error: CI gate could not read findings: {error:#}");
                return 1;
            }
        };
        exit_code_from_actionability(
            &actionability,
            fail_on_actionability,
            args.min_actionability_confidence,
        )
    } else {
        exit_code_from_buckets(&findings, args.fail_on)
    };
    if let Some(policy) = args.policy.as_ref() {
        match governance::ci_policy_gate_with_runner_plan(
            &work_dir,
            policy,
            args.runner_plan.as_deref(),
        ) {
            Ok(gate) => {
                exit_code = if gate
                    .pointer("/gate/failed")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    1
                } else {
                    0
                };
            }
            Err(error) => {
                eprintln!("warning: could not evaluate CI policy gate: {error:#}");
                exit_code = 1;
            }
        }
    }
    if let Some(path) = args.dashboard_out {
        let dashboard = governance::ci_dashboard_data(
            &work_dir,
            args.policy.as_deref(),
            args.runner_plan.as_deref(),
            &findings,
            exit_code != 0,
        );
        if let Err(error) = dashboard.and_then(|value| {
            governance::write_json(&path, &value)?;
            Ok(value)
        }) {
            eprintln!("warning: could not write CI dashboard JSON: {error:#}");
        }
    }
    exit_code
}

fn summary_path_resolution(flag: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = flag {
        return Some(p.to_path_buf());
    }
    std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from)
}

fn bucket_findings(work_dir: &Path) -> anyhow::Result<BTreeMap<String, usize>> {
    let findings_dir = work_dir.join("findings");
    let mut buckets: BTreeMap<String, usize> = BTreeMap::new();
    if !findings_dir.is_dir() {
        return Ok(buckets);
    }
    // A failure to enumerate an *existing* findings directory is a hard
    // error: the gate must fail closed, never silently report zero.
    let entries = fs::read_dir(&findings_dir)
        .with_context(|| format!("read findings directory {}", findings_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "read findings directory entry in {}",
                findings_dir.display()
            )
        })?;
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => {}
            // A single unreadable/non-dir entry is skipped, not fatal,
            // but it must never make a real finding disappear — so we
            // only `continue` here, not for parse failures below.
            _ => continue,
        }
        let finding_json = entry.path().join("finding.json");
        if !finding_json.is_file() {
            continue;
        }
        // A finding directory exists, so a finding exists. If its
        // finding.json is unreadable or malformed we count it as an
        // `unknown`-severity finding (visible to the gate) instead of
        // dropping it — a corrupt/partial record must never turn the
        // security gate green.
        let severity = match fs::read(&finding_json)
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        {
            Some(value) => finding_severity(&value),
            None => {
                eprintln!(
                    "warning: unreadable/malformed {}; counting as an unknown-severity finding",
                    finding_json.display()
                );
                "unknown".to_owned()
            }
        };
        *buckets.entry(severity).or_insert(0) += 1;
    }
    Ok(buckets)
}

pub fn bucket_actionability_for_test(work_dir: &Path) -> anyhow::Result<ActionabilityBuckets> {
    bucket_actionability(work_dir)
}

pub fn exit_code_from_actionability_for_test(
    buckets: &ActionabilityBuckets,
    fail_on: FailOnActionability,
    min_confidence: MinActionabilityConfidence,
) -> i32 {
    exit_code_from_actionability(buckets, fail_on, min_confidence)
}

fn bucket_actionability(work_dir: &Path) -> anyhow::Result<ActionabilityBuckets> {
    let findings_dir = work_dir.join("findings");
    let mut buckets = ActionabilityBuckets::default();
    if !findings_dir.is_dir() {
        return Ok(buckets);
    }
    let entries = fs::read_dir(&findings_dir)
        .with_context(|| format!("read findings directory {}", findings_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "read findings directory entry in {}",
                findings_dir.display()
            )
        })?;
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => {}
            _ => continue,
        }
        let finding_json = entry.path().join("finding.json");
        if !finding_json.is_file() {
            continue;
        }
        // A malformed finding.json still counts as a finding, with an
        // "unknown" verdict at "unknown" confidence, so the
        // actionability gate cannot be defeated by a corrupt record.
        let (verdict, confidence) = match fs::read(&finding_json)
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        {
            Some(value) => {
                let record = actionability::existing_actionability_or_backfill(
                    actionability::RunMode::Reporting,
                    &value,
                    Some(&finding_json),
                );
                (
                    record.verdict.as_str().to_owned(),
                    record.confidence.as_str().to_owned(),
                )
            }
            None => {
                eprintln!(
                    "warning: unreadable/malformed {}; counting as an unknown-verdict finding",
                    finding_json.display()
                );
                ("unknown".to_owned(), "unknown".to_owned())
            }
        };
        *buckets.by_verdict.entry(verdict.clone()).or_insert(0) += 1;
        *buckets
            .by_verdict_and_confidence
            .entry((verdict, confidence))
            .or_insert(0) += 1;
    }
    Ok(buckets)
}

fn finding_severity(value: &serde_json::Value) -> String {
    // Prefer the explicit severity field on the record; fall back
    // to the rule's default via rule_id.
    if let Some(severity) = value.get("severity").and_then(|v| v.as_str()) {
        return severity.to_owned();
    }
    if let Some(rule_id) = value.get("rule_id").and_then(|v| v.as_str()) {
        if let Some(rule) = finding_rules::by_id(rule_id) {
            return rule.default_severity.as_str().to_owned();
        }
    }
    "unknown".to_owned()
}

fn render_summary(work_dir: &Path, total: usize, buckets: &BTreeMap<String, usize>) -> String {
    let mut out = String::new();
    out.push_str("### GovFuzz CI\n\n");
    out.push_str(&format!(
        "- Findings: **{total}** ({})\n",
        format_buckets(buckets)
    ));
    let actionability = bucket_actionability(work_dir).unwrap_or_default();
    if !actionability.by_verdict.is_empty() {
        out.push_str(&format!(
            "- Actionability: {}\n",
            format_actionability_buckets(&actionability.by_verdict)
        ));
    }
    out.push_str(&format!("- Work dir: `{}`\n", work_dir.display()));
    out.push_str(&format!(
        "- Report: `{}/reports/run-last.md`\n",
        work_dir.display()
    ));
    out
}

fn format_actionability_buckets(buckets: &BTreeMap<String, usize>) -> String {
    const ORDER: &[&str] = &[
        "real_reachable",
        "likely_reachable",
        "lab_only",
        "blocked",
        "unknown",
    ];
    format_buckets_with_order(buckets, ORDER)
}

fn format_buckets(buckets: &BTreeMap<String, usize>) -> String {
    const ORDER: &[&str] = &["critical", "high", "medium", "low", "info"];
    format_buckets_with_order(buckets, ORDER)
}

fn format_buckets_with_order(buckets: &BTreeMap<String, usize>, order: &[&str]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in order {
        if let Some(count) = buckets.get(*key) {
            if *count > 0 {
                parts.push(format!("{key} {count}"));
            }
        }
    }
    for (key, count) in buckets {
        if !order.contains(&key.as_str()) && *count > 0 {
            parts.push(format!("{key} {count}"));
        }
    }
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join(", ")
    }
}

fn append_summary(path: &Path, markdown: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(markdown.as_bytes())?;
    Ok(())
}

fn exit_code_from_buckets(buckets: &BTreeMap<String, usize>, fail_on: FailOn) -> i32 {
    let threshold = fail_on.rank();
    for (severity, count) in buckets {
        if *count == 0 {
            continue;
        }
        let rank = severity_for_name(severity).map(severity_rank).unwrap_or(0);
        if rank >= threshold {
            return 1;
        }
    }
    0
}

fn exit_code_from_actionability(
    buckets: &ActionabilityBuckets,
    fail_on: FailOnActionability,
    min_confidence: MinActionabilityConfidence,
) -> i32 {
    for ((verdict, confidence), count) in &buckets.by_verdict_and_confidence {
        if *count == 0 {
            continue;
        }
        if verdict_matches_threshold(verdict, fail_on)
            && confidence_meets_min(confidence, min_confidence)
        {
            return 1;
        }
    }
    0
}

fn verdict_matches_threshold(verdict: &str, fail_on: FailOnActionability) -> bool {
    match fail_on {
        FailOnActionability::Real => verdict == "real_reachable",
        FailOnActionability::Likely => {
            matches!(verdict, "real_reachable" | "likely_reachable")
        }
        FailOnActionability::Lab => {
            matches!(verdict, "real_reachable" | "likely_reachable" | "lab_only")
        }
        FailOnActionability::Any => matches!(
            verdict,
            "real_reachable" | "likely_reachable" | "lab_only" | "blocked" | "unknown"
        ),
    }
}

fn confidence_meets_min(confidence: &str, min: MinActionabilityConfidence) -> bool {
    confidence_rank_name(confidence) >= confidence_rank_min(min)
}

fn confidence_rank_name(confidence: &str) -> u8 {
    match confidence {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn confidence_rank_min(min: MinActionabilityConfidence) -> u8 {
    match min {
        MinActionabilityConfidence::High => 3,
        MinActionabilityConfidence::Medium => 2,
        MinActionabilityConfidence::Low => 1,
    }
}

fn severity_for_name(name: &str) -> Option<Severity> {
    match name.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tempdir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-ci-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_finding(work_dir: &Path, id: &str, rule_id: &str, severity: &str) {
        let dir = work_dir.join("findings").join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": id,
                "rule_id": rule_id,
                "severity": severity,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn ci_parses_and_forwards_new_budget_flags() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            ci: CiArgs,
        }
        // Defaults: the new budget knobs are unset.
        let def = TestCli::try_parse_from(["govfuzz", "src"]).expect("parses");
        assert_eq!(def.ci.per_target_finding_count, None);
        assert_eq!(def.ci.campaign_time, None);
        assert_eq!(def.ci.min_target_time, None);
        // ...and they forward to auto as unset.
        let def_auto = auto_args_from_ci(&def.ci);
        assert_eq!(def_auto.per_target_finding_count, None);
        assert_eq!(def_auto.campaign_time, None);
        assert_eq!(def_auto.min_target_time, None);

        // Explicit values parse on `govfuzz ci` and forward into the AutoArgs.
        let set = TestCli::try_parse_from([
            "govfuzz",
            "src",
            "--per-target-finding-count",
            "2",
            "--campaign-time",
            "120",
            "--min-target-time",
            "10",
        ])
        .expect("parses");
        let auto = auto_args_from_ci(&set.ci);
        assert_eq!(auto.per_target_finding_count, Some(2));
        assert_eq!(auto.campaign_time, Some(120));
        assert_eq!(auto.min_target_time, Some(10));
        // The deprecated alias is never set from CI.
        assert_eq!(auto.total_time, None);

        // --min-target-time requires --campaign-time, same rule as `govfuzz auto`.
        assert!(
            TestCli::try_parse_from(["govfuzz", "src", "--min-target-time", "10"]).is_err(),
            "--min-target-time without --campaign-time must error"
        );
    }

    #[test]
    fn ci_languages_flag_parses_and_forwards_to_auto() {
        use crate::auto::candidate::LangSelector;
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            ci: CiArgs,
        }
        // Default: no language filter forwarded (fuzz every language found).
        let def = TestCli::try_parse_from(["govfuzz", "src"]).expect("parses");
        assert!(def.ci.languages.is_empty());
        assert!(auto_args_from_ci(&def.ci).languages.is_empty());

        // Explicit (with aliases + the `--lang` flag alias) forwards verbatim.
        let set = TestCli::try_parse_from(["govfuzz", "src", "--lang", "py,go"]).expect("parses");
        assert_eq!(
            auto_args_from_ci(&set.ci).languages,
            vec![LangSelector::Python, LangSelector::Go]
        );
    }

    // Serialize the two env-var-dependent tests so they don't
    // race on the shared GITHUB_STEP_SUMMARY slot when cargo runs
    // them on parallel threads.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn summary_path_resolution_flag_wins_over_env() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var_os("GITHUB_STEP_SUMMARY");
        std::env::set_var("GITHUB_STEP_SUMMARY", "/tmp/from_env");
        let flag_path = PathBuf::from("/tmp/from_flag");
        let resolved = summary_path_resolution(Some(&flag_path));
        assert_eq!(resolved, Some(PathBuf::from("/tmp/from_flag")));
        if let Some(prev) = original {
            std::env::set_var("GITHUB_STEP_SUMMARY", prev);
        } else {
            std::env::remove_var("GITHUB_STEP_SUMMARY");
        }
    }

    #[test]
    fn summary_path_resolution_uses_env_when_flag_omitted() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var_os("GITHUB_STEP_SUMMARY");
        std::env::set_var("GITHUB_STEP_SUMMARY", "/tmp/from_env_only");
        let resolved = summary_path_resolution(None);
        assert_eq!(resolved, Some(PathBuf::from("/tmp/from_env_only")));
        if let Some(prev) = original {
            std::env::set_var("GITHUB_STEP_SUMMARY", prev);
        } else {
            std::env::remove_var("GITHUB_STEP_SUMMARY");
        }
    }

    #[test]
    fn bucket_findings_groups_by_severity() {
        let work = tempdir("bucket");
        write_finding(&work, "F-0001-aaaa", "GF-201", "high");
        write_finding(&work, "F-0002-bbbb", "GF-101", "medium");
        write_finding(&work, "F-0003-cccc", "GF-101", "medium");
        let buckets = bucket_findings(&work).unwrap();
        assert_eq!(buckets.get("high"), Some(&1));
        assert_eq!(buckets.get("medium"), Some(&2));
    }

    #[test]
    fn malformed_finding_json_counts_as_unknown_not_dropped() {
        // Regression: a truncated/corrupt finding.json must not make
        // the whole gate report zero findings and pass.
        let work = tempdir("malformed");
        write_finding(&work, "F-0001-aaaa", "GF-201", "high");
        let bad = work.join("findings/F-0002-bbbb");
        fs::create_dir_all(&bad).unwrap();
        fs::write(bad.join("finding.json"), b"{ this is not json").unwrap();

        let buckets = bucket_findings(&work).unwrap();
        let total: usize = buckets.values().sum();
        assert_eq!(total, 2, "the valid + the malformed finding both count");
        assert_eq!(buckets.get("high"), Some(&1));
        assert_eq!(
            buckets.get("unknown"),
            Some(&1),
            "malformed record is visible as unknown severity"
        );
        // The gate must be able to fail on it.
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::Any), 1);
    }

    #[test]
    fn bucket_findings_uses_rule_default_severity_when_field_missing() {
        let work = tempdir("rule-default");
        let dir = work.join("findings/F-0001");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({ "id": "F-0001", "rule_id": "GF-208" }))
                .unwrap(),
        )
        .unwrap();
        let buckets = bucket_findings(&work).unwrap();
        // GF-208 default_severity is Low (per finding_rules).
        assert_eq!(buckets.get("low"), Some(&1));
    }

    #[test]
    fn exit_code_from_buckets_returns_one_when_above_threshold() {
        let mut buckets = BTreeMap::new();
        buckets.insert("high".to_owned(), 1);
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::High), 1);
    }

    #[test]
    fn exit_code_from_buckets_returns_zero_below_threshold() {
        let mut buckets = BTreeMap::new();
        buckets.insert("low".to_owned(), 1);
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::High), 0);
    }

    #[test]
    fn exit_code_from_buckets_any_threshold_treats_any_finding_as_failure() {
        let mut buckets = BTreeMap::new();
        buckets.insert("info".to_owned(), 1);
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::Any), 1);
    }

    #[test]
    fn render_summary_includes_counts() {
        let mut buckets = BTreeMap::new();
        buckets.insert("critical".to_owned(), 1);
        buckets.insert("medium".to_owned(), 4);
        let summary = render_summary(Path::new("/tmp/work"), 5, &buckets);
        assert!(summary.contains("Findings: **5**"));
        assert!(summary.contains("critical 1"));
        assert!(summary.contains("medium 4"));
        assert!(summary.contains("/tmp/work"));
    }

    #[test]
    fn render_summary_includes_actionability_counts_when_present() {
        let work = tempdir("summary-actionability");
        let dir = work.join("findings/F-0001");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0001",
                "severity": "high",
                "actionability": {
                    "mode": "attacking",
                    "verdict": "real_reachable",
                    "impact": "high",
                    "confidence": "high",
                    "prosthetics": { "used": false, "items": [] }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let mut buckets = BTreeMap::new();
        buckets.insert("high".to_owned(), 1);
        let summary = render_summary(&work, 1, &buckets);

        assert!(summary.contains("Actionability: real_reachable 1"));
    }

    #[test]
    fn format_buckets_zero_findings_renders_none() {
        let buckets = BTreeMap::new();
        assert_eq!(format_buckets(&buckets), "none");
    }
}
