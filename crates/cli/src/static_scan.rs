// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct StaticScanArgs {
    /// Source or project root to scan.
    pub path: PathBuf,

    /// Output directory for static-report.json and optional SARIF.
    #[arg(long, default_value = "govfuzz_work/static")]
    pub out: PathBuf,

    /// JSON suppression file with exact rule/path/line suppressions.
    #[arg(long)]
    pub suppressions: Option<PathBuf>,

    /// Prior static-report.json baseline to compare against.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// GovFuzz policy-as-code JSON file; rule enabled/disabled sets are honored.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Only emit these rule ids. Repeatable.
    #[arg(long = "enable-rule")]
    pub enabled_rules: Vec<String>,

    /// Suppress these rule ids before baseline comparison. Repeatable.
    #[arg(long = "disable-rule")]
    pub disabled_rules: Vec<String>,

    /// Also write static-report.sarif.
    #[arg(long)]
    pub sarif: bool,

    /// Write an accurate per-language SLOC breakdown (LANGUAGE, FILES, TOTAL,
    /// COMMENTS, BLANKS, SLOC). A relative path lands in the `--out` report
    /// directory, beside static-report.json; an absolute path is written as given.
    /// A `.json` extension emits JSON; anything else emits an aligned text table.
    /// Uses the same dependency/build-tree pruning and language-aware comment
    /// stripping as the scan, so counts exclude vendored/`node_modules`/`.venv` code.
    #[arg(long)]
    pub sloc: Option<PathBuf>,

    /// Exit non-zero when an active finding meets or exceeds this severity.
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnSeverity>,

    /// Incremental scan: only analyze files changed since this git revision
    /// (tag/branch/SHA). The dominant repeat-CI case — near-instant on a huge tree.
    #[arg(long)]
    pub since: Option<String>,

    /// Maximum RSS for govfuzz's static-analysis process, in MiB. When reached,
    /// the scanner stops admitting new files/interprocedural work and records an
    /// analysis gap instead of risking a host OOM. By default it uses the smaller
    /// of 80% of host-available memory and 70% of the cgroup memory limit.
    #[arg(long = "max-memory-mb", value_name = "MB")]
    pub max_memory_mb: Option<u64>,

    /// Parallel static-analysis workers. Lower this on memory-constrained hosts;
    /// each worker may temporarily hold a source file and its parsed copy.
    #[arg(long, value_name = "N")]
    pub jobs: Option<usize>,

    /// Also run installed, profile-allowed external analyzers (gosec/Bandit/semgrep/
    /// GNATcheck) as subprocesses and fold their findings — the rule breadth govfuzz
    /// deliberately doesn't reimplement (XSS/CSRF and framework rules) — into
    /// `<out>/external-findings.json`. Breadth WITHOUT fuzzing. The license profile
    /// gates which tools run (GOVFUZZ_PROFILE; defaults to `external-tools` when this
    /// flag is set, so the permissive tools run; never links any of them).
    #[arg(long)]
    pub external_tools: bool,
}

pub fn run(args: StaticScanArgs) -> i32 {
    let fail_on = args.fail_on;
    // Plumb the incremental `--since <rev>` scope to the engine (which restricts
    // the file walk to the git diff). Env-carried to avoid threading it through
    // every StaticScanOptions construction site.
    if let Some(rev) = &args.since {
        std::env::set_var("GOVFUZZ_SINCE_REV", rev);
    }
    if let Some(mb) = args.max_memory_mb {
        std::env::set_var("GOVFUZZ_MAX_MEMORY_KB", mb.saturating_mul(1024).to_string());
    }
    if let Some(jobs) = args.jobs {
        std::env::set_var("GOVFUZZ_STATIC_JOBS", jobs.max(1).to_string());
    }
    if let Some(sloc_path) = &args.sloc {
        // A relative path lands in the report output dir (`--out`), beside
        // static-report.json — not the caller's CWD; an absolute path is honored.
        let resolved = if sloc_path.is_absolute() {
            sloc_path.clone()
        } else {
            args.out.join(sloc_path)
        };
        if let Err(code) = write_sloc_report(&args.path, &resolved) {
            return code;
        }
    }
    let external_tools = args.external_tools;
    let external_root = args.path.clone();
    let external_out = args.out.clone();
    let options = static_analysis::StaticScanOptions {
        root: args.path,
        out_dir: args.out,
        suppressions_path: args.suppressions,
        baseline_path: args.baseline,
        policy_path: args.policy,
        enabled_rules: args.enabled_rules.into_iter().collect(),
        disabled_rules: args.disabled_rules.into_iter().collect(),
        emit_sarif: args.sarif,
    };

    match static_analysis::write_static_scan(&options) {
        Ok(summary) => {
            println!(
                "static scan: {} findings, {} suppressed, {} resolved",
                summary.findings_count, summary.suppressed_count, summary.resolved_count
            );
            println!("json: {}", summary.json_path.display());
            println!("markdown: {}", summary.markdown_path.display());
            if let Some(path) = summary.sarif_path {
                println!("sarif: {}", path.display());
            }
            let mut external_gate_trips = false;
            if external_tools {
                external_gate_trips = run_external_tools(&external_root, &external_out, fail_on);
            }
            if let Some(threshold) = fail_on {
                if severity_gate_trips(&summary.by_severity, threshold) || external_gate_trips {
                    return 1;
                }
            }
            0
        }
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    }
}

/// Compute the per-language SLOC breakdown for `root` and write it to `out`.
/// `.json` extension → JSON; otherwise an aligned text table. Returns `Err(code)`
/// on failure so the caller can exit non-zero.
pub(crate) fn write_sloc_report(root: &std::path::Path, out: &std::path::Path) -> Result<(), i32> {
    let report = static_analysis::sloc_report(root).map_err(|error| {
        eprintln!("sloc: {error:#}");
        1
    })?;
    let is_json = out
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
    let body = if is_json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => format!("{json}\n"),
            Err(error) => {
                eprintln!("sloc: {error}");
                return Err(1);
            }
        }
    } else {
        static_analysis::render_sloc_table(&report)
    };
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    if let Err(error) = std::fs::write(out, body) {
        eprintln!("sloc: cannot write {}: {error}", out.display());
        return Err(1);
    }
    println!(
        "sloc: {} language(s), {} code line(s) → {}",
        report.languages.len(),
        report.total.code_lines,
        out.display()
    );
    Ok(())
}

/// Run the profile-allowed external analyzers over `root` and write their findings
/// to `<out>/external-findings.json` — breadth (XSS/CSRF and framework rules) with
/// no fuzzing. Returns whether the findings trip the `--fail-on` severity gate.
fn run_external_tools(
    root: &std::path::Path,
    out: &std::path::Path,
    fail_on: Option<FailOnSeverity>,
) -> bool {
    let profile = resolve_external_profile();
    let findings = crate::auto::external_tools::collect_external_findings(root, profile);
    if profile == config::Profile::StrictPermissive {
        eprintln!(
            "external tools: profile 'strict-permissive' allows no analyzers — set GOVFUZZ_PROFILE=external-tools"
        );
    }
    let mut by_tool: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut with_cwe = 0usize;
    let mut gate = false;
    let json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            *by_tool.entry(f.tool.as_str()).or_default() += 1;
            if f.cwe.is_some() {
                with_cwe += 1;
            }
            if let Some(threshold) = fail_on {
                if severity_rank(&f.severity) >= severity_threshold_rank(threshold) {
                    gate = true;
                }
            }
            serde_json::json!({
                "tool": f.tool,
                "rule": f.rule,
                "cwe": f.cwe,
                "severity": f.severity,
                "path": f.path,
                "line": f.line,
                "message": f.message,
            })
        })
        .collect();
    let path = out.join("external-findings.json");
    let _ = std::fs::create_dir_all(out);
    if let Ok(bytes) = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "govfuzz.external-findings.v1",
        "profile": profile.as_str(),
        "findings": json,
    })) {
        let _ = std::fs::write(&path, bytes);
    }
    let summary: Vec<String> = by_tool.iter().map(|(t, n)| format!("{t}:{n}")).collect();
    println!(
        "external tools ({}): {} finding(s) [{}], {} with CWE — {}",
        profile.as_str(),
        findings.len(),
        summary.join(" "),
        with_cwe,
        path.display(),
    );
    gate
}

/// The license profile for `--external-tools`: an explicit `GOVFUZZ_PROFILE` wins;
/// otherwise the flag itself opts into `external-tools` (the permissive analyzers),
/// mirroring `auto` while making the flag do something useful by default.
fn resolve_external_profile() -> config::Profile {
    std::env::var("GOVFUZZ_PROFILE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(config::Profile::ExternalTools)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FailOnSeverity {
    Low,
    Medium,
    High,
    Critical,
}

fn severity_gate_trips(
    buckets: &std::collections::BTreeMap<String, usize>,
    threshold: FailOnSeverity,
) -> bool {
    buckets.iter().any(|(severity, count)| {
        *count > 0 && severity_rank(severity) >= severity_threshold_rank(threshold)
    })
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_threshold_rank(threshold: FailOnSeverity) -> u8 {
    match threshold {
        FailOnSeverity::Low => 1,
        FailOnSeverity::Medium => 2,
        FailOnSeverity::High => 3,
        FailOnSeverity::Critical => 4,
    }
}
