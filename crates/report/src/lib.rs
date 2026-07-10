// SPDX-License-Identifier: Apache-2.0

pub use finding_rules as rules;

use finding_rules::Rule;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

pub const REPORT_SCHEMA_VERSION: &str = "govfuzz.report.v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportOptions {
    pub run_id: String,
    pub findings_dir: PathBuf,
    pub out_dir: PathBuf,
    pub emit_sarif: bool,
    pub emit_junit: bool,
    pub emit_csv: bool,
    pub confidence_model_path: Option<PathBuf>,
    pub collapse_clusters: bool,
}

impl ReportOptions {
    pub fn new(findings_dir: impl Into<PathBuf>, out_dir: impl Into<PathBuf>) -> Self {
        Self {
            run_id: "last".to_owned(),
            findings_dir: findings_dir.into(),
            out_dir: out_dir.into(),
            emit_sarif: false,
            emit_junit: false,
            emit_csv: false,
            confidence_model_path: None,
            collapse_clusters: false,
        }
    }

    pub fn with_collapse_clusters(mut self, collapse: bool) -> Self {
        self.collapse_clusters = collapse;
        self
    }

    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = run_id.into();
        self
    }

    pub fn with_sarif(mut self, emit_sarif: bool) -> Self {
        self.emit_sarif = emit_sarif;
        self
    }

    pub fn with_junit(mut self, emit_junit: bool) -> Self {
        self.emit_junit = emit_junit;
        self
    }

    pub fn with_csv(mut self, emit_csv: bool) -> Self {
        self.emit_csv = emit_csv;
        self
    }

    pub fn with_confidence_model_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.confidence_model_path = Some(path.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSummary {
    pub run_id: String,
    pub findings_count: usize,
    pub json_path: PathBuf,
    pub markdown_path: PathBuf,
    pub sarif_path: Option<PathBuf>,
    pub junit_path: Option<PathBuf>,
    pub csv_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReportDocument {
    pub schema_version: String,
    pub run: RunReport,
    pub counts: CountReport,
    pub findings: Vec<FindingReport>,
    pub clusters: Vec<ClusterReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClusterReport {
    pub key: String,
    pub key_full: String,
    pub member_count: usize,
    pub representative: String,
    pub member_finding_ids: Vec<String>,
    pub top_frames: Vec<String>,
    pub fallback: bool,
    pub quality: ClusterQuality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClusterQuality {
    pub signal: String,
    pub frame_count: usize,
    pub stability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReport {
    pub id: String,
    pub findings_dir: String,
    /// Absolute scan/source root the findings were produced against, recovered
    /// from the sibling `auto/run.json` (`source_root`). Threaded into the SARIF
    /// renderer so on-disk crash sites under the root become repo-root-relative
    /// `uriBaseId: SRCROOT` URIs. `None` when no `auto/run.json` is reachable —
    /// the SARIF then degrades to leaving artifact paths as-is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CountReport {
    pub findings: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_actionability_verdict: BTreeMap<String, usize>,
    pub by_impact: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingReport {
    pub id: String,
    pub source_path: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_key_full: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cluster_frames: Vec<String>,
    #[serde(default)]
    pub cluster_fallback: bool,
    pub cluster_quality: ClusterQuality,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    /// Numeric rule id (`GF-NNNN`) the finding maps to, or `None` when no rule
    /// in the catalog matches. Auto-derived from `classification` +
    /// `exception_name` at load time; consumers can override by including
    /// `rule_id` in the on-disk finding JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub confidence: Value,
    pub target: Value,
    pub build: Value,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub sandbox: Value,
    pub input: Value,
    pub call_sequence: Value,
    pub exception: Value,
    pub replay: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimal_reproducer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_repro_ada: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repro_ada_omitted_reason: Option<String>,
    /// Path to the standalone Python reproducer (`replay.py`) generated for this
    /// finding. Written for ALL findings (C/C++/Ada/unknown); runs the built
    /// harness on the recorded testcase with the sanitizer env.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_repro_py: Option<String>,
    pub investigation_steps: Value,
    pub actionability: actionability::ActionabilityRecord,
    pub raw: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("I/O error during report generation")]
    Io(#[from] std::io::Error),
    #[error("JSON error during report generation")]
    Json(#[from] serde_json::Error),
    #[error("findings directory does not exist: {}", path.display())]
    MissingFindingsDir { path: PathBuf },
    #[error("finding record must be a JSON object: {}", path.display())]
    FindingRecordNotObject { path: PathBuf },
    #[error("invalid confidence model {}: {source}", path.display())]
    ConfidenceModel {
        path: PathBuf,
        source: confidence_model::ModelLoadError,
    },
    #[error("SARIF validation failed: {0}")]
    SarifValidation(String),
}

pub fn write_reports(options: ReportOptions) -> Result<ReportSummary, ReportError> {
    let document = build_report(&options)?;
    fs::create_dir_all(&options.out_dir)?;

    let stem = report_file_stem(&options.run_id);
    let json_path = options.out_dir.join(format!("{stem}.json"));
    let markdown_path = options.out_dir.join(format!("{stem}.md"));
    let sarif_path = options
        .emit_sarif
        .then(|| options.out_dir.join(format!("{stem}.sarif")));
    let junit_path = options
        .emit_junit
        .then(|| options.out_dir.join(format!("{stem}.junit.xml")));
    let csv_path = options
        .emit_csv
        .then(|| options.out_dir.join(format!("{stem}.csv")));

    fs::write(&json_path, serde_json::to_vec_pretty(&document)?)?;
    fs::write(
        &markdown_path,
        render_markdown_report_with(&document, &options),
    )?;
    if let Some(path) = &sarif_path {
        let sarif = render_sarif_report(&document);
        validate_sarif_report(&sarif)?;
        fs::write(path, serde_json::to_vec_pretty(&sarif)?)?;
    }
    if let Some(path) = &junit_path {
        fs::write(path, render_junit_report(&document))?;
    }
    if let Some(path) = &csv_path {
        fs::write(path, render_csv_report(&document))?;
    }

    Ok(ReportSummary {
        run_id: document.run.id,
        findings_count: document.counts.findings,
        json_path,
        markdown_path,
        sarif_path,
        junit_path,
        csv_path,
    })
}

/// Render the findings as RFC 4180 CSV, **one row per root-cause issue** (not per
/// crash): if 30 findings collapse to 2 fixes, the CSV has 2 data rows. Findings
/// are grouped by [`issue_key`] (cluster key, else the finding id for a
/// singleton). Columns:
/// `issue_id,count,severity,cwe,fix_file,fix_line,impact,verdict,sink_file,sink_line,sink_function,cluster_key,classification,confirmation,member_finding_ids,reproducers`.
///
/// `count` is the number of raw findings collapsed into the issue; `severity` is
/// the HIGHEST severity among its members; `cwe` is the representative's CWE
/// unioned with any genuinely different member CWE (`;`-joined). The actionable
/// columns lead: `fix_file`/`fix_line` (the representative's `fix_location` — the
/// single place to fix the whole issue) come right after `cwe`. The tail keeps
/// the issue ACTIONABLE after collapsing: `member_finding_ids` (`;`-joined ids of
/// every collapsed finding) and `reproducers` (`;`-joined, deduped — each
/// member's minimal reproducer, else its generated Python reproducer) so a
/// developer can reach every triggering input, not just the representative's.
/// The remaining columns project the issue's representative (most-actionable)
/// finding, read from its serialized actionability record so the projection stays
/// in lockstep with the JSON/SARIF outputs. Issues are ordered by severity then
/// issue id.
///
/// Two fields are intentionally NOT projected here: the internal `GF-NNNN`
/// `rule_id` (it remains in SARIF's `ruleId`, the standard machine-readable
/// home for it) and the on-disk `source_path` of the finding record (a govfuzz
/// workspace path, not an attacker-input source — the `sink_*` columns carry
/// the real defect location).
pub fn render_csv_report(document: &ReportDocument) -> String {
    let mut out = String::new();
    out.push_str(
        "issue_id,count,severity,cwe,fix_file,fix_line,impact,verdict,sink_file,sink_line,sink_function,cluster_key,classification,confirmation,member_finding_ids,reproducers\n",
    );
    for issue in group_findings_into_issues(&document.findings) {
        let representative = issue.representative;
        let act = serde_json::to_value(&representative.actionability).unwrap_or(Value::Null);
        let str_at = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let sink = act.get("sink");
        let count = issue.count().to_string();
        let severity = issue.severity().to_owned();
        let cwe = issue.cwe();
        let (fix_file, fix_line) = match issue.fix_location() {
            Some((path, line)) => (
                path.to_owned(),
                line.map(|line| line.to_string()).unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };
        let impact = str_at(&act, "impact");
        let verdict = str_at(&act, "verdict");
        let sink_file = sink.map(|s| str_at(s, "file")).unwrap_or_default();
        let sink_function = sink.map(|s| str_at(s, "function")).unwrap_or_default();
        let sink_line = sink
            .and_then(|s| s.get("line"))
            .and_then(Value::as_u64)
            .map(|n| n.to_string())
            .unwrap_or_default();
        let cluster = representative.cluster_key.clone().unwrap_or_default();
        let classification = representative.classification.clone().unwrap_or_default();
        // #484: provenance — strongest across the issue's members (a fuzz-confirmed
        // static finding outranks a plain fuzz crash, which outranks a scanner hit).
        let confirmation = issue
            .members
            .iter()
            .map(|m| finding_confirmation(m))
            .max_by_key(|c| confirmation_rank(c))
            .unwrap_or_else(|| finding_confirmation(representative));
        let member_finding_ids = issue.member_finding_ids();
        let reproducers = issue.reproducers().join(";");
        let cols = [
            issue.issue_id.as_str(),
            count.as_str(),
            severity.as_str(),
            cwe.as_str(),
            fix_file.as_str(),
            fix_line.as_str(),
            impact.as_str(),
            verdict.as_str(),
            sink_file.as_str(),
            sink_line.as_str(),
            sink_function.as_str(),
            cluster.as_str(),
            classification.as_str(),
            confirmation.as_str(),
            member_finding_ids.as_str(),
            reproducers.as_str(),
        ];
        let row = cols
            .iter()
            .map(|c| csv_escape(c))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// RFC 4180 field escaping: quote when the value contains a comma, quote, CR or
/// LF, doubling any embedded quotes.
fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

pub fn build_report(options: &ReportOptions) -> Result<ReportDocument, ReportError> {
    let confidence_model = load_confidence_model(options.confidence_model_path.as_deref())?;
    let findings = load_findings_with_model(&options.findings_dir, confidence_model.as_ref())?;
    let actionability_counts =
        actionability::aggregate_counts(findings.iter().map(|finding| &finding.actionability));
    let counts = CountReport {
        findings: findings.len(),
        by_severity: severity_counts(&findings),
        by_actionability_verdict: actionability_counts.by_actionability_verdict,
        by_impact: actionability_counts.by_impact,
    };
    let clusters = aggregate_clusters(&findings);

    Ok(ReportDocument {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        run: RunReport {
            id: normalized_run_id(&options.run_id),
            findings_dir: path_string(&options.findings_dir),
            source_root: discover_source_root(&options.findings_dir),
        },
        counts,
        findings,
        clusters,
    })
}

/// Recover the scan source root from the conventional `auto/run.json` that the
/// `govfuzz auto` sweep writes next to the findings directory
/// (`<work>/findings` ⇒ `<work>/auto/run.json`). Returns `None` (and the SARIF
/// degrades to non-relativised paths) when no run ledger is reachable — never
/// fails the report.
fn discover_source_root(findings_dir: &Path) -> Option<String> {
    let candidates = [
        findings_dir.parent().map(|p| p.join("auto/run.json")),
        Some(findings_dir.join("auto/run.json")),
    ];
    candidates
        .into_iter()
        .flatten()
        .find_map(|path| read_source_root_from_run_json(&path))
}

fn read_source_root_from_run_json(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("source_root")
        .and_then(Value::as_str)
        .filter(|root| !root.is_empty())
        .map(ToOwned::to_owned)
}

fn aggregate_clusters(findings: &[FindingReport]) -> Vec<ClusterReport> {
    let mut groups: BTreeMap<String, Vec<&FindingReport>> = BTreeMap::new();
    for finding in findings {
        let Some(key) = finding.cluster_key.as_deref() else {
            continue;
        };
        groups.entry(key.to_owned()).or_default().push(finding);
    }
    let mut out: Vec<ClusterReport> = groups
        .into_iter()
        .map(|(key, mut members)| {
            members.sort_by(|left, right| {
                actionability::finding_sort_key(&left.actionability)
                    .cmp(&actionability::finding_sort_key(&right.actionability))
                    .then_with(|| left.id.cmp(&right.id))
            });
            let representative = members[0].id.clone();
            let key_full = members[0]
                .cluster_key_full
                .clone()
                .unwrap_or_else(|| key.clone());
            let top_frames = members[0].cluster_frames.clone();
            let fallback = members[0].cluster_fallback;
            let member_finding_ids = members.iter().map(|f| f.id.clone()).collect::<Vec<_>>();
            let member_count = member_finding_ids.len();
            let quality = cluster_quality(&top_frames, fallback);
            ClusterReport {
                key,
                key_full,
                member_count,
                representative,
                member_finding_ids,
                top_frames,
                fallback,
                quality,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.member_count
            .cmp(&a.member_count)
            .then_with(|| a.key.cmp(&b.key))
    });
    out
}

fn cluster_quality(frames: &[String], fallback: bool) -> ClusterQuality {
    if fallback {
        return ClusterQuality {
            signal: "fallback_signature".to_owned(),
            frame_count: frames.len(),
            stability: "low".to_owned(),
        };
    }
    if frames.is_empty() {
        return ClusterQuality {
            signal: "none".to_owned(),
            frame_count: 0,
            stability: "none".to_owned(),
        };
    }
    ClusterQuality {
        signal: "stack_root".to_owned(),
        frame_count: frames.len(),
        stability: "stable".to_owned(),
    }
}

/// One root-cause **issue**: the set of raw findings that collapse to a single
/// fix. Crash-only reports show one row per crash; we instead show one row per
/// issue so a reader sees "2 fixes" rather than "30 crashes". The exception is
/// SARIF, which idiomatically keeps one result per occurrence (deduped by the
/// cluster fingerprint).
struct IssueGroup<'a> {
    /// The grouping key: a finding's `cluster_key_full`/`cluster_key` when it has
    /// one, else its own id (a singleton issue).
    issue_id: String,
    /// The most-actionable member, source of the per-issue projected columns.
    representative: &'a FindingReport,
    /// Every raw finding collapsed into this issue, representative first.
    members: Vec<&'a FindingReport>,
}

impl IssueGroup<'_> {
    fn count(&self) -> usize {
        self.members.len()
    }

    /// The HIGHEST severity among the members (a cluster is as severe as its
    /// worst crash).
    fn severity(&self) -> &str {
        self.members
            .iter()
            .min_by_key(|finding| severity_rank(&finding.severity))
            .map_or("unknown", |finding| finding.severity.as_str())
    }

    /// The representative's CWE, unioned with any genuinely different member CWE
    /// (`;`-joined). Non-empty whenever finding loading ran (every finding is
    /// CWE-backfilled at load time).
    fn cwe(&self) -> String {
        let mut ids: Vec<&str> = Vec::new();
        for finding in &self.members {
            for cwe in &finding.actionability.cwe {
                if !ids.contains(&cwe.as_str()) {
                    ids.push(cwe.as_str());
                }
            }
        }
        ids.join(";")
    }

    /// The single place to fix the whole issue: the representative's
    /// `fix_location` as `(file, line)`. `None` when no source location resolved.
    fn fix_location(&self) -> Option<(&str, Option<u64>)> {
        self.representative
            .actionability
            .fix_location
            .as_ref()
            .map(|location| (location.path.as_str(), location.line))
    }

    /// `file:line` (or bare `file`) for the issue's fix location, else `—`.
    fn fix_location_label(&self) -> String {
        match self.fix_location() {
            Some((path, Some(line))) => format!("{path}:{line}"),
            Some((path, None)) => path.to_owned(),
            None => "—".to_owned(),
        }
    }

    /// All member finding ids, in stable (representative-first) order.
    fn member_finding_ids(&self) -> String {
        self.members
            .iter()
            .map(|finding| finding.id.as_str())
            .collect::<Vec<_>>()
            .join(";")
    }

    /// The deduped reproducer path for each member (its minimal reproducer, else
    /// its generated Python reproducer), in stable member order — so a developer
    /// can reach EVERY triggering input the issue collapses.
    fn reproducers(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for finding in &self.members {
            if let Some(path) = finding_reproducer(finding) {
                if !out.iter().any(|existing| existing == path) {
                    out.push(path.to_owned());
                }
            }
        }
        out
    }
}

/// The reproducer that drives a finding's triggering input: its minimal
/// reproducer when minimization produced one, else the standalone generated
/// Python reproducer (`replay.py`) written for every finding. `None` when neither
/// is recorded.
fn finding_reproducer(finding: &FindingReport) -> Option<&str> {
    finding
        .minimal_reproducer
        .as_deref()
        .or(finding.generated_repro_py.as_deref())
}

/// The root-cause issue key for a finding: its full cluster key, else its short
/// cluster key, else its own id (a singleton issue). Mirrors the SARIF
/// `govfuzzIssueKey` fingerprint so every format groups by the same key.
fn issue_key(finding: &FindingReport) -> String {
    finding
        .cluster_key_full
        .clone()
        .or_else(|| finding.cluster_key.clone())
        .unwrap_or_else(|| finding.id.clone())
}

/// Collapse findings into one [`IssueGroup`] per root cause. Deterministic:
/// issues are ordered by severity (highest first) then issue id, and members
/// within an issue by actionability sort key then id (so the representative — the
/// most actionable member — is stable and matches the cluster representative).
fn group_findings_into_issues(findings: &[FindingReport]) -> Vec<IssueGroup<'_>> {
    let mut groups: BTreeMap<String, Vec<&FindingReport>> = BTreeMap::new();
    for finding in findings {
        groups.entry(issue_key(finding)).or_default().push(finding);
    }
    let mut issues: Vec<IssueGroup<'_>> = groups
        .into_iter()
        .map(|(issue_id, mut members)| {
            members.sort_by(|left, right| {
                actionability::finding_sort_key(&left.actionability)
                    .cmp(&actionability::finding_sort_key(&right.actionability))
                    .then_with(|| left.id.cmp(&right.id))
            });
            let representative = members[0];
            IssueGroup {
                issue_id,
                representative,
                members,
            }
        })
        .collect();
    issues.sort_by(|left, right| {
        severity_rank(left.severity())
            .cmp(&severity_rank(right.severity()))
            .then_with(|| left.issue_id.cmp(&right.issue_id))
    });
    issues
}

/// Canonical severity ordering (0 = most severe) for grouping / sorting.
/// Unknown severities sort after the known set so they still surface, last.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" | "informational" => 4,
        "unknown" => 5,
        _ => 6,
    }
}

pub fn load_findings(findings_dir: &Path) -> Result<Vec<FindingReport>, ReportError> {
    load_findings_with_model(findings_dir, None)
}

pub fn load_findings_with_model(
    findings_dir: &Path,
    confidence_model: Option<&confidence_model::LearnedConfidenceModel>,
) -> Result<Vec<FindingReport>, ReportError> {
    if !findings_dir.is_dir() {
        return Err(ReportError::MissingFindingsDir {
            path: findings_dir.to_path_buf(),
        });
    }

    let mut findings = Vec::new();
    for entry in fs::read_dir(findings_dir)? {
        let entry = entry?;
        let finding_dir = entry.path();
        if !finding_dir.is_dir() {
            continue;
        }

        let finding_path = finding_dir.join("finding.json");
        if !finding_path.is_file() {
            continue;
        }

        findings.push(load_finding(&finding_dir, &finding_path, confidence_model)?);
    }

    findings.sort_by(|left, right| {
        actionability::finding_sort_key(&left.actionability)
            .cmp(&actionability::finding_sort_key(&right.actionability))
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.source_path.cmp(&right.source_path))
    });
    Ok(findings)
}

pub fn render_markdown_report(document: &ReportDocument) -> String {
    render_markdown_inner(document, false)
}

pub fn render_markdown_report_with(document: &ReportDocument, options: &ReportOptions) -> String {
    render_markdown_inner(document, options.collapse_clusters)
}

fn render_markdown_inner(document: &ReportDocument, collapse_clusters: bool) -> String {
    use std::collections::{HashMap, HashSet};
    let mut out = String::new();
    out.push_str(&format!("# GovFuzz Report: {}\n\n", document.run.id));
    out.push_str(&format!("Findings: {}\n\n", document.counts.findings));

    if document.findings.is_empty() {
        out.push_str("No findings recorded.\n");
        return out;
    }

    // Lead with the root-cause issue count so a reader sees "2 issues", not
    // "30 crashes". The grouped-issue table (below) is the primary view; the
    // per-finding table and detail sections remain as evidence.
    let issues = group_findings_into_issues(&document.findings);
    out.push_str(&format!(
        "Issues: {} (grouped from {} findings)\n\n",
        issues.len(),
        document.findings.len()
    ));

    let severity_breakdown = severity_breakdown(&document.findings);
    if !severity_breakdown.is_empty() {
        out.push_str("Severity breakdown:\n");
        for (severity, count) in &severity_breakdown {
            out.push_str(&format!("- {}: {}\n", md_text(severity), count));
        }
        out.push('\n');
    }

    if !document.counts.by_actionability_verdict.is_empty() {
        out.push_str("Actionability breakdown:\n");
        for verdict in [
            "real_reachable",
            "likely_reachable",
            "lab_only",
            "blocked",
            "unknown",
        ] {
            if let Some(count) = document.counts.by_actionability_verdict.get(verdict) {
                out.push_str(&format!("- {}: {}\n", verdict, count));
            }
        }
        out.push('\n');
    }

    if !document.counts.by_impact.is_empty() {
        out.push_str("Impact breakdown:\n");
        for impact in ["critical", "high", "medium", "low", "info", "unknown"] {
            if let Some(count) = document.counts.by_impact.get(impact) {
                out.push_str(&format!("- {}: {}\n", impact, count));
            }
        }
        for (impact, count) in &document.counts.by_impact {
            if !matches!(
                impact.as_str(),
                "critical" | "high" | "medium" | "low" | "info" | "unknown"
            ) {
                out.push_str(&format!("- {}: {}\n", md_text(impact), count));
            }
        }
        out.push('\n');
    }

    // Primary presentation: one entry per root-cause issue (count + CWE + the
    // single place to fix), so the reader sees the handful of fixes — and WHERE
    // to make them — before the per-crash detail.
    out.push_str("## Issues\n\n");
    out.push_str("One row per root-cause issue — findings grouped by cluster.\n\n");
    out.push_str("| Issue | Findings | Severity | CWE | Fix location | Target |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for issue in &issues {
        let representative = issue.representative;
        let cwe = issue.cwe();
        let cwe_cell = if cwe.is_empty() {
            "(none)".to_owned()
        } else {
            cwe
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            md_cell(&representative.id),
            issue.count(),
            md_cell(issue.severity()),
            md_cell(&cwe_cell),
            md_cell(&issue.fix_location_label()),
            md_cell(&target_summary(representative))
        ));
    }
    out.push('\n');

    if !document.clusters.is_empty() {
        out.push_str("## Clusters\n\n");
        out.push_str("| Cluster | Findings | Quality | Top frames |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for cluster in &document.clusters {
            let frames = if cluster.top_frames.is_empty() {
                "(none)".to_owned()
            } else {
                cluster.top_frames.join(" > ")
            };
            let quality = format!("{}/{}", cluster.quality.signal, cluster.quality.stability);
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                md_cell(&cluster.key),
                cluster.member_count,
                md_cell(&quality),
                md_cell(&frames)
            ));
        }
        out.push('\n');
    }

    let real_findings = document
        .findings
        .iter()
        .filter(|finding| finding.actionability.verdict == actionability::Verdict::RealReachable)
        .collect::<Vec<_>>();
    if !real_findings.is_empty() {
        out.push_str("## Real Reachable Findings\n\n");
        for finding in real_findings {
            out.push_str(&format!(
                "- `{}` {} {}\n",
                md_code(&finding.id),
                md_text(&finding.severity),
                md_text(&target_summary(finding))
            ));
        }
        out.push('\n');
    }

    out.push_str("| ID | Severity | Classification | Target | Signature |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for finding in &document.findings {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md_cell(&finding.id),
            md_cell(&finding.severity),
            md_cell(finding.classification.as_deref().unwrap_or("unknown")),
            md_cell(&target_summary(finding)),
            md_cell(finding.signature.as_deref().unwrap_or("unknown"))
        ));
    }

    // Per-issue detail keys off the ISSUE representative (not the raw cluster) so
    // the member list, fix-once framing, and collapse all agree on one row per
    // root cause.
    let issue_by_rep: HashMap<&str, &IssueGroup<'_>> = issues
        .iter()
        .map(|issue| (issue.representative.id.as_str(), issue))
        .collect();
    let issue_representatives: HashSet<&str> = issue_by_rep.keys().copied().collect();

    for finding in &document.findings {
        if collapse_clusters && !issue_representatives.contains(finding.id.as_str()) {
            continue;
        }
        out.push_str(&format!("\n## {}\n\n", finding.id));
        if let Some(explanation) = &finding.actionability.explanation {
            out.push_str(&format!(
                "**In plain English:** {}\n\n",
                md_text(explanation)
            ));
        }
        // "Fix once": make explicit that a single edit resolves every member of
        // the issue this finding represents.
        if let Some(issue) = issue_by_rep.get(finding.id.as_str()) {
            out.push_str(&fix_once_line(issue));
        }
        out.push_str(&format!("- Severity: {}\n", md_text(&finding.severity)));
        out.push_str(&format!(
            "- Actionability: {} / {} / {}\n",
            finding.actionability.verdict.as_str(),
            finding.actionability.impact.as_str(),
            finding.actionability.confidence.as_str()
        ));
        if let Some((primary, rest)) = finding.actionability.cwe.split_first() {
            let mut line = match finding.actionability.cwe_name.as_deref() {
                Some(name) => format!("- CWE: {} ({})", md_text(primary), md_text(name)),
                None => format!("- CWE: {}", md_text(primary)),
            };
            if !rest.is_empty() {
                line.push_str(&format!(", also {}", md_text(&rest.join(", "))));
            }
            out.push_str(&line);
            out.push('\n');
        }
        if let Some(replay) = &finding.actionability.replay {
            out.push_str(&format!("- Replay status: {}\n", md_text(&replay.status)));
        }
        // Reachability honesty: when the fuzzed entry is NOT a proven
        // attacker-controlled input channel, say public-API reachability is
        // unproven. We deliberately do not surface a `- Source:` line naming the
        // synthetic govfuzz harness entry — it reads as a real attacker entry
        // point when it is not, and the Sink / fix-location below already point
        // at the actual defect.
        let reachability_unproven = finding
            .actionability
            .entry_path
            .as_ref()
            .is_some_and(|entry| entry.attacker_reachable == Some(false));
        if reachability_unproven {
            out.push_str(
                "- Reachability: public-API reachability UNPROVEN — the fault was reached by exercising the function directly, not through a confirmed untrusted-input path\n",
            );
        }
        if let Some(sink) = &finding.actionability.sink {
            match (&sink.file, sink.line) {
                (Some(file), Some(line)) => out.push_str(&format!(
                    "- Sink: `{}:{}` `{}`\n",
                    md_code(file),
                    line,
                    md_code(&sink.function)
                )),
                (Some(file), None) => out.push_str(&format!(
                    "- Sink: `{}` `{}`\n",
                    md_code(file),
                    md_code(&sink.function)
                )),
                (None, _) => out.push_str(&format!("- Sink: `{}`\n", md_code(&sink.function))),
            }
        }
        if let Some(location) = &finding.actionability.fix_location {
            let line = location
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "- Fix location: `{}{}` ({})\n",
                md_code(&location.path),
                line,
                md_text(&location.reason)
            ));
        } else {
            out.push_str("- Fix location: no source location resolved\n");
        }
        if let Some(entry) = &finding.actionability.entry_path {
            out.push_str(&format!(
                "- Entry path: {} `{}` -> `{}`\n",
                md_text(&entry.kind),
                md_code(&entry.source),
                md_code(&entry.target)
            ));
        }
        if finding.actionability.prosthetics.used {
            out.push_str("- Prosthetics:\n");
            for item in &finding.actionability.prosthetics.items {
                out.push_str(&format!(
                    "  - {} `{}` via {}\n",
                    md_text(&item.kind),
                    md_code(&item.name),
                    md_text(&item.evidence)
                ));
            }
        }
        if !finding.actionability.patch_hints.is_empty() {
            out.push_str("- Suggested fix:\n");
            for hint in &finding.actionability.patch_hints {
                out.push_str(&format!(
                    "  - {}: {}\n",
                    md_text(&hint.title),
                    md_text(&hint.guidance)
                ));
                // Surface the suggested patch as a fenced diff so a developer can
                // read (or apply) the change directly.
                if let Some(diff) = hint
                    .diff
                    .as_deref()
                    .map(str::trim)
                    .filter(|d| !d.is_empty())
                {
                    out.push_str("\n    ```diff\n");
                    for line in diff.lines() {
                        out.push_str("    ");
                        out.push_str(line);
                        out.push('\n');
                    }
                    out.push_str("    ```\n\n");
                }
            }
        }
        if !finding.actionability.next_steps.is_empty() {
            out.push_str("- Next steps:\n");
            for step in &finding.actionability.next_steps {
                out.push_str(&format!("  - {}\n", md_text(step)));
            }
        }
        if let Some(confidence) = confidence_summary(&finding.confidence) {
            out.push_str(&format!("- Confidence: {}\n", md_text(&confidence)));
        }
        if let Some(classification) = finding.classification.as_deref() {
            out.push_str(&format!("- Classification: {}\n", md_text(classification)));
        }
        if let Some(signature) = finding.signature.as_deref() {
            out.push_str(&format!("- Signature: `{}`\n", md_code(signature)));
        }
        if let Some(cluster) = finding.cluster_key.as_deref() {
            out.push_str(&format!("- Cluster: `{}`\n", md_code(cluster)));
        }

        out.push_str(&format!(
            "- Target: {}\n",
            md_text(&target_summary(finding))
        ));

        if let Some(exception) = exception_summary(&finding.exception) {
            out.push_str(&format!("- Exception: {}\n", md_text(&exception)));
        }
        let stack_lines = markdown_stack_frames(&finding.exception);
        if !stack_lines.is_empty() {
            out.push_str("- Stack:\n");
            for line in stack_lines {
                out.push_str(&format!("  - {}\n", line));
            }
        }
        if let Some(mode) = string_at(&finding.sandbox, &["mode"]) {
            out.push_str(&format!("- Sandbox: {}\n", md_text(&mode)));
        }
        if let Some(command) = string_at(&finding.replay, &["command"]) {
            out.push_str(&format!("- Replay: `{}`\n", md_code(&command)));
        }
        if let Some(path) = finding.minimal_reproducer.as_deref() {
            out.push_str(&format!("- Minimal reproducer: `{}`\n", md_code(path)));
        }
        if let Some(path) = finding.generated_repro_py.as_deref() {
            out.push_str(&format!("- Reproducer (Python): `{}`\n", md_code(path)));
        }
        if renders_ada_repro(finding) {
            if let Some(path) = finding.generated_repro_ada.as_deref() {
                out.push_str(&format!("- Reproducer Ada: `{}`\n", md_code(path)));
            }
            if let Some(reason) = finding.repro_ada_omitted_reason.as_deref() {
                out.push_str(&format!("- Reproducer Ada omitted: {}\n", md_text(reason)));
            }
        }

        let steps = investigation_steps(&finding.investigation_steps);
        if !steps.is_empty() {
            out.push_str("\nInvestigation steps:\n");
            for (index, step) in steps.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", index + 1, md_text(step)));
            }
        }

        // Enumerate every member of the issue this finding represents, so a
        // developer can reach EVERY triggering input — not just the
        // representative's. Shown whether or not clusters are collapsed.
        if let Some(issue) = issue_by_rep.get(finding.id.as_str()) {
            if issue.count() > 1 {
                out.push_str(&format!(
                    "\n- Member findings ({}): one fix resolves all\n",
                    issue.count()
                ));
                for member in &issue.members {
                    out.push_str(&member_findings_line(member));
                }
            }
        }
    }

    out
}

/// The per-member writeup line under a grouped issue: finding id, sink
/// `file:line` + function, signature, reproducer path, and replay command — so a
/// reader can locate and re-trigger each collapsed variant.
fn member_findings_line(finding: &FindingReport) -> String {
    let mut parts: Vec<String> = vec![format!("`{}`", md_code(&finding.id))];
    if let Some(sink) = &finding.actionability.sink {
        let location = match (&sink.file, sink.line) {
            (Some(file), Some(line)) => format!("{}:{}", md_text(file), line),
            (Some(file), None) => md_text(file),
            (None, _) => String::new(),
        };
        if location.is_empty() {
            parts.push(format!("`{}`", md_code(&sink.function)));
        } else {
            parts.push(format!("{} `{}`", location, md_code(&sink.function)));
        }
    }
    if let Some(signature) = finding.signature.as_deref() {
        parts.push(format!("sig `{}`", md_code(signature)));
    }
    if let Some(reproducer) = finding_reproducer(finding) {
        parts.push(format!("reproducer: `{}`", md_code(reproducer)));
    }
    if let Some(command) = string_at(&finding.replay, &["command"]) {
        parts.push(format!("replay: `{}`", md_code(&command)));
    }
    format!("  - {}\n", parts.join(" — "))
}

/// The "Fix once" framing line for an issue: the single place to edit and the
/// representative's top fix guidance, asserting that one fix resolves all
/// members. Honest when no fix location resolved.
fn fix_once_line(issue: &IssueGroup<'_>) -> String {
    let count = issue.count();
    let hint = issue
        .representative
        .actionability
        .patch_hints
        .first()
        .map(|hint| {
            let guidance = hint.guidance.trim();
            if guidance.is_empty() {
                hint.title.clone()
            } else {
                format!("{} — {}", hint.title, guidance)
            }
        });
    match issue.fix_location() {
        Some((path, line)) => {
            let location = match line {
                Some(line) => format!("{path}:{line}"),
                None => path.to_owned(),
            };
            let guidance = hint
                .map(|hint| format!(" — {}", md_text(&hint)))
                .unwrap_or_default();
            format!(
                "**Fix once:** edit `{}`{}. Resolves all {} finding(s).\n\n",
                md_code(&location),
                guidance,
                count
            )
        }
        None => format!(
            "**Fix once:** no source fix location resolved — triage from the sink/stack below. Covers all {count} finding(s).\n\n"
        ),
    }
}

pub fn render_sarif_report(document: &ReportDocument) -> Value {
    let rules = sarif_rules_for_document(document);
    let cluster_index: std::collections::HashMap<String, (usize, String, bool, ClusterQuality)> =
        document
            .clusters
            .iter()
            .map(|c| {
                (
                    c.key.clone(),
                    (
                        c.member_count,
                        c.representative.clone(),
                        c.fallback,
                        c.quality.clone(),
                    ),
                )
            })
            .collect();
    // Only enable the SRCROOT relativisation when we recovered an *absolute*
    // source root: a relative root cannot produce a valid `file://` base URI.
    let root: Option<PathBuf> = document
        .run
        .source_root
        .as_deref()
        .map(PathBuf::from)
        .filter(|root| root.is_absolute());
    let mut run = json!({
        "tool": {
            "driver": {
                "name": "GovFuzz",
                "version": env!("CARGO_PKG_VERSION"),
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/Tarmo-Technologies/govfuzz",
                "rules": rules,
            }
        },
        "results": document
            .findings
            .iter()
            .map(|f| sarif_result(f, &cluster_index, root.as_deref()))
            .collect::<Vec<_>>(),
        "properties": {
            "govfuzzRunId": document.run.id,
            "govfuzzReportSchemaVersion": document.schema_version,
        }
    });
    if let Some(root) = root.as_deref() {
        run.as_object_mut()
            .expect("run is an object")
            .insert("originalUriBaseIds".to_owned(), original_uri_base_ids(root));
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run]
    })
}

/// Build the run-level `originalUriBaseIds` entry that anchors `SRCROOT`-based
/// artifact URIs to an absolute `file://` directory (trailing slash required so
/// it is a valid base URI).
fn original_uri_base_ids(root: &Path) -> Value {
    let mut uri = file_uri(&root.to_string_lossy());
    if !uri.ends_with('/') {
        uri.push('/');
    }
    json!({ "SRCROOT": { "uri": uri } })
}

/// Build a SARIF `artifactLocation` object for `path`. When `root` is a known
/// absolute scan root and `path` is an absolute path *under* it, the URI is made
/// root-relative (forward slashes, no leading `/`) and tagged
/// `uriBaseId: SRCROOT` so GitHub/Azure code scanning can map the finding to a
/// repo file. Absolute paths outside the root become valid `file://` URIs;
/// already-relative paths are left as-is. Never panics on a non-relativisable
/// path.
fn sarif_artifact_location(path: &str, root: Option<&Path>) -> Value {
    let candidate = Path::new(path);
    match root {
        Some(root) if candidate.is_absolute() => {
            if let Ok(relative) = candidate.strip_prefix(root) {
                let relative = relative.to_string_lossy().replace('\\', "/");
                let relative = relative.trim_start_matches('/');
                let uri = if relative.is_empty() {
                    ".".to_owned()
                } else {
                    relative.to_owned()
                };
                json!({ "uri": uri, "uriBaseId": "SRCROOT" })
            } else {
                json!({ "uri": file_uri(path) })
            }
        }
        _ => json!({ "uri": path }),
    }
}

/// Render an absolute filesystem path as a `file://` URI. Paths that already
/// carry a scheme (or are not absolute) are returned unchanged.
fn file_uri(path: &str) -> String {
    if path.contains("://") {
        path.to_owned()
    } else if let Some(rest) = path.strip_prefix('/') {
        format!("file:///{rest}")
    } else {
        path.to_owned()
    }
}

fn sarif_rules_for_document(document: &ReportDocument) -> Vec<Value> {
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    let mut rules = Vec::new();
    let mut has_generic = false;

    for finding in &document.findings {
        match finding.rule_id.as_deref().and_then(rules::by_id) {
            Some(rule) => {
                if seen_ids.insert(rule.id.to_owned()) {
                    rules.push(sarif_rule_entry(rule));
                }
            }
            None => has_generic = true,
        }
    }

    if has_generic || rules.is_empty() {
        rules.push(json!({
            "id": "govfuzz.finding",
            "name": "GovFuzz finding",
            "shortDescription": { "text": "GovFuzz finding" },
            "fullDescription": {
                "text": "A GovFuzz input triggered an exception-related finding."
            },
            "defaultConfiguration": { "level": "warning" },
        }));
    }

    rules
}

fn sarif_rule_entry(rule: &Rule) -> Value {
    let mut tags = vec!["security".to_owned(), rule.cwe.to_owned()];
    if let Some(place) = rule.cwe_top_25 {
        tags.push(format!("cwe-top-25-{place}"));
        tags.push("cwe-top-25".to_owned());
    }
    if let Some(owasp) = rule.owasp_top_10 {
        tags.push(owasp.to_owned());
    }
    if let Some(value) = rule.cert_c {
        tags.push(format!("cert-c:{value}"));
    }
    if let Some(value) = rule.cert_cpp {
        tags.push(format!("cert-cpp:{value}"));
    }
    if let Some(value) = rule.misra_c {
        tags.push(format!("misra-c:{value}"));
    }
    if let Some(value) = rule.misra_cpp {
        tags.push(format!("misra-cpp:{value}"));
    }
    for value in rule.iso_tr_24772_ada {
        tags.push(format!("iso-tr-24772-ada:{value}"));
    }
    tags.push(format!("govfuzz.slug:{}", rule.slug));

    let help_uri = rule
        .references
        .first()
        .copied()
        .unwrap_or("https://github.com/Tarmo-Technologies/govfuzz");
    let references_markdown: String = rule
        .references
        .iter()
        .map(|reference| format!("- {reference}\n"))
        .collect();

    json!({
        "id": rule.id,
        "name": rule.slug,
        "shortDescription": { "text": rule.name },
        "fullDescription": { "text": rule.description },
        "help": {
            "text": format!("{}\n\nReferences:\n{}", rule.description, references_markdown),
            "markdown": format!("{}\n\n**References:**\n\n{}", rule.description, references_markdown),
        },
        "helpUri": help_uri,
        "defaultConfiguration": {
            "level": sarif_level(rule.default_severity.as_str()),
        },
        "properties": {
            "tags": tags,
            "security-severity": format!("{:.1}", rule.security_severity),
            "precision": rule.default_confidence.as_str(),
            "govfuzz.slug": rule.slug,
            "cwe": rule.cwe,
            "cwe_top_25": rule.cwe_top_25,
        }
    })
}

pub fn validate_sarif_report(report: &Value) -> Result<(), ReportError> {
    expect_string_eq(report, &["version"], "2.1.0")?;
    let runs = expect_array(report, &["runs"])?;
    if runs.is_empty() {
        return Err(ReportError::SarifValidation(
            "runs must contain at least one run".to_owned(),
        ));
    }

    for (run_index, run) in runs.iter().enumerate() {
        let run_path = format!("runs[{run_index}]");
        expect_string(run, &["tool", "driver", "name"], &run_path)?;
        expect_string(run, &["tool", "driver", "version"], &run_path)?;
        expect_array(run, &["tool", "driver", "rules"])?;
        let results = expect_array(run, &["results"])?;
        for (result_index, result) in results.iter().enumerate() {
            let result_path = format!("{run_path}.results[{result_index}]");
            expect_string_eq(result, &["kind"], "fail")?;
            expect_string(result, &["message", "text"], &result_path)?;
            expect_string(
                result,
                &["properties", "govfuzzExceptionSignature"],
                &result_path,
            )?;
            expect_string(result, &["properties", "govfuzzFindingId"], &result_path)?;
            validate_sarif_locations(result, &result_path)?;
            validate_sarif_related_locations(result, &result_path)?;
        }
        validate_sarif_uri_base_ids(run, &run_path)?;
    }

    Ok(())
}

/// Enforce the SRCROOT contract on every `artifactLocation` in a run: a
/// `uriBaseId: SRCROOT` URI must be relative (no leading `/`, no scheme), and a
/// run that uses SRCROOT anywhere must define `originalUriBaseIds.SRCROOT.uri`.
fn validate_sarif_uri_base_ids(run: &Value, run_path: &str) -> Result<(), ReportError> {
    let mut artifact_locations = Vec::new();
    collect_artifact_locations(run, &mut artifact_locations);
    let mut uses_srcroot = false;
    for location in &artifact_locations {
        if location.get("uriBaseId").and_then(Value::as_str) != Some("SRCROOT") {
            continue;
        }
        uses_srcroot = true;
        let uri = location
            .get("uri")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if uri.is_empty() || uri.starts_with('/') || uri.contains("://") {
            return Err(ReportError::SarifValidation(format!(
                "{run_path}: artifactLocation with uriBaseId SRCROOT must be a relative uri, got {uri:?}"
            )));
        }
    }
    if uses_srcroot {
        let base = run
            .pointer("/originalUriBaseIds/SRCROOT/uri")
            .and_then(Value::as_str);
        if !matches!(base, Some(uri) if !uri.is_empty()) {
            return Err(ReportError::SarifValidation(format!(
                "{run_path}: originalUriBaseIds.SRCROOT.uri must be present when results use uriBaseId SRCROOT"
            )));
        }
    }
    Ok(())
}

/// Recursively gather every nested `artifactLocation` object (primary locations,
/// related locations, and stackFrame physical locations) so the SRCROOT
/// invariants can be checked uniformly.
fn collect_artifact_locations<'a>(value: &'a Value, out: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if let Some(location) = map.get("artifactLocation") {
                if location.is_object() {
                    out.push(location);
                }
            }
            for nested in map.values() {
                collect_artifact_locations(nested, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_artifact_locations(item, out);
            }
        }
        _ => {}
    }
}

/// Render JUnit XML with **one `<testcase>` per root-cause issue** (not per
/// crash), so a CI gate counts fixes, not duplicate occurrences. Each testcase is
/// named after the issue's representative finding; the failure message leads with
/// the CWE, and the failure body records the issue id, collapsed `count`, and the
/// member finding ids.
pub fn render_junit_report(document: &ReportDocument) -> String {
    let issues = group_findings_into_issues(&document.findings);
    let tests = issues.len();
    let failures = tests;
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\" skipped=\"0\">\n",
        xml_attr(&format!("govfuzz.{}", document.run.id)),
        tests,
        failures
    ));

    for issue in &issues {
        let finding = issue.representative;
        let classname = format!("govfuzz.{}", target_summary(finding));
        let failure_type = finding
            .classification
            .as_deref()
            .unwrap_or("govfuzz_finding");
        let failure_message = junit_failure_message(finding);
        let verdict = finding.actionability.verdict.as_str();
        let test_name = match finding.cluster_key.as_deref() {
            Some(key) => format!("{} [{verdict}] [cluster:{}]", finding.id, key),
            None => format!("{} [{verdict}]", finding.id),
        };
        out.push_str(&format!(
            "  <testcase classname=\"{}\" name=\"{}\">\n",
            xml_attr(&classname),
            xml_attr(&test_name)
        ));
        out.push_str(&format!(
            "    <failure type=\"{}\" message=\"{}\">{}</failure>\n",
            xml_attr(failure_type),
            xml_attr(&failure_message),
            xml_text(&junit_failure_body_for_issue(issue))
        ));
        out.push_str(&format!(
            "    <system-out>{}</system-out>\n",
            xml_text(&junit_system_out(finding))
        ));
        out.push_str("  </testcase>\n");
    }

    out.push_str("</testsuite>\n");
    out
}

fn load_confidence_model(
    path: Option<&Path>,
) -> Result<Option<confidence_model::LearnedConfidenceModel>, ReportError> {
    let Some(path) = path else {
        return Ok(None);
    };
    confidence_model::LearnedConfidenceModel::from_slice(&fs::read(path)?)
        .map(Some)
        .map_err(|source| ReportError::ConfidenceModel {
            path: path.to_path_buf(),
            source,
        })
}

fn load_finding(
    finding_dir: &Path,
    finding_path: &Path,
    confidence_model: Option<&confidence_model::LearnedConfidenceModel>,
) -> Result<FindingReport, ReportError> {
    let raw: Value = serde_json::from_slice(&fs::read(finding_path)?)?;
    if !raw.is_object() {
        return Err(ReportError::FindingRecordNotObject {
            path: finding_path.to_path_buf(),
        });
    }

    let id = string_at(&raw, &["id"]).unwrap_or_else(|| {
        finding_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown-finding")
            .to_owned()
    });
    let minimal_reproducer = string_at(&raw, &["minimal_reproducer"])
        .or_else(|| string_at(&raw, &["paths", "minimized"]));
    let raw_generated_repro_ada = string_at(&raw, &["generated_repro_ada"]);
    let (generated_repro_ada, repro_ada_omitted_reason) =
        repro_ada_status(finding_dir, &id, raw_generated_repro_ada.as_deref());

    let classification = string_at(&raw, &["classification"])
        .or_else(|| string_at(&raw, &["exception", "classification"]))
        .or_else(|| string_at(&raw, &["result", "kind"]));
    let exception_name = string_at(&raw, &["exception", "name"])
        .or_else(|| string_at(&raw, &["exception", "exception_name"]))
        .or_else(|| string_at(&raw, &["exception", "handler", "exception_name"]));
    let rule_id = string_at(&raw, &["rule_id"]).or_else(|| {
        rules::derive_rule_id(classification.as_deref(), exception_name.as_deref())
            .map(str::to_owned)
    });

    let severity = string_at(&raw, &["severity"]).unwrap_or_else(|| {
        rule_id
            .as_deref()
            .and_then(rules::by_id)
            .map(|rule| rule.default_severity.as_str().to_owned())
            .unwrap_or_else(|| "unknown".to_owned())
    });

    let cluster = corpus::cluster::cluster_from_finding_json(&raw);
    let (cluster_key, cluster_key_full, cluster_frames, cluster_fallback) = match cluster {
        Some(c) => (Some(c.short), Some(c.full), c.frames, c.fallback),
        None => (None, None, Vec::new(), false),
    };
    let cluster_quality = cluster_quality(&cluster_frames, cluster_fallback);
    let mut actionability = actionability::existing_actionability_or_backfill(
        actionability::RunMode::Reporting,
        &raw,
        Some(finding_path),
    );
    // Reporting contract: every finding row in every format carries a non-empty
    // CWE. Backfill from the on-disk CWE / the matched catalog rule / a documented
    // generic when the bug-class map left it empty.
    ensure_finding_cwe(&mut actionability, &raw, rule_id.as_deref());
    // Standalone Python reproducer for EVERY finding (C/C++/Ada/unknown): runs the
    // built harness on the recorded testcase with the sanitizer env.
    let generated_repro_py = repro_py_status(finding_dir, &id, &raw, &actionability);

    Ok(FindingReport {
        id: id.clone(),
        source_path: path_string(finding_path),
        severity,
        signature: string_at(&raw, &["signature"])
            .or_else(|| string_at(&raw, &["exception", "signature"])),
        cluster_key,
        cluster_key_full,
        cluster_frames,
        cluster_fallback,
        cluster_quality,
        classification,
        rule_id,
        confidence: confidence_value(&raw, confidence_model),
        target: value_at(&raw, &["target"]).unwrap_or_else(|| fallback_target(&raw)),
        build: value_at(&raw, &["build"]).unwrap_or_else(|| json!({})),
        sandbox: value_at(&raw, &["sandbox"])
            .or_else(|| value_at(&raw, &["build", "sandbox"]))
            .unwrap_or(Value::Null),
        input: value_at(&raw, &["input"]).unwrap_or_else(|| fallback_input(&id)),
        call_sequence: value_at(&raw, &["call_sequence"]).unwrap_or_else(|| json!([])),
        exception: value_at(&raw, &["exception"]).unwrap_or_else(|| fallback_exception(&raw)),
        replay: value_at(&raw, &["replay"]).unwrap_or_else(|| fallback_replay(&id)),
        minimal_reproducer: minimal_reproducer.map(|path| finding_artifact_path(&id, &path)),
        generated_repro_ada,
        repro_ada_omitted_reason,
        generated_repro_py,
        investigation_steps: value_at(&raw, &["investigation_steps"]).unwrap_or_else(|| json!([])),
        actionability,
        raw,
    })
}

/// Guarantee a finding carries a non-empty CWE, the load-bearing reporting
/// contract that every CSV / JUnit / SARIF / Markdown row maps to a weakness.
/// Priority:
///   1. an explicit `cwe` on the on-disk finding JSON — authoritative, honored
///      verbatim (normalised to `CWE-NNN`);
///   2. the bug-class CWE the `actionability` backfill already resolved for a
///      crash that classified (kept when present — it is the most specific);
///   3. the authoritative CWE of the matched `finding_rules` catalog rule
///      (`Rule.cwe`) — this is where behavioral oracle findings (`GF-NNNN`),
///      whose bug class is `Unknown`, get their CWE;
///   4. a documented last-resort generic (see [`final_resort_cwe`]).
///
/// Steps 2 and 3 are practically disjoint (a rule only derives for Ada-exception
/// classifications, which never classify to a memory-safety bug class), so the
/// order between them is not observable on real findings.
fn ensure_finding_cwe(
    record: &mut actionability::ActionabilityRecord,
    raw: &Value,
    rule_id: Option<&str>,
) {
    if let Some(explicit) = explicit_cwe(raw) {
        record.cwe = explicit;
        return;
    }
    if !record.cwe.is_empty() {
        return;
    }
    if let Some(rule) = rule_id.and_then(rules::by_id) {
        record.cwe = vec![rule.cwe.to_owned()];
        return;
    }
    record.cwe = vec![final_resort_cwe(raw).to_owned()];
}

/// An explicit `cwe` on the finding JSON (a single id or an array), normalised so
/// a bare number becomes `CWE-NNN`. `None` when absent or empty.
fn explicit_cwe(raw: &Value) -> Option<Vec<String>> {
    let value = raw.get("cwe")?;
    let mut out = Vec::new();
    match value {
        Value::String(text) => push_cwe_id(&mut out, text),
        Value::Number(number) => push_cwe_id(&mut out, &number.to_string()),
        Value::Array(items) => {
            for item in items {
                if let Some(text) = item.as_str() {
                    push_cwe_id(&mut out, text);
                } else if let Some(number) = item.as_u64() {
                    push_cwe_id(&mut out, &number.to_string());
                }
            }
        }
        _ => {}
    }
    (!out.is_empty()).then_some(out)
}

fn push_cwe_id(out: &mut Vec<String>, raw: &str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    let normalized = if trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("CWE-{trimmed}")
    } else {
        trimmed.to_owned()
    };
    if !out.contains(&normalized) {
        out.push(normalized);
    }
}

/// Last-resort CWE for a crash that matched no sanitizer bug class, no catalog
/// rule, and carried no explicit CWE — so the report never emits a blank CWE
/// cell. The choice is deliberately conservative and taxonomy-valid:
///
///   - `CWE-1006` (a *category*, "Bad Coding Practices") and the `CWE-noinfo`
///     placeholder are NOT real weakness leaves and are rejected by SARIF/SCA
///     taxonomies — never used.
///   - A bare `CWE-20` (Improper Input Validation) over-claims an input-handling
///     root cause we did not establish — rejected.
///   - When the crash report carries out-of-bounds **write** evidence we map to
///     `CWE-787` (Out-of-bounds Write), the most defensible specific weakness;
///     we never claim memory corruption without that evidence.
///   - Otherwise we assert only what we can defend: fuzzed input drove the
///     process to a reachable abnormal termination, i.e. `CWE-617` (Reachable
///     Assertion). It is a valid leaf and an honest umbrella for "the program
///     reached a fatal state on attacker-supplied input" without over-claiming a
///     specific memory-safety mechanism.
fn final_resort_cwe(raw: &Value) -> &'static str {
    let haystack = format!(
        "{} {}",
        string_at(raw, &["exception", "name"]).unwrap_or_default(),
        string_at(raw, &["exception", "message"]).unwrap_or_default()
    )
    .to_ascii_lowercase();
    if haystack.contains("write") {
        "CWE-787"
    } else {
        "CWE-617"
    }
}

/// Whether to surface the Ada reproducer lines for this finding. The Ada repro
/// is only meaningful for Ada-dialect findings — `ensure_repro_ada` writes a
/// `repro.adb` for any finding with a `testcase.bin`, so its mere presence does
/// NOT imply the finding is Ada. A C / C++ sanitizer crash (dialect `unknown`
/// from the C pipeline, or any non-Ada dialect) must never mention Ada.
fn renders_ada_repro(finding: &FindingReport) -> bool {
    let dialect = string_at(&finding.raw, &["dialect"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    if dialect.starts_with("ada") {
        return true;
    }
    if !dialect.is_empty() {
        // An explicit non-Ada dialect (`unknown` / `c` / `cpp`): never Ada.
        return false;
    }
    // No dialect recorded at all (older / hand-written Ada-flavored findings):
    // mention the Ada reproducer only when one was actually generated and the
    // finding is not a C / C++ sanitizer crash.
    let has_sanitizer = string_at(&finding.raw, &["exception", "sanitizer"])
        .is_some_and(|sanitizer| !sanitizer.trim().is_empty());
    !has_sanitizer && finding.generated_repro_ada.is_some()
}

fn repro_ada_status(
    finding_dir: &Path,
    id: &str,
    raw_generated_repro_ada: Option<&str>,
) -> (Option<String>, Option<String>) {
    match ensure_repro_ada(finding_dir) {
        Ok(()) => (Some(finding_artifact_path(id, "repro.adb")), None),
        Err(reason) => (
            raw_generated_repro_ada.map(|path| finding_artifact_path(id, path)),
            raw_generated_repro_ada.is_none().then_some(reason),
        ),
    }
}

fn ensure_repro_ada(finding_dir: &Path) -> Result<(), String> {
    let testcase_path = finding_dir.join("testcase.bin");
    if !testcase_path.is_file() {
        return Err("missing testcase.bin".to_owned());
    }

    let testcase = fs::read(&testcase_path)
        .map_err(|error| format!("read {}: {error}", testcase_path.display()))?;
    let repro_path = finding_dir.join("repro.adb");
    fs::write(&repro_path, render_repro_ada(&testcase))
        .map_err(|error| format!("write {}: {error}", repro_path.display()))
}

fn render_repro_ada(testcase: &[u8]) -> String {
    let mut out = String::new();
    out.push_str("--  SPDX-License-Identifier: Apache-2.0\n\n");
    out.push_str("with Ada.Streams.Stream_IO;\n");
    out.push_str("with Ada.Text_IO;\n\n");
    out.push_str("procedure Repro is\n");
    if !testcase.is_empty() {
        let len = testcase.len();
        out.push_str("   Data : constant Ada.Streams.Stream_Element_Array ");
        let _ = writeln!(out, "(1 .. {len}) := (");
        for (index, byte) in testcase.iter().enumerate() {
            let comma = if index + 1 == testcase.len() { "" } else { "," };
            let ada_index = index + 1;
            let _ = writeln!(out, "      {ada_index} => 16#{byte:02X}#{comma}");
        }
        out.push_str("   );\n");
    }
    out.push_str("   File : Ada.Streams.Stream_IO.File_Type;\n");
    out.push_str("begin\n");
    out.push_str(
        "   Ada.Streams.Stream_IO.Create (File, Ada.Streams.Stream_IO.Out_File, \"repro_testcase.bin\");\n",
    );
    if !testcase.is_empty() {
        out.push_str("   Ada.Streams.Stream_IO.Write (File, Data);\n");
    }
    out.push_str("   Ada.Streams.Stream_IO.Close (File);\n");
    out.push_str("   Ada.Text_IO.Put_Line (\"wrote repro_testcase.bin\");\n");
    out.push_str("end Repro;\n");
    out
}

/// Generate `replay.py` for a finding and return its report-relative path. Best
/// effort: writes a standalone Python reproducer into the finding dir for EVERY
/// finding (C / C++ / Ada / unknown). Returns `None` on write failure so a
/// read-only / broken finding dir never aborts the whole report.
fn repro_py_status(
    finding_dir: &Path,
    id: &str,
    raw: &Value,
    actionability: &actionability::ActionabilityRecord,
) -> Option<String> {
    match ensure_repro_py(finding_dir, raw, actionability) {
        Ok(()) => Some(finding_artifact_path(id, "replay.py")),
        Err(_) => None,
    }
}

fn ensure_repro_py(
    finding_dir: &Path,
    raw: &Value,
    actionability: &actionability::ActionabilityRecord,
) -> Result<(), String> {
    let testcase_name =
        string_at(raw, &["paths", "testcase"]).unwrap_or_else(|| "testcase.bin".to_owned());
    let fixture_path = string_at(raw, &["fixture_path"]).unwrap_or_default();
    let harness_id = string_at(raw, &["harness_id"]).unwrap_or_default();
    let asan_options = asan_options_for(raw);
    let extra_env = raw
        .pointer("/runtime_mode/env_injected")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut header_lines = Vec::new();
    if let Some(explanation) = &actionability.explanation {
        header_lines.push(explanation.clone());
    }
    if let Some(sink) = &actionability.sink {
        header_lines.push(format!("Sink: {}", sink_header_line(sink)));
    }

    let script = render_repro_py(
        &testcase_name,
        &fixture_path,
        &harness_id,
        &asan_options,
        "print_stacktrace=1",
        &extra_env,
        &header_lines,
    );
    let path = finding_dir.join("replay.py");
    fs::write(&path, script).map_err(|error| format!("write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&path, perms);
        }
    }
    Ok(())
}

/// The default `ASAN_OPTIONS` for a finding's reproducer. Leak findings (LSan)
/// MUST keep leak detection on to reproduce, so they get `detect_leaks=1`; every
/// other class disables leak detection so libFuzzer's own exit-time leak noise
/// doesn't mask the real crash being replayed.
fn asan_options_for(raw: &Value) -> String {
    let sanitizer = string_at(raw, &["exception", "sanitizer"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let message = string_at(raw, &["exception", "message"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_leak = sanitizer == "lsan" || message.contains("leak");
    if is_leak {
        "detect_leaks=1:abort_on_error=1".to_owned()
    } else {
        "detect_leaks=0:abort_on_error=1".to_owned()
    }
}

/// Compact `file:line (function)` reference to the sink for the reproducer header.
fn sink_header_line(sink: &actionability::Sink) -> String {
    match (&sink.file, sink.line) {
        (Some(file), Some(line)) => format!("{file}:{line} ({})", sink.function),
        (Some(file), None) => format!("{file} ({})", sink.function),
        (None, _) => sink.function.clone(),
    }
}

/// Render a standalone `replay.py`. The script auto-discovers the harness (from
/// the sibling `finding.json`'s `fixture_path` / `harness_id`, or argv[1]), sets
/// the sanitizer env unless already set, runs the harness on the recorded
/// testcase (argv-file for libFuzzer/driver harnesses, stdin for AFL), and prints
/// the output + exit status. Embedded string values are JSON-encoded, which is a
/// valid Python string/dict literal, so paths/symbols with quotes are safe.
fn render_repro_py(
    testcase_name: &str,
    fixture_path: &str,
    harness_id: &str,
    asan_options: &str,
    ubsan_options: &str,
    extra_env: &serde_json::Map<String, Value>,
    header_lines: &[String],
) -> String {
    let py_str = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned());
    let extra_env_py = serde_json::to_string(&Value::Object(extra_env.clone()))
        .unwrap_or_else(|_| "{}".to_owned());
    let header = if header_lines.is_empty() {
        "#".to_owned()
    } else {
        header_lines
            .iter()
            .map(|line| format!("# {}", line.replace(['\n', '\r'], " ")))
            .collect::<Vec<_>>()
            .join("\n")
    };

    const TEMPLATE: &str = r##"#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Auto-generated by govfuzz. Standalone reproducer for this finding.
__HEADER__
#
# Usage:
#   python3 replay.py [HARNESS]
#
# With no argument the harness is auto-discovered from the sibling finding.json
# (fixture_path / harness_id + <work>/auto/<harness_id>/main). Pass a path to
# override. The harness runs on the recorded testcase with the sanitizer env and
# its output + exit status are printed.
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTCASE = HERE / __TESTCASE__
FIXTURE_PATH = __FIXTURE__
HARNESS_ID = __HARNESS_ID__
ASAN_OPTIONS_DEFAULT = __ASAN__
UBSAN_OPTIONS_DEFAULT = __UBSAN__
EXTRA_ENV = __EXTRA_ENV__


def load_finding():
    try:
        return json.loads((HERE / "finding.json").read_text())
    except Exception:
        return {}


def candidate_harnesses(finding):
    # 1) explicit override on the command line
    if len(sys.argv) > 1:
        yield Path(sys.argv[1])
        return
    # 2) fixture_path recorded in finding.json, then the embedded fallback
    for fixture in (finding.get("fixture_path"), FIXTURE_PATH):
        if fixture:
            yield Path(fixture)
    # 3) <work>/auto/<harness_id>/<leaf> relative to this finding dir
    hid = finding.get("harness_id") or HARNESS_ID
    if hid:
        for root in (HERE.parent.parent, HERE.parent):
            for leaf in ("main", "main_afl", "main.exe", "main_afl.exe"):
                yield root / "auto" / hid / leaf


def resolve_harness(finding):
    tried = []
    for cand in candidate_harnesses(finding):
        if cand.is_file():
            return cand
        tried.append(str(cand))
    sys.stderr.write("could not auto-discover the harness; pass it as the first argument.\n")
    sys.stderr.write("tried:\n")
    for path in tried:
        sys.stderr.write("  " + path + "\n")
    sys.exit(2)


def main():
    finding = load_finding()
    harness = resolve_harness(finding)

    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", ASAN_OPTIONS_DEFAULT)
    env.setdefault("UBSAN_OPTIONS", UBSAN_OPTIONS_DEFAULT)
    for key, value in EXTRA_ENV.items():
        env.setdefault(key, value)

    # AFL persistent-mode harnesses read the testcase from stdin; libFuzzer /
    # govfuzz driver harnesses take it as argv[1]. Detect from the harness name,
    # else default to argv[1] (the govfuzz convention).
    if harness.name.startswith("main_afl"):
        data = TESTCASE.read_bytes() if TESTCASE.is_file() else b""
        print("running (AFL/stdin): %s < %s" % (harness, TESTCASE))
        proc = subprocess.run(
            [str(harness)],
            input=data,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    else:
        print("running (libFuzzer/argv): %s %s" % (harness, TESTCASE))
        proc = subprocess.run(
            [str(harness), str(TESTCASE)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    sys.stdout.write(proc.stdout.decode("utf-8", "replace"))
    if not proc.stdout.endswith(b"\n"):
        print()
    print("exit status: %d" % proc.returncode)
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
"##;

    TEMPLATE
        .replace("__HEADER__", &header)
        .replace("__TESTCASE__", &py_str(testcase_name))
        .replace("__FIXTURE__", &py_str(fixture_path))
        .replace("__HARNESS_ID__", &py_str(harness_id))
        .replace("__ASAN__", &py_str(asan_options))
        .replace("__UBSAN__", &py_str(ubsan_options))
        .replace("__EXTRA_ENV__", &extra_env_py)
}

fn value_at(value: &Value, path: &[&str]) -> Option<Value> {
    let mut current = value;
    for component in path {
        current = current.get(*component)?;
    }
    Some(current.clone())
}

fn confidence_value(
    raw: &Value,
    model: Option<&confidence_model::LearnedConfidenceModel>,
) -> Value {
    value_at(raw, &["confidence"])
        .filter(has_explicit_confidence)
        .unwrap_or_else(|| {
            serde_json::to_value(confidence_model::confidence_with_model(raw, model))
                .expect("confidence report serializes")
        })
}

fn has_explicit_confidence(confidence: &Value) -> bool {
    !confidence.is_null()
        && !confidence
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for component in path {
        current = current.get(*component)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn fallback_target(raw: &Value) -> Value {
    let mut target = serde_json::Map::new();
    if let Some(harness_id) = string_at(raw, &["harness_id"]) {
        target.insert("harness_id".to_owned(), json!(harness_id));
    }
    if let Some(package) = string_at(raw, &["package"]) {
        target.insert("package".to_owned(), json!(package));
    }
    if let Some(subprogram) = string_at(raw, &["subprogram"]) {
        target.insert("subprogram".to_owned(), json!(subprogram));
    }
    Value::Object(target)
}

fn fallback_input(id: &str) -> Value {
    json!({ "bytes_path": format!("{id}/testcase.bin") })
}

fn fallback_exception(raw: &Value) -> Value {
    let mut exception = serde_json::Map::new();
    if let Some(name) =
        string_at(raw, &["name"]).or_else(|| string_at(raw, &["handler", "exception_name"]))
    {
        exception.insert("name".to_owned(), json!(name));
    }
    if let Some(message) =
        string_at(raw, &["message"]).or_else(|| string_at(raw, &["handler", "exception_message"]))
    {
        exception.insert("message".to_owned(), json!(message));
    }
    if let Some(classification) = string_at(raw, &["classification"]) {
        exception.insert("classification".to_owned(), json!(classification));
    }
    if let Some(file) =
        string_at(raw, &["handler_file"]).or_else(|| string_at(raw, &["handler", "handler_file"]))
    {
        let mut handler = serde_json::Map::new();
        handler.insert("file".to_owned(), json!(file));
        if let Some(line) = raw
            .get("handler_line")
            .or_else(|| raw.pointer("/handler/handler_line"))
            .and_then(Value::as_u64)
        {
            handler.insert("line".to_owned(), json!(line));
        }
        exception.insert("handler".to_owned(), Value::Object(handler));
    }
    Value::Object(exception)
}

fn fallback_replay(id: &str) -> Value {
    json!({ "command": format!("govfuzz replay --finding {id}") })
}

fn finding_artifact_path(id: &str, path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path.starts_with('/') || path.contains('/') || path.contains('\\') {
        path.to_owned()
    } else {
        format!("{id}/{path}")
    }
}

fn severity_counts(findings: &[FindingReport]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.severity.clone()).or_insert(0) += 1;
    }
    counts
}

fn report_file_stem(run_id: &str) -> String {
    format!("run-{}", sanitized_run_id(run_id))
}

fn normalized_run_id(run_id: &str) -> String {
    let trimmed = run_id.trim();
    if trimmed.is_empty() {
        "last".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn sanitized_run_id(run_id: &str) -> String {
    let normalized = normalized_run_id(run_id);
    let sanitized = normalized
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.trim_matches('_').is_empty() {
        "last".to_owned()
    } else {
        sanitized
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A finding's provenance for the `confirmation` SARIF property / CSV column. An
/// explicit on-disk `confirmation` wins (`fuzz_confirmed` from the #484 join,
/// `runtime` from an oracle hit, `static` from a scanner hit); a finding without
/// one is a runtime crash, so it defaults to `fuzz` — except a static-scan finding
/// with no marker, which is `static`.
fn finding_confirmation(finding: &FindingReport) -> String {
    match string_at(&finding.raw, &["confirmation"]) {
        Some(value) if !value.trim().is_empty() => value,
        _ if finding.classification.as_deref() == Some("static_scan") => "static".to_owned(),
        _ => "fuzz".to_owned(),
    }
}

/// Provenance strength (higher wins) for collapsing an issue group's members to
/// one `confirmation` value: a dynamically-confirmed finding outranks a plain
/// crash, which outranks a scanner-only hit.
fn confirmation_rank(confirmation: &str) -> u8 {
    match confirmation {
        "fuzz_confirmed" | "runtime" => 3,
        "fuzz" | "oracle" => 2,
        _ => 1,
    }
}

fn sarif_result(
    finding: &FindingReport,
    cluster_index: &std::collections::HashMap<String, (usize, String, bool, ClusterQuality)>,
    root: Option<&Path>,
) -> Value {
    let signature = finding.signature.as_deref().unwrap_or("unknown");
    let classification = finding.classification.as_deref().unwrap_or("unknown");
    let confirmation = finding_confirmation(finding);
    let exception = exception_summary(&finding.exception);
    let target = target_summary(finding);
    let message = match exception {
        Some(exception) => format!("{classification} in {target}: {exception}"),
        None => format!("{classification} in {target}"),
    };

    let rule = finding.rule_id.as_deref().and_then(rules::by_id);
    let rule_id = rule.map(|rule| rule.id).unwrap_or("govfuzz.finding");
    let mut properties = json!({
        "govfuzzFindingId": finding.id,
        "govfuzzExceptionSignature": signature,
        "classification": classification,
        // #484: provenance — `static` (scanner-only), `fuzz` (runtime crash),
        // `runtime` (oracle hit), or `fuzz_confirmed` (a static finding a fuzz
        // input reached). Lets a SARIF consumer trust confirmed rows over flagged.
        "confirmation": confirmation,
        "severity": finding.severity,
        // Always carry the finding's CWE(s) so every SARIF result is mapped to a
        // weakness even when no catalog rule matched (the scalar `cwe` below is
        // set only for rule-matched findings).
        "cwes": &finding.actionability.cwe,
        "replayCommand": string_at(&finding.replay, &["command"]),
        "sandbox": finding.sandbox,
        "generatedReproAda": finding.generated_repro_ada,
        "reproAdaOmittedReason": finding.repro_ada_omitted_reason,
        "generatedReproPy": finding.generated_repro_py,
        "actionabilityVerdict": finding.actionability.verdict.as_str(),
        "actionabilityImpact": finding.actionability.impact.as_str(),
        "actionabilityConfidence": finding.actionability.confidence.as_str(),
        "actionabilityEntryPath": &finding.actionability.entry_path,
        "actionabilityFixLocation": &finding.actionability.fix_location,
        "actionabilityReplayStatus": finding.actionability.replay.as_ref().map(|r| r.status.as_str()),
        "actionabilityProsthetics": &finding.actionability.prosthetics,
        "actionabilityPatchHints": &finding.actionability.patch_hints,
        "actionabilityNextSteps": &finding.actionability.next_steps,
    });
    if let Some(rule) = rule {
        let mut tags = vec![rule.cwe.to_owned()];
        if let Some(place) = rule.cwe_top_25 {
            tags.push(format!("cwe-top-25-{place}"));
            tags.push("cwe-top-25".to_owned());
        }
        if let Some(owasp) = rule.owasp_top_10 {
            tags.push(owasp.to_owned());
        }
        tags.push(format!("govfuzz.slug:{}", rule.slug));
        let obj = properties.as_object_mut().expect("properties is an object");
        obj.insert("tags".to_owned(), json!(tags));
        obj.insert(
            "security-severity".to_owned(),
            json!(format!("{:.1}", rule.security_severity)),
        );
        obj.insert("cwe".to_owned(), json!(rule.cwe));
        obj.insert("cwe_top_25".to_owned(), json!(rule.cwe_top_25));
        obj.insert("govfuzz.rule_slug".to_owned(), json!(rule.slug));
        obj.insert(
            "precision".to_owned(),
            json!(rule.default_confidence.as_str()),
        );
    }

    let mut result = json!({
        "ruleId": rule_id,
        "kind": "fail",
        "level": sarif_level(&finding.severity),
        "message": {
            "text": message,
        },
        "locations": sarif_locations(finding, root),
        "relatedLocations": sarif_related_locations(finding, root),
        "partialFingerprints": {
            "govfuzzExceptionSignature": signature,
            "govfuzzRuleSignature": rule_signature(rule_id, signature),
            // SARIF keeps one result per occurrence (the justified exception to
            // one-row-per-issue); this fingerprint lets SCA tools dedup results
            // by root-cause issue. Mirrors `issue_key`: cluster key, else id.
            "govfuzzIssueKey": issue_key(finding),
        },
        "properties": properties,
    });
    let stacks = sarif_stacks(&finding.exception, root);
    if !stacks.is_empty() {
        result
            .as_object_mut()
            .expect("result is an object")
            .insert("stacks".to_owned(), json!(stacks));
    }
    if let Some(cluster_key) = finding.cluster_key.as_deref() {
        let (size, representative, fallback, quality) =
            cluster_index.get(cluster_key).cloned().unwrap_or((
                1,
                finding.id.clone(),
                finding.cluster_fallback,
                finding.cluster_quality.clone(),
            ));
        let pf = result
            .get_mut("partialFingerprints")
            .and_then(|v| v.as_object_mut())
            .expect("partialFingerprints is an object");
        pf.insert("govfuzzClusterKey".to_owned(), json!(cluster_key));
        if let Some(full) = finding.cluster_key_full.as_deref() {
            pf.insert("govfuzzClusterKeyFull".to_owned(), json!(full));
        }
        let props = result
            .get_mut("properties")
            .and_then(|v| v.as_object_mut())
            .expect("properties is an object");
        props.insert("clusterKey".to_owned(), json!(cluster_key));
        props.insert("clusterSize".to_owned(), json!(size));
        props.insert("clusterRepresentative".to_owned(), json!(representative));
        props.insert("clusterFallback".to_owned(), json!(fallback));
        props.insert("clusterQuality".to_owned(), json!(quality));
    }
    // IDE one-click fix: when a patch hint carries a suggested diff, emit a SARIF
    // `result.fixes[]` entry. The diff is a unified-diff text, not a structured
    // region edit, so this is a DESCRIPTION-ONLY fix (title/guidance) with the raw
    // patch stashed in `properties.govfuzzSuggestedPatch` — valid SARIF that
    // surfaces the suggestion without fabricating an offset-based replacement.
    if let Some((description, diff)) = sarif_fix_for(finding) {
        result.as_object_mut().expect("result is an object").insert(
            "fixes".to_owned(),
            json!([{
                "description": { "text": description },
                "properties": { "govfuzzSuggestedPatch": diff },
            }]),
        );
    }
    result
}

/// The description + diff for a finding's SARIF `fix`, from the first patch hint
/// that carries a non-empty suggested diff. `None` when no hint has a diff.
fn sarif_fix_for(finding: &FindingReport) -> Option<(String, String)> {
    let hint = finding.actionability.patch_hints.iter().find(|hint| {
        hint.diff
            .as_deref()
            .map(str::trim)
            .is_some_and(|diff| !diff.is_empty())
    })?;
    let guidance = hint.guidance.trim();
    let description = if guidance.is_empty() {
        hint.title.clone()
    } else {
        format!("{}: {}", hint.title, guidance)
    };
    let diff = hint.diff.as_deref().unwrap_or_default().trim().to_owned();
    Some((description, diff))
}

/// Convert the per-frame entries from a sanitizer report (stored in
/// `exception.stack` by the C/C++ fuzz path) into a SARIF 2.1.0
/// `result.stacks` array. Each frame may be either a bare symbol
/// string or a `{ function, file?, line? }` object - when file/line
/// are present the stackFrame gets a `physicalLocation` so SARIF
/// consumers (DefectDojo, GitHub code scanning, Snyk) can deep-link
/// into the source. No-op for Ada findings, which don't carry
/// `exception.stack`.
fn sarif_stacks(exception: &Value, root: Option<&Path>) -> Vec<Value> {
    let raw = exception
        .get("stack")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut sarif_frames: Vec<Value> = Vec::new();
    for item in raw {
        let frame = match &item {
            Value::String(s) if !s.is_empty() => sarif_logical_frame(s, None, None, root),
            Value::Object(map) => {
                let function = map.get("function").and_then(Value::as_str).unwrap_or("");
                if function.is_empty() {
                    continue;
                }
                let file = map.get("file").and_then(Value::as_str);
                let line = map.get("line").and_then(Value::as_u64);
                sarif_logical_frame(function, file, line, root)
            }
            _ => continue,
        };
        sarif_frames.push(frame);
    }
    if sarif_frames.is_empty() {
        return Vec::new();
    }
    let sanitizer = exception
        .get("sanitizer")
        .and_then(Value::as_str)
        .unwrap_or("sanitizer");
    vec![json!({
        "message": { "text": format!("{sanitizer} stack trace") },
        "frames": sarif_frames,
    })]
}

/// Render up to the top-5 sanitizer stack frames as markdown list items,
/// prefixing each with the function name and (when known) the file:line
/// it points at. Mirrors the SARIF stack output so the markdown report
/// and SARIF deep-link to the same crash site.
/// Group findings by severity, returning the counts in canonical
/// ordering (critical -> info). Severities outside the canonical set
/// are listed at the end alphabetically so unknown future severities
/// still surface in the report.
fn severity_breakdown(findings: &[FindingReport]) -> Vec<(String, usize)> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for finding in findings {
        *counts
            .entry(finding.severity.to_ascii_lowercase())
            .or_insert(0) += 1;
    }
    const ORDER: &[&str] = &["critical", "high", "medium", "low", "info", "unknown"];
    let mut out = Vec::new();
    for key in ORDER {
        if let Some(c) = counts.remove(*key) {
            out.push(((*key).to_owned(), c));
        }
    }
    for (k, c) in counts {
        out.push((k, c));
    }
    out
}

/// Boundary line inserted where the govfuzz harness scaffold begins, so a reader
/// can see the real target call path stops and the synthetic driver takes over.
const HARNESS_BOUNDARY_MARKER: &str = "… ↑ govfuzz harness (synthetic driver; frames omitted)";

/// Render the crash stack for the human-facing writeup, showing only the
/// target's call path. The govfuzz harness scaffolding (`govfuzz_run_one`,
/// `LLVMFuzzerTestOneInput`, the generated `main`) is trimmed — using the SAME
/// `actionability::is_harness_frame` predicate the sink computation relies on —
/// and replaced by a single boundary marker so the synthetic driver is never
/// mistaken for the target's own call path. Sanitizer-runtime and allocator
/// frames are left in place (they sit above the fault and carry useful context).
/// The raw `exception.stack` in `finding.json` is never modified — this only
/// affects what the report displays.
fn markdown_stack_frames(exception: &Value) -> Vec<String> {
    let Some(arr) = exception.get("stack").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut harness_marked = false;
    let mut shown = 0usize;
    for item in arr {
        let (is_harness, line) = match item {
            Value::String(s) if !s.is_empty() => {
                (actionability::is_harness_frame(s, None), md_text(s))
            }
            Value::Object(map) => {
                let function = map.get("function").and_then(Value::as_str).unwrap_or("");
                if function.is_empty() {
                    continue;
                }
                let file = map.get("file").and_then(Value::as_str);
                let line_no = map.get("line").and_then(Value::as_u64);
                let rendered = match (file, line_no) {
                    (Some(file), Some(line_no)) => {
                        format!("{} ({}:{})", md_text(function), md_text(file), line_no)
                    }
                    (Some(file), None) => format!("{} ({})", md_text(function), md_text(file)),
                    _ => md_text(function),
                };
                (actionability::is_harness_frame(function, file), rendered)
            }
            _ => continue,
        };
        if is_harness {
            // First harness frame: mark the boundary once, then omit this and
            // every later harness frame from the displayed stack.
            if !harness_marked {
                out.push(HARNESS_BOUNDARY_MARKER.to_owned());
                harness_marked = true;
            }
            continue;
        }
        out.push(line);
        shown += 1;
        if shown >= 5 {
            break;
        }
    }
    out
}

fn sarif_logical_frame(
    function: &str,
    file: Option<&str>,
    line: Option<u64>,
    root: Option<&Path>,
) -> Value {
    let mut location = serde_json::Map::new();
    location.insert(
        "logicalLocations".to_owned(),
        json!([{ "name": function, "kind": "function" }]),
    );
    if let Some(file) = file {
        let mut physical = serde_json::Map::new();
        physical.insert(
            "artifactLocation".to_owned(),
            sarif_artifact_location(file, root),
        );
        if let Some(line) = line {
            physical.insert("region".to_owned(), json!({ "startLine": line.max(1) }));
        }
        location.insert("physicalLocation".to_owned(), Value::Object(physical));
    }
    location.insert(
        "message".to_owned(),
        json!({ "text": "Sanitizer stack frame" }),
    );
    json!({ "location": Value::Object(location) })
}

/// Stable cross-run dedup key combining the matched rule and the existing
/// exception signature (which hashes the top frame + sanitizer + breadcrumb).
///
/// Two runs that crash on the same bug under the same rule get the same
/// `govfuzzRuleSignature`, which lets SARIF consumers (GitHub Code Scanning,
/// DefectDojo, Snyk import) collapse duplicate findings without touching the
/// raw exception signature used for crash-level dedup.
fn rule_signature(rule_id: &str, exception_signature: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    rule_id.hash(&mut hasher);
    "|".hash(&mut hasher);
    exception_signature.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn sarif_level(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" | "unknown" => "warning",
        "low" | "info" | "informational" => "note",
        _ => "warning",
    }
}

fn sarif_locations(finding: &FindingReport, root: Option<&Path>) -> Vec<Value> {
    let mut locations = Vec::new();
    if let Some(location) = &finding.actionability.fix_location {
        let mut physical_location = serde_json::Map::new();
        physical_location.insert(
            "artifactLocation".to_owned(),
            sarif_artifact_location(&location.path, root),
        );
        let mut region = serde_json::Map::new();
        if let Some(line) = location.line {
            region.insert("startLine".to_owned(), json!(line.max(1)));
        }
        if let Some(col) = location.col {
            region.insert("startColumn".to_owned(), json!(col.max(1)));
        }
        if !region.is_empty() {
            physical_location.insert("region".to_owned(), Value::Object(region));
        }
        push_unique_sarif_location(
            &mut locations,
            json!({
                "physicalLocation": Value::Object(physical_location),
                "message": { "text": format!("Actionability fix location: {}", location.reason) },
            }),
        );
    }
    if let Some(location) =
        sarif_location(&finding.exception, &["handler"], "Exception handler", root)
    {
        push_unique_sarif_location(&mut locations, location);
    }
    if let Some(location) = sarif_location(
        &finding.exception,
        &["last_breadcrumb"],
        "Last breadcrumb",
        root,
    ) {
        push_unique_sarif_location(&mut locations, location);
    }
    if let Some(location) = sarif_location(
        &finding.exception,
        &["explicit_raise"],
        "Explicit raise",
        root,
    ) {
        push_unique_sarif_location(&mut locations, location);
    }
    // SARIF 2.1.0 expects result.locations to carry at least one entry
    // when the result has a primary code location. Ada findings already
    // populate `handler`/`last_breadcrumb`; C/C++ findings carry only an
    // `exception.stack[]`. When the Ada-path probes came up empty,
    // fall back to the first resolved sanitizer frame so consumers
    // like GitHub Code Scanning have a `physicalLocation` to anchor on.
    if locations.is_empty() {
        if let Some(location) = sarif_location_from_stack(&finding.exception, root) {
            locations.push(location);
        }
    }
    locations
}

fn push_unique_sarif_location(locations: &mut Vec<Value>, location: Value) {
    let new_key = sarif_location_key(&location);
    if new_key.is_some()
        && locations
            .iter()
            .any(|existing| sarif_location_key(existing) == new_key)
    {
        return;
    }
    locations.push(location);
}

fn sarif_location_key(location: &Value) -> Option<(String, Option<u64>, Option<u64>)> {
    let physical = location.get("physicalLocation")?;
    let uri = string_at(physical, &["artifactLocation", "uri"])?;
    let line = physical
        .pointer("/region/startLine")
        .and_then(Value::as_u64);
    let col = physical
        .pointer("/region/startColumn")
        .and_then(Value::as_u64);
    Some((uri, line, col))
}

fn sarif_location_from_stack(exception: &Value, root: Option<&Path>) -> Option<Value> {
    let frames = exception.get("stack").and_then(Value::as_array)?;
    for frame in frames {
        let Some(obj) = frame.as_object() else {
            continue;
        };
        let Some(file) = obj.get("file").and_then(Value::as_str) else {
            continue;
        };
        if file.starts_with('(') {
            continue;
        }
        let mut physical_location = serde_json::Map::new();
        physical_location.insert(
            "artifactLocation".to_owned(),
            sarif_artifact_location(file, root),
        );
        if let Some(line) = obj.get("line").and_then(Value::as_u64) {
            physical_location.insert("region".to_owned(), json!({ "startLine": line.max(1) }));
        }
        let function = obj.get("function").and_then(Value::as_str).unwrap_or("");
        return Some(json!({
            "physicalLocation": Value::Object(physical_location),
            "message": { "text": format!("Crash site in {function}") },
        }));
    }
    None
}

fn sarif_location(
    value: &Value,
    path: &[&str],
    message: &str,
    root: Option<&Path>,
) -> Option<Value> {
    let location = path
        .iter()
        .try_fold(value, |current, component| current.get(*component))?;
    let file = string_at(location, &["file"])?;
    let mut physical_location = serde_json::Map::new();
    physical_location.insert(
        "artifactLocation".to_owned(),
        sarif_artifact_location(&file, root),
    );

    let mut region = serde_json::Map::new();
    if let Some(line) = location.get("line").and_then(Value::as_u64) {
        region.insert("startLine".to_owned(), json!(line.max(1)));
    }
    if let Some(col) = location.get("col").and_then(Value::as_u64) {
        region.insert("startColumn".to_owned(), json!(col.max(1)));
    }
    if !region.is_empty() {
        physical_location.insert("region".to_owned(), Value::Object(region));
    }

    Some(json!({
        "physicalLocation": physical_location,
        "message": {
            "text": message,
        }
    }))
}

fn sarif_related_locations(finding: &FindingReport, root: Option<&Path>) -> Vec<Value> {
    let mut locations = Vec::new();
    let mut next_id = 1_u64;
    for (path, message) in build_dependency_paths(&finding.build) {
        locations.push(json!({
            "id": next_id,
            "physicalLocation": {
                "artifactLocation": sarif_artifact_location(&path, root),
            },
            "message": {
                "text": message,
            }
        }));
        next_id = next_id.saturating_add(1);
    }
    locations
}

fn build_dependency_paths(build: &Value) -> Vec<(String, &'static str)> {
    let mut paths = Vec::new();
    for path in string_array_at(build, &["deps", "stubbed"]) {
        paths.push((path, "Stubbed dependency"));
    }
    for path in string_array_at(build, &["deps", "fake_corba"]) {
        paths.push((path, "Fake CORBA dependency"));
    }
    paths
}

fn string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    let Some(value) = path
        .iter()
        .try_fold(value, |current, component| current.get(*component))
    else {
        return Vec::new();
    };
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn expect_string_eq(value: &Value, path: &[&str], expected: &str) -> Result<(), ReportError> {
    let actual = path
        .iter()
        .try_fold(value, |current, component| current.get(*component))
        .and_then(Value::as_str);
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(ReportError::SarifValidation(format!(
            "{} must be {expected:?}",
            json_path(path)
        )))
    }
}

fn expect_string<'a>(
    value: &'a Value,
    path: &[&str],
    parent_path: &str,
) -> Result<&'a str, ReportError> {
    path.iter()
        .try_fold(value, |current, component| current.get(*component))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ReportError::SarifValidation(format!(
                "{parent_path}.{} must be a non-empty string",
                json_path(path)
            ))
        })
}

fn expect_array<'a>(value: &'a Value, path: &[&str]) -> Result<&'a [Value], ReportError> {
    value
        .pointer(&format!("/{}", path.join("/")))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            ReportError::SarifValidation(format!("{} must be an array", json_path(path)))
        })
}

fn validate_sarif_locations(result: &Value, result_path: &str) -> Result<(), ReportError> {
    let locations = expect_array(result, &["locations"])?;
    for (index, location) in locations.iter().enumerate() {
        expect_string(
            location,
            &["physicalLocation", "artifactLocation", "uri"],
            &format!("{result_path}.locations[{index}]"),
        )?;
    }
    Ok(())
}

fn validate_sarif_related_locations(result: &Value, result_path: &str) -> Result<(), ReportError> {
    let locations = expect_array(result, &["relatedLocations"])?;
    for (index, location) in locations.iter().enumerate() {
        let prefix = format!("{result_path}.relatedLocations[{index}]");
        if location.get("id").and_then(Value::as_u64).is_none() {
            return Err(ReportError::SarifValidation(format!(
                "{prefix}.id must be an integer"
            )));
        }
        expect_string(
            location,
            &["physicalLocation", "artifactLocation", "uri"],
            &prefix,
        )?;
    }
    Ok(())
}

fn json_path(path: &[&str]) -> String {
    path.join(".")
}

fn junit_failure_message(finding: &FindingReport) -> String {
    let classification = finding.classification.as_deref().unwrap_or("unknown");
    let base = match exception_summary(&finding.exception) {
        Some(exception) => format!("{classification}: {exception}"),
        None => classification.to_owned(),
    };
    // Lead with the CWE so the CI failure line carries the weakness class.
    match finding.actionability.cwe.first() {
        Some(cwe) => format!("[{cwe}] {base}"),
        None => base,
    }
}

/// JUnit failure body for an ISSUE: the issue id, collapsed `count`, unioned CWE,
/// and the member finding ids, followed by the representative finding's detail
/// body so the evidence for the chosen fix is preserved.
fn junit_failure_body_for_issue(issue: &IssueGroup<'_>) -> String {
    let mut lines = vec![
        format!("issue_id={}", issue.issue_id),
        format!("count={}", issue.count()),
    ];
    let cwe = issue.cwe();
    if !cwe.is_empty() {
        lines.push(format!("cwe={cwe}"));
    }
    if issue.count() > 1 {
        let members = issue
            .members
            .iter()
            .map(|finding| finding.id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        lines.push(format!("members={members}"));
    }
    lines.push(junit_failure_body(issue.representative));
    lines.join("\n")
}

fn junit_failure_body(finding: &FindingReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("finding_id={}", finding.id));
    lines.push(format!("severity={}", finding.severity));
    if let Some(classification) = finding.classification.as_deref() {
        lines.push(format!("classification={classification}"));
    }
    if let Some(signature) = finding.signature.as_deref() {
        lines.push(format!("signature={signature}"));
    }
    lines.push(format!(
        "actionability_verdict={}",
        finding.actionability.verdict.as_str()
    ));
    lines.push(format!(
        "actionability_impact={}",
        finding.actionability.impact.as_str()
    ));
    lines.push(format!(
        "actionability_confidence={}",
        finding.actionability.confidence.as_str()
    ));
    if let Some(location) = &finding.actionability.fix_location {
        let line = location
            .line
            .map(|line| format!(":{line}"))
            .unwrap_or_default();
        lines.push(format!("fix_location={}{}", location.path, line));
    }
    if let Some(exception) = exception_summary(&finding.exception) {
        lines.push(format!("exception={exception}"));
    }
    lines.push(format!("target={}", target_summary(finding)));
    if let Some(path) = finding.minimal_reproducer.as_deref() {
        lines.push(format!("minimal_reproducer={path}"));
    }
    if let Some(path) = finding.generated_repro_ada.as_deref() {
        lines.push(format!("generated_repro_ada={path}"));
    }
    if let Some(reason) = finding.repro_ada_omitted_reason.as_deref() {
        lines.push(format!("repro_ada_omitted_reason={reason}"));
    }
    let stack = markdown_stack_frames(&finding.exception);
    if !stack.is_empty() {
        lines.push("stack:".to_owned());
        for frame in stack {
            lines.push(format!("  {frame}"));
        }
    }
    lines.join("\n")
}

fn junit_system_out(finding: &FindingReport) -> String {
    let mut lines = Vec::new();
    if let Some(command) = string_at(&finding.replay, &["command"]) {
        lines.push(format!("replay={command}"));
    }
    if let Some(signature) = finding.signature.as_deref() {
        lines.push(format!("govfuzzExceptionSignature={signature}"));
    }
    if let Some(mode) = string_at(&finding.sandbox, &["mode"]) {
        lines.push(format!("sandbox={mode}"));
    }
    lines.join("\n")
}

fn xml_attr(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars().map(sanitize_xml_char) {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn xml_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars().map(sanitize_xml_char) {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn sanitize_xml_char(ch: char) -> char {
    if is_xml_1_0_char(ch) {
        ch
    } else {
        '?'
    }
}

fn is_xml_1_0_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

fn target_summary(finding: &FindingReport) -> String {
    let package = string_at(&finding.target, &["package"]);
    let subprogram = string_at(&finding.target, &["subprogram"]);
    let harness = string_at(&finding.target, &["harness_id"]);

    match (package, subprogram, harness) {
        (Some(package), Some(subprogram), Some(harness)) => {
            format!("{package}.{subprogram} ({harness})")
        }
        (Some(package), Some(subprogram), None) => format!("{package}.{subprogram}"),
        (None, Some(subprogram), Some(harness)) => format!("{subprogram} ({harness})"),
        (Some(package), None, Some(harness)) => format!("{package} ({harness})"),
        (Some(package), None, None) => package,
        (None, Some(subprogram), None) => subprogram,
        (None, None, Some(harness)) => harness,
        (None, None, None) => "unknown".to_owned(),
    }
}

fn exception_summary(exception: &Value) -> Option<String> {
    let name = string_at(exception, &["name"]);
    let message = string_at(exception, &["message"]);
    let handler = location_summary(exception.get("handler"));
    let explicit_raise = location_summary(exception.get("explicit_raise"));

    match (name, message, handler, explicit_raise) {
        (Some(name), Some(message), Some(handler), Some(explicit_raise)) => Some(format!(
            "{name}: {message}; raise at {explicit_raise}; handler at {handler}"
        )),
        (Some(name), None, Some(handler), Some(explicit_raise)) => Some(format!(
            "{name}; raise at {explicit_raise}; handler at {handler}"
        )),
        (Some(name), Some(message), Some(handler), None) => {
            Some(format!("{name}: {message}; handler at {handler}"))
        }
        (Some(name), None, Some(handler), None) => Some(format!("{name}; handler at {handler}")),
        (Some(name), Some(message), None, Some(explicit_raise)) => {
            Some(format!("{name}: {message}; raise at {explicit_raise}"))
        }
        (Some(name), None, None, Some(explicit_raise)) => {
            Some(format!("{name}; raise at {explicit_raise}"))
        }
        (Some(name), Some(message), None, None) => Some(format!("{name}: {message}")),
        (Some(name), None, None, None) => Some(name),
        (None, _, Some(handler), _) => Some(format!("handler at {handler}")),
        (None, _, None, Some(explicit_raise)) => Some(format!("raise at {explicit_raise}")),
        (None, _, None, None) => None,
    }
}

fn location_summary(location: Option<&Value>) -> Option<String> {
    let location = location?;
    let file = string_at(location, &["file"])?;
    let line = location.get("line").and_then(Value::as_u64);
    let col = location.get("col").and_then(Value::as_u64);

    match (line, col) {
        (Some(line), Some(col)) => Some(format!("{file}:{line}:{col}")),
        (Some(line), None) => Some(format!("{file}:{line}")),
        (None, _) => Some(file),
    }
}

fn confidence_summary(confidence: &Value) -> Option<String> {
    if confidence.is_null()
        || confidence
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    {
        return None;
    }

    if let Some(blend) = confidence.get("blend").and_then(Value::as_f64) {
        return Some(format!("{blend:.2} blend"));
    }
    if let Some(calibrated) = confidence.get("calibrated").and_then(Value::as_f64) {
        return Some(format!("{calibrated:.2} calibrated"));
    }
    if let Some(value) = confidence.as_f64() {
        return Some(format!("{value:.2}"));
    }

    Some(confidence.to_string())
}

fn investigation_steps(steps: &Value) -> Vec<String> {
    steps
        .as_array()
        .map(|steps| {
            steps
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn md_cell(value: &str) -> String {
    md_text(value).replace('|', "\\|")
}

fn md_text(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn md_code(value: &str) -> String {
    value.replace('`', "\\`")
}

#[cfg(test)]
mod tests {
    use super::{
        build_report, is_xml_1_0_char, load_findings, load_findings_with_model,
        render_junit_report, render_markdown_report, render_markdown_report_with,
        render_sarif_report, rule_signature, rules, validate_sarif_report, write_reports,
        ClusterQuality, ClusterReport, CountReport, FindingReport, ReportDocument, ReportOptions,
        RunReport, REPORT_SCHEMA_VERSION,
    };
    use confidence_model::{ConfidenceLabel, TrainingSample};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn write_reports_emits_sorted_json_and_markdown() {
        let root = temp_dir("emit");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0002-beta"),
            json!({
                "id": "F-0002-beta",
                "severity": "medium",
                "signature": "bbbb",
                "target": { "subprogram": "Decode", "harness_id": "H-2" }
            }),
        );
        write_finding(
            &findings.join("F-0001-alpha"),
            json!({
                "id": "F-0001-alpha",
                "severity": "high",
                "confidence": { "calibrated": 0.72, "blend": 0.75 },
                "target": { "package": "Pkg", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "message": "bad length",
                    "handler": { "file": "pkg.adb", "line": 42 },
                    "explicit_raise": { "file": "pkg.adb", "line": 40 }
                },
                "classification": "explicit_raise",
                "signature": "aaaa",
                "minimal_reproducer": "min_testcase.bin",
                "investigation_steps": ["Inspect handler at pkg.adb:42"]
            }),
        );

        let summary =
            write_reports(ReportOptions::new(&findings, &out).with_run_id("unit")).unwrap();

        assert_eq!(summary.findings_count, 2);
        assert_eq!(summary.json_path, out.join("run-unit.json"));
        assert_eq!(summary.markdown_path, out.join("run-unit.md"));
        assert_eq!(summary.sarif_path, None);
        assert_eq!(summary.junit_path, None);

        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(summary.json_path).unwrap()).unwrap();
        assert_eq!(report["schema_version"], "govfuzz.report.v2");
        assert_eq!(report["run"]["id"], "unit");
        assert_eq!(report["counts"]["findings"], 2);
        assert_eq!(report["counts"]["by_severity"]["high"], 1);
        assert_eq!(report["findings"][0]["id"], "F-0001-alpha");
        assert_eq!(
            report["findings"][0]["minimal_reproducer"],
            "F-0001-alpha/min_testcase.bin"
        );
        assert_eq!(
            report["findings"][0]["replay"]["command"],
            "govfuzz replay --finding F-0001-alpha"
        );

        let markdown = fs::read_to_string(summary.markdown_path).unwrap();
        assert!(markdown.contains("# GovFuzz Report: unit"));
        assert!(
            markdown.contains("| F-0001-alpha | high | explicit_raise | Pkg.Parse (H-1) | aaaa |")
        );
        assert!(markdown.contains(
            "- Exception: CONSTRAINT_ERROR: bad length; raise at pkg.adb:40; handler at pkg.adb:42"
        ));
        assert!(markdown.contains("- Minimal reproducer: `F-0001-alpha/min_testcase.bin`"));
    }

    #[test]
    fn load_findings_adds_calibrated_confidence_when_missing() {
        let root = temp_dir("confidence");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-confidence"),
            json!({
                "id": "F-0001-confidence",
                "classification": "swallowed_predefined",
                "build": {
                    "deps": {
                        "stubbed": ["external_lib.ads", "external_lib.adb"],
                        "calls_through_stub": 2
                    }
                }
            }),
        );

        let loaded = load_findings(&findings).unwrap();

        assert_eq!(loaded[0].confidence["calibrated"], 0.9);
        assert_eq!(loaded[0].confidence["blend"], 0.9);
        assert_eq!(loaded[0].confidence["learned"], serde_json::Value::Null);
        assert_eq!(
            loaded[0].confidence["calibration_id"],
            "govfuzz.calibrated.v1"
        );
        assert_eq!(loaded[0].confidence["features"]["calls_through_stub"], 2);
    }

    #[test]
    fn load_findings_preserves_explicit_confidence() {
        let root = temp_dir("confidence-explicit");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-confidence"),
            json!({
                "id": "F-0001-confidence",
                "confidence": { "calibrated": 0.72, "blend": 0.75 }
            }),
        );

        let loaded = load_findings(&findings).unwrap();

        assert_eq!(loaded[0].confidence["calibrated"], 0.72);
        assert_eq!(loaded[0].confidence["blend"], 0.75);
        assert!(loaded[0].confidence.get("calibration_id").is_none());
    }

    #[test]
    fn load_findings_backfills_actionability_for_older_records() {
        let root = temp_dir("actionability-backfill");
        write_finding(
            &root.join("F-0001-old"),
            json!({
                "id": "F-0001-old",
                "severity": "high",
                "classification": "explicit_raise",
                "signature": "abcd",
                "target": { "harness_id": "H-old" },
                "exception": { "handler": { "file": "src/pkg.adb", "line": 9 } }
            }),
        );

        let findings = load_findings(&root).unwrap();

        assert_eq!(
            findings[0].actionability.verdict,
            actionability::Verdict::LikelyReachable
        );
        assert_eq!(
            findings[0]
                .actionability
                .fix_location
                .as_ref()
                .unwrap()
                .path,
            "src/pkg.adb"
        );
    }

    #[test]
    fn report_counts_include_actionability_verdict_and_impact() {
        let root = temp_dir("actionability-counts");
        write_finding(
            &root.join("F-0001-real"),
            json!({
                "id": "F-0001-real",
                "rule_id": "GF-201",
                "severity": "critical",
                "harness_id": "H-real",
                "exception": { "stack": [{ "function": "parse", "file": "src/p.c", "line": 4 }] },
                "replay": { "status": "reproduced" }
            }),
        );
        write_finding(
            &root.join("F-0002-lab"),
            json!({
                "id": "F-0002-lab",
                "rule_id": "GF-201",
                "severity": "critical",
                "harness_id": "H-lab",
                "build": { "deps": { "stubbed": ["Missing"] } },
                "exception": { "stack": [{ "function": "parse", "file": "src/p.c", "line": 4 }] }
            }),
        );

        let document = build_report(&ReportOptions::new(&root, root.join("out"))).unwrap();

        assert_eq!(
            document.counts.by_actionability_verdict["real_reachable"],
            1
        );
        assert_eq!(document.counts.by_actionability_verdict["lab_only"], 1);
        assert_eq!(document.counts.by_impact["critical"], 2);
    }

    #[test]
    fn markdown_renders_real_reachable_section_and_action_block() {
        let document = ReportDocument {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            run: RunReport {
                id: "unit".to_owned(),
                findings_dir: "findings".to_owned(),
                source_root: None,
            },
            counts: CountReport {
                findings: 1,
                by_severity: BTreeMap::new(),
                by_actionability_verdict: BTreeMap::from([("real_reachable".to_owned(), 1)]),
                by_impact: BTreeMap::from([("high".to_owned(), 1)]),
            },
            findings: vec![finding_report_with_actionability(
                "F-real",
                actionability::Verdict::RealReachable,
            )],
            clusters: Vec::new(),
        };

        let markdown = render_markdown_report(&document);

        assert!(markdown.contains("## Real Reachable Findings"));
        assert!(markdown.contains("- Actionability: real_reachable / high / high"));
        assert!(markdown.contains("- Fix location: `src/pkg.adb:42` (explicit_raise_site)"));
    }

    #[test]
    fn markdown_renders_impact_breakdown() {
        let document = ReportDocument {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            run: RunReport {
                id: "unit".to_owned(),
                findings_dir: "findings".to_owned(),
                source_root: None,
            },
            counts: CountReport {
                findings: 2,
                by_severity: BTreeMap::new(),
                by_actionability_verdict: BTreeMap::new(),
                by_impact: BTreeMap::from([("critical".to_owned(), 1), ("medium".to_owned(), 1)]),
            },
            findings: vec![
                finding_report_with_actionability("F-critical", actionability::Verdict::Blocked),
                finding_report_with_actionability("F-medium", actionability::Verdict::Unknown),
            ],
            clusters: Vec::new(),
        };

        let markdown = render_markdown_report(&document);

        assert!(markdown.contains("Impact breakdown:\n"));
        assert!(markdown.contains("- critical: 1\n"));
        assert!(markdown.contains("- medium: 1\n"));
    }

    #[test]
    fn markdown_renders_replay_status_and_next_steps_for_non_real_findings() {
        let mut blocked =
            finding_report_with_actionability("F-blocked", actionability::Verdict::Blocked);
        blocked.actionability.replay = Some(actionability::ReplayEvidence {
            status: "blocked".to_owned(),
        });
        blocked.actionability.next_steps =
            vec!["Provide the missing real resource and rerun.".to_owned()];

        let mut lab_only =
            finding_report_with_actionability("F-lab", actionability::Verdict::LabOnly);
        lab_only.actionability.replay = Some(actionability::ReplayEvidence {
            status: "available".to_owned(),
        });
        lab_only.actionability.next_steps =
            vec!["Replace stubbed dependencies before claiming reachability.".to_owned()];

        let mut unknown =
            finding_report_with_actionability("F-unknown", actionability::Verdict::Unknown);
        unknown.actionability.replay = None;
        unknown.actionability.next_steps =
            vec!["Replay the testcase and collect source-location evidence.".to_owned()];

        let document = ReportDocument {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            run: RunReport {
                id: "unit".to_owned(),
                findings_dir: "findings".to_owned(),
                source_root: None,
            },
            counts: CountReport {
                findings: 3,
                by_severity: BTreeMap::new(),
                by_actionability_verdict: BTreeMap::new(),
                by_impact: BTreeMap::new(),
            },
            findings: vec![blocked, lab_only, unknown],
            clusters: Vec::new(),
        };

        let markdown = render_markdown_report(&document);

        assert!(markdown.contains("- Replay status: blocked"));
        assert!(markdown.contains("- Replay status: available"));
        assert!(
            markdown.contains("- Next steps:\n  - Provide the missing real resource and rerun.")
        );
        assert!(markdown.contains("  - Replace stubbed dependencies before claiming reachability."));
        assert!(markdown.contains("  - Replay the testcase and collect source-location evidence."));
    }

    #[test]
    fn sarif_primary_location_uses_actionability_fix_location() {
        let document = report_document_with_single_actionability_finding();

        let sarif = render_sarif_report(&document);
        let location = &sarif["runs"][0]["results"][0]["locations"][0];

        assert_eq!(
            location["physicalLocation"]["artifactLocation"]["uri"],
            "src/pkg.adb"
        );
        assert_eq!(location["physicalLocation"]["region"]["startLine"], 42);
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["actionabilityVerdict"],
            "real_reachable"
        );
        // #484: a runtime finding with no explicit marker is provenance "fuzz".
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["confirmation"],
            "fuzz"
        );
    }

    /// #484: SARIF results carry a `confirmation` property. A `fuzz_confirmed`
    /// static finding (join-upgraded) surfaces that provenance; a static-scan
    /// finding with no marker defaults to `static`.
    #[test]
    fn sarif_result_carries_confirmation_property() {
        let mut confirmed = finding_report_with_actionability(
            "F-confirmed",
            actionability::Verdict::LikelyReachable,
        );
        confirmed.classification = Some("static_scan".to_owned());
        confirmed.raw = json!({ "confirmation": "fuzz_confirmed" });

        let mut flagged =
            finding_report_with_actionability("F-flagged", actionability::Verdict::Unknown);
        flagged.classification = Some("static_scan".to_owned());
        flagged.raw = json!({}); // no marker -> defaults to "static"

        let mut document = report_document_with_single_actionability_finding();
        document.findings = vec![confirmed, flagged];

        let sarif = render_sarif_report(&document);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let prop = |id: &str| -> String {
            results
                .iter()
                .find(|r| r["properties"]["govfuzzFindingId"] == id)
                .and_then(|r| r["properties"]["confirmation"].as_str())
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(prop("F-confirmed"), "fuzz_confirmed");
        assert_eq!(prop("F-flagged"), "static");
    }

    #[test]
    fn junit_name_and_body_include_verdict_cluster_and_fix_location() {
        let document = report_document_with_single_actionability_finding();

        let junit = render_junit_report(&document);

        assert!(junit.contains("name=\"F-real [real_reachable]"));
        assert!(junit.contains("actionability_verdict=real_reachable"));
        assert!(junit.contains("fix_location=src/pkg.adb:42"));
    }

    #[test]
    fn load_findings_preserves_non_calibrated_confidence_metadata() {
        let root = temp_dir("confidence-explicit-shape");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-confidence"),
            json!({
                "id": "F-0001-confidence",
                "confidence": {
                    "score": 0.72,
                    "source": "manual",
                    "notes": ["reviewed"]
                }
            }),
        );

        let loaded = load_findings(&findings).unwrap();

        assert_eq!(loaded[0].confidence["score"], 0.72);
        assert_eq!(loaded[0].confidence["source"], "manual");
        assert_eq!(loaded[0].confidence["notes"][0], "reviewed");
        assert!(loaded[0].confidence.get("calibration_id").is_none());
    }

    #[test]
    fn load_findings_preserves_sandbox_metadata_for_reports() {
        let root = temp_dir("load-findings-sandbox");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001"),
            json!({
                "id": "F-0001",
                "signature": "aabbccdd",
                "sandbox": { "mode": "firejail", "strict": true, "tool": "/usr/bin/firejail" },
                "build": {
                    "sandbox": { "mode": "firejail", "strict": true, "tool": "/usr/bin/firejail" }
                }
            }),
        );

        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let markdown = render_markdown_report(&document);
        let sarif = render_sarif_report(&document);
        let junit = render_junit_report(&document);

        assert_eq!(document.findings[0].sandbox["mode"], "firejail");
        assert!(markdown.contains("- Sandbox: firejail"));
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["sandbox"]["mode"],
            "firejail"
        );
        assert!(junit.contains("sandbox=firejail"));
    }

    #[test]
    fn load_findings_uses_learned_confidence_model_when_requested() {
        let root = temp_dir("confidence-learned");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-confidence"),
            true_positive_finding("F-0001-confidence"),
        );
        let model = confidence_model::train_model(&confidence_samples(100));

        let loaded = load_findings_with_model(&findings, Some(&model)).unwrap();

        assert!(loaded[0].confidence["learned"].is_f64());
        assert_eq!(loaded[0].confidence["model_id"], model.model_id);
        assert_eq!(
            loaded[0].confidence["calibration_id"],
            "govfuzz.calibrated.v1"
        );
    }

    #[test]
    fn build_report_loads_confidence_model_from_options() {
        let root = temp_dir("confidence-model-path");
        let findings = root.join("findings");
        let model_path = root.join("models/tenant-model.bin");
        write_finding(
            &findings.join("F-0001-confidence"),
            true_positive_finding("F-0001-confidence"),
        );
        let model = write_confidence_model(&model_path);

        let document = build_report(
            &ReportOptions::new(&findings, root.join("reports"))
                .with_confidence_model_path(&model_path),
        )
        .unwrap();

        assert_eq!(document.findings[0].confidence["model_id"], model.model_id);
        assert!(document.findings[0].confidence["learned"].is_f64());
    }

    #[test]
    fn build_report_rejects_tampered_confidence_model_id() {
        let root = temp_dir("confidence-model-tampered-id");
        let findings = root.join("findings");
        let model_path = root.join("models/tenant-model.bin");
        fs::create_dir_all(&findings).unwrap();
        write_confidence_model(&model_path);
        mutate_confidence_model(&model_path, |model| {
            model["model_id"] = json!("govfuzz.learned.v1.tampered");
        });

        let error = build_report(
            &ReportOptions::new(&findings, root.join("reports"))
                .with_confidence_model_path(&model_path),
        )
        .unwrap_err();

        assert!(error.to_string().contains("model_id mismatch"));
    }

    #[test]
    fn build_report_rejects_incompatible_confidence_model_layout() {
        let root = temp_dir("confidence-model-layout");
        let findings = root.join("findings");
        let model_path = root.join("models/tenant-model.bin");
        fs::create_dir_all(&findings).unwrap();
        write_confidence_model(&model_path);
        mutate_confidence_model(&model_path, |model| {
            model["feature_names"] = json!(["stub_count"]);
            model["weights"] = json!([0.0]);
            model["model_id"] = json!("govfuzz.learned.v1.tampered");
        });

        let error = build_report(
            &ReportOptions::new(&findings, root.join("reports"))
                .with_confidence_model_path(&model_path),
        )
        .unwrap_err();

        assert!(error.to_string().contains("feature_names"));
    }

    #[test]
    fn build_report_accepts_valid_cold_confidence_model() {
        let root = temp_dir("confidence-model-cold");
        let findings = root.join("findings");
        let model_path = root.join("models/tenant-model.bin");
        write_finding(
            &findings.join("F-0001-confidence"),
            true_positive_finding("F-0001-confidence"),
        );
        let model = confidence_model::train_model(&confidence_samples(99));
        fs::create_dir_all(model_path.parent().unwrap()).unwrap();
        fs::write(&model_path, serde_json::to_vec_pretty(&model).unwrap()).unwrap();

        let document = build_report(
            &ReportOptions::new(&findings, root.join("reports"))
                .with_confidence_model_path(&model_path),
        )
        .unwrap();

        assert_eq!(
            document.findings[0].confidence["learned"],
            serde_json::Value::Null
        );
        assert_eq!(
            document.findings[0].confidence["model_id"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn build_report_preserves_explicit_confidence_with_model_path() {
        let root = temp_dir("confidence-explicit-model");
        let findings = root.join("findings");
        let model_path = root.join("models/tenant-model.bin");
        write_finding(
            &findings.join("F-0001-confidence"),
            json!({
                "id": "F-0001-confidence",
                "confidence": { "score": 0.72, "source": "manual" },
                "classification": "explicit_raise"
            }),
        );
        write_confidence_model(&model_path);

        let document = build_report(
            &ReportOptions::new(&findings, root.join("reports"))
                .with_confidence_model_path(&model_path),
        )
        .unwrap();

        assert_eq!(document.findings[0].confidence["score"], 0.72);
        assert_eq!(document.findings[0].confidence["source"], "manual");
        assert!(document.findings[0].confidence.get("model_id").is_none());
    }

    #[test]
    fn write_reports_emits_valid_sarif_when_requested() {
        let root = temp_dir("sarif");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0001-sarif"),
            json!({
                "id": "F-0001-sarif",
                "severity": "high",
                "classification": "explicit_raise",
                "signature": "abcd1234",
                "target": { "package": "Pkg", "subprogram": "Parse", "harness_id": "H-1" },
                "build": {
                    "deps": {
                        "stubbed": ["generated_stubs/external_lib.ads"],
                        "fake_corba": ["fake_corba/corba.ads"]
                    }
                },
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "message": "bad length",
                    "handler": { "file": "src/pkg.adb", "line": 42 },
                    "last_breadcrumb": { "file": "src/pkg.adb", "line": 40, "col": 7 },
                    "explicit_raise": { "file": "src/pkg.adb", "line": 39 }
                }
            }),
        );

        let summary = write_reports(
            ReportOptions::new(&findings, &out)
                .with_run_id("unit")
                .with_sarif(true),
        )
        .unwrap();

        let sarif_path = summary.sarif_path.expect("SARIF path is recorded");
        assert_eq!(sarif_path, out.join("run-unit.sarif"));

        let sarif: serde_json::Value =
            serde_json::from_slice(&fs::read(sarif_path).unwrap()).unwrap();
        validate_sarif_report(&sarif).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["kind"], "fail");
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["govfuzzExceptionSignature"],
            "abcd1234"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["relatedLocations"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn sarif_emits_rule_catalog_entry_for_each_finding_rule() {
        let root = temp_dir("sarif-rule-catalog");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0001-unhandled"),
            json!({
                "id": "F-0001-unhandled",
                "classification": "unhandled",
                "exception": {
                    "name": "PROGRAM_ERROR",
                    "handler": { "file": "src/pkg.adb", "line": 1 },
                }
            }),
        );
        write_finding(
            &findings.join("F-0002-swallowed-constraint"),
            json!({
                "id": "F-0002-swallowed-constraint",
                "classification": "swallowed_predefined",
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "handler": { "file": "src/pkg.adb", "line": 1 },
                }
            }),
        );
        write_finding(
            &findings.join("F-0003-also-unhandled"),
            json!({
                "id": "F-0003-also-unhandled",
                "classification": "unhandled",
                "exception": {
                    "name": "TASKING_ERROR",
                    "handler": { "file": "src/pkg.adb", "line": 1 },
                }
            }),
        );

        let summary = write_reports(
            ReportOptions::new(&findings, &out)
                .with_run_id("rule-catalog")
                .with_sarif(true),
        )
        .unwrap();

        let sarif: serde_json::Value = serde_json::from_slice(
            &fs::read(summary.sarif_path.expect("SARIF path is recorded")).unwrap(),
        )
        .unwrap();
        validate_sarif_report(&sarif).unwrap();

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array present");
        let rule_ids: Vec<&str> = rules
            .iter()
            .map(|rule| rule["id"].as_str().unwrap())
            .collect();
        assert!(rule_ids.contains(&"GF-101"));
        assert!(rule_ids.contains(&"GF-102"));
        assert_eq!(rule_ids.iter().filter(|id| **id == "GF-101").count(), 1);

        let gf102 = rules
            .iter()
            .find(|rule| rule["id"] == "GF-102")
            .expect("GF-102 rule present");
        assert_eq!(gf102["properties"]["cwe"], "CWE-129");
        assert_eq!(
            gf102["properties"]["security-severity"].as_str().unwrap(),
            "7.0"
        );
        let tags = gf102["properties"]["tags"].as_array().unwrap();
        assert!(tags.iter().any(|tag| tag == "CWE-129"));
        assert!(tags.iter().any(|tag| tag == "cert-c:ARR30-C"));
        assert!(tags
            .iter()
            .any(|tag| tag == "govfuzz.slug:govfuzz.ada/swallowed-range-or-index-check"));

        let result = &sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["properties"]["govfuzzFindingId"] == "F-0002-swallowed-constraint")
            .expect("finding result present")
            .clone();
        assert_eq!(result["ruleId"], "GF-102");
        assert_eq!(result["properties"]["cwe"], "CWE-129");
    }

    #[test]
    fn sarif_falls_back_to_generic_rule_when_classification_unmapped() {
        let root = temp_dir("sarif-generic");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0001-generic"),
            json!({
                "id": "F-0001-generic",
                "classification": "mystery",
                "exception": {
                    "name": "Custom_Error",
                    "handler": { "file": "src/pkg.adb", "line": 1 },
                }
            }),
        );

        let summary = write_reports(
            ReportOptions::new(&findings, &out)
                .with_run_id("generic")
                .with_sarif(true),
        )
        .unwrap();

        let sarif: serde_json::Value = serde_json::from_slice(
            &fs::read(summary.sarif_path.expect("SARIF path is recorded")).unwrap(),
        )
        .unwrap();
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert!(rules.iter().any(|rule| rule["id"] == "govfuzz.finding"));
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "govfuzz.finding");
    }

    #[test]
    fn sarif_top25_finding_carries_top25_tag() {
        let root = temp_dir("sarif-top25");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0001-uaf"),
            json!({
                "id": "F-0001-uaf",
                "rule_id": "GF-202",
                "classification": "unhandled",
                "exception": {
                    "name": "ASAN_USE_AFTER_FREE",
                    "handler": { "file": "src/pkg.c", "line": 1 },
                }
            }),
        );

        let summary = write_reports(
            ReportOptions::new(&findings, &out)
                .with_run_id("top25")
                .with_sarif(true),
        )
        .unwrap();

        let sarif: serde_json::Value = serde_json::from_slice(
            &fs::read(summary.sarif_path.expect("SARIF path is recorded")).unwrap(),
        )
        .unwrap();
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "GF-202");
        assert_eq!(result["properties"]["cwe_top_25"], 8);
        let tags = result["properties"]["tags"].as_array().unwrap();
        assert!(tags.iter().any(|tag| tag == "cwe-top-25"));
        assert!(tags.iter().any(|tag| tag == "cwe-top-25-8"));
    }

    #[test]
    fn sarif_rule_signature_is_stable_across_runs_with_same_rule_and_exception() {
        let sig1 = rule_signature("GF-102", "abcd1234");
        let sig2 = rule_signature("GF-102", "abcd1234");
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 16);
    }

    #[test]
    fn sarif_rule_signature_differs_when_rule_differs() {
        let sig_a = rule_signature("GF-101", "abcd1234");
        let sig_b = rule_signature("GF-102", "abcd1234");
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn sarif_rule_signature_differs_when_exception_signature_differs() {
        let sig_a = rule_signature("GF-201", "deadbeef");
        let sig_b = rule_signature("GF-201", "cafebabe");
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn sarif_result_emits_rule_signature_in_partial_fingerprints() {
        let root = temp_dir("rule-signature");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0001-fingerprint"),
            json!({
                "id": "F-0001-fingerprint",
                "rule_id": "GF-202",
                "signature": "deadbeefcafe",
                "classification": "unhandled",
                "exception": {
                    "name": "ASAN_USE_AFTER_FREE",
                    "handler": { "file": "src/pkg.c", "line": 7 },
                }
            }),
        );

        let summary = write_reports(
            ReportOptions::new(&findings, &out)
                .with_run_id("fingerprint")
                .with_sarif(true),
        )
        .unwrap();

        let sarif: serde_json::Value = serde_json::from_slice(
            &fs::read(summary.sarif_path.expect("SARIF path is recorded")).unwrap(),
        )
        .unwrap();
        let fingerprints = &sarif["runs"][0]["results"][0]["partialFingerprints"];
        assert_eq!(fingerprints["govfuzzExceptionSignature"], "deadbeefcafe");
        let rule_sig = fingerprints["govfuzzRuleSignature"]
            .as_str()
            .expect("rule signature present");
        assert_eq!(rule_sig.len(), 16);
        assert_eq!(rule_sig, rule_signature("GF-202", "deadbeefcafe"));
    }

    #[test]
    fn sarif_iso_tr_24772_codes_each_emitted_as_separate_tag() {
        let root = temp_dir("sarif-iso-tags");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0001-iso"),
            json!({
                "id": "F-0001-iso",
                "rule_id": "GF-102",
                "classification": "swallowed_predefined",
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "handler": { "file": "src/pkg.adb", "line": 1 },
                }
            }),
        );

        let summary = write_reports(
            ReportOptions::new(&findings, &out)
                .with_run_id("iso")
                .with_sarif(true),
        )
        .unwrap();

        let sarif: serde_json::Value = serde_json::from_slice(
            &fs::read(summary.sarif_path.expect("SARIF path is recorded")).unwrap(),
        )
        .unwrap();
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let gf102 = rules
            .iter()
            .find(|rule| rule["id"] == "GF-102")
            .expect("GF-102 rule present");
        let tags: Vec<&str> = gf102["properties"]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tag| tag.as_str().unwrap())
            .collect();
        assert!(
            tags.contains(&"iso-tr-24772-ada:OYB"),
            "expected OYB primary tag, got {tags:?}"
        );
        assert!(
            tags.contains(&"iso-tr-24772-ada:XYZ"),
            "expected XYZ contributing-mechanism tag, got {tags:?}"
        );
    }

    #[test]
    fn sarif_emits_stacks_from_sanitizer_stack_frames() {
        let root = temp_dir("sarif-stacks");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-stack"),
            json!({
                "id": "F-0001-stack",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "deadbeefcafe",
                "target": { "package": "cJSON", "subprogram": "Parse", "harness_id": "H-CJSON" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "message": "heap-buffer-overflow on address 0xdead",
                    "sanitizer": "asan",
                    "stack": [
                        "cJSON_ParseWithLength",
                        "parse_value",
                        "LLVMFuzzerTestOneInput"
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );

        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let sarif = render_sarif_report(&document);
        let stacks = &sarif["runs"][0]["results"][0]["stacks"];
        assert!(stacks.is_array(), "expected stacks array, got {sarif:?}");
        let stack_arr = stacks.as_array().unwrap();
        assert_eq!(stack_arr.len(), 1);
        assert_eq!(stack_arr[0]["message"]["text"], "asan stack trace");
        let frames = stack_arr[0]["frames"].as_array().unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(
            frames[0]["location"]["logicalLocations"][0]["name"],
            "cJSON_ParseWithLength"
        );
        assert_eq!(
            frames[0]["location"]["logicalLocations"][0]["kind"],
            "function"
        );
    }

    #[test]
    fn junit_failure_body_includes_sanitizer_stack() {
        let root = temp_dir("junit-stack");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-junit-stack"),
            json!({
                "id": "F-0001-junit-stack",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "junit-sig",
                "target": { "package": "lib", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "parse_with_oob", "file": "/src/parse.c", "line": 8 }
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let junit = render_junit_report(&document);
        assert!(junit.contains("stack:"));
        assert!(
            junit.contains("parse_with_oob (/src/parse.c:8)"),
            "junit body should embed resolved frame: {junit}"
        );
    }

    #[test]
    fn markdown_renders_severity_breakdown_in_canonical_order() {
        let root = temp_dir("md-severity");
        let findings = root.join("findings");
        for (idx, severity) in ["low", "critical", "medium", "high", "high"]
            .iter()
            .enumerate()
        {
            let id = format!("F-{idx:04}");
            write_finding(
                &findings.join(&id),
                json!({
                    "id": id,
                    "rule_id": "GF-201",
                    "severity": severity,
                    "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "signature": id.clone(),
                    "target": { "package": "lib", "subprogram": "Parse", "harness_id": "H-1" },
                    "exception": { "name": "X" },
                    "minimal_reproducer": "min_testcase.bin"
                }),
            );
        }
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let md = render_markdown_report(&document);
        let breakdown_start = md
            .find("Severity breakdown:")
            .expect("markdown should include severity breakdown");
        let breakdown_block = &md[breakdown_start..];
        let critical_pos = breakdown_block.find("- critical").unwrap();
        let high_pos = breakdown_block.find("- high").unwrap();
        let medium_pos = breakdown_block.find("- medium").unwrap();
        let low_pos = breakdown_block.find("- low").unwrap();
        assert!(critical_pos < high_pos, "critical must precede high");
        assert!(high_pos < medium_pos, "high must precede medium");
        assert!(medium_pos < low_pos, "medium must precede low");
        assert!(breakdown_block.contains("- high: 2"));
        assert!(breakdown_block.contains("- critical: 1"));
    }

    #[test]
    fn markdown_includes_sanitizer_stack_frames() {
        let root = temp_dir("md-stack");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-mdstack"),
            json!({
                "id": "F-0001-mdstack",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "sig",
                "target": { "package": "lib", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "parse_with_oob", "file": "/src/parse.c", "line": 8 },
                        { "function": "__asan_memcpy" }
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let md = render_markdown_report(&document);
        assert!(
            md.contains("- Stack:"),
            "markdown should include Stack: {md}"
        );
        assert!(
            md.contains("parse_with_oob (/src/parse.c:8)"),
            "markdown should include resolved frame: {md}"
        );
        assert!(
            md.contains("__asan_memcpy"),
            "markdown should include unresolved frame: {md}"
        );
    }

    #[test]
    fn markdown_stack_trims_govfuzz_harness_frames() {
        let root = temp_dir("md-stack-harness");
        let findings = root.join("findings");
        let finding_dir = findings.join("F-0001-harness");
        write_finding(
            &finding_dir,
            json!({
                "id": "F-0001-harness",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "sig",
                "target": { "package": "lib", "subprogram": "nsvgParse", "harness_id": "H-1" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "nsvg__parseSVG", "file": "/src/nanosvg.h", "line": 2304 },
                        { "function": "nsvgParse", "file": "/src/nanosvg.h", "line": 2880 },
                        { "function": "govfuzz_run_one", "file": "/work/auto/main.cpp", "line": 41 },
                        { "function": "LLVMFuzzerTestOneInput", "file": "/work/auto/main.cpp", "line": 58 },
                        { "function": "main", "file": "/work/auto/main.cpp", "line": 72 }
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let md = render_markdown_report(&document);

        // Isolate the per-finding "- Stack:" block (the only thing (A) trims; the
        // cluster "Top frames" column is a separate dedup signal left untouched).
        let stack_start = md.find("- Stack:").expect("writeup should render a Stack");
        let stack_block: String = md[stack_start..]
            .lines()
            .skip(1)
            .take_while(|line| line.starts_with("  - "))
            .collect::<Vec<_>>()
            .join("\n");

        // The real target call path is shown ...
        assert!(
            stack_block.contains("nsvgParse (/src/nanosvg.h:2880)"),
            "target frame must remain in the rendered Stack: {stack_block}"
        );
        // ... but the govfuzz harness scaffolding is trimmed and replaced by a
        // single boundary marker.
        assert!(
            !stack_block.contains("govfuzz_run_one"),
            "harness frame must NOT appear in the rendered Stack: {stack_block}"
        );
        assert!(
            !stack_block.contains("LLVMFuzzerTestOneInput"),
            "harness driver must NOT appear in the rendered Stack: {stack_block}"
        );
        assert!(
            stack_block.contains("govfuzz harness (synthetic driver; frames omitted)"),
            "rendered Stack must mark the harness boundary: {stack_block}"
        );

        // The full stack (including the harness frames) is preserved verbatim in
        // finding.json — only the rendered writeup is trimmed.
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        let stack = raw["exception"]["stack"].as_array().unwrap();
        assert!(
            stack
                .iter()
                .any(|frame| frame["function"] == "govfuzz_run_one"),
            "finding.json must keep the harness frame for debugging"
        );
    }

    #[test]
    fn markdown_flags_unproven_reachability_without_naming_harness() {
        let root = temp_dir("md-source-unproven");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-unproven"),
            json!({
                "id": "F-0001-unproven",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "sig",
                "target": { "package": "lib", "subprogram": "write_uint24", "harness_id": "H-1" },
                "input_reachability": "reachability_unproven",
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "write_uint24", "file": "/src/enc.c", "line": 20 }
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let md = render_markdown_report(&document);
        // Honesty signal preserved: the writeup still says public-API
        // reachability is unproven (carried by the verdict + this caveat).
        assert!(
            md.contains("public-API reachability UNPROVEN"),
            "writeup must flag unproven reachability: {md}"
        );
        assert!(
            md.contains("- Reachability:"),
            "unproven reachability must render as a Reachability caveat: {md}"
        );
        // ...but the writeup no longer emits a `- Source:` line that points at
        // the synthetic govfuzz harness entry — the Sink / fix-location below
        // carry the real defect location.
        assert!(
            !md.contains("- Source:"),
            "writeup must not emit a harness-referencing Source line: {md}"
        );
        assert!(
            !md.contains("harness driving"),
            "writeup must not name the synthetic harness as the source: {md}"
        );
    }

    #[test]
    fn sarif_falls_back_to_first_resolved_stack_frame_for_primary_location() {
        let root = temp_dir("sarif-primary");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-primary"),
            json!({
                "id": "F-0001-primary",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "sig",
                "target": { "package": "lib", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "__asan_memcpy" },
                        { "function": "parse_with_oob", "file": "/src/parse.c", "line": 8 }
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let sarif = render_sarif_report(&document);
        let locations = sarif["runs"][0]["results"][0]["locations"]
            .as_array()
            .unwrap();
        assert_eq!(locations.len(), 1, "primary location must be set");
        assert_eq!(
            locations[0]["physicalLocation"]["artifactLocation"]["uri"],
            "/src/parse.c"
        );
        assert_eq!(locations[0]["physicalLocation"]["region"]["startLine"], 8);
        assert!(locations[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("Actionability fix location"));
    }

    #[test]
    fn sarif_keeps_ada_handler_after_actionability_primary_location() {
        let root = temp_dir("sarif-ada-loc");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-ada"),
            json!({
                "id": "F-0001-ada",
                "rule_id": "GF-101",
                "severity": "medium",
                "classification": "swallowed_exception",
                "signature": "ada-sig",
                "target": { "package": "Pkg", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "handler": { "file": "src/pkg.adb", "line": 42 },
                    "stack": [{ "function": "should_not_appear", "file": "/other.c", "line": 1 }]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let sarif = render_sarif_report(&document);
        let locations = sarif["runs"][0]["results"][0]["locations"]
            .as_array()
            .unwrap();
        assert_eq!(locations.len(), 2);
        assert_eq!(
            locations[0]["physicalLocation"]["artifactLocation"]["uri"],
            "/other.c"
        );
        assert_eq!(
            locations[1]["physicalLocation"]["artifactLocation"]["uri"],
            "src/pkg.adb"
        );
    }

    #[test]
    fn sarif_emits_physical_location_when_frame_has_file_and_line() {
        let root = temp_dir("sarif-physloc");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-physloc"),
            json!({
                "id": "F-0001-physloc",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "physloc-sig",
                "target": { "package": "lib", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "target_parse", "file": "/src/parse.c", "line": 42 },
                        { "function": "stripped+0xab" }
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );

        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let sarif = render_sarif_report(&document);
        let frames = sarif["runs"][0]["results"][0]["stacks"][0]["frames"]
            .as_array()
            .unwrap();
        assert_eq!(frames.len(), 2);
        let phys = &frames[0]["location"]["physicalLocation"];
        assert_eq!(phys["artifactLocation"]["uri"], "/src/parse.c");
        assert_eq!(phys["region"]["startLine"], 42);
        assert!(
            frames[1]["location"].get("physicalLocation").is_none(),
            "frames without file should not emit physicalLocation"
        );
    }

    #[test]
    fn sarif_omits_stacks_when_no_sanitizer_frames() {
        let root = temp_dir("sarif-nostack");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-ada"),
            json!({
                "id": "F-0001-ada",
                "rule_id": "GF-101",
                "severity": "medium",
                "classification": "swallowed_exception",
                "signature": "ada-fake-sig",
                "target": { "package": "Pkg", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "handler": { "file": "src/pkg.adb", "line": 42 }
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );

        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        let sarif = render_sarif_report(&document);
        assert!(
            sarif["runs"][0]["results"][0].get("stacks").is_none(),
            "Ada findings without sanitizer stack must not emit stacks"
        );
    }

    #[test]
    fn sarif_driver_carries_version_and_semantic_version() {
        let document = build_report(&ReportOptions::new(
            empty_findings_dir("sarif-version"),
            "reports",
        ))
        .unwrap();
        let sarif = render_sarif_report(&document);
        let driver = &sarif["runs"][0]["tool"]["driver"];

        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(driver["semanticVersion"], env!("CARGO_PKG_VERSION"));
        assert!(!driver["version"].as_str().unwrap().is_empty());
        validate_sarif_report(&sarif).unwrap();
    }

    /// A crash site under the recovered source root is emitted root-relative with
    /// `uriBaseId: SRCROOT`; a harness frame outside the root keeps an absolute
    /// `file://` URI with no `uriBaseId`; the run carries `originalUriBaseIds`.
    #[test]
    fn sarif_relativises_under_root_and_keeps_absolute_outside_root() {
        let work = temp_dir("sarif-srcroot");
        let src_root = work.join("srctree");
        let under_root = src_root.join("src/cbor/internal/loaders.c");
        let outside_root = work.join("auto/H-C000E/main.c");
        fs::create_dir_all(work.join("auto")).unwrap();
        fs::write(
            work.join("auto/run.json"),
            serde_json::to_vec(&json!({ "source_root": src_root.to_str().unwrap() })).unwrap(),
        )
        .unwrap();

        let findings = work.join("findings");
        write_finding(
            &findings.join("F-0001-srcroot"),
            json!({
                "id": "F-0001-srcroot",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "srcroot-sig",
                "target": { "package": "lib", "subprogram": "Decode", "harness_id": "H-C000E" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "_cbor_load_str", "file": under_root.to_str().unwrap(), "line": 20 },
                        { "function": "LLVMFuzzerTestOneInput", "file": outside_root.to_str().unwrap(), "line": 7 }
                    ]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );

        let document = build_report(&ReportOptions::new(&findings, work.join("reports"))).unwrap();
        assert_eq!(document.run.source_root.as_deref(), src_root.to_str());

        let sarif = render_sarif_report(&document);
        // Run must declare the SRCROOT base as an absolute file:// URI w/ trailing slash.
        let base = sarif["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(base, format!("file://{}/", src_root.display()));
        assert!(base.starts_with("file:///") && base.ends_with('/'));

        // Primary location (top non-runtime frame) under root → relative + SRCROOT.
        let primary =
            &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(primary["uri"], "src/cbor/internal/loaders.c");
        assert_eq!(primary["uriBaseId"], "SRCROOT");

        // Stack frames: under-root frame relative+SRCROOT, harness frame file:// no base.
        let frames = sarif["runs"][0]["results"][0]["stacks"][0]["frames"]
            .as_array()
            .unwrap();
        let under = &frames[0]["location"]["physicalLocation"]["artifactLocation"];
        assert_eq!(under["uri"], "src/cbor/internal/loaders.c");
        assert_eq!(under["uriBaseId"], "SRCROOT");
        let outside = &frames[1]["location"]["physicalLocation"]["artifactLocation"];
        assert_eq!(outside["uri"], format!("file://{}", outside_root.display()));
        assert!(outside.get("uriBaseId").is_none());

        validate_sarif_report(&sarif).unwrap();
    }

    /// With no recoverable `auto/run.json`, the renderer degrades gracefully:
    /// absolute paths stay as-is, no `uriBaseId`, and no `originalUriBaseIds`.
    #[test]
    fn sarif_without_source_root_emits_no_uri_base_ids() {
        let root = temp_dir("sarif-no-root");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-noroot"),
            json!({
                "id": "F-0001-noroot",
                "rule_id": "GF-201",
                "severity": "high",
                "classification": "ASAN_HEAP_BUFFER_OVERFLOW",
                "signature": "noroot-sig",
                "target": { "package": "lib", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [{ "function": "parse", "file": "/abs/elsewhere/parse.c", "line": 8 }]
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );

        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();
        assert_eq!(document.run.source_root, None);

        let sarif = render_sarif_report(&document);
        assert!(sarif["runs"][0].get("originalUriBaseIds").is_none());
        let primary =
            &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(primary["uri"], "/abs/elsewhere/parse.c");
        assert!(primary.get("uriBaseId").is_none());
        validate_sarif_report(&sarif).unwrap();
    }

    /// `validate_sarif_report` rejects an SRCROOT artifactLocation whose URI is
    /// absolute (no leading slash / scheme allowed under a uriBaseId).
    #[test]
    fn sarif_validator_rejects_absolute_uri_under_srcroot() {
        let document = build_report(&ReportOptions::new(
            empty_findings_dir("sarif-bad-srcroot"),
            "reports",
        ))
        .unwrap();
        let mut sarif = render_sarif_report(&document);
        sarif["runs"][0]["originalUriBaseIds"] =
            json!({ "SRCROOT": { "uri": "file:///abs/root/" } });
        sarif["runs"][0]["results"] = json!([{
            "ruleId": "govfuzz.finding",
            "kind": "fail",
            "message": { "text": "x" },
            "properties": {
                "govfuzzExceptionSignature": "sig",
                "govfuzzFindingId": "F-x"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": "/abs/root/src/p.c", "uriBaseId": "SRCROOT" }
                }
            }],
            "relatedLocations": []
        }]);

        let error = validate_sarif_report(&sarif).unwrap_err();
        assert!(error.to_string().contains("uriBaseId SRCROOT"));
    }

    /// A run that uses SRCROOT but omits `originalUriBaseIds` is rejected.
    #[test]
    fn sarif_validator_requires_original_uri_base_ids_when_srcroot_used() {
        let document = build_report(&ReportOptions::new(
            empty_findings_dir("sarif-missing-base"),
            "reports",
        ))
        .unwrap();
        let mut sarif = render_sarif_report(&document);
        sarif["runs"][0]["results"] = json!([{
            "ruleId": "govfuzz.finding",
            "kind": "fail",
            "message": { "text": "x" },
            "properties": {
                "govfuzzExceptionSignature": "sig",
                "govfuzzFindingId": "F-x"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": "src/p.c", "uriBaseId": "SRCROOT" }
                }
            }],
            "relatedLocations": []
        }]);

        let error = validate_sarif_report(&sarif).unwrap_err();
        assert!(error.to_string().contains("originalUriBaseIds.SRCROOT.uri"));
    }

    #[test]
    fn sarif_schema_validator_rejects_wrong_version() {
        let document = build_report(&ReportOptions::new(
            empty_findings_dir("sarif-invalid"),
            "reports",
        ))
        .unwrap();
        let mut sarif = render_sarif_report(&document);
        sarif["version"] = json!("2.0.0");

        let error = validate_sarif_report(&sarif).unwrap_err();

        assert!(error.to_string().contains("version must be"));
    }

    #[test]
    fn write_reports_emits_junit_when_requested() {
        let root = temp_dir("junit");
        let findings = root.join("findings");
        let out = root.join("reports");
        write_finding(
            &findings.join("F-0001-junit"),
            json!({
                "id": "F-0001-junit",
                "severity": "high",
                "classification": "explicit_raise",
                "signature": "abcd1234",
                "target": { "package": "Pkg", "subprogram": "Parse", "harness_id": "H-1" },
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "message": "bad <length> & \"quote\"",
                    "handler": { "file": "src/pkg.adb", "line": 42 }
                },
                "minimal_reproducer": "min_testcase.bin"
            }),
        );

        let summary = write_reports(
            ReportOptions::new(&findings, &out)
                .with_run_id("unit")
                .with_junit(true),
        )
        .unwrap();

        let junit_path = summary.junit_path.expect("JUnit path is recorded");
        assert_eq!(junit_path, out.join("run-unit.junit.xml"));

        let junit = fs::read_to_string(junit_path).unwrap();
        assert!(junit.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(junit.contains(
            "<testsuite name=\"govfuzz.unit\" tests=\"1\" failures=\"1\" errors=\"0\" skipped=\"0\">"
        ));
        assert!(junit.contains(
            "<testcase classname=\"govfuzz.Pkg.Parse (H-1)\" name=\"F-0001-junit [likely_reachable]\">"
        ));
        assert!(junit.contains("type=\"explicit_raise\""));
        // JUnit failure message leads with the finding's CWE (GF-106 -> CWE-754).
        assert!(junit.contains("message=\"[CWE-754] explicit_raise: CONSTRAINT_ERROR: bad &lt;length&gt; &amp; &quot;quote&quot;; handler at src/pkg.adb:42\""));
        assert!(junit.contains("minimal_reproducer=F-0001-junit/min_testcase.bin"));
        assert!(junit.contains("govfuzzExceptionSignature=abcd1234"));
    }

    #[test]
    fn junit_generation_uses_current_finding_emitter_exception_shape() {
        let root = temp_dir("junit-emitter-shape");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0000-aabbccdd"),
            json!({
                "id": "F-0000-aabbccdd",
                "signature": "aabbccdd",
                "classification": "swallowed_predefined",
                "handler": {
                    "sequence_index": 3,
                    "exception_name": "CONSTRAINT_ERROR",
                    "exception_message": "bad input",
                    "handler_file": "pkg.adb",
                    "handler_line": 9,
                    "last_breadcrumb": 1,
                    "target_id": 66,
                    "testcase_id": 1
                },
                "harness_id": "H-M5",
                "paths": {
                    "testcase": "testcase.bin",
                    "decoded": "decoded.json",
                    "finding": "finding.json"
                }
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();

        let junit = render_junit_report(&document);

        assert!(junit.contains("tests=\"1\" failures=\"1\""));
        assert!(junit.contains("type=\"swallowed_predefined\""));
        assert!(junit.contains("CONSTRAINT_ERROR: bad input; handler at pkg.adb:9"));
        assert!(junit.contains("govfuzzExceptionSignature=aabbccdd"));
    }

    #[test]
    fn junit_generation_replaces_invalid_xml_control_chars() {
        let root = temp_dir("junit-control-chars");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0001-control"),
            json!({
                "id": "F-\u{0000}-control",
                "severity": "high",
                "classification": "explicit\u{0001}_raise",
                "signature": "sig\u{0008}",
                "target": { "package": "Pkg", "subprogram": "Parse" },
                "exception": {
                    "name": "CONSTRAINT_ERROR",
                    "message": "bad\u{000B}<input>&\"quote\""
                },
                "replay": { "command": "govfuzz\u{001F} replay" }
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();

        let junit = render_junit_report(&document);

        assert!(
            junit.chars().all(is_xml_1_0_char),
            "JUnit XML contains invalid XML 1.0 characters: {junit:?}"
        );
        assert!(junit.contains("name=\"F-?-control [likely_reachable]\""));
        assert!(junit.contains("type=\"explicit?_raise\""));
        // Unclassified crash (control-char classification matches no rule, no
        // bug class) falls back to the documented last-resort CWE-617.
        assert!(junit.contains(
            "message=\"[CWE-617] explicit?_raise: CONSTRAINT_ERROR: bad?&lt;input&gt;&amp;&quot;quote&quot;\""
        ));
        assert!(junit.contains("govfuzzExceptionSignature=sig?"));
        assert!(junit.contains("replay=govfuzz? replay"));
    }

    #[test]
    fn sarif_generation_uses_current_finding_emitter_exception_shape() {
        let root = temp_dir("sarif-emitter-shape");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0000-aabbccdd"),
            json!({
                "id": "F-0000-aabbccdd",
                "signature": "aabbccdd",
                "classification": "swallowed_predefined",
                "handler": {
                    "sequence_index": 3,
                    "exception_name": "CONSTRAINT_ERROR",
                    "exception_message": "bad input",
                    "handler_file": "pkg.adb",
                    "handler_line": 9,
                    "last_breadcrumb": 1,
                    "target_id": 66,
                    "testcase_id": 1
                },
                "last_breadcrumb": 1,
                "raises": [],
                "harness_id": "H-M5",
                "dialect": "Ada 2012",
                "fixture_path": "examples/swallowed",
                "paths": {
                    "testcase": "testcase.bin",
                    "decoded": "decoded.json",
                    "finding": "finding.json"
                }
            }),
        );
        let document = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();

        let sarif = render_sarif_report(&document);

        validate_sarif_report(&sarif).unwrap();
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["govfuzzExceptionSignature"],
            "aabbccdd"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "pkg.adb"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            9
        );
        assert!(sarif["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("CONSTRAINT_ERROR: bad input"));
    }

    #[test]
    fn build_report_allows_empty_findings_directory() {
        let root = temp_dir("empty");
        let findings = root.join("findings");
        fs::create_dir_all(&findings).unwrap();

        let report = build_report(&ReportOptions::new(&findings, root.join("reports"))).unwrap();

        assert_eq!(report.counts.findings, 0);
        assert_eq!(
            render_markdown_report(&report),
            "# GovFuzz Report: last\n\nFindings: 0\n\nNo findings recorded.\n"
        );
    }

    #[test]
    fn load_findings_uses_directory_name_when_id_is_absent() {
        let root = temp_dir("fallback-id");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-dir-id"),
            json!({ "signature": "cccc", "paths": { "minimized": "min_testcase.bin" } }),
        );

        let loaded = load_findings(&findings).unwrap();

        assert_eq!(loaded[0].id, "F-dir-id");
        assert_eq!(
            loaded[0].input,
            json!({ "bytes_path": "F-dir-id/testcase.bin" })
        );
        assert_eq!(
            loaded[0].minimal_reproducer.as_deref(),
            Some("F-dir-id/min_testcase.bin")
        );
    }

    #[test]
    fn load_findings_normalizes_current_finding_emitter_exception_shape() {
        let root = temp_dir("emitter-shape");
        let findings = root.join("findings");
        write_finding(
            &findings.join("F-0000-aabbccdd"),
            json!({
                "id": "F-0000-aabbccdd",
                "signature": "aabbccdd",
                "classification": "swallowed_predefined",
                "handler": {
                    "sequence_index": 3,
                    "exception_name": "CONSTRAINT_ERROR",
                    "exception_message": "bad input",
                    "handler_file": "pkg.adb",
                    "handler_line": 9,
                    "last_breadcrumb": 1,
                    "target_id": 66,
                    "testcase_id": 1
                },
                "last_breadcrumb": 1,
                "raises": [],
                "harness_id": "H-M5",
                "dialect": "Ada 2012",
                "fixture_path": "examples/swallowed",
                "paths": {
                    "testcase": "testcase.bin",
                    "decoded": "decoded.json",
                    "finding": "finding.json"
                }
            }),
        );

        let loaded = load_findings(&findings).unwrap();

        assert_eq!(
            loaded[0].classification.as_deref(),
            Some("swallowed_predefined")
        );
        assert_eq!(loaded[0].target, json!({ "harness_id": "H-M5" }));
        assert_eq!(loaded[0].exception["name"], "CONSTRAINT_ERROR");
        assert_eq!(loaded[0].exception["message"], "bad input");
        assert_eq!(
            loaded[0].exception["classification"],
            "swallowed_predefined"
        );
        assert_eq!(loaded[0].exception["handler"]["file"], "pkg.adb");
        assert_eq!(loaded[0].exception["handler"]["line"], 9);

        let markdown = render_markdown_report(
            &build_report(
                &ReportOptions::new(&findings, root.join("reports")).with_run_id("current"),
            )
            .unwrap(),
        );
        assert!(markdown.contains("- Exception: CONSTRAINT_ERROR: bad input; handler at pkg.adb:9"));
    }

    #[test]
    fn write_reports_sanitizes_run_id_for_file_names() {
        let root = temp_dir("sanitize");
        let findings = root.join("findings");
        let out = root.join("reports");
        fs::create_dir_all(&findings).unwrap();

        let summary =
            write_reports(ReportOptions::new(&findings, &out).with_run_id("release/alpha 1"))
                .unwrap();

        assert_eq!(summary.run_id, "release/alpha 1");
        assert_eq!(summary.json_path, out.join("run-release_alpha_1.json"));
        assert_eq!(summary.markdown_path, out.join("run-release_alpha_1.md"));
    }

    fn finding_report_with_actionability(
        id: &str,
        verdict: actionability::Verdict,
    ) -> FindingReport {
        FindingReport {
            id: id.to_owned(),
            source_path: "findings/F-real/finding.json".to_owned(),
            severity: "high".to_owned(),
            signature: Some("sig".to_owned()),
            cluster_key: Some("cluster".to_owned()),
            cluster_key_full: Some("cluster-full".to_owned()),
            cluster_frames: vec!["frame".to_owned()],
            cluster_fallback: false,
            cluster_quality: ClusterQuality {
                signal: "stack_root".to_owned(),
                frame_count: 1,
                stability: "stable".to_owned(),
            },
            classification: Some("explicit_raise".to_owned()),
            rule_id: Some("GF-101".to_owned()),
            confidence: json!({}),
            target: json!({ "harness_id": "H-real" }),
            build: json!({}),
            sandbox: Value::Null,
            input: json!({}),
            call_sequence: json!([]),
            exception: json!({ "handler": { "file": "src/handler.adb", "line": 50 } }),
            replay: json!({ "command": "govfuzz replay --finding F-real" }),
            minimal_reproducer: None,
            generated_repro_ada: None,
            repro_ada_omitted_reason: None,
            generated_repro_py: None,
            investigation_steps: json!([]),
            actionability: actionability::ActionabilityRecord {
                mode: actionability::RunMode::Attacking,
                verdict,
                impact: actionability::Impact::High,
                confidence: actionability::ActionabilityConfidence::High,
                entry_path: Some(actionability::EntryPath {
                    kind: "harness".to_owned(),
                    source: "testcase.bin".to_owned(),
                    target: "H-real".to_owned(),
                    evidence: Vec::new(),
                    attacker_reachable: None,
                }),
                cwe: Vec::new(),
                cwe_name: None,
                fix_location: Some(actionability::FixLocation {
                    path: "src/pkg.adb".to_owned(),
                    line: Some(42),
                    col: None,
                    reason: "explicit_raise_site".to_owned(),
                }),
                source: None,
                sink: None,
                explanation: None,
                replay: Some(actionability::ReplayEvidence {
                    status: "reproduced".to_owned(),
                }),
                prosthetics: actionability::Prosthetics::default(),
                patch_hints: Vec::new(),
                next_steps: Vec::new(),
            },
            raw: json!({}),
        }
    }

    fn report_document_with_single_actionability_finding() -> ReportDocument {
        let finding =
            finding_report_with_actionability("F-real", actionability::Verdict::RealReachable);
        ReportDocument {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            run: RunReport {
                id: "unit".to_owned(),
                findings_dir: "findings".to_owned(),
                source_root: None,
            },
            counts: CountReport {
                findings: 1,
                by_severity: BTreeMap::new(),
                by_actionability_verdict: BTreeMap::from([("real_reachable".to_owned(), 1)]),
                by_impact: BTreeMap::from([("high".to_owned(), 1)]),
            },
            clusters: vec![ClusterReport {
                key: "cluster".to_owned(),
                key_full: "cluster-full".to_owned(),
                member_count: 1,
                representative: "F-real".to_owned(),
                member_finding_ids: vec!["F-real".to_owned()],
                top_frames: vec!["frame".to_owned()],
                fallback: false,
                quality: ClusterQuality {
                    signal: "stack_root".to_owned(),
                    frame_count: 1,
                    stability: "stable".to_owned(),
                },
            }],
            findings: vec![finding],
        }
    }

    fn write_finding(finding_dir: &Path, finding: serde_json::Value) {
        fs::create_dir_all(finding_dir).unwrap();
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&finding).unwrap(),
        )
        .unwrap();
    }

    fn write_confidence_model(path: &Path) -> confidence_model::LearnedConfidenceModel {
        let model = confidence_model::train_model(&confidence_samples(100));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec_pretty(&model).unwrap()).unwrap();
        model
    }

    fn mutate_confidence_model(path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
        let mut model: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        mutate(&mut model);
        fs::write(path, serde_json::to_vec_pretty(&model).unwrap()).unwrap();
    }

    fn confidence_samples(count: usize) -> Vec<TrainingSample> {
        (0..count)
            .map(|index| {
                if index % 2 == 0 {
                    TrainingSample::new(
                        ConfidenceLabel::TruePositive,
                        true_positive_finding("training-true"),
                    )
                } else {
                    TrainingSample::new(ConfidenceLabel::FalsePositive, false_positive_finding())
                }
            })
            .collect()
    }

    fn true_positive_finding(id: &str) -> serde_json::Value {
        json!({
            "id": id,
            "classification": "explicit_raise",
            "return_class": "failure",
            "breadcrumbs": [1, 2, 3],
            "raises": [{}],
            "signature_age": 1,
            "target": { "score": 95.0, "param_shape_complexity": 1 },
            "build": { "deps": { "stubbed": [], "fake_corba": [] } }
        })
    }

    fn false_positive_finding() -> serde_json::Value {
        json!({
            "id": "training-false",
            "classification": "unknown",
            "return_class": "normal",
            "signature_age": 80,
            "target": { "score": 5.0, "param_shape_complexity": 14 },
            "build": {
                "deps": {
                    "stubbed": ["external.ads", "external.adb"],
                    "stubbed_call_depth": 5,
                    "calls_through_stub": 5,
                    "fake_corba": ["corba.ads"]
                }
            }
        })
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-report-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn empty_findings_dir(name: &str) -> PathBuf {
        let root = temp_dir(name);
        let findings = root.join("findings");
        fs::create_dir_all(&findings).unwrap();
        findings
    }

    fn write_cluster_finding(dir: &std::path::Path, id: &str, cluster_key: &str, frame: &str) {
        let finding_dir = dir.join(id);
        fs::create_dir_all(&finding_dir).unwrap();
        let cluster_full = cluster_key.to_owned() + &"0".repeat(48);
        let signature = "deadbeefcafef00d".to_owned() + &"0".repeat(48);
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": id,
                "signature": signature,
                "classification": "unhandled",
                "cluster_key": cluster_key,
                "cluster_key_full": cluster_full,
                "cluster_normalized_frames": [frame],
                "cluster_fallback": false,
                "exception": { "name": "DOES_NOT_MATTER" }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn load_findings_backfills_cluster_key_when_missing_on_disk() {
        let dir = temp_dir("backfill");
        let finding_dir = dir.join("F-0001-aaaaaa");
        fs::create_dir_all(&finding_dir).unwrap();
        fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0001-aaaaaa",
                "signature": "deadbeefcafef00d".to_owned() + &"0".repeat(48),
                "classification": "unhandled",
                "exception": {
                    "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "__asan_memcpy" },
                        { "function": "real_parse", "file": "/src/p.c", "line": 9 },
                        { "function": "LLVMFuzzerTestOneInput" }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let findings = load_findings(&dir).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.cluster_frames, vec!["real_parse".to_owned()]);
        assert!(f.cluster_key.is_some());
        assert_eq!(f.cluster_key.as_deref().unwrap().len(), 16);
        assert!(!f.cluster_fallback);
    }

    #[test]
    fn build_report_groups_findings_into_clusters_by_cluster_key() {
        let findings_dir = temp_dir("clusters");
        let out_dir = temp_dir("clusters-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0003-cccccc",
            "k2bbbbbbbbbbbbbb",
            "parse_b",
        );

        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        assert_eq!(document.clusters.len(), 2);
        let by_key: std::collections::HashMap<_, _> = document
            .clusters
            .iter()
            .map(|c| (c.key.clone(), c))
            .collect();
        assert_eq!(by_key["k1aaaaaaaaaaaaaa"].member_count, 2);
        assert_eq!(by_key["k2bbbbbbbbbbbbbb"].member_count, 1);
        assert_eq!(by_key["k1aaaaaaaaaaaaaa"].representative, "F-0001-aaaaaa");
        assert_eq!(by_key["k1aaaaaaaaaaaaaa"].top_frames, vec!["parse_a"]);
    }

    #[test]
    fn build_report_exposes_cluster_quality_metadata() {
        let findings_dir = temp_dir("cluster-quality");
        let out_dir = temp_dir("cluster-quality-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );

        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();

        assert_eq!(document.clusters[0].quality.signal, "stack_root");
        assert_eq!(document.clusters[0].quality.frame_count, 1);
        assert_eq!(document.clusters[0].quality.stability, "stable");
        assert_eq!(document.findings[0].cluster_quality.signal, "stack_root");
    }

    #[test]
    fn markdown_report_includes_clusters_table() {
        let findings_dir = temp_dir("md-clusters");
        let out_dir = temp_dir("md-clusters-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0003-cccccc",
            "k2bbbbbbbbbbbbbb",
            "parse_b",
        );

        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        let md = render_markdown_report(&document);
        assert!(md.contains("## Clusters"));
        assert!(md.contains("| k1aaaaaaaaaaaaaa | 2 | stack_root/stable | parse_a |"));
        assert!(md.contains("| k2bbbbbbbbbbbbbb | 1 | stack_root/stable | parse_b |"));
        assert!(md.contains("- Cluster: `k1aaaaaaaaaaaaaa`"));
    }

    #[test]
    fn sarif_result_carries_cluster_key_in_partial_fingerprints() {
        let findings_dir = temp_dir("sarif-clusters");
        let out_dir = temp_dir("sarif-clusters-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        let sarif = render_sarif_report(&document);
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(
            result["partialFingerprints"]["govfuzzClusterKey"],
            "k1aaaaaaaaaaaaaa"
        );
        assert_eq!(result["properties"]["clusterKey"], "k1aaaaaaaaaaaaaa");
        assert_eq!(result["properties"]["clusterSize"], 2);
        assert_eq!(
            result["properties"]["clusterRepresentative"],
            "F-0001-aaaaaa"
        );
        assert_eq!(result["properties"]["clusterFallback"], false);
        assert_eq!(
            result["properties"]["clusterQuality"]["signal"],
            "stack_root"
        );
        assert_eq!(
            result["properties"]["clusterQuality"]["stability"],
            "stable"
        );
    }

    #[test]
    fn junit_testcase_name_includes_cluster_suffix() {
        let findings_dir = temp_dir("junit-clusters");
        let out_dir = temp_dir("junit-clusters-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        let xml = render_junit_report(&document);
        assert!(xml.contains("name=\"F-0001-aaaaaa [unknown] [cluster:k1aaaaaaaaaaaaaa]\""));
    }

    #[test]
    fn markdown_collapse_clusters_only_emits_representative_detail() {
        let findings_dir = temp_dir("collapse");
        let out_dir = temp_dir("collapse-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0003-cccccc",
            "k2bbbbbbbbbbbbbb",
            "parse_b",
        );

        let options = ReportOptions::new(findings_dir, out_dir).with_collapse_clusters(true);
        let document = build_report(&options).unwrap();
        let md = render_markdown_report_with(&document, &options);
        // The report LEADS with the grouped-issue view: 3 findings -> 2 issues.
        assert!(md.contains("Issues: 2 (grouped from 3 findings)"));
        assert!(md.contains("## Issues\n"));
        assert!(md.contains("\n## F-0001-aaaaaa\n"));
        assert!(!md.contains("\n## F-0002-bbbbbb\n"));
        // The collapse stub is replaced by a real member list under the issue so
        // a dev can reach every triggering input.
        assert!(md.contains("- Member findings (2): one fix resolves all"));
        assert!(md.contains("`F-0002-bbbbbb`"));
        // "Fix once" framing is present for every issue representative.
        assert!(md.contains("**Fix once:**"));
        assert!(md.contains("\n## F-0003-cccccc\n"));
    }

    #[test]
    fn render_csv_report_emits_header_and_one_row_per_issue() {
        let findings_dir = temp_dir("csv");
        let out_dir = temp_dir("csv-out");
        // Two findings in DISTINCT clusters -> two issues -> two data rows.
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k2bbbbbbbbbbbbbb",
            "parse_b",
        );
        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        let csv = super::render_csv_report(&document);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "issue_id,count,severity,cwe,fix_file,fix_line,impact,verdict,sink_file,sink_line,sink_function,cluster_key,classification,confirmation,member_finding_ids,reproducers"
        );
        assert_eq!(lines[0].split(',').count(), 16);
        assert_eq!(document.findings.len(), 2);
        // One row per ISSUE; these two findings are distinct issues.
        assert_eq!(lines.len(), 3, "one header line + one row per issue");
        for row in &lines[1..] {
            // No field in these fixtures embeds a separator, so a plain split is
            // a valid column count; rows must project all 16 columns.
            if !row.contains('"') {
                let cols: Vec<&str> = row.split(',').collect();
                assert_eq!(cols.len(), 16, "row must project 16 columns: {row}");
                // count == 1 (singleton issue) and a non-empty CWE column.
                assert_eq!(cols[1], "1", "count column: {row}");
                assert_eq!(cols[3], "CWE-248", "cwe column (GF-101): {row}");
                // #484: a plain runtime finding is provenance "fuzz".
                assert_eq!(cols[13], "fuzz", "confirmation column: {row}");
                // member_finding_ids carries this single member's id.
                assert!(cols[14].starts_with("F-000"), "member_finding_ids: {row}");
            }
        }
        // Issue id is the full cluster key (short key + padding).
        assert!(csv.contains("k1aaaaaaaaaaaaaa") && csv.contains("k2bbbbbbbbbbbbbb"));
    }

    #[test]
    fn render_csv_report_collapses_a_cluster_to_one_issue_row() {
        let findings_dir = temp_dir("csv-collapse");
        let out_dir = temp_dir("csv-collapse-out");
        // Three findings: two share a cluster (one issue), one is its own.
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0003-cccccc",
            "k2bbbbbbbbbbbbbb",
            "parse_b",
        );
        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        let csv = super::render_csv_report(&document);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(document.findings.len(), 3);
        // 3 findings collapse to 2 issues -> 2 data rows.
        assert_eq!(lines.len(), 3, "header + one row per issue (2 issues)");
        // The shared-cluster issue row carries count=2 and a non-empty CWE.
        let counts: Vec<&str> = lines[1..]
            .iter()
            .map(|row| row.split(',').nth(1).unwrap())
            .collect();
        assert!(
            counts.contains(&"2"),
            "an issue collapses two findings: {counts:?}"
        );
        assert!(counts.contains(&"1"));
        for row in &lines[1..] {
            let cwe = row.split(',').nth(3).unwrap();
            assert!(!cwe.is_empty(), "every issue row carries a CWE: {row}");
        }
        // The collapsed (count=2) issue enumerates BOTH member ids so a dev can
        // reach every triggering input, not just the representative's.
        let collapsed_row = lines[1..]
            .iter()
            .find(|row| row.split(',').nth(1) == Some("2"))
            .expect("a count=2 issue row");
        let member_ids = collapsed_row.split(',').nth(14).unwrap();
        assert!(
            member_ids.contains("F-0001-aaaaaa"),
            "members: {member_ids}"
        );
        assert!(
            member_ids.contains("F-0002-bbbbbb"),
            "members: {member_ids}"
        );
        assert!(
            member_ids.contains(';'),
            "member ids are ;-joined: {member_ids}"
        );
    }

    #[test]
    fn sarif_result_carries_cwe_and_cluster_fingerprint() {
        let findings_dir = temp_dir("sarif-cwe");
        let out_dir = temp_dir("sarif-cwe-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        let sarif = render_sarif_report(&document);
        let result = &sarif["runs"][0]["results"][0];
        // Every result carries the CWE(s) so SARIF is mapped to a weakness.
        assert_eq!(result["properties"]["cwes"][0], "CWE-248");
        // And dedups by root-cause issue via the cluster fingerprints.
        let pf = &result["partialFingerprints"];
        assert_eq!(pf["govfuzzClusterKey"], "k1aaaaaaaaaaaaaa");
        assert_eq!(
            pf["govfuzzIssueKey"],
            json!("k1aaaaaaaaaaaaaa".to_owned() + &"0".repeat(48))
        );
    }

    #[test]
    fn load_finding_backfills_cwe_from_rule_for_oracle_finding() {
        // A behavioral oracle finding has a rule_id but NO bug class -> its CWE
        // comes from the finding_rules catalog (priority 2).
        let findings_dir = temp_dir("oracle-cwe");
        write_finding(
            &findings_dir.join("F-0001-oracle"),
            json!({
                "id": "F-0001-oracle",
                "rule_id": "GF-405",
                "classification": "path_control",
                "exception": { "name": "GF-405", "message": "attacker-controlled path open" }
            }),
        );
        let findings = load_findings(&findings_dir).unwrap();
        let rule_cwe = rules::by_id("GF-405").unwrap().cwe;
        assert_eq!(findings[0].actionability.cwe, vec![rule_cwe.to_owned()]);
        assert!(!findings[0].actionability.cwe.is_empty());
    }

    #[test]
    fn markdown_and_sarif_surface_patch_diff_and_fix() {
        let mut document = report_document_with_single_actionability_finding();
        document.findings[0].actionability.patch_hints = vec![actionability::PatchHint {
            rule_id: "GF-101".to_owned(),
            title: "Guard the index".to_owned(),
            guidance: "Bounds-check before the write.".to_owned(),
            diff: Some(
                "--- a/src/pkg.adb\n+++ b/src/pkg.adb\n@@\n-  X (I) := 0;\n+  if I in X'Range then X (I) := 0; end if;".to_owned(),
            ),
        }];

        // Markdown: the suggested patch renders as a fenced ```diff block, and the
        // issue carries the "Fix once" framing pointing at the fix location.
        let md = render_markdown_report(&document);
        assert!(md.contains("```diff"));
        assert!(md.contains("+  if I in X'Range then"));
        assert!(md.contains("**Fix once:** edit `src/pkg.adb:42`"));
        assert!(md.contains("Resolves all 1 finding(s)."));

        // SARIF: a description-only `result.fixes[]` entry surfaces the patch, and
        // the report still validates.
        let sarif = render_sarif_report(&document);
        validate_sarif_report(&sarif).expect("SARIF with a fix still validates");
        let fix = &sarif["runs"][0]["results"][0]["fixes"][0];
        assert_eq!(
            fix["description"]["text"],
            "Guard the index: Bounds-check before the write."
        );
        assert!(fix["properties"]["govfuzzSuggestedPatch"]
            .as_str()
            .unwrap()
            .contains("if I in X'Range"));
    }

    #[test]
    fn markdown_enumerates_issue_members_with_reproducers() {
        let findings_dir = temp_dir("md-members");
        let out_dir = temp_dir("md-members-out");
        write_cluster_finding(
            &findings_dir,
            "F-0001-aaaaaa",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        write_cluster_finding(
            &findings_dir,
            "F-0002-bbbbbb",
            "k1aaaaaaaaaaaaaa",
            "parse_a",
        );
        let document = build_report(&ReportOptions::new(findings_dir, out_dir)).unwrap();
        // No collapse: the issue still enumerates EVERY member under the
        // representative so a dev can reach each triggering input.
        let md = render_markdown_report(&document);
        assert!(md.contains("- Member findings (2): one fix resolves all"));
        assert!(md.contains("`F-0001-aaaaaa`"));
        assert!(md.contains("`F-0002-bbbbbb`"));
    }

    #[test]
    fn csv_escape_quotes_fields_with_separators_and_quotes() {
        assert_eq!(super::csv_escape("plain"), "plain");
        assert_eq!(super::csv_escape("a,b"), "\"a,b\"");
        assert_eq!(super::csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(super::csv_escape("l1\nl2"), "\"l1\nl2\"");
    }
}
