// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const SEEDED_METRICS_SCHEMA_VERSION: &str = "govfuzz.seeded_benchmark.metrics.v1";
const PATTERN_COVERAGE_SCHEMA_VERSION: &str = "govfuzz.legacy_patterns.coverage.v1";

#[derive(Debug, clap::Args)]
pub struct BenchmarkArgs {
    #[command(subcommand)]
    command: BenchmarkCommand,
}

#[derive(Debug, clap::Subcommand)]
enum BenchmarkCommand {
    Seeded(SeededArgs),
    Patterns(PatternArgs),
}

#[derive(Debug, clap::Args)]
struct SeededArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    markdown: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct PatternArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    markdown: Option<PathBuf>,
}

pub fn run(args: BenchmarkArgs) -> i32 {
    let result = match args.command {
        BenchmarkCommand::Seeded(args) => run_seeded(args),
        BenchmarkCommand::Patterns(args) => run_patterns(args),
    };
    match result {
        Ok(exit_code) => exit_code,
        Err(error) => {
            gfeprintln!("{error:#}");
            1
        }
    }
}

fn run_seeded(args: SeededArgs) -> Result<i32> {
    let manifest: SeededManifest = read_json(&args.manifest)?;
    let manifest_dir = args
        .manifest
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let source_root = manifest_dir.join(manifest.root.as_deref().unwrap_or("."));
    let observed_static = scan_static_findings(&source_root)?;
    let observed = observed_findings(&manifest, observed_static);
    let metrics = seeded_metrics(&manifest, &observed, &args.manifest);

    write_json(&args.out, &metrics)?;
    if let Some(markdown) = args.markdown {
        write_text(&markdown, &render_seeded_markdown(&metrics))?;
    }

    let failed = metrics["metrics"]["false_negatives"].as_u64().unwrap_or(0) > 0
        || metrics["metrics"]["false_positives"].as_u64().unwrap_or(0) > 0;
    Ok(if failed { 1 } else { 0 })
}

fn run_patterns(args: PatternArgs) -> Result<i32> {
    let manifest: LegacyPatternManifest = read_json(&args.manifest)?;
    let manifest_dir = args
        .manifest
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let coverage = pattern_coverage(&manifest, &manifest_dir, &args.manifest);
    write_json(&args.out, &coverage)?;
    if let Some(markdown) = args.markdown {
        write_text(&markdown, &render_patterns_markdown(&coverage))?;
    }
    Ok(
        if coverage["missing_fixtures"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            1
        } else {
            0
        },
    )
}

#[derive(Debug, Deserialize)]
struct SeededManifest {
    #[allow(dead_code)]
    schema_version: String,
    suite_id: String,
    root: Option<String>,
    #[serde(default)]
    limitations: Vec<String>,
    #[serde(default)]
    cases: Vec<SeededCase>,
}

#[derive(Debug, Deserialize)]
struct SeededCase {
    id: String,
    finding_kind: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    expected_findings: Vec<ExpectedFinding>,
    #[serde(default)]
    expected_non_findings: Vec<ExpectedFinding>,
    #[serde(default)]
    observed_findings: Vec<ExpectedFinding>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ExpectedFinding {
    rule_id: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ObservedFinding {
    case_id: String,
    finding_kind: String,
    rule_id: String,
    path: String,
}

#[derive(Debug, Deserialize)]
struct LegacyPatternManifest {
    #[allow(dead_code)]
    schema_version: String,
    corpus_id: String,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    patterns: Vec<LegacyPattern>,
}

#[derive(Debug, Deserialize)]
struct LegacyPattern {
    id: String,
    track: String,
    path: String,
    expected_behavior: String,
    #[serde(default)]
    breakage: bool,
}

fn scan_static_findings(root: &Path) -> Result<Vec<ObservedFinding>> {
    let report = static_analysis::scan(&static_analysis::StaticScanOptions {
        root: root.to_path_buf(),
        out_dir: root.join(".govfuzz-benchmark-unused"),
        suppressions_path: None,
        baseline_path: None,
        policy_path: None,
        enabled_rules: BTreeSet::new(),
        disabled_rules: BTreeSet::new(),
        emit_sarif: false,
    })
    .with_context(|| format!("scan seeded static root {}", root.display()))?;

    Ok(report
        .findings
        .into_iter()
        .map(|finding| ObservedFinding {
            case_id: String::new(),
            finding_kind: "static".to_owned(),
            rule_id: finding.rule_id,
            path: finding.location.path,
        })
        .collect())
}

fn observed_findings(
    manifest: &SeededManifest,
    observed_static: Vec<ObservedFinding>,
) -> Vec<ObservedFinding> {
    let mut observed = Vec::new();
    for case in &manifest.cases {
        if case.finding_kind == "static" {
            let source = case.source.as_deref().unwrap_or_default();
            for finding in &observed_static {
                if source.is_empty() || path_matches(&finding.path, source) {
                    let mut finding = finding.clone();
                    finding.case_id = case.id.clone();
                    observed.push(finding);
                }
            }
        }
        for finding in &case.observed_findings {
            observed.push(ObservedFinding {
                case_id: case.id.clone(),
                finding_kind: case.finding_kind.clone(),
                rule_id: finding.rule_id.clone(),
                path: finding.path.clone(),
            });
        }
    }
    observed.sort();
    observed.dedup();
    observed
}

fn seeded_metrics(
    manifest: &SeededManifest,
    observed: &[ObservedFinding],
    manifest_path: &Path,
) -> Value {
    let mut true_positives = Vec::new();
    let mut false_negatives = Vec::new();
    let mut false_positives = Vec::new();
    let mut by_kind: BTreeMap<String, RuleStats> = BTreeMap::new();
    let mut by_rule: BTreeMap<String, RuleStats> = BTreeMap::new();
    let mut expected_count = 0usize;

    for case in &manifest.cases {
        for expected in &case.expected_findings {
            expected_count += 1;
            by_kind
                .entry(case.finding_kind.clone())
                .or_default()
                .expected += 1;
            by_rule
                .entry(expected.rule_id.clone())
                .or_default()
                .expected += 1;
            if observed
                .iter()
                .any(|finding| observed_matches(finding, &case.id, expected))
            {
                true_positives.push(json!({
                    "case_id": case.id,
                    "finding_kind": case.finding_kind,
                    "rule_id": expected.rule_id,
                    "path": expected.path,
                }));
                by_kind
                    .entry(case.finding_kind.clone())
                    .or_default()
                    .true_positives += 1;
                by_rule
                    .entry(expected.rule_id.clone())
                    .or_default()
                    .true_positives += 1;
            } else {
                false_negatives.push(json!({
                    "case_id": case.id,
                    "finding_kind": case.finding_kind,
                    "rule_id": expected.rule_id,
                    "path": expected.path,
                }));
            }
        }

        for non_finding in &case.expected_non_findings {
            if observed
                .iter()
                .any(|finding| observed_matches(finding, &case.id, non_finding))
            {
                false_positives.push(json!({
                    "case_id": case.id,
                    "finding_kind": case.finding_kind,
                    "rule_id": non_finding.rule_id,
                    "path": non_finding.path,
                }));
                by_kind
                    .entry(case.finding_kind.clone())
                    .or_default()
                    .false_positives += 1;
                by_rule
                    .entry(non_finding.rule_id.clone())
                    .or_default()
                    .false_positives += 1;
            }
        }
    }

    let true_positive_count = true_positives.len();
    let false_negative_count = false_negatives.len();
    let false_positive_count = false_positives.len();

    json!({
        "schema_version": SEEDED_METRICS_SCHEMA_VERSION,
        "suite_id": manifest.suite_id,
        "manifest": manifest_path.display().to_string(),
        "limitations": if manifest.limitations.is_empty() {
            vec!["Seeded suite metrics are proxies; they are not population recall or precision estimates.".to_owned()]
        } else {
            manifest.limitations.clone()
        },
        "metrics": {
            "expected_findings": expected_count,
            "true_positives": true_positive_count,
            "false_negatives": false_negative_count,
            "false_positives": false_positive_count,
            "recall": ratio(true_positive_count, true_positive_count + false_negative_count),
            "precision_proxy": ratio(true_positive_count, true_positive_count + false_positive_count),
            "by_kind": map_stats(by_kind),
            "by_rule": map_stats(by_rule),
        },
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "observed": observed.iter().map(|finding| json!({
            "case_id": finding.case_id,
            "finding_kind": finding.finding_kind,
            "rule_id": finding.rule_id,
            "path": finding.path,
        })).collect::<Vec<_>>(),
    })
}

#[derive(Debug, Default)]
struct RuleStats {
    expected: usize,
    true_positives: usize,
    false_positives: usize,
}

fn map_stats(stats: BTreeMap<String, RuleStats>) -> BTreeMap<String, Value> {
    stats
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                json!({
                    "expected": value.expected,
                    "true_positives": value.true_positives,
                    "false_positives": value.false_positives,
                    "recall": ratio(value.true_positives, value.expected),
                }),
            )
        })
        .collect()
}

fn observed_matches(observed: &ObservedFinding, case_id: &str, expected: &ExpectedFinding) -> bool {
    observed.case_id == case_id
        && observed.rule_id == expected.rule_id
        && path_matches(&observed.path, &expected.path)
}

fn path_matches(observed: &str, expected: &str) -> bool {
    observed == expected || observed.ends_with(expected) || expected.ends_with(observed)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        ((numerator as f64 / denominator as f64) * 10_000.0).round() / 10_000.0
    }
}

fn pattern_coverage(
    manifest: &LegacyPatternManifest,
    manifest_dir: &Path,
    manifest_path: &Path,
) -> Value {
    let mut tracks = BTreeSet::new();
    let mut by_track: BTreeMap<String, PatternStats> = BTreeMap::new();
    let mut missing = Vec::new();
    let mut breakage_patterns = 0usize;
    let mut patterns = Vec::new();

    for pattern in &manifest.patterns {
        tracks.insert(pattern.track.clone());
        let stats = by_track.entry(pattern.track.clone()).or_default();
        stats.patterns += 1;
        if pattern.breakage {
            stats.breakage_patterns += 1;
            breakage_patterns += 1;
        }
        let exists = manifest_dir.join(&pattern.path).is_file();
        if !exists {
            missing.push(json!({
                "id": pattern.id,
                "track": pattern.track,
                "path": pattern.path,
            }));
        }
        patterns.push(json!({
            "id": pattern.id,
            "track": pattern.track,
            "path": pattern.path,
            "expected_behavior": pattern.expected_behavior,
            "breakage": pattern.breakage,
            "fixture_present": exists,
        }));
    }

    json!({
        "schema_version": PATTERN_COVERAGE_SCHEMA_VERSION,
        "corpus_id": manifest.corpus_id,
        "manifest": manifest_path.display().to_string(),
        "license": manifest.license,
        "counts": {
            "tracks": tracks.len(),
            "patterns": manifest.patterns.len(),
            "breakage_patterns": breakage_patterns,
            "missing_fixtures": missing.len(),
        },
        "by_track": by_track.into_iter().map(|(track, stats)| {
            (track, json!({
                "patterns": stats.patterns,
                "breakage_patterns": stats.breakage_patterns,
            }))
        }).collect::<BTreeMap<_, _>>(),
        "patterns": patterns,
        "missing_fixtures": missing,
    })
}

#[derive(Debug, Default)]
struct PatternStats {
    patterns: usize,
    breakage_patterns: usize,
}

fn render_seeded_markdown(metrics: &Value) -> String {
    format!(
        "# Seeded Benchmark Metrics\n\n- Suite: {}\n- Recall: {}\n- Precision proxy: {}\n- False negatives: {}\n- False positives: {}\n\nLimitations are recorded in the JSON report.\n",
        metrics["suite_id"].as_str().unwrap_or("unknown"),
        metrics["metrics"]["recall"],
        metrics["metrics"]["precision_proxy"],
        metrics["metrics"]["false_negatives"],
        metrics["metrics"]["false_positives"],
    )
}

fn render_patterns_markdown(coverage: &Value) -> String {
    format!(
        "# Government Legacy Pattern Coverage\n\n- Corpus: {}\n- Tracks: {}\n- Patterns: {}\n- Breakage patterns: {}\n\n",
        coverage["corpus_id"].as_str().unwrap_or("unknown"),
        coverage["counts"]["tracks"],
        coverage["counts"]["patterns"],
        coverage["counts"]["breakage_patterns"],
    )
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write {}", path.display()))
}

fn write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("write {}", path.display()))
}
