// SPDX-License-Identifier: Apache-2.0

//! `govfuzz introspect` surfaces the first practical coverage-blocker
//! view: discovered targets versus a prior `govfuzz auto` run.

use crate::auto::candidate::{Candidate, Lang};
use crate::auto::discovery;
use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct IntrospectArgs {
    /// Source root to inspect.
    pub path: PathBuf,

    /// Work directory containing optional auto/run.json.
    #[arg(long, default_value = "govfuzz_work")]
    pub work_dir: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
    pub format: OutputFormat,

    /// Maximum number of target rows to show.
    #[arg(long, default_value_t = 20)]
    pub top: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Markdown,
    Json,
}

#[derive(Debug, Serialize)]
struct IntrospectionReport {
    schema_version: u32,
    source_root: String,
    work_dir: String,
    discovered: DiscoverySummary,
    prior_run: PriorRunSummary,
    recommendations: Vec<String>,
    coverage_blockers: Vec<CoverageBlockerInsight>,
    targets: Vec<TargetInsight>,
}

#[derive(Debug, Serialize)]
struct DiscoverySummary {
    total: usize,
    languages: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct PriorRunSummary {
    present: bool,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct TargetInsight {
    harness_id: String,
    name: String,
    language: &'static str,
    source: String,
    line: u32,
    score: i32,
    prior_outcome: String,
    blocker_kind: &'static str,
    recommendation: String,
    static_reachability: StaticReachabilityInsight,
    dynamic_coverage: DynamicCoverageInsight,
}

#[derive(Debug, Clone, Default, Serialize)]
struct StaticReachabilityInsight {
    direct_callees: Vec<ReachableTargetInsight>,
    uncovered_direct_callees: Vec<ReachableTargetInsight>,
    reachable_callees: Vec<ReachableTargetInsight>,
    uncovered_reachable_callees: Vec<ReachableTargetInsight>,
    unresolved_calls: Vec<UnresolvedCallInsight>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct DynamicCoverageInsight {
    #[serde(skip_serializing_if = "Option::is_none")]
    cmplog: Option<CmpLogCoverageInsight>,
}

#[derive(Debug, Clone, Serialize)]
struct CmpLogCoverageInsight {
    enabled: bool,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_path: Option<String>,
    entries: usize,
    dictionary_tokens: usize,
    seed_splice_candidates: usize,
    suggested_dictionary_tokens: Vec<SuggestedTokenInsight>,
}

#[derive(Debug, Clone, Serialize)]
struct SuggestedTokenInsight {
    hex: String,
    preview: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReachableTargetInsight {
    harness_id: String,
    name: String,
    language: &'static str,
    source: String,
    line: u32,
    prior_outcome: String,
    blocker_kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct UnresolvedCallInsight {
    call: String,
    source: String,
    line: u32,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageBlockerInsight {
    kind: &'static str,
    source_target: ReachableTargetInsight,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_target: Option<ReachableTargetInsight>,
    recommendation: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    evidence: Vec<BlockerEvidenceInsight>,
}

#[derive(Debug, Clone, Serialize)]
struct BlockerEvidenceInsight {
    key: String,
    value: String,
}

struct PriorRun {
    summary: PriorRunSummary,
    target_outcomes: HashMap<String, String>,
}

pub fn run(args: IntrospectArgs) -> Result<()> {
    let format = args.format;
    let report = build_report(args)?;
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Markdown => {
            print!("{}", render_markdown(&report));
        }
    }
    Ok(())
}

fn build_report(args: IntrospectArgs) -> Result<IntrospectionReport> {
    let candidates = discovery::discover(&args.path)
        .with_context(|| format!("discover {}", args.path.display()))?;
    let prior_run = load_prior_run(&args.work_dir)?;
    let call_graph = static_analysis::analyze_call_graph(&args.path)
        .with_context(|| format!("build call graph for {}", args.path.display()))?;
    let (mut reachability, coverage_blockers) =
        static_reachability(&candidates, &prior_run, &call_graph);
    let (mut dynamic_coverage, dynamic_blockers) =
        dynamic_coverage(&candidates, &prior_run, &args.work_dir)?;
    let mut coverage_blockers = coverage_blockers;
    coverage_blockers.extend(dynamic_blockers);
    sort_coverage_blockers(&mut coverage_blockers);
    let discovered = discovery_summary(&candidates);
    let mut targets = candidates
        .iter()
        .map(|candidate| {
            let static_reachability = reachability
                .remove(&candidate.harness_id)
                .unwrap_or_default();
            let dynamic_coverage = dynamic_coverage
                .remove(&candidate.harness_id)
                .unwrap_or_default();
            target_insight(candidate, &prior_run, static_reachability, dynamic_coverage)
        })
        .collect::<Vec<_>>();
    targets.truncate(args.top);
    let recommendations = recommendations(
        &prior_run,
        &targets,
        &coverage_blockers,
        &args.path,
        &args.work_dir,
    );

    Ok(IntrospectionReport {
        schema_version: 1,
        source_root: args.path.display().to_string(),
        work_dir: args.work_dir.display().to_string(),
        discovered,
        prior_run: prior_run.summary,
        recommendations,
        coverage_blockers,
        targets,
    })
}

fn discovery_summary(candidates: &[Candidate]) -> DiscoverySummary {
    let mut languages = BTreeMap::new();
    for candidate in candidates {
        *languages
            .entry(language_name(&candidate.lang).to_owned())
            .or_insert(0) += 1;
    }
    DiscoverySummary {
        total: candidates.len(),
        languages,
    }
}

fn load_prior_run(work_dir: &Path) -> Result<PriorRun> {
    let run_json = work_dir.join("auto/run.json");
    if !run_json.is_file() {
        return Ok(PriorRun {
            summary: PriorRunSummary {
                present: false,
                path: run_json.display().to_string(),
                summary: None,
            },
            target_outcomes: HashMap::new(),
        });
    }

    let raw = std::fs::read(&run_json).with_context(|| format!("read {}", run_json.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).with_context(|| format!("parse {}", run_json.display()))?;
    let target_outcomes = parse_prior_target_outcomes(&value);
    Ok(PriorRun {
        summary: PriorRunSummary {
            present: true,
            path: run_json.display().to_string(),
            summary: value.get("summary").cloned(),
        },
        target_outcomes,
    })
}

fn parse_prior_target_outcomes(value: &serde_json::Value) -> HashMap<String, String> {
    let mut outcomes = HashMap::new();
    let Some(targets) = value.get("targets").and_then(|targets| targets.as_array()) else {
        return outcomes;
    };
    for target in targets {
        let Some(harness_id) = target.get("harness_id").and_then(|id| id.as_str()) else {
            continue;
        };
        let outcome = target
            .get("outcome")
            .and_then(outcome_name)
            .unwrap_or("unknown");
        outcomes.insert(harness_id.to_owned(), outcome.to_owned());
    }
    outcomes
}

fn outcome_name(value: &serde_json::Value) -> Option<&str> {
    value
        .get("outcome")
        .and_then(|inner| inner.as_str())
        .or_else(|| value.as_str())
}

fn target_insight(
    candidate: &Candidate,
    prior: &PriorRun,
    static_reachability: StaticReachabilityInsight,
    dynamic_coverage: DynamicCoverageInsight,
) -> TargetInsight {
    let prior_outcome = prior
        .target_outcomes
        .get(&candidate.harness_id)
        .cloned()
        .unwrap_or_else(|| {
            if prior.summary.present {
                "not_seen_in_prior_run".to_owned()
            } else {
                "no_prior_run".to_owned()
            }
        });
    let blocker_kind = blocker_kind(&prior_outcome);
    TargetInsight {
        harness_id: candidate.harness_id.clone(),
        name: candidate.name.clone(),
        language: language_name(&candidate.lang),
        source: candidate.source_path.display().to_string(),
        line: candidate.line,
        score: candidate.score,
        prior_outcome: prior_outcome.clone(),
        blocker_kind,
        recommendation: recommendation_for(blocker_kind, candidate),
        static_reachability,
        dynamic_coverage,
    }
}

fn language_name(lang: &Lang) -> &'static str {
    match lang {
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
    }
}

fn blocker_kind(outcome: &str) -> &'static str {
    match outcome {
        "built_and_fuzzed" => "already_fuzzed",
        "built" => "built_not_fuzzed",
        "failed_build" => "build_blocked",
        "unsupported_params" => "unsupported_params",
        "unrecoverable_link" => "link_blocked",
        "unrecoverable_runtime" => "runtime_blocked",
        "not_seen_in_prior_run" => "not_run",
        "no_prior_run" => "no_prior_run",
        _ => "needs_review",
    }
}

fn recommendation_for(blocker_kind: &str, candidate: &Candidate) -> String {
    match blocker_kind {
        "already_fuzzed" => "Already built and fuzzed in the prior auto run.".to_owned(),
        "built_not_fuzzed" => {
            "Built previously but did not fuzz; rerun auto or replay the harness manually."
                .to_owned()
        }
        "build_blocked" => {
            "Build blocked previously; inspect auto/run.md and needed_for_build before rerunning."
                .to_owned()
        }
        "unsupported_params" => {
            "Harness generation skipped unsupported parameters; add a wrapper or type decoder."
                .to_owned()
        }
        "link_blocked" => {
            "Link blocked previously; provide the missing library or add an external-tool build profile."
                .to_owned()
        }
        "runtime_blocked" => {
            "Runtime safety rail tripped; inspect runtrace events and replay bundle."
                .to_owned()
        }
        "not_run" => format!(
            "Discovered after or outside the prior run; add or run a harness for {}.",
            candidate.name
        ),
        "no_prior_run" => {
            "No prior auto run found; run govfuzz auto to collect build and fuzz outcomes."
                .to_owned()
        }
        _ => "Prior outcome is unknown; inspect auto/run.json for this harness.".to_owned(),
    }
}

/// Map an Ada body path to its sibling spec path string (`foo.adb` ->
/// `foo.ads`). Used so a call graph node that points at a body definition can
/// resolve to the harnessable candidate, which is discovered from the spec.
fn ada_spec_sibling_path(path: &str) -> Option<String> {
    path.strip_suffix(".adb").map(|stem| format!("{stem}.ads"))
}

fn static_reachability(
    candidates: &[Candidate],
    prior: &PriorRun,
    call_graph: &static_analysis::CallGraphReport,
) -> (
    HashMap<String, StaticReachabilityInsight>,
    Vec<CoverageBlockerInsight>,
) {
    let mut candidate_by_path_name: HashMap<(String, String), usize> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        candidate_by_path_name.insert(
            (
                normalized_path_string(&candidate.source_path),
                candidate.name.clone(),
            ),
            index,
        );
    }

    let mut candidate_by_node_id: HashMap<String, usize> = HashMap::new();
    for node in &call_graph.nodes {
        // The call graph resolves an Ada call to the callee's *body*
        // (`helpers.adb`), but the harnessable candidate lives in the package
        // *spec* (`helpers.ads`) - only spec/library-level subprograms are
        // discovered as targets. Fall back to the sibling spec so body-defined
        // callees still resolve to their spec candidate.
        let index = candidate_by_path_name
            .get(&(node.path.clone(), node.name.clone()))
            .or_else(|| {
                ada_spec_sibling_path(&node.path)
                    .and_then(|spec| candidate_by_path_name.get(&(spec, node.name.clone())))
            });
        if let Some(index) = index {
            candidate_by_node_id.insert(node.id.clone(), *index);
        }
    }

    let mut reachability: HashMap<String, StaticReachabilityInsight> = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.harness_id.clone(),
                StaticReachabilityInsight::default(),
            )
        })
        .collect();
    let mut coverage_blockers = Vec::new();
    let mut adjacency: HashMap<usize, Vec<usize>> = HashMap::new();

    for edge in &call_graph.edges {
        let Some(&caller_index) = candidate_by_node_id.get(&edge.caller_id) else {
            continue;
        };
        let Some(&callee_index) = candidate_by_node_id.get(&edge.callee_id) else {
            continue;
        };
        let entry = adjacency.entry(caller_index).or_default();
        if !entry.contains(&callee_index) {
            entry.push(callee_index);
        }
        let caller = &candidates[caller_index];
        let callee = &candidates[callee_index];
        let callee_summary = reachable_target_summary(callee, prior);
        let caller_summary = reachable_target_summary(caller, prior);
        if let Some(insight) = reachability.get_mut(&caller.harness_id) {
            push_unique_target(&mut insight.direct_callees, callee_summary.clone());
            if caller_summary.prior_outcome == "built_and_fuzzed"
                && callee_summary.prior_outcome != "built_and_fuzzed"
            {
                push_unique_target(
                    &mut insight.uncovered_direct_callees,
                    callee_summary.clone(),
                );
                if !coverage_blockers
                    .iter()
                    .any(|blocker: &CoverageBlockerInsight| {
                        blocker.source_target.harness_id == caller_summary.harness_id
                            && blocker.blocked_target.as_ref().is_some_and(|blocked| {
                                blocked.harness_id == callee_summary.harness_id
                            })
                    })
                {
                    coverage_blockers.push(CoverageBlockerInsight {
                        kind: "static_reachability_gap",
                        source_target: caller_summary.clone(),
                        blocked_target: Some(callee_summary.clone()),
                        recommendation: format!(
                            "Add or run a harness for {}; it is a direct static callee of fuzzed target {}.",
                            callee.name, caller.name
                        ),
                        evidence: reachability_blocker_evidence(
                            1,
                            &[caller_index, callee_index],
                            candidates,
                        ),
                    });
                }
            }
        }
    }

    for (source_index, source) in candidates.iter().enumerate() {
        let source_summary = reachable_target_summary(source, prior);
        for reachable_path in reachable_candidate_descendants(source_index, &adjacency) {
            let reachable_index = reachable_path.candidate_index;
            let depth = reachable_path.depth;
            let reachable = &candidates[reachable_index];
            let reachable_summary = reachable_target_summary(reachable, prior);
            if let Some(insight) = reachability.get_mut(&source.harness_id) {
                push_unique_target(&mut insight.reachable_callees, reachable_summary.clone());
                if source_summary.prior_outcome == "built_and_fuzzed"
                    && reachable_summary.prior_outcome != "built_and_fuzzed"
                {
                    push_unique_target(
                        &mut insight.uncovered_reachable_callees,
                        reachable_summary.clone(),
                    );
                }
            }
            if source_summary.prior_outcome != "built_and_fuzzed"
                || reachable_summary.prior_outcome == "built_and_fuzzed"
            {
                continue;
            }
            if coverage_blockers
                .iter()
                .any(|blocker: &CoverageBlockerInsight| {
                    blocker.source_target.harness_id == source_summary.harness_id
                        && blocker.blocked_target.as_ref().is_some_and(|blocked| {
                            blocked.harness_id == reachable_summary.harness_id
                        })
                })
            {
                continue;
            }
            coverage_blockers.push(CoverageBlockerInsight {
                kind: "static_reachability_gap",
                source_target: source_summary.clone(),
                blocked_target: Some(reachable_summary),
                recommendation: if depth == 1 {
                    format!(
                        "Add or run a harness for {}; it is a direct static callee of fuzzed target {}.",
                        reachable.name, source.name
                    )
                } else {
                    format!(
                        "Add or run a harness for {}; it is statically reachable from fuzzed target {} through {} call edge(s).",
                        reachable.name, source.name, depth
                    )
                },
                evidence: reachability_blocker_evidence(depth, &reachable_path.path, candidates),
            });
        }
    }

    emit_unreached_public_target_blockers(candidates, prior, &mut coverage_blockers);

    for unresolved in &call_graph.unresolved_calls {
        let Some(&caller_index) = candidate_by_node_id.get(&unresolved.caller_id) else {
            continue;
        };
        let caller = &candidates[caller_index];
        let caller_summary = reachable_target_summary(caller, prior);
        if let Some(insight) = reachability.get_mut(&caller.harness_id) {
            let unresolved_call = UnresolvedCallInsight {
                call: unresolved.call.clone(),
                source: unresolved.path.clone(),
                line: unresolved.line,
            };
            if !insight.unresolved_calls.iter().any(|existing| {
                existing.call == unresolved_call.call
                    && existing.source == unresolved_call.source
                    && existing.line == unresolved_call.line
            }) {
                insight.unresolved_calls.push(unresolved_call);
            }
        }
        if caller_summary.prior_outcome == "built_and_fuzzed"
            && !coverage_blockers
                .iter()
                .any(|blocker: &CoverageBlockerInsight| {
                    blocker.kind == "unresolved_static_call"
                        && blocker.source_target.harness_id == caller_summary.harness_id
                        && blocker.evidence.iter().any(|evidence| {
                            evidence.key == "call" && evidence.value == unresolved.call
                        })
                        && blocker.evidence.iter().any(|evidence| {
                            evidence.key == "line" && evidence.value == unresolved.line.to_string()
                        })
                })
        {
            coverage_blockers.push(CoverageBlockerInsight {
                kind: "unresolved_static_call",
                source_target: caller_summary,
                blocked_target: None,
                recommendation: format!(
                    "Resolve static call {} from {}; include the defining source/header or add a wrapper so reachable code is visible to introspection.",
                    unresolved.call, caller.name
                ),
                evidence: vec![
                    BlockerEvidenceInsight {
                        key: "call".to_owned(),
                        value: unresolved.call.clone(),
                    },
                    BlockerEvidenceInsight {
                        key: "source".to_owned(),
                        value: unresolved.path.clone(),
                    },
                    BlockerEvidenceInsight {
                        key: "line".to_owned(),
                        value: unresolved.line.to_string(),
                    },
                ],
            });
        }
    }

    for insight in reachability.values_mut() {
        insight
            .direct_callees
            .sort_by(|left, right| left.name.cmp(&right.name));
        insight
            .uncovered_direct_callees
            .sort_by(|left, right| left.name.cmp(&right.name));
        insight
            .reachable_callees
            .sort_by(|left, right| left.name.cmp(&right.name));
        insight
            .uncovered_reachable_callees
            .sort_by(|left, right| left.name.cmp(&right.name));
        insight
            .unresolved_calls
            .sort_by(|left, right| left.line.cmp(&right.line).then(left.call.cmp(&right.call)));
    }
    sort_coverage_blockers(&mut coverage_blockers);

    (reachability, coverage_blockers)
}

fn emit_unreached_public_target_blockers(
    candidates: &[Candidate],
    prior: &PriorRun,
    coverage_blockers: &mut Vec<CoverageBlockerInsight>,
) {
    if !prior.summary.present {
        return;
    }
    for candidate in candidates {
        let summary = reachable_target_summary(candidate, prior);
        if summary.prior_outcome != "not_seen_in_prior_run" {
            continue;
        }
        let already_explained_by_fuzzed_source = coverage_blockers.iter().any(|blocker| {
            blocker.kind == "static_reachability_gap"
                && blocker
                    .blocked_target
                    .as_ref()
                    .is_some_and(|blocked| blocked.harness_id == summary.harness_id)
        });
        if already_explained_by_fuzzed_source {
            continue;
        }
        coverage_blockers.push(CoverageBlockerInsight {
            kind: "unreached_public_target",
            source_target: summary.clone(),
            blocked_target: None,
            recommendation: format!(
                "Discovered public target {} was not reached by any fuzzed static call chain in the prior auto run; add or run a harness for it.",
                candidate.name
            ),
            evidence: vec![BlockerEvidenceInsight {
                key: "prior_outcome".to_owned(),
                value: summary.prior_outcome,
            }],
        });
    }
}

#[derive(Debug, Clone)]
struct ReachableCandidatePath {
    candidate_index: usize,
    depth: usize,
    path: Vec<usize>,
}

fn reachable_candidate_descendants(
    source_index: usize,
    adjacency: &HashMap<usize, Vec<usize>>,
) -> Vec<ReachableCandidatePath> {
    let mut seen: HashMap<usize, ReachableCandidatePath> = HashMap::new();
    let mut queue = VecDeque::new();
    queue.push_back((source_index, vec![source_index]));
    while let Some((current, path)) = queue.pop_front() {
        let Some(next) = adjacency.get(&current) else {
            continue;
        };
        for &candidate_index in next {
            if candidate_index == source_index || seen.contains_key(&candidate_index) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(candidate_index);
            let reachable = ReachableCandidatePath {
                candidate_index,
                depth: next_path.len().saturating_sub(1),
                path: next_path.clone(),
            };
            seen.insert(candidate_index, reachable);
            queue.push_back((candidate_index, next_path));
        }
    }
    let mut out = seen.into_values().collect::<Vec<_>>();
    out.sort_by_key(|reachable| (reachable.depth, reachable.candidate_index));
    out
}

fn reachability_blocker_evidence(
    depth: usize,
    path: &[usize],
    candidates: &[Candidate],
) -> Vec<BlockerEvidenceInsight> {
    let mut evidence = vec![BlockerEvidenceInsight {
        key: "depth".to_owned(),
        value: depth.to_string(),
    }];
    let call_chain = path
        .iter()
        .filter_map(|index| candidates.get(*index))
        .map(|candidate| candidate.name.as_str())
        .collect::<Vec<_>>();
    if call_chain.len() >= 2 {
        evidence.push(BlockerEvidenceInsight {
            key: "call_chain".to_owned(),
            value: call_chain.join(" -> "),
        });
    }
    evidence
}

fn dynamic_coverage(
    candidates: &[Candidate],
    prior: &PriorRun,
    work_dir: &Path,
) -> Result<(
    HashMap<String, DynamicCoverageInsight>,
    Vec<CoverageBlockerInsight>,
)> {
    let mut insights = HashMap::new();
    let mut blockers = Vec::new();
    let fuzz_runs = work_dir.join("fuzz_runs");
    for candidate in candidates {
        let summary_path = fuzz_runs.join(format!("{}-latest.json", candidate.harness_id));
        if !summary_path.is_file() {
            continue;
        }
        let raw = std::fs::read(&summary_path)
            .with_context(|| format!("read {}", summary_path.display()))?;
        let value: serde_json::Value = serde_json::from_slice(&raw)
            .with_context(|| format!("parse {}", summary_path.display()))?;
        let Some(cmplog_value) = value.get("cmplog") else {
            continue;
        };
        let cmplog = cmplog_coverage_insight(cmplog_value, work_dir);
        if cmplog.enabled && cmplog.entries > 0 && cmplog.seed_splice_candidates == 0 {
            let source_target = reachable_target_summary(candidate, prior);
            let mut evidence = Vec::new();
            if let Some(token) = cmplog.suggested_dictionary_tokens.first() {
                evidence.push(BlockerEvidenceInsight {
                    key: "token_hex".to_owned(),
                    value: token.hex.clone(),
                });
            }
            evidence.push(BlockerEvidenceInsight {
                key: "entries".to_owned(),
                value: cmplog.entries.to_string(),
            });
            blockers.push(CoverageBlockerInsight {
                kind: "comparison_gate",
                source_target,
                blocked_target: None,
                recommendation: comparison_gate_recommendation(candidate, &cmplog),
                evidence,
            });
        }
        insights.insert(
            candidate.harness_id.clone(),
            DynamicCoverageInsight {
                cmplog: Some(cmplog),
            },
        );
    }
    sort_coverage_blockers(&mut blockers);
    Ok((insights, blockers))
}

fn cmplog_coverage_insight(value: &serde_json::Value, work_dir: &Path) -> CmpLogCoverageInsight {
    let enabled = value
        .get("enabled")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let status = value
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown")
        .to_owned();
    let log_path = value
        .get("log_path")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    let entries = value
        .get("entries")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as usize;
    let dictionary_tokens = value
        .get("dictionary_tokens")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as usize;
    let seed_splice_candidates = value
        .get("seed_splice_candidates")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as usize;
    let suggested_dictionary_tokens = log_path
        .as_deref()
        .and_then(|path| load_cmplog_token_suggestions(path, work_dir).ok())
        .unwrap_or_default();

    CmpLogCoverageInsight {
        enabled,
        status,
        log_path,
        entries,
        dictionary_tokens,
        seed_splice_candidates,
        suggested_dictionary_tokens,
    }
}

fn load_cmplog_token_suggestions(
    log_path: &str,
    work_dir: &Path,
) -> Result<Vec<SuggestedTokenInsight>> {
    let path = resolve_run_summary_path(log_path, work_dir);
    let log = cmplog::ingest_from_jsonl_log(&path)
        .with_context(|| format!("ingest cmplog log {}", path.display()))?;
    Ok(log
        .dictionary_tokens()
        .into_iter()
        .take(8)
        .map(|token| SuggestedTokenInsight {
            hex: hex_encode(&token),
            preview: token_preview(&token),
        })
        .collect())
}

fn resolve_run_summary_path(path: &str, work_dir: &Path) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        work_dir.join(path)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn token_preview(bytes: &[u8]) -> String {
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        format!("0x{}", hex_encode(bytes))
    }
}

fn comparison_gate_recommendation(candidate: &Candidate, cmplog: &CmpLogCoverageInsight) -> String {
    let token_hint = cmplog
        .suggested_dictionary_tokens
        .first()
        .map(|token| format!(" such as 0x{}", token.hex))
        .unwrap_or_default();
    format!(
        "CmpLog observed {} comparison operand(s) for {} but no seed splice candidates; add dictionary tokens{} or seed inputs containing observed operands.",
        cmplog.entries, candidate.name, token_hint
    )
}

fn sort_coverage_blockers(blockers: &mut [CoverageBlockerInsight]) {
    blockers.sort_by(|left, right| {
        coverage_blocker_priority(right)
            .cmp(&coverage_blocker_priority(left))
            .then_with(|| left.kind.cmp(right.kind))
            .then_with(|| left.source_target.name.cmp(&right.source_target.name))
            .then_with(|| blocker_target_name(left).cmp(blocker_target_name(right)))
    });
}

fn coverage_blocker_priority(blocker: &CoverageBlockerInsight) -> i32 {
    match blocker.kind {
        "static_reachability_gap" => {
            10_000 - (blocker_evidence_usize(blocker, "depth", 100) as i32 * 100)
        }
        "unresolved_static_call" => 8_500,
        "comparison_gate" => 8_000,
        "unreached_public_target" => 6_000,
        _ => 0,
    }
}

fn blocker_evidence_usize(
    blocker: &CoverageBlockerInsight,
    key: &str,
    default_value: usize,
) -> usize {
    blocker
        .evidence
        .iter()
        .find(|evidence| evidence.key == key)
        .and_then(|evidence| evidence.value.parse().ok())
        .unwrap_or(default_value)
}

fn blocker_target_name(blocker: &CoverageBlockerInsight) -> &str {
    blocker
        .blocked_target
        .as_ref()
        .map(|target| target.name.as_str())
        .unwrap_or("")
}

fn reachable_target_summary(candidate: &Candidate, prior: &PriorRun) -> ReachableTargetInsight {
    let prior_outcome = prior
        .target_outcomes
        .get(&candidate.harness_id)
        .cloned()
        .unwrap_or_else(|| {
            if prior.summary.present {
                "not_seen_in_prior_run".to_owned()
            } else {
                "no_prior_run".to_owned()
            }
        });
    ReachableTargetInsight {
        harness_id: candidate.harness_id.clone(),
        name: candidate.name.clone(),
        language: language_name(&candidate.lang),
        source: candidate.source_path.display().to_string(),
        line: candidate.line,
        blocker_kind: blocker_kind(&prior_outcome),
        prior_outcome,
    }
}

fn push_unique_target(targets: &mut Vec<ReachableTargetInsight>, target: ReachableTargetInsight) {
    if !targets
        .iter()
        .any(|existing| existing.harness_id == target.harness_id)
    {
        targets.push(target);
    }
}

fn normalized_path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn recommendations(
    prior: &PriorRun,
    targets: &[TargetInsight],
    coverage_blockers: &[CoverageBlockerInsight],
    source_root: &Path,
    work_dir: &Path,
) -> Vec<String> {
    let mut out = Vec::new();
    if !prior.summary.present {
        out.push(format!(
            "Run `govfuzz auto {} --work-dir {}` to collect build and fuzz outcomes.",
            source_root.display(),
            work_dir.display()
        ));
        return out;
    }

    let not_run = targets
        .iter()
        .filter(|target| target.blocker_kind == "not_run")
        .count();
    if not_run > 0 {
        out.push(format!(
            "Add or run harnesses for {not_run} discovered target(s) missing from the prior auto run."
        ));
    }
    let build_blocked = targets
        .iter()
        .filter(|target| matches!(target.blocker_kind, "build_blocked" | "link_blocked"))
        .count();
    if build_blocked > 0 {
        out.push(format!(
            "Inspect needed_for_build for {build_blocked} build/link-blocked target(s)."
        ));
    }
    let static_gaps = coverage_blockers
        .iter()
        .filter(|blocker| blocker.kind == "static_reachability_gap")
        .count();
    if static_gaps > 0 {
        out.push(format!(
            "Static call graph found {} reachable callee coverage gap(s) from fuzzed targets.",
            static_gaps
        ));
    }
    let unreached_public_targets = coverage_blockers
        .iter()
        .filter(|blocker| blocker.kind == "unreached_public_target")
        .count();
    if unreached_public_targets > 0 {
        out.push(format!(
            "Per-tree introspection found {unreached_public_targets} discovered public target(s) not reached by any fuzzed static call chain."
        ));
    }
    let comparison_gates = coverage_blockers
        .iter()
        .filter(|blocker| blocker.kind == "comparison_gate")
        .count();
    if comparison_gates > 0 {
        out.push(format!(
            "CmpLog found {comparison_gates} comparison-gated target(s); add the suggested operands to seeds or dictionaries."
        ));
    }
    let unresolved_static_calls = coverage_blockers
        .iter()
        .filter(|blocker| blocker.kind == "unresolved_static_call")
        .count();
    if unresolved_static_calls > 0 {
        out.push(format!(
            "Static call graph found {unresolved_static_calls} unresolved call(s) from fuzzed targets; add source roots, headers, or wrappers so reachable code is visible."
        ));
    }
    if out.is_empty() {
        out.push("The shown targets were already fuzzed or have no obvious blocker.".to_owned());
    }
    out
}

fn render_markdown(report: &IntrospectionReport) -> String {
    let mut out = String::new();
    out.push_str("# GovFuzz Introspection\n\n");
    out.push_str(&format!("- Source root: `{}`\n", report.source_root));
    out.push_str(&format!("- Work dir: `{}`\n", report.work_dir));
    out.push_str(&format!(
        "- Discovered targets: **{}** ({})\n",
        report.discovered.total,
        format_languages(&report.discovered.languages)
    ));
    if report.prior_run.present {
        out.push_str(&format!("- Prior auto run: `{}`\n", report.prior_run.path));
    } else {
        out.push_str("- Prior auto run: not found\n");
    }
    out.push('\n');

    out.push_str("## Recommendations\n\n");
    for recommendation in &report.recommendations {
        out.push_str(&format!("- {recommendation}\n"));
    }
    out.push('\n');

    if !report.coverage_blockers.is_empty() {
        out.push_str("## Coverage Blockers\n\n");
        out.push_str("| Kind | Fuzzed target | Blocked target | Recommendation |\n");
        out.push_str("|---|---|---|---|\n");
        for blocker in &report.coverage_blockers {
            let blocked_target = blocker
                .blocked_target
                .as_ref()
                .map(|target| format!("`{}`", target.name))
                .unwrap_or_else(|| "-".to_owned());
            out.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                blocker.kind, blocker.source_target.name, blocked_target, blocker.recommendation
            ));
        }
        out.push('\n');
    }

    out.push_str("## Highest Priority Targets\n\n");
    out.push_str("| Score | Lang | Status | Target | Location | Recommendation |\n");
    out.push_str("|---:|---|---|---|---|---|\n");
    for target in &report.targets {
        out.push_str(&format!(
            "| {} | {} | {} | `{}` | `{}` | {} |\n",
            target.score,
            target.language,
            target.blocker_kind,
            target.name,
            format_location(target),
            target.recommendation
        ));
    }
    out
}

fn format_languages(languages: &BTreeMap<String, usize>) -> String {
    if languages.is_empty() {
        return "none".to_owned();
    }
    languages
        .iter()
        .map(|(language, count)| format!("{language} {count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_location(target: &TargetInsight) -> String {
    if target.line == 0 {
        target.source.clone()
    } else {
        format!("{}:{}", target.source, target.line)
    }
}
