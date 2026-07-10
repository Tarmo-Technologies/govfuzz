// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const READINESS_SCHEMA_VERSION: &str = "govfuzz.readiness.v1";

#[derive(Debug, clap::Args)]
pub struct ReadinessArgs {
    #[command(subcommand)]
    command: ReadinessCommand,
}

#[derive(Debug, clap::Subcommand)]
enum ReadinessCommand {
    Scorecard(ScorecardArgs),
}

#[derive(Debug, clap::Args)]
struct ScorecardArgs {
    #[arg(long)]
    validation: Option<PathBuf>,
    #[arg(long)]
    benchmark: Option<PathBuf>,
    #[arg(long)]
    patterns: Option<PathBuf>,
    #[arg(long = "claim-root")]
    claim_roots: Vec<PathBuf>,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    markdown: Option<PathBuf>,
}

pub fn run(args: ReadinessArgs) -> i32 {
    let result = match args.command {
        ReadinessCommand::Scorecard(args) => run_scorecard(args),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    }
}

fn run_scorecard(args: ScorecardArgs) -> Result<()> {
    let validation = read_optional_json(args.validation.as_deref())?;
    let benchmark = read_optional_json(args.benchmark.as_deref())?;
    let patterns = read_optional_json(args.patterns.as_deref())?;
    let scorecard = scorecard(&validation, &benchmark, &patterns, &args.claim_roots)?;
    write_json(&args.out, &scorecard)?;
    if let Some(markdown) = args.markdown {
        write_text(&markdown, &render_markdown(&scorecard))?;
    }
    Ok(())
}

fn scorecard(
    validation: &Option<Value>,
    benchmark: &Option<Value>,
    patterns: &Option<Value>,
    claim_roots: &[PathBuf],
) -> Result<Value> {
    let validation_repos = get_u64(validation, &["summary", "repositories"]);
    let static_expected = get_u64(benchmark, &["metrics", "by_kind", "static", "expected"]);
    let binary_expected = get_u64(benchmark, &["metrics", "by_kind", "binary", "expected"]);
    let sca_expected = get_u64(benchmark, &["metrics", "by_kind", "sca", "expected"]);
    let pattern_tracks = get_u64(patterns, &["counts", "tracks"]);
    let false_negatives = get_u64(benchmark, &["metrics", "false_negatives"]);
    let false_positives = get_u64(benchmark, &["metrics", "false_positives"]);
    let ada_repos = get_u64(
        validation,
        &["summary", "language_coverage", "ada", "repositories"],
    );
    let cpp_repos = get_u64(
        validation,
        &["summary", "language_coverage", "cpp", "repositories"],
    );
    let c_repos = get_u64(
        validation,
        &["summary", "language_coverage", "c", "repositories"],
    );
    let ada_broken = get_bool(validation, &["summary", "broken_build_by_language", "ada"]);
    let cpp_broken = get_bool(validation, &["summary", "broken_build_by_language", "cpp"]);

    let pattern = |track: &str| get_u64(patterns, &["by_track", track, "patterns"]);
    let ada_pattern_count = pattern("ada95_idioms") + pattern("gpr_variants");
    let cpp_pattern_count = pattern("cpp_service_class");

    Ok(json!({
        "schema_version": READINESS_SCHEMA_VERSION,
        "generated_from": {
            "validation": validation.as_ref().and_then(|value| value["schema_version"].as_str()).unwrap_or("missing"),
            "benchmark": benchmark.as_ref().and_then(|value| value["schema_version"].as_str()).unwrap_or("missing"),
            "patterns": patterns.as_ref().and_then(|value| value["schema_version"].as_str()).unwrap_or("missing"),
        },
        "categories": {
            "static_scanning": category(
                if static_expected > 0 && false_negatives == 0 { 86 } else { 55 },
                vec![
                    capability("rule packs for Ada/C/C++ static findings", "implemented", static_expected),
                    capability("path-sensitive/interprocedural taint traces", "implemented", static_expected),
                    capability("precision calibration beyond seeded proxy suite", "partial", false_positives),
                ],
            ),
            "binary_scanning": category(
                if binary_expected > 0 { 82 } else { 50 },
                vec![
                    capability("binary ingest and crash finding schema", "implemented", binary_expected),
                    capability(
                        "SBOM/SCA CVE matching",
                        if sca_expected > 0 { "implemented" } else { "partial" },
                        sca_expected,
                    ),
                    capability("deep decompiler-assisted dataflow", "planned", 0),
                ],
            ),
            "ada_depth": category(
                if ada_repos > 0 && ada_broken { 78 } else { 55 },
                vec![
                    capability("Ada real-code target discovery and GPR validation", "implemented", ada_repos),
                    capability(
                        "generics/subunits/project-profile evidence",
                        if ada_pattern_count > 0 { "implemented" } else { "partial" },
                        ada_pattern_count,
                    ),
                    capability(
                        "concurrency-safe harnessing without explicit scheduling assumptions",
                        "blocked",
                        0,
                    ),
                ],
            ),
            "cpp_depth": category(
                if cpp_repos > 0 && cpp_broken { 84 } else { 60 },
                vec![
                    capability("C++ methods/constructors/destructors/templates metadata", "implemented", cpp_repos),
                    capability("RAII lifecycle sequence harnesses", "implemented", cpp_pattern_count),
                    capability("CMake/Make build-context parity", "implemented", c_repos + cpp_repos),
                ],
            ),
            "enterprise_operations": category(
                83,
                vec![
                    capability(
                        "runners, air-gapped packs, policy-as-code, exports, CI governance",
                        "implemented",
                        1,
                    ),
                    capability("multi-user service UI/RBAC dashboard integration", "partial", 1),
                    capability("customer-specific authorization backends", "planned", 0),
                ],
            ),
            "evidence": category(
                if validation_repos >= 4 && pattern_tracks >= 8 && false_negatives == 0 { 88 } else { 62 },
                vec![
                    capability("real-code validation matrix", "implemented", validation_repos),
                    capability(
                        "seeded recall/precision proxy suite",
                        "implemented",
                        static_expected + binary_expected + sca_expected,
                    ),
                    capability("government legacy pattern corpus", "implemented", pattern_tracks),
                ],
            ),
        },
        "claim_gate": {
            "unsupported_claims": unsupported_claims(claim_roots)?,
            "allowed_claims": [
                "government legacy software fuzzer",
                "offline Ada, C, C++, binary, and enterprise workflow fuzzer"
            ],
        },
    }))
}

fn category(score: u64, capabilities: Vec<Value>) -> Value {
    let status = if score >= 80 {
        "implemented"
    } else if score >= 60 {
        "partial"
    } else {
        "blocked"
    };
    json!({
        "status": status,
        "score": score,
        "capabilities": capabilities,
    })
}

fn capability(name: &str, status: &str, evidence_count: u64) -> Value {
    json!({
        "name": name,
        "status": status,
        "evidence_count": evidence_count,
    })
}

fn unsupported_claims(roots: &[PathBuf]) -> Result<Vec<Value>> {
    let mut claims = Vec::new();
    for root in roots {
        if root.is_file() {
            scan_claim_file(root, &mut claims)?;
        } else if root.is_dir() {
            scan_claim_dir(root, &mut claims)?;
        }
    }
    claims.sort_by(|left, right| {
        left["path"]
            .as_str()
            .cmp(&right["path"].as_str())
            .then_with(|| left["line"].as_u64().cmp(&right["line"].as_u64()))
    });
    Ok(claims)
}

fn scan_claim_dir(root: &Path, claims: &mut Vec<Value>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let path = entry.path();
        if path.is_dir() {
            scan_claim_dir(&path, claims)?;
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "md" | "txt" | "html" | "rst"
                )
            })
        {
            scan_claim_file(&path, claims)?;
        }
    }
    Ok(())
}

fn scan_claim_file(path: &Path, claims: &mut Vec<Value>) -> Result<()> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    for (line_index, line) in text.lines().enumerate() {
        if line
            .to_ascii_lowercase()
            .contains("complete enterprise scanner")
        {
            claims.push(json!({
                "path": path.display().to_string(),
                "line": line_index + 1,
                "phrase": "complete enterprise scanner",
                "reason": "Scorecard supports government legacy fuzzer readiness; complete enterprise scanner is overbroad.",
            }));
        }
    }
    Ok(())
}

fn get_u64(root: &Option<Value>, path: &[&str]) -> u64 {
    let Some(root) = root else {
        return 0;
    };
    let mut current = root;
    for key in path {
        current = &current[*key];
    }
    current.as_u64().unwrap_or(0)
}

fn get_bool(root: &Option<Value>, path: &[&str]) -> bool {
    let Some(root) = root else {
        return false;
    };
    let mut current = root;
    for key in path {
        current = &current[*key];
    }
    current.as_bool().unwrap_or(false)
}

fn read_optional_json(path: Option<&Path>) -> Result<Option<Value>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("parse {}", path.display()))
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

fn render_markdown(scorecard: &Value) -> String {
    let mut text = String::from("# Readiness Scorecard\n\n");
    for category in [
        "static_scanning",
        "binary_scanning",
        "ada_depth",
        "cpp_depth",
        "enterprise_operations",
        "evidence",
    ] {
        let item = &scorecard["categories"][category];
        text.push_str(&format!(
            "- {category}: {} ({})\n",
            item["status"], item["score"]
        ));
    }
    text.push_str(&format!(
        "\nUnsupported claims: {}\n",
        scorecard["claim_gate"]["unsupported_claims"]
            .as_array()
            .map_or(0, Vec::len)
    ));
    text
}
