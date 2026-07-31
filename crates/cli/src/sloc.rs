// SPDX-License-Identifier: Apache-2.0

//! Standalone `govfuzz sloc` — a dedicated fast path for per-language SLOC
//! counting. Unlike `static-scan --sloc`, this runs ONLY the SLOC tree walk
//! (`static_analysis::sloc_report`) and never invokes the rule engine, so a
//! whole-corpus count is near-instant. Accepts multiple roots in one call and
//! emits a per-root table plus a grand total.

use std::path::PathBuf;

use static_analysis::SlocReport;

#[derive(Debug, clap::Args)]
pub struct SlocArgs {
    /// One or more source roots to count. Each is reported as its own section;
    /// a grand total across all roots is appended when more than one is given.
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Write the report here instead of stdout. A `.json` extension (or the
    /// `--json` flag) emits JSON; otherwise an aligned text table.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Emit JSON instead of the text table (inferred from a `.json` `--out`).
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: SlocArgs) -> i32 {
    // Count each root independently — NO rule scanning, that's the whole point.
    let mut reports: Vec<SlocReport> = Vec::with_capacity(args.paths.len());
    for path in &args.paths {
        match static_analysis::sloc_report(path) {
            Ok(report) => reports.push(report),
            Err(error) => {
                gfeprintln!("sloc: {}: {error:#}", path.display());
                return 1;
            }
        }
    }

    let want_json = args.json
        || args.out.as_ref().is_some_and(|out| {
            out.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        });

    let body = if want_json {
        match serde_json::to_string_pretty(&render_json(&reports)) {
            Ok(json) => format!("{json}\n"),
            Err(error) => {
                gfeprintln!("sloc: {error}");
                return 1;
            }
        }
    } else {
        render_text(&reports)
    };

    match &args.out {
        Some(out) => {
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            if let Err(error) = std::fs::write(out, &body) {
                gfeprintln!("sloc: cannot write {}: {error}", out.display());
                return 1;
            }
            println!("sloc: {} root(s) → {}", reports.len(), out.display());
        }
        None => print!("{body}"),
    }
    0
}

/// A combined `SlocLanguage`-shaped grand total across every root's languages,
/// so callers can read `total.code_lines` for the whole corpus.
fn grand_total(reports: &[SlocReport]) -> static_analysis::SlocLanguage {
    let mut total = static_analysis::SlocLanguage {
        language: "TOTAL".to_string(),
        files: 0,
        total_lines: 0,
        comment_lines: 0,
        blank_lines: 0,
        code_lines: 0,
    };
    for report in reports {
        total.files += report.total.files;
        total.total_lines += report.total.total_lines;
        total.comment_lines += report.total.comment_lines;
        total.blank_lines += report.total.blank_lines;
        total.code_lines += report.total.code_lines;
    }
    total
}

/// JSON payload: per-root `SlocReport`s plus a corpus-wide grand total whose
/// `total.code_lines` is the sum across all roots.
fn render_json(reports: &[SlocReport]) -> serde_json::Value {
    serde_json::json!({
        "schema": "govfuzz.sloc.v1",
        "roots": reports,
        "total": grand_total(reports),
    })
}

/// A per-root text section (each root's own table) plus a grand-total table when
/// more than one root was given.
fn render_text(reports: &[SlocReport]) -> String {
    let mut out = String::new();
    for report in reports {
        out.push_str(&report.root);
        out.push('\n');
        out.push_str(&static_analysis::render_sloc_table(report));
        out.push('\n');
    }
    if reports.len() > 1 {
        let total = grand_total(reports);
        // One row per root (labeled by its path) + the grand-total footer, so a
        // whole-corpus invocation shows the per-repo split and the sum at a glance.
        let rows = reports
            .iter()
            .map(|r| static_analysis::SlocLanguage {
                language: r.root.clone(),
                ..r.total.clone()
            })
            .collect();
        let combined = SlocReport {
            schema_version: reports[0].schema_version,
            root: "GRAND TOTAL".to_string(),
            languages: rows,
            total,
        };
        out.push_str("GRAND TOTAL (all roots)\n");
        out.push_str(&static_analysis::render_sloc_table(&combined));
    }
    out
}
