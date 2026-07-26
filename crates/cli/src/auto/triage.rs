// SPDX-License-Identifier: Apache-2.0

//! End-of-run UX: a NEXT-STEPS triage block (aggregate failure causes → the exact
//! lever to try) and a TOP-FINDINGS digest (the most severe findings with a one-line
//! reproduce command each), so the operator learns what to do and what matters without
//! opening run.json / the SARIF.

use crate::auto::preflight::PreflightReport;
use std::path::Path;

pub struct TriageInputs<'a> {
    pub built_and_fuzzed: usize,
    pub failed_build: usize,
    pub skipped: usize,
    /// Of `skipped`, those an interpreted lane could not load because a package
    /// is not installed. `--force` cannot install a package, so these get the
    /// install action instead of the force one.
    pub skipped_missing_package: usize,
    pub report_only: usize,
    pub findings: usize,
    pub preflight: &'a PreflightReport,
    /// A detected custom build in the tree root, if any (marker, suggested command).
    pub custom_build: Option<(String, String)>,
}

/// Render the next-steps triage, or empty when the run was healthy (targets fuzzed,
/// no build trouble, toolchains present).
pub fn render_triage(inputs: &TriageInputs) -> String {
    let trouble = inputs.failed_build > 0
        || inputs.skipped > 0
        || inputs.preflight.any_missing()
        || (inputs.built_and_fuzzed == 0 && inputs.findings == 0);
    if !trouble {
        return String::new();
    }

    let mut actions: Vec<String> = Vec::new();

    // 1. Missing toolchains block a whole lane — highest priority.
    let missing: Vec<String> = inputs
        .preflight
        .missing_lanes()
        .map(|l| format!("{} — {}", l.lang, l.install_hint))
        .collect();
    if !missing.is_empty() {
        actions.push(format!(
            "Install missing toolchains (those lanes can't build):\n      {}",
            missing.join("\n      ")
        ));
    }

    // 2. Failed builds -> the recovery levers, in likely-usefulness order.
    if inputs.failed_build > 0 {
        let mut s = format!(
            "{} target(s) failed to build (per-target reason in run.json → targets[].outcome.reason). Try:",
            inputs.failed_build
        );
        match &inputs.custom_build {
            Some((marker, cmd)) => s.push_str(&format!(
                "\n      - this tree has its own build ({marker}); recover its exact flags: --build-command {cmd:?}  (or --unsafe-search-and-run-build-commands)"
            )),
            None => s.push_str(
                "\n      - if the tree has its own build, recover its flags: --build-command \"<your build>\"",
            ),
        }
        s.push_str("\n      - old C++: the dialect ladder runs automatically; pin it with --cxx-std <std> if it still fails");
        s.push_str(
            "\n      - missing dependency headers: --extra-include <dir> / --extra-source <file>",
        );
        s.push_str(
            "\n      - force past undefined symbols/types (stub-heavy, Low-confidence): --force",
        );
        actions.push(s);
    }

    // 3a. Skipped because a package isn't installed. Named separately because the
    // remedy is the package manager, not --force: advertising --force here sent
    // operators after the one lever that provably cannot help, on what was the
    // single largest skip cause across a 534-project corpus.
    if inputs.skipped_missing_package > 0 {
        actions.push(format!(
            "{} target(s) could not be loaded because a package they import is not installed — \
             each one is named in auto/missing-deps.txt. Install them (or run --install-deps) \
             and re-run; --force cannot substitute for a missing package.",
            inputs.skipped_missing_package
        ));
    }

    // 3b. Skipped (a parameter couldn't be driven) — what --force is actually for.
    let undrivable = inputs
        .skipped
        .saturating_sub(inputs.skipped_missing_package);
    if undrivable > 0 {
        actions.push(format!(
            "{undrivable} target(s) were skipped (a parameter couldn't be driven — opaque handle, callback, unknown type). Attempt them anyway with --force.",
        ));
    }

    // 4. Report-only is expected for legacy dialects, not a failure.
    if inputs.report_only > 0 {
        actions.push(format!(
            "{} target(s) are report-only (statically analyzed, not fuzzed — e.g. Ada 83, or an unbuildable unit). Expected for legacy dialects.",
            inputs.report_only
        ));
    }

    if actions.is_empty() {
        return String::new();
    }
    let mut out = String::from("\ngovfuzz auto: next steps\n");
    for (i, action) in actions.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", i + 1, action));
    }
    out
}

struct FindingRow {
    severity_rank: u8,
    severity: String,
    rule_id: String,
    message: String,
    dir: std::path::PathBuf,
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// The most severe `max` findings, each with a one-line reproduce command. Empty when
/// there are no findings.
pub fn render_top_findings(work_dir: &Path, max: usize) -> String {
    let Ok(entries) = std::fs::read_dir(work_dir.join("findings")) else {
        return String::new();
    };
    let mut rows: Vec<FindingRow> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(raw) = std::fs::read_to_string(dir.join("finding.json")) else {
            continue;
        };
        let Ok(json): Result<serde_json::Value, _> = serde_json::from_str(&raw) else {
            continue;
        };
        let severity = json
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let rule_id = json
            .get("rule_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        // The one-line message lives at exception.message or a top-level message.
        let message = json
            .pointer("/exception/message")
            .and_then(|v| v.as_str())
            .or_else(|| json.get("message").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_owned();
        rows.push(FindingRow {
            severity_rank: severity_rank(&severity),
            severity,
            rule_id,
            message,
            dir,
        });
    }
    if rows.is_empty() {
        return String::new();
    }
    // Most severe first; stable within a severity.
    rows.sort_by(|a, b| b.severity_rank.cmp(&a.severity_rank));
    let shown = rows.len().min(max);
    let mut out = format!(
        "\ngovfuzz auto: top findings ({} shown of {})\n",
        shown,
        rows.len()
    );
    for row in rows.iter().take(max) {
        let msg = truncate(&row.message, 90);
        out.push_str(&format!(
            "  [{}] {} — {}\n      reproduce: govfuzz replay --finding {}\n",
            row.severity.to_uppercase(),
            row.rule_id,
            msg,
            row.dir.display(),
        ));
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() <= max {
        s
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::preflight::PreflightReport;

    fn healthy() -> PreflightReport {
        PreflightReport { lanes: vec![] }
    }

    #[test]
    fn triage_is_empty_on_a_healthy_run() {
        let inputs = TriageInputs {
            built_and_fuzzed: 5,
            failed_build: 0,
            skipped: 0,
            skipped_missing_package: 0,
            report_only: 0,
            findings: 2,
            preflight: &healthy(),
            custom_build: None,
        };
        assert!(render_triage(&inputs).is_empty());
    }

    #[test]
    fn triage_lists_levers_for_failed_builds_and_skips() {
        let inputs = TriageInputs {
            built_and_fuzzed: 0,
            failed_build: 3,
            skipped: 2,
            skipped_missing_package: 0,
            report_only: 0,
            findings: 0,
            preflight: &healthy(),
            custom_build: Some(("build.sh".to_owned(), "./build.sh".to_owned())),
        };
        let text = render_triage(&inputs);
        assert!(text.contains("next steps"));
        assert!(text.contains("3 target(s) failed to build"));
        assert!(text.contains("--build-command \"./build.sh\""));
        assert!(text.contains("--cxx-std"));
        assert!(text.contains("2 target(s) were skipped") && text.contains("--force"));
    }

    /// A target that skipped because a package isn't installed must be told to
    /// install it, not to run `--force`. Across a 534-project sweep this was the
    /// largest skip cause in the corpus, and every one of them was pointed at the
    /// one lever that cannot install a package.
    #[test]
    fn a_skip_for_a_missing_package_asks_for_the_package_not_force() {
        let inputs = TriageInputs {
            built_and_fuzzed: 0,
            failed_build: 0,
            skipped: 4,
            skipped_missing_package: 4,
            report_only: 0,
            findings: 0,
            preflight: &healthy(),
            custom_build: None,
        };
        let text = render_triage(&inputs);
        assert!(
            text.contains("4 target(s) could not be loaded because a package"),
            "missing-package skips must be named as such:\n{text}"
        );
        assert!(
            text.contains("missing-deps.txt"),
            "point at the manifest:\n{text}"
        );
        assert!(
            !text.contains("were skipped (a parameter couldn't be driven"),
            "no undrivable-parameter action when every skip was a missing package:\n{text}"
        );
    }

    /// The two causes are counted apart, so a run with both gets both actions and
    /// neither count is inflated by the other.
    #[test]
    fn mixed_skips_split_between_the_package_action_and_the_force_action() {
        let inputs = TriageInputs {
            built_and_fuzzed: 1,
            failed_build: 0,
            skipped: 7,
            skipped_missing_package: 5,
            report_only: 0,
            findings: 0,
            preflight: &healthy(),
            custom_build: None,
        };
        let text = render_triage(&inputs);
        assert!(text.contains("5 target(s) could not be loaded"), "{text}");
        assert!(
            text.contains("2 target(s) were skipped (a parameter couldn't be driven"),
            "the force action must count only the undrivable ones:\n{text}"
        );
    }

    #[test]
    fn top_findings_ranks_by_severity_with_replay_command() {
        let tmp = std::env::temp_dir().join(format!("govfuzz-triage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let findings = tmp.join("findings");
        for (id, sev, rule) in [("F-1", "low", "GF-100"), ("F-2", "high", "GF-200")] {
            let d = findings.join(id);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("finding.json"),
                format!(
                    r#"{{"id":"{id}","severity":"{sev}","rule_id":"{rule}","exception":{{"message":"boom {id}"}}}}"#
                ),
            )
            .unwrap();
        }
        let text = render_top_findings(&tmp, 8);
        // The high finding must be listed before the low one.
        let hi = text.find("GF-200").unwrap();
        let lo = text.find("GF-100").unwrap();
        assert!(hi < lo, "high severity should rank first:\n{text}");
        assert!(text.contains("govfuzz replay --finding"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
