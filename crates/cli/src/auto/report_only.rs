// SPDX-License-Identifier: Apache-2.0

//! M22 report-only path: when a discovered candidate cannot be fuzzed
//! end-to-end — its detected [`lang_profile::Dialect`] has no fuzzing lane yet,
//! the required legacy toolchain is absent, or the build could not be recovered
//! — govfuzz does not silently drop it. It runs the existing source static
//! analyzer over the target and emits CWE-tagged findings into the same findings
//! tree the fuzz path uses, so they flow into every report format (JSON /
//! Markdown / SARIF / JUnit / CSV) with a `report_only` marker, then returns an
//! [`Outcome::ReportOnly`].
//!
//! This reuses [`static_analysis::scan`] (the engine behind `govfuzz
//! static-scan`) and [`finding_rules`] for the CWE, so report-only findings
//! carry the same weakness mapping as a fuzz finding.

use crate::auto::attempt::Outcome;
use crate::auto::candidate::Candidate;
use std::collections::BTreeSet;
use std::path::Path;

/// Discover + statically analyze `candidate` without fuzzing it, writing one
/// CWE-tagged `finding.json` per static hit under `findings_root/findings/` and
/// returning an [`Outcome::ReportOnly`] carrying the reason, detected dialect,
/// and the number of findings emitted.
///
/// `findings_root` is the same directory the fuzz path's `FindingEmitter` uses;
/// findings land at `findings_root/findings/<id>/finding.json`.
pub fn emit_report_only(candidate: &Candidate, reason: String, findings_root: &Path) -> Outcome {
    let dialect = candidate.dialect.map(|d| d.as_str().to_owned());
    let finding_ids = write_static_findings(candidate, findings_root).unwrap_or_default();
    Outcome::ReportOnly {
        reason,
        dialect,
        static_findings: finding_ids.len(),
        finding_ids,
    }
}

/// Run the static analyzer over the candidate's source file and persist each hit
/// as a minimal corpus-format `finding.json` the report loader accepts. Returns
/// the finding ids written, or `None` if the scan could not run (which degrades
/// to a report-only entry with zero static findings — the reason still stands).
fn write_static_findings(candidate: &Candidate, findings_root: &Path) -> Option<Vec<String>> {
    let source = candidate.source_path.as_path();
    // Scan the source file's directory (the scanner walks a tree), then keep only
    // hits on this candidate's own file so a shared directory does not attribute
    // a neighbor's weakness to this target.
    let scan_root = source.parent().unwrap_or(Path::new("."));
    let options = static_analysis::StaticScanOptions {
        root: scan_root.to_path_buf(),
        out_dir: findings_root.join("report-only-scan"),
        suppressions_path: None,
        baseline_path: None,
        policy_path: None,
        enabled_rules: BTreeSet::new(),
        disabled_rules: BTreeSet::new(),
        emit_sarif: false,
    };
    let report = static_analysis::scan(&options).ok()?;

    let source_canon = std::fs::canonicalize(source).ok();
    let findings_dir = findings_root.join("findings");
    let mut written: Vec<String> = Vec::new();
    for f in report
        .findings
        .iter()
        .filter(|f| same_file(&f.location.path, source, source_canon.as_deref()))
    {
        // The id is derived from WHAT was found, not from which target was being
        // harnessed when it was found. A file's static findings belong to the
        // file: keying them by harness meant every report-only target in the same
        // translation unit re-reported all of them, and one 281-target Fortran
        // project turned 24 real findings into 120 rows. Content-addressing makes
        // the repeats land on the same directory and collapse.
        let id = format!(
            "F-RO-{}-{:08X}",
            f.rule_id,
            static_finding_fingerprint(&f.location.path, f.location.line)
        );
        let dir = findings_dir.join(&id);
        if std::fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let full_source_path = source_canon
            .as_deref()
            .unwrap_or(source)
            .to_string_lossy()
            .into_owned();
        let record = static_finding_record(
            &id,
            &candidate.harness_id,
            &candidate.name,
            &full_source_path,
            candidate.dialect.map(|d| d.as_str()),
            f,
        );
        if std::fs::write(
            dir.join("finding.json"),
            serde_json::to_vec_pretty(&record).ok()?,
        )
        .is_ok()
        {
            written.push(id);
        }
    }
    Some(written)
}

/// A stable identity for a static finding: the rule plus where it is. Two
/// targets in one file report the same weakness, and it is one weakness.
fn static_finding_fingerprint(path: &str, line: u32) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    line.hash(&mut hasher);
    (hasher.finish() >> 32) as u32
}

/// The corpus-format `finding.json` record for one static-scan hit. Shared by the
/// per-target report-only path and the tree-wide `--static` scan so the report
/// contract never drifts: `classification: static_scan` + `report_only: true` so
/// consumers can filter statics from confirmed crashes, and an explicit CWE
/// (every reported row must carry one).
fn static_finding_record(
    id: &str,
    harness_id: &str,
    target_name: &str,
    source_path: &str,
    dialect: Option<&str>,
    f: &static_analysis::StaticFinding,
) -> serde_json::Value {
    let cwe: Vec<String> = finding_rules::by_id(&f.rule_id)
        .map(|r| vec![r.cwe.to_owned()])
        .unwrap_or_default();
    // The report's actionability backfill derives the sink from a crash stack or
    // an oracle `source` evidence line, and the fix location from `target.location`
    // (among others). A static hit has neither a stack nor a rich actionability
    // record, so surface its file:line through both paths — else findings.csv
    // renders empty sink columns / "no source location resolved" for statics.
    // `file:line:function` when the analyzer resolved the sink's enclosing
    // function, so actionability's `parse_source_location` fills the report's
    // `sink_function` column with the real function name instead of falling back
    // to the file basename. `file:line` when no function was resolved.
    let source_line = match f.analysis.enclosing_function.as_deref() {
        Some(function) if !function.trim().is_empty() => {
            format!("{source_path}:{}:{function}", f.location.line)
        }
        _ => format!("{source_path}:{}", f.location.line),
    };
    // #6: the tainted variable / sink expression this finding is about — the
    // "entity" commercial SAST tools name in their findings table. Prefer the
    // resolved sink expression, else the first tainted parameter, else empty.
    let entity = f
        .analysis
        .precision
        .sink
        .clone()
        .or_else(|| f.analysis.precision.tainted_parameters.first().cloned())
        .unwrap_or_default();
    // #1: source→sink dataflow. An interprocedural taint rule (GF-304/405/419/…)
    // records the flow in `analysis.trace`; a pure pattern rule (GF-401 unsafe
    // strcpy) flags a call site with an EMPTY trace, so these stay empty for it
    // (correct — we do not fabricate a flow). The FIRST trace step is the taint
    // SOURCE: surface its file/line via `exception.source_file`/`source_line` so
    // load_csv_finding's `source` column populates, and join every step as
    // `path:line` (deduped consecutive) into `data_flow` for the full path.
    let (source_file, source_line_num, data_flow) = if let Some(first) = f.analysis.trace.first() {
        let mut steps: Vec<String> = Vec::with_capacity(f.analysis.trace.len());
        for step in &f.analysis.trace {
            let s = format!("{}:{}", step.path, step.line);
            if steps.last() != Some(&s) {
                steps.push(s);
            }
        }
        (
            first.path.clone(),
            first.line.to_string(),
            steps.join(" -> "),
        )
    } else {
        (String::new(), String::new(), String::new())
    };
    serde_json::json!({
        "id": id,
        "rule_id": f.rule_id,
        "entity": entity,
        "data_flow": data_flow,
        "classification": "static_scan",
        "severity": f.severity,
        "report_only": true,
        "confirmation": "static",
        "harness_id": harness_id,
        "dialect": dialect,
        "target": {
            "name": target_name,
            "source_path": source_path,
            "line": f.location.line,
            // Read by actionability::select_fix_location (`["target","location"]`).
            "location": { "path": source_path, "line": f.location.line },
        },
        // Read by actionability::sink_from -> oracle_sink: a `source` evidence line
        // formatted `file:line` becomes the finding's sink (file/line columns).
        "oracle": {
            "evidence": [ { "key": "source", "value": source_line } ]
        },
        // #1: taint SOURCE file:line (first trace step) — populates the CSV `source`
        // column via load_csv_finding. Empty for pattern rules with no trace.
        "exception": {
            "message": f.message,
            "source_file": source_file,
            "source_line": source_line_num,
        },
        "actionability": {
            "cwe": cwe,
            "verdict": "static_only",
            "confidence": f.confidence,
        },
    })
}

/// `--static`: run the static analyzer over the ENTIRE scanned tree and persist
/// every hit as a corpus-format finding the report renders next to the fuzz
/// findings. Runs regardless of per-target build/fuzz outcomes, and covers files
/// with no fuzzable subprogram. Returns the number of static findings written.
/// Best-effort: a scan failure writes nothing and never fails the (already
/// complete) fuzz run.
pub fn emit_tree_static_findings(root: &Path, work: &Path) -> usize {
    let options = static_analysis::StaticScanOptions {
        root: root.to_path_buf(),
        out_dir: work.join("static-scan"),
        suppressions_path: None,
        baseline_path: None,
        policy_path: None,
        enabled_rules: BTreeSet::new(),
        disabled_rules: BTreeSet::new(),
        emit_sarif: false,
    };
    let Ok(report) = static_analysis::scan(&options) else {
        return 0;
    };
    // The scan walks `root`; when the govfuzz work-dir lives INSIDE `root` (any
    // `--work-dir`, not just the name-excluded `govfuzz_work`), it would flag
    // govfuzz's OWN generated harnesses/stubs/runtime copies — CWE-22/CWE-15 noise
    // on `main.c`, never the user's code. Drop every finding under the work-dir so
    // `--static` reports the target tree, not govfuzz's scaffolding.
    let work_canon = std::fs::canonicalize(work).unwrap_or_else(|_| work.to_path_buf());
    let findings_dir = work.join("findings");
    let mut written = 0usize;
    let mut next_index = 0usize;
    for f in report.findings.iter() {
        if path_under(&f.location.path, root, &work_canon) {
            continue;
        }
        let i = next_index;
        next_index += 1;
        let id = format!("F-STATIC-{i:04}");
        let dir = findings_dir.join(&id);
        if std::fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let target_name = Path::new(&f.location.path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "static-scan".to_owned());
        let full_source_path = absolute_reported_path(root, &f.location.path);
        let record =
            static_finding_record(&id, "static-scan", &target_name, &full_source_path, None, f);
        if std::fs::write(
            dir.join("finding.json"),
            serde_json::to_vec_pretty(&record).unwrap_or_default(),
        )
        .is_ok()
        {
            written += 1;
        }
    }
    written
}

/// Resolve a scanner path against its scan root for report consumers. Keep the
/// joined absolute path even when canonicalization fails (for example, if a file
/// is removed between scanning and report emission).
fn absolute_reported_path(root: &Path, reported: &str) -> String {
    let path = Path::new(reported);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    std::fs::canonicalize(&joined)
        .unwrap_or(joined)
        .to_string_lossy()
        .into_owned()
}

/// Whether a scan-reported path lies inside the govfuzz work-dir (its generated
/// harnesses/stubs/runtime copies). The scanner reports paths RELATIVE to the scan
/// root (or occasionally absolute), so resolve the reported path against `root`
/// before comparing to the canonical work-dir.
fn path_under(reported: &str, root: &Path, work_canon: &Path) -> bool {
    let reported_path = Path::new(reported);
    let absolute = if reported_path.is_absolute() {
        reported_path.to_path_buf()
    } else {
        root.join(reported_path)
    };
    if let Ok(canon) = std::fs::canonicalize(&absolute) {
        if canon.starts_with(work_canon) {
            return true;
        }
    }
    absolute.starts_with(work_canon)
}

/// Whether a static-finding path string refers to `source` (by canonical path
/// when available, else by suffix/exact match — the scanner may report a
/// relative or absolute path depending on how it walked the tree).
fn same_file(reported: &str, source: &Path, source_canon: Option<&Path>) -> bool {
    let reported_path = Path::new(reported);
    if reported_path == source {
        return true;
    }
    if let Some(canon) = source_canon {
        if let Ok(rc) = std::fs::canonicalize(reported_path) {
            if rc == canon {
                return true;
            }
        }
    }
    // Fall back to filename match so a relative-vs-absolute mismatch does not
    // drop a real hit on the candidate's file.
    match (reported_path.file_name(), source.file_name()) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::candidate::Lang;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("govfuzz-ro-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// `--static` must not flag govfuzz's OWN generated harness: a `--work-dir`
    /// inside the scanned tree (with a name the scanner doesn't exclude) would
    /// otherwise surface CWE noise on the generated `main.c`. `emit_tree_static_findings`
    /// drops every hit under the work-dir path.
    #[test]
    fn tree_scan_excludes_the_work_dir() {
        let root = temp_dir("treeroot");
        // A weak file in the user's tree (must be reported).
        std::fs::write(
            root.join("app.c"),
            "#include <string.h>\nint f(char *d, char *s){ strcpy(d, s); return 0; }\n",
        )
        .unwrap();
        // The govfuzz work-dir lives INSIDE the tree, named `work` (NOT the
        // name-excluded `govfuzz_work`), holding a generated harness with the same
        // weak pattern (must NOT be reported).
        let work = root.join("work");
        let harness_dir = work.join("harnesses").join("H-0001");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("main.c"),
            "#include <string.h>\nint g(char *d, char *s){ strcpy(d, s); return 0; }\n",
        )
        .unwrap();

        let written = emit_tree_static_findings(&root, &work);
        assert!(written >= 1, "the user's app.c weakness must be reported");

        // Every emitted finding must be on app.c, never the work-dir harness.
        let findings_dir = work.join("findings");
        for entry in std::fs::read_dir(&findings_dir).unwrap().flatten() {
            let fj = entry.path().join("finding.json");
            if !fj.exists() {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&fj).unwrap()).unwrap();
            let path = v["target"]["source_path"].as_str().unwrap_or_default();
            assert!(
                !path.contains("work/") && !path.contains("harnesses"),
                "work-dir harness finding leaked into --static report: {path}"
            );
            assert!(
                Path::new(path).is_absolute(),
                "static sink path must be absolute: {path}"
            );
            assert!(
                path.ends_with("app.c"),
                "static sink must name the user's full source path: {path}"
            );
        }
    }

    /// #1: an interprocedural taint finding (a Go `exec.Command(userInput)` sink
    /// reached from a tainted parameter) records a source→sink trace, so its
    /// finding.json must carry `exception.source_file`/`source_line` (populating
    /// the CSV `source` column) and a `data_flow` path. A pure PATTERN rule
    /// (GF-401 unsafe strcpy) has an EMPTY trace, so both stay empty — we do NOT
    /// fabricate a flow.
    #[test]
    fn taint_finding_records_data_flow_pattern_finding_does_not() {
        let root = temp_dir("dataflow");
        std::fs::write(
            root.join("cmd.go"),
            "package main\n\
             import \"os/exec\"\n\
             func run(userInput string) {\n\
                exec.Command(userInput)\n\
             }\n",
        )
        .unwrap();
        // A pure pattern hit (GF-401 unsafe strcpy) with no traced origin.
        std::fs::write(
            root.join("weak.c"),
            "#include <string.h>\nint f(char *d, char *s){ strcpy(d, s); return 0; }\n",
        )
        .unwrap();

        let work = temp_dir("dataflow-work");
        let written = emit_tree_static_findings(&root, &work);
        assert!(written >= 2, "expected the taint + pattern findings");

        let findings_dir = work.join("findings");
        let mut saw_taint = false;
        let mut saw_pattern = false;
        for entry in std::fs::read_dir(&findings_dir).unwrap().flatten() {
            let fj = entry.path().join("finding.json");
            if !fj.exists() {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&fj).unwrap()).unwrap();
            let source_file = v["exception"]["source_file"].as_str().unwrap_or_default();
            let data_flow = v["data_flow"].as_str().unwrap_or_default();
            let rule = v["rule_id"].as_str().unwrap_or_default();
            if !data_flow.is_empty() {
                // A taint finding: source + data_flow populated, flow ends at the sink.
                saw_taint = true;
                assert!(
                    !source_file.is_empty(),
                    "taint finding must carry a source_file: {v}"
                );
                assert!(
                    data_flow.contains(" -> ") || data_flow.contains(':'),
                    "data_flow must be a path:line flow: {data_flow}"
                );
            } else if rule == "GF-401" {
                // The pattern finding: no traced origin, so source stays empty.
                saw_pattern = true;
                assert!(
                    source_file.is_empty(),
                    "pattern finding must NOT fabricate a source: {v}"
                );
            }
        }
        assert!(saw_taint, "expected a taint finding with a data_flow");
        assert!(saw_pattern, "expected a GF-401 pattern finding with none");
    }

    #[test]
    fn two_targets_in_one_file_do_not_double_report_its_static_findings() {
        // A file's static weaknesses belong to the file. Keying the finding id by
        // harness made every report-only target in a translation unit re-report
        // all of them: one Fortran project turned 24 real findings into 120 rows,
        // which is exactly the per-crash duplication the report is meant to avoid.
        let a = static_finding_fingerprint("flemon.c", 1319);
        let b = static_finding_fingerprint("flemon.c", 1319);
        assert_eq!(a, b, "the same weakness has one identity");
        assert_ne!(
            a,
            static_finding_fingerprint("flemon.c", 1321),
            "a different line is a different weakness"
        );
        assert_ne!(
            a,
            static_finding_fingerprint("other.c", 1319),
            "a different file is a different weakness"
        );
    }

    #[test]
    fn report_only_emits_cwe_tagged_static_finding() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("legacy.c");
        // A K&R-style definition with an unbounded strcpy — GF-401 (CWE-120/787).
        std::fs::write(
            &src,
            "int copy(dst, s)\n    char *dst;\n    char *s;\n{\n    strcpy(dst, s);\n    return 0;\n}\n",
        )
        .unwrap();

        let candidate = Candidate {
            harness_id: "H-C0001".to_owned(),
            lang: Lang::C,
            source_path: src.clone(),
            line: 1,
            name: "copy".to_owned(),
            score: 50,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: Some(lang_profile::Dialect::CKAndR),
        };

        let work = temp_dir("work");
        let outcome = emit_report_only(
            &candidate,
            "K&R C has no fuzzing lane yet (M22 Phase 3)".to_owned(),
            &work,
        );

        let count = match &outcome {
            Outcome::ReportOnly {
                reason,
                dialect,
                static_findings,
                ..
            } => {
                assert!(reason.contains("K&R"));
                assert_eq!(dialect.as_deref(), Some("c_knr"));
                *static_findings
            }
            other => panic!("expected ReportOnly, got {other:?}"),
        };
        assert!(count >= 1, "expected >=1 static finding, got {count}");

        // Every emitted finding.json carries a non-empty CWE.
        let findings_dir = work.join("findings");
        let mut saw_cwe = false;
        for entry in std::fs::read_dir(&findings_dir).unwrap() {
            let fj = entry.unwrap().path().join("finding.json");
            if !fj.exists() {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&fj).unwrap()).unwrap();
            let cwe = v["actionability"]["cwe"].as_array().unwrap();
            assert!(!cwe.is_empty(), "report-only finding must carry a CWE");
            assert!(cwe[0].as_str().unwrap().starts_with("CWE-"));
            saw_cwe = true;
        }
        assert!(saw_cwe, "expected at least one finding.json on disk");
    }
}
