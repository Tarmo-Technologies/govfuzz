// SPDX-License-Identifier: Apache-2.0

use cli::run_from;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn fuzz_accepts_attacking_mode_and_stamps_findings() {
    let temp = temp_dir("fuzz-mode");
    let work_dir = temp.join("govfuzz_work");
    let harness_id = "H-ACT";
    install_fake_harness(&work_dir, harness_id);

    let exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from(harness_id),
        OsString::from("--mode"),
        OsString::from("attacking"),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--seed-input"),
        OsString::from("crash"),
    ]);

    assert_eq!(exit, 0);
    let finding_json = fs::read(only_finding_dir(&work_dir).join("finding.json")).unwrap();
    let finding: serde_json::Value = serde_json::from_slice(&finding_json).unwrap();
    assert_eq!(finding["actionability"]["mode"], "attacking");

    let run_summary: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("fuzz_runs/H-ACT-latest.json")).unwrap())
            .unwrap();
    assert_eq!(run_summary["mode"], "attacking");
}

#[test]
fn fuzz_rejects_invalid_mode_value() {
    let temp = temp_dir("bad-mode");
    let work_dir = temp.join("govfuzz_work");
    fs::create_dir_all(&work_dir).unwrap();

    let exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("fuzz"),
        work_dir.into_os_string(),
        OsString::from("--harness"),
        OsString::from("H"),
        OsString::from("--mode"),
        OsString::from("attack"),
    ]);

    assert_ne!(exit, 0);
}

#[test]
fn auto_accepts_reporting_and_attacking_modes() {
    let temp = temp_dir("auto-mode");
    let source = temp.join("src");
    let report_work_dir = temp.join("govfuzz_work_reporting");
    let attack_work_dir = temp.join("govfuzz_work_attacking");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("parse.c"),
        "int parse(const unsigned char *d, unsigned long n) { return n > 0 && d[0] == 1; }\n",
    )
    .unwrap();

    let report_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("auto"),
        source.clone().into_os_string(),
        OsString::from("--work-dir"),
        report_work_dir.into_os_string(),
        OsString::from("--mode"),
        OsString::from("reporting"),
        OsString::from("--per-target-time"),
        OsString::from("0"),
    ]);
    assert!(matches!(report_exit, 0..=2));

    let attack_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("auto"),
        source.into_os_string(),
        OsString::from("--work-dir"),
        attack_work_dir.into_os_string(),
        OsString::from("--mode"),
        OsString::from("attacking"),
        OsString::from("--per-target-time"),
        OsString::from("0"),
    ]);
    assert!(matches!(attack_exit, 0..=2));
}

#[test]
fn auto_empty_candidate_report_records_mode() {
    let temp = temp_dir("auto-empty-mode");
    let source = temp.join("src");
    let work_dir = temp.join("govfuzz_work");
    fs::create_dir_all(&source).unwrap();

    let exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("auto"),
        source.into_os_string(),
        OsString::from("--work-dir"),
        work_dir.clone().into_os_string(),
        OsString::from("--mode"),
        OsString::from("attacking"),
        OsString::from("--per-target-time"),
        OsString::from("0"),
    ]);

    assert_eq!(exit, 2);
    let run_json: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("auto/run.json")).unwrap()).unwrap();
    assert_eq!(run_json["mode"], "attacking");
    let run_md = fs::read_to_string(work_dir.join("auto/run.md")).unwrap();
    assert!(run_md.contains("Mode: attacking"));
}

#[test]
fn ci_actionability_threshold_counts_real_and_likely_only() {
    let temp = temp_dir("ci-actionability");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    write_actionability_finding(&findings.join("F-0001-lab"), "lab_only", "high");
    write_actionability_finding(&findings.join("F-0002-real"), "real_reachable", "high");

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();

    assert_eq!(buckets.by_verdict["lab_only"], 1);
    assert_eq!(buckets.by_verdict["real_reachable"], 1);
    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Likely,
            cli::ci::MinActionabilityConfidence::High
        ),
        1
    );
}

#[test]
fn ci_actionability_threshold_ignores_low_confidence_when_min_high() {
    let temp = temp_dir("ci-confidence");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    write_actionability_finding(&findings.join("F-0001-real"), "real_reachable", "low");

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();

    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Real,
            cli::ci::MinActionabilityConfidence::High
        ),
        0
    );
}

#[test]
fn ci_actionability_threshold_includes_low_confidence_when_min_low() {
    let temp = temp_dir("ci-low-confidence");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    write_actionability_finding(&findings.join("F-0001-real"), "real_reachable", "low");

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();

    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Real,
            cli::ci::MinActionabilityConfidence::Low
        ),
        1
    );
}

#[test]
fn ci_actionability_threshold_likely_reachable_trips_likely_gate() {
    let temp = temp_dir("ci-likely-threshold");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    write_actionability_finding(
        &findings.join("F-0001-likely"),
        "likely_reachable",
        "medium",
    );

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();

    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Likely,
            cli::ci::MinActionabilityConfidence::Medium
        ),
        1
    );
}

#[test]
fn ci_actionability_threshold_any_includes_blocked_and_unknown() {
    let temp = temp_dir("ci-any-threshold");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    write_actionability_finding(&findings.join("F-0001-blocked"), "blocked", "medium");
    write_actionability_finding(&findings.join("F-0002-unknown"), "unknown", "low");

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();

    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Any,
            cli::ci::MinActionabilityConfidence::Medium
        ),
        1
    );
    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Any,
            cli::ci::MinActionabilityConfidence::Low
        ),
        1
    );
}

#[test]
fn ci_actionability_buckets_old_findings_through_backfill() {
    let temp = temp_dir("ci-backfill");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    write_legacy_likely_finding(&findings.join("F-0001-legacy-likely"));

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();

    assert_eq!(buckets.by_verdict["likely_reachable"], 1);
    assert_eq!(
        buckets.by_verdict_and_confidence[&("likely_reachable".to_owned(), "medium".to_owned())],
        1
    );
    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Likely,
            cli::ci::MinActionabilityConfidence::Medium
        ),
        1
    );
}

#[test]
fn ci_actionability_threshold_does_not_treat_lab_as_real_or_likely() {
    let temp = temp_dir("ci-lab-honesty");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    write_actionability_finding(&findings.join("F-0001-lab"), "lab_only", "high");

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();

    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Real,
            cli::ci::MinActionabilityConfidence::High
        ),
        0
    );
    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Likely,
            cli::ci::MinActionabilityConfidence::High
        ),
        0
    );
    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Lab,
            cli::ci::MinActionabilityConfidence::High
        ),
        1
    );
}

#[test]
fn ci_actionability_forwards_mode_to_auto() {
    let temp = temp_dir("ci-mode");
    let source = temp.join("src");
    let work_dir = temp.join("govfuzz_work");
    fs::create_dir_all(&source).unwrap();

    let exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("ci"),
        source.into_os_string(),
        OsString::from("--work-dir"),
        work_dir.clone().into_os_string(),
        OsString::from("--mode"),
        OsString::from("attacking"),
        OsString::from("--per-target-time"),
        OsString::from("0"),
        OsString::from("--fail-on-actionability"),
        OsString::from("any"),
    ]);

    assert_eq!(exit, 0);
    let run_json: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("auto/run.json")).unwrap()).unwrap();
    assert_eq!(run_json["mode"], "attacking");
}

#[test]
fn report_and_ci_do_not_count_stale_prosthetic_real_as_real() {
    let temp = temp_dir("stale-real-prosthetic");
    let work_dir = temp.join("govfuzz_work");
    let findings = work_dir.join("findings");
    let reports = work_dir.join("reports");
    write_stale_real_with_stubbed_dependency(&findings.join("F-0001-stale-real"));

    let report_exit = run_from(vec![
        OsString::from("govfuzz"),
        OsString::from("report"),
        OsString::from("--findings"),
        findings.clone().into_os_string(),
        OsString::from("--out"),
        reports.clone().into_os_string(),
        OsString::from("--run"),
        OsString::from("actionability-e2e"),
    ]);

    assert_eq!(report_exit, 0);
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(reports.join("run-actionability-e2e.json")).unwrap())
            .unwrap();
    assert_eq!(report["counts"]["by_actionability_verdict"]["lab_only"], 1);
    assert!(report["counts"]["by_actionability_verdict"]
        .get("real_reachable")
        .is_none());
    assert_eq!(
        report["findings"][0]["actionability"]["verdict"],
        "lab_only"
    );

    let buckets = cli::ci::bucket_actionability_for_test(&work_dir).unwrap();
    assert_eq!(buckets.by_verdict.get("real_reachable").copied(), None);
    assert_eq!(buckets.by_verdict["lab_only"], 1);
    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Real,
            cli::ci::MinActionabilityConfidence::High
        ),
        0
    );
    assert_eq!(
        cli::ci::exit_code_from_actionability_for_test(
            &buckets,
            cli::ci::FailOnActionability::Lab,
            cli::ci::MinActionabilityConfidence::High
        ),
        1
    );
}

fn install_fake_harness(work_dir: &Path, harness_id: &str) -> PathBuf {
    let harness = PathBuf::from(env!("CARGO_BIN_EXE_cli_fake_harness"));
    let target = work_dir
        .join("build")
        .join(harness_id)
        .join("obj")
        .join("main");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::copy(&harness, &target).unwrap();
    make_executable(&target);
    target
}

fn only_finding_dir(work_dir: &Path) -> PathBuf {
    let findings = fs::read_dir(work_dir.join("findings"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 1);
    findings[0].clone()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-actionability-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_stale_real_with_stubbed_dependency(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "id": dir.file_name().unwrap().to_string_lossy(),
            "severity": "high",
            "rule_id": "GF-201",
            "harness_id": "H-lab",
            "build": { "deps": { "stubbed": ["Missing.Driver"] } },
            "exception": {
                "stack": [
                    { "function": "parse", "file": "src/parse.c", "line": 12 }
                ]
            },
            "replay": { "status": "reproduced" },
            "actionability": {
                "mode": "attacking",
                "verdict": "real_reachable",
                "impact": "high",
                "confidence": "high",
                "entry_path": {
                    "kind": "harness",
                    "source": "testcase.bin",
                    "target": "H-lab"
                },
                "fix_location": {
                    "path": "src/parse.c",
                    "line": 12,
                    "reason": "sanitizer_stack_frame"
                },
                "replay": { "status": "reproduced" },
                "prosthetics": { "used": false, "items": [] }
            }
        }))
        .unwrap(),
    )
    .unwrap();
}

fn write_actionability_finding(dir: &Path, verdict: &str, confidence: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "id": dir.file_name().unwrap().to_string_lossy(),
            "severity": "high",
            "actionability": {
                "mode": "attacking",
                "verdict": verdict,
                "impact": "high",
                "confidence": confidence,
                "prosthetics": { "used": verdict == "lab_only", "items": [] }
            }
        }))
        .unwrap(),
    )
    .unwrap();
}

fn write_legacy_likely_finding(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "id": dir.file_name().unwrap().to_string_lossy(),
            "rule_id": "GF-205",
            "harness_id": "H-legacy",
            "exception": {
                "stack": [
                    { "function": "size_calc", "file": "src/parse.c", "line": 30 }
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
