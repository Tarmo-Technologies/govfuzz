// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn report_subcommand_writes_json_and_markdown_reports() {
    let root = temp_dir("write");
    let findings = root.join("findings");
    let out = root.join("reports");
    write_finding(
        &findings.join("F-0001-report"),
        json!({
            "id": "F-0001-report",
            "severity": "high",
            "classification": "explicit_raise",
            "signature": "abcd",
            "target": { "package": "Pkg", "subprogram": "Parse", "harness_id": "H-report" },
            "minimal_reproducer": "min_testcase.bin"
        }),
    );

    let exit = cli::run_from([
        "govfuzz",
        "report",
        "--findings",
        findings.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--run",
        "ci",
    ]);

    assert_eq!(exit, 0);

    let json_path = out.join("run-ci.json");
    let markdown_path = out.join("run-ci.md");
    assert!(json_path.is_file());
    assert!(markdown_path.is_file());

    let report: serde_json::Value = serde_json::from_slice(&fs::read(json_path).unwrap()).unwrap();
    assert_eq!(report["schema_version"], "govfuzz.report.v2");
    assert_eq!(report["run"]["id"], "ci");
    assert_eq!(report["counts"]["findings"], 1);
    assert_eq!(report["findings"][0]["id"], "F-0001-report");
    assert_eq!(
        report["findings"][0]["minimal_reproducer"],
        "F-0001-report/min_testcase.bin"
    );

    let markdown = fs::read_to_string(markdown_path).unwrap();
    assert!(markdown.contains("# GovFuzz Report: ci"));
    assert!(markdown
        .contains("| F-0001-report | high | explicit_raise | Pkg.Parse (H-report) | abcd |"));
}

#[test]
fn report_subcommand_writes_sarif_when_requested() {
    let root = temp_dir("sarif");
    let findings = root.join("findings");
    let out = root.join("reports");
    write_finding(
        &findings.join("F-0001-sarif"),
        json!({
            "id": "F-0001-sarif",
            "severity": "high",
            "classification": "explicit_raise",
            "signature": "abcd",
            "exception": {
                "handler": { "file": "pkg.adb", "line": 9 }
            }
        }),
    );

    let exit = cli::run_from([
        "govfuzz",
        "report",
        "--findings",
        findings.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--run",
        "ci",
        "--sarif",
    ]);

    assert_eq!(exit, 0);

    let sarif_path = out.join("run-ci.sarif");
    assert!(sarif_path.is_file());
    let sarif: serde_json::Value = serde_json::from_slice(&fs::read(sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["govfuzzExceptionSignature"],
        "abcd"
    );
}

#[test]
fn report_subcommand_generates_repro_adb_for_finding_testcase() {
    let root = temp_dir("repro-adb");
    let findings = root.join("findings");
    let out = root.join("reports");
    let finding_dir = findings.join("F-0001-repro");
    write_finding(
        &finding_dir,
        json!({
            "id": "F-0001-repro",
            "severity": "high",
            "classification": "swallowed_predefined",
            "signature": "abcd",
            "target": { "package": "Pkg", "subprogram": "Parse", "harness_id": "H-repro" }
        }),
    );
    fs::write(finding_dir.join("testcase.bin"), [0x00, 0x41, 0xFF]).unwrap();

    let exit = cli::run_from([
        "govfuzz",
        "report",
        "--findings",
        findings.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--run",
        "ci",
        "--sarif",
    ]);

    assert_eq!(exit, 0);
    let repro = fs::read_to_string(finding_dir.join("repro.adb")).unwrap();
    assert!(repro.starts_with("--  SPDX-License-Identifier: Apache-2.0\n"));
    assert!(repro.contains("16#00#"));
    assert!(repro.contains("16#41#"));
    assert!(repro.contains("16#FF#"));

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("run-ci.json")).unwrap()).unwrap();
    assert_eq!(
        report["findings"][0]["generated_repro_ada"],
        "F-0001-repro/repro.adb"
    );
    assert!(report["findings"][0]["repro_ada_omitted_reason"].is_null());

    let markdown = fs::read_to_string(out.join("run-ci.md")).unwrap();
    assert!(markdown.contains("- Reproducer Ada: `F-0001-repro/repro.adb`"));

    let sarif: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("run-ci.sarif")).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["generatedReproAda"],
        "F-0001-repro/repro.adb"
    );
}

#[test]
fn report_subcommand_generates_replay_py_for_every_finding() {
    // A C/C++ sanitizer finding (lsan leak) — no Ada anywhere — still gets a
    // standalone, syntactically-valid replay.py surfaced in the writeup + JSON.
    let root = temp_dir("replay-py");
    let findings = root.join("findings");
    let out = root.join("reports");
    let finding_dir = findings.join("F-0002-py");
    write_finding(
        &finding_dir,
        json!({
            "id": "F-0002-py",
            "severity": "medium",
            "classification": "unhandled",
            "signature": "deadbeef",
            "rule_id": "GF-208",
            "harness_id": "H-X0C65-56DA8C32",
            "fixture_path": "/work/auto/H-X0C65-56DA8C32/main",
            "dialect": "unknown",
            "paths": { "testcase": "testcase.bin" },
            "exception": {
                "name": "LSAN_MEMORY_LEAK",
                "message": "==1==ERROR: LeakSanitizer: detected memory leaks",
                "sanitizer": "lsan",
                "stack": [
                    { "function": "malloc" },
                    { "function": "nsvg__createParser()", "file": "/src/nanosvg.h", "line": 646 }
                ]
            }
        }),
    );
    fs::write(finding_dir.join("testcase.bin"), b"").unwrap();

    let exit = cli::run_from([
        "govfuzz",
        "report",
        "--findings",
        findings.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--run",
        "ci",
    ]);
    assert_eq!(exit, 0);

    let script = fs::read_to_string(finding_dir.join("replay.py")).unwrap();
    assert!(script.starts_with("#!/usr/bin/env python3\n"));
    // Leak finding keeps leak detection ON so the LSan report reproduces.
    assert!(
        script.contains("detect_leaks=1:abort_on_error=1"),
        "expected leak detection on for an lsan finding:\n{script}"
    );
    assert!(script.contains("\"testcase.bin\""));
    assert!(script.contains("/work/auto/H-X0C65-56DA8C32/main"));

    // It must be importable/compilable Python when python3 is present.
    if let Ok(output) = std::process::Command::new("python3")
        .args([
            "-c",
            "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')",
        ])
        .arg(finding_dir.join("replay.py"))
        .output()
    {
        assert!(
            output.status.success(),
            "replay.py failed to compile:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("run-ci.json")).unwrap()).unwrap();
    assert_eq!(
        report["findings"][0]["generated_repro_py"],
        "F-0002-py/replay.py"
    );

    let markdown = fs::read_to_string(out.join("run-ci.md")).unwrap();
    assert!(markdown.contains("- Reproducer (Python): `F-0002-py/replay.py`"));
    // A C/C++ (non-Ada-dialect) finding must NOT surface the Ada reproducer line,
    // even though repro.adb is written for any testcase — the writeup is gated.
    assert!(!markdown.contains("- Reproducer Ada:"));
    // CWE line rendered from the bug-class mapping (lsan -> CWE-401).
    assert!(
        markdown.contains("- CWE: CWE-401"),
        "expected CWE-401 line in writeup:\n{markdown}"
    );
}

#[test]
fn report_subcommand_writes_junit_when_requested() {
    let root = temp_dir("junit");
    let findings = root.join("findings");
    let out = root.join("reports");
    write_finding(
        &findings.join("F-0001-junit"),
        json!({
            "id": "F-0001-junit",
            "severity": "high",
            "classification": "explicit_raise",
            "signature": "abcd",
            "exception": {
                "handler": { "file": "pkg.adb", "line": 9 }
            }
        }),
    );

    let exit = cli::run_from([
        "govfuzz",
        "report",
        "--findings",
        findings.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--run",
        "ci",
        "--junit",
    ]);

    assert_eq!(exit, 0);

    let junit_path = out.join("run-ci.junit.xml");
    assert!(junit_path.is_file());
    let junit = fs::read_to_string(junit_path).unwrap();
    assert!(junit.contains("<testsuite name=\"govfuzz.ci\" tests=\"1\" failures=\"1\""));
    assert!(
        junit.contains("<testcase classname=\"govfuzz.unknown\" name=\"F-0001-junit [unknown]\">")
    );
    assert!(junit.contains("govfuzzExceptionSignature=abcd"));
}

#[test]
fn report_subcommand_returns_one_when_findings_root_is_missing() {
    let root = temp_dir("missing");

    let exit = cli::run_from([
        "govfuzz",
        "report",
        "--findings",
        root.join("missing-findings").to_str().unwrap(),
        "--out",
        root.join("reports").to_str().unwrap(),
    ]);

    assert_eq!(exit, 1);
}

fn write_finding(finding_dir: &Path, finding: serde_json::Value) {
    fs::create_dir_all(finding_dir).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec_pretty(&finding).unwrap(),
    )
    .unwrap();
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-report-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
