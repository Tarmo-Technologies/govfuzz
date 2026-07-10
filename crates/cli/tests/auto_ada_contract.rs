// SPDX-License-Identifier: Apache-2.0
//! Ada 2012 contracts as fuzzing oracles: `govfuzz auto` builds Ada targets with
//! -gnata, so a violated Pre/Post/Type_Invariant raises Assertion_Error, which the
//! exception oracle reports as a contract violation (GF-557 / CWE-617).
//!
//! The fixture's `Parsed_Length` has an off-by-one (returns Data'Length + 1) that its
//! postcondition (`Result <= Data'Length`) catches on every call — so any input,
//! including the empty one, trips it. This drives the real `govfuzz auto` and asserts
//! a GF-557 finding is recorded. Gated on the Ada toolchain; skipped otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn have_ada_toolchain() -> bool {
    which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok()
}

fn copy_ada_sources(fixture: &Path, dest: &Path) {
    for entry in std::fs::read_dir(fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        let is_ada = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "ads" || e == "adb");
        if is_ada {
            std::fs::copy(&path, dest.join(path.file_name().unwrap())).expect("copy ada source");
        }
    }
}

fn findings_contain_rule(work_dir: &Path, rule_id: &str) -> bool {
    let findings = work_dir.join("findings");
    let Ok(entries) = std::fs::read_dir(&findings) else {
        return false;
    };
    for entry in entries.flatten() {
        if let Ok(json) = std::fs::read_to_string(entry.path().join("finding.json")) {
            if json.contains(rule_id) {
                return true;
            }
        }
    }
    false
}

#[test]
fn ada_contract_violation_reports_gf557() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-contract-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/ada_contract");
    copy_ada_sources(&fixture, &srcroot);

    let work_dir = srcroot.join("govfuzz_work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("5")
        .output()
        .expect("spawn govfuzz auto");

    assert!(
        findings_contain_rule(&work_dir, "GF-557"),
        "expected a GF-557 Ada contract-violation finding under {}; govfuzz auto exit={:?}\nstderr=\n{}",
        work_dir.join("findings").display(),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}
