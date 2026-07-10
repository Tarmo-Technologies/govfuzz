// SPDX-License-Identifier: Apache-2.0
//! Campaign regression: a multi-dimensional (2-D) Ada array parameter
//! (`Covariance_Matrix_Type is array (R, C) of Float`). The array decoder used
//! to emit a single-subscript fill loop that fails to compile on an N-D array
//! ("too few subscripts in array reference"); it now nests one loop per
//! dimension. Drives the real `govfuzz auto` and asserts the target built+fuzzed.
//!
//! Gated on the Ada toolchain being installed; skipped (with a notice) otherwise.

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

#[test]
fn two_dimensional_array_param_builds_and_fuzzes() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-multidim-array-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/ada_multidim_array");
    for entry in std::fs::read_dir(&fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        let is_ada = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "ads" || e == "adb");
        if is_ada {
            std::fs::copy(&path, srcroot.join(path.file_name().unwrap())).expect("copy ada source");
        }
    }

    let work_dir = srcroot.join("govfuzz_work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("2")
        .output()
        .expect("spawn govfuzz auto");

    let run_json_path = work_dir.join("auto/run.json");
    let run_json_bytes = std::fs::read(&run_json_path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; govfuzz auto exit={:?}\nstderr=\n{}",
            run_json_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    let run_json: serde_json::Value =
        serde_json::from_slice(&run_json_bytes).expect("parse run.json");

    let consume = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("consume"))
        .unwrap_or_else(|| {
            panic!(
                "no `consume` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        consume["outcome"]["outcome"].as_str(),
        Some("built_and_fuzzed"),
        "the 2-D array param must decode with nested loops and build; \
         target={consume}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let harness_id = consume["harness_id"].as_str().expect("harness_id");
    let main_adb =
        std::fs::read_to_string(work_dir.join("harnesses").join(harness_id).join("main.adb"))
            .expect("read harness main.adb");
    assert!(
        main_adb.contains("'Range (1)") && main_adb.contains("'Range (2)"),
        "the harness must iterate both array dimensions:\n{main_adb}"
    );
}
