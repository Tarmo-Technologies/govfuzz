// SPDX-License-Identifier: Apache-2.0
//! End-to-end regression (group 6): a C++ target with an out-of-tree CLASS
//! parameter (`const CString &`) used with member-call syntax, but WITHOUT any
//! MFC header include so the MFC stub never fires. The repair loop
//! placeholder-synthesizes `CString` as an opaque scalar, and the rebuild then
//! fails with generic "called object type '...' is not a function" diagnostics.
//! govfuzz must recognize this as an unsuppliable external class and degrade to
//! a report-only static scan (`report_only`), NOT leave it a bare `failed_build`.
//!
//! Gated on the C++ toolchain being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

mod support;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[test]
fn external_class_param_degrades_to_report_only() {
    if which::which("clang++").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang++/make not installed — C++ lane unavailable");
        return;
    }
    if !support::cpp_stdlib_toolchain_available("clang++") {
        eprintln!("SKIP: clang++ can't compile the C++ standard headers");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-cpp-external-class-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/cpp_external_class");
    for entry in std::fs::read_dir(&fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("cpp") {
            std::fs::copy(&path, srcroot.join(path.file_name().unwrap())).expect("copy source");
        }
    }

    let work_dir = srcroot.join("govfuzz_work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("1")
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

    let target = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("process_command"))
        .unwrap_or_else(|| {
            panic!(
                "no `process_command` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        target["outcome"]["outcome"].as_str(),
        Some("report_only"),
        "an out-of-tree class param placeholdered as a scalar must degrade to a \
         report-only scan, not a bare failed_build; target={target}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
