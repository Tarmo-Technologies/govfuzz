// SPDX-License-Identifier: Apache-2.0
//! Campaign regression: a C++ pimpl whose implementation type
//! (`EncryptionParametersImpl`) is forward-declared but defined only in a .cpp
//! the harness TU never sees. A target returning it by value fails to compile
//! ("incomplete return type"). Before the fix this was classified `Other` and
//! the all-or-nothing external-type gate kept it a hard `failed_build`; now it
//! classifies as `IncompleteType` and degrades to `report_only`.
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
fn forward_declared_pimpl_return_type_degrades_to_report_only() {
    if which::which("clang++").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang++/make not installed — C++ lane unavailable");
        return;
    }
    if !support::cpp_stdlib_toolchain_available("clang++") {
        eprintln!("SKIP: clang++ can't compile the C++ standard headers");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-cpp-pimpl-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/cpp_pimpl_incomplete");
    for entry in std::fs::read_dir(&fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        let keep = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "h" || e == "cpp");
        if keep {
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
        .find(|t| t["name"].as_str() == Some("load_params"))
        .unwrap_or_else(|| {
            panic!(
                "no `load_params` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        target["outcome"]["outcome"].as_str(),
        Some("report_only"),
        "a forward-declared pimpl return type must degrade to report_only, not \
         failed_build; target={target}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
