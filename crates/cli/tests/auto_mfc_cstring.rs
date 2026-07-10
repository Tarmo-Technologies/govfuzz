// SPDX-License-Identifier: Apache-2.0
//! End-to-end regression: an MFC target (`#include <afxwin.h>`) with a
//! `const CString &` parameter. On an offline non-Windows lab CString is
//! undefined, so this used to fail the build ("undefined type 'CString'").
//! govfuzz now (1) supplies an MFC stub defining CString + the window classes
//! (routed via the win32/MFC platform stub, unblocked by the wchar_t fix) and
//! (2) drives a CString parameter from a fuzz string, so the target builds+fuzzes.
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
fn mfc_cstring_param_builds_and_fuzzes() {
    if which::which("clang++").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang++/make not installed — C++ lane unavailable");
        return;
    }
    if !support::cpp_stdlib_toolchain_available("clang++") {
        eprintln!("SKIP: clang++ can't compile the C++ standard headers");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-mfc-cstring-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/mfc_cstring");
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
        Some("built_and_fuzzed"),
        "an MFC CString param must build (stub defines CString) and fuzz (decoder \
         drives it); target={target}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let harness_id = target["harness_id"].as_str().expect("harness_id");
    let main_cpp =
        std::fs::read_to_string(work_dir.join("harnesses").join(harness_id).join("main.cpp"))
            .expect("read harness main.cpp");
    assert!(
        main_cpp.contains("CString cmd(_tmp_cmd") && main_cpp.contains("gf_c_string"),
        "the CString param must be driven from a fuzz string:\n{main_cpp}"
    );
}
