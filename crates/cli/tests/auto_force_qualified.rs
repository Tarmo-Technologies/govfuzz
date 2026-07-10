// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz Phase 1: a free function in a C++ namespace must build and fuzz
//! both WITH a declaring header (`qualified_ns`) and WITHOUT one
//! (`qualified_ns_noheader`).
//!
//! For the no-header case the generator emits a namespace-qualified forward
//! declaration of the reconstructed signature so the qualified call resolves the
//! identifier (regression for the `use of undeclared identifier 'UtilitiesLib'`
//! codegen bug); the harness then links against the real definition. For the
//! header case the header already brings the symbol into scope.
//!
//! Gated on the C++ toolchain being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn run_fixture(name: &str) {
    if which::which("clang").is_err() && which::which("clang++").is_err() {
        eprintln!("skipping: no clang");
        return;
    }

    let fixture = repo_root().join("tests/fixtures/force_fuzz").join(name);

    // Work-dir OUTSIDE the scanned tree so it is not itself discovered.
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-qualified-")
        .tempdir()
        .expect("tempdir");
    let work_dir = tmp.path().join("auto_work");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&fixture)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--languages")
        .arg("cpp")
        .arg("--per-target-time")
        .arg("2")
        .arg("--no-discovery-cache")
        .output()
        .expect("spawn govfuzz auto");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let run_json = work_dir.join("auto/run.json");
    let raw = std::fs::read_to_string(&run_json).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; stdout=\n{stdout}\nstderr=\n{stderr}",
            run_json.display()
        )
    });
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse run.json");

    let targets = doc["targets"].as_array().expect("targets array");
    assert!(
        targets
            .iter()
            .any(|t| t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed")),
        "namespaced free function ({name}) must build and fuzz; run.json=\n{raw}\n\
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
}

#[test]
fn namespaced_free_function_with_header_builds_and_fuzzes() {
    run_fixture("qualified_ns");
}

#[test]
fn namespaced_free_function_without_header_builds_and_fuzzes() {
    run_fixture("qualified_ns_noheader");
}

/// The real MFC trigger: the source includes a precompiled-style header
/// (`StdAfx.h`) that does NOT declare the namespaced free function. The harness
/// auto-includes that header (so `has_target_header` is true), yet must still
/// emit its own namespace forward declaration — otherwise the qualified call is
/// `use of undeclared identifier`. Regression for the reported `UtilitiesLib` bug.
#[test]
fn namespaced_free_function_with_unrelated_pch_header_builds_and_fuzzes() {
    run_fixture("qualified_ns_pch");
}
