// SPDX-License-Identifier: Apache-2.0
//! Ada legacy-dialect ladder: govfuzz compiles every Ada harness build with
//! `-gnat2022` (which accepts most older code), but pre-2012 code that uses a
//! now-reserved word as an identifier (`Overriding`, `Interface`, ...) is rejected
//! under Ada 2012+. On such a failure the build ladders down through older
//! standards; the first that BUILDS is cached and the target reaches
//! `built_and_fuzzed` — so govfuzz supports Ada back to (at least) Ada 95.
//!
//! Gated on the Ada toolchain; skipped (with a notice) otherwise.

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
fn pre_2012_ada_reserved_word_identifier_builds_via_dialect_ladder() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let fixture = repo_root().join("tests/fixtures/ada_dialect_ladder");
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-dialect-")
        .tempdir()
        .expect("tempdir");
    let work_dir = tmp.path().join("auto_work");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&fixture)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--languages")
        .arg("ada")
        .arg("--per-target-time")
        .arg("2")
        .arg("--no-discovery-cache")
        .output()
        .expect("spawn govfuzz auto");

    let run_json = work_dir.join("auto/run.json");
    let raw = std::fs::read_to_string(&run_json).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; stderr=\n{}",
            run_json.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse run.json");
    let outcome = doc["targets"][0]["outcome"]["outcome"].as_str();
    assert_eq!(
        outcome,
        Some("built_and_fuzzed"),
        "the Ada 95 target must build via the dialect ladder; run.json=\n{doc}"
    );
}
