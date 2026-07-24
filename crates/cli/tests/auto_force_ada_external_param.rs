// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz: a fuzz target whose PARAMETER type comes from a MISSING external
//! library (`Vendorlib.Handle`). Under `--force`, govfuzz stubs the library AND
//! best-effort drives the target: the opaque external handle is bare-declared
//! (default-initialized, qualified and `with`ed via the source's context clauses)
//! while the `String` parameter receives real fuzz bytes. WITHOUT `--force` the
//! target is `unsupported_params`; WITH it, `built_and_fuzzed`.
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

fn run_auto(force: bool) -> serde_json::Value {
    let fixture = repo_root().join("tests/fixtures/force_fuzz/ada_external_param");
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-ext-param-")
        .tempdir()
        .expect("tempdir");
    let work_dir = tmp.path().join("auto_work");

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    cmd.arg("auto")
        .arg(&fixture)
        .arg("--work-dir")
        .arg(&work_dir);
    if force {
        cmd.arg("--force");
    }
    cmd.arg("--languages")
        .arg("ada")
        .arg("--per-target-time")
        .arg("2")
        .arg("--no-discovery-cache");

    let output = cmd.output().expect("spawn govfuzz auto");
    let run_json = work_dir.join("auto/run.json");
    let raw = std::fs::read_to_string(&run_json).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; stderr=\n{}",
            run_json.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    serde_json::from_str(&raw).expect("parse run.json")
}

fn sole_outcome(doc: &serde_json::Value) -> String {
    let targets = doc["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1, "expected one target; run.json=\n{doc}");
    targets[0]["outcome"]["outcome"]
        .as_str()
        .expect("outcome tag")
        .to_owned()
}

#[test]
fn external_library_param_is_unsupported_without_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(false);
    assert_ne!(
        sole_outcome(&doc),
        "built_and_fuzzed",
        "without --force a missing-library param type must NOT build+fuzz; run.json=\n{doc}"
    );
}

#[test]
fn force_drives_external_library_param_and_builds_and_fuzzes() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(true);
    assert_eq!(
        sole_outcome(&doc),
        "built_and_fuzzed",
        "with --force the stubbed external handle param is bare-declared so the \
         target builds + fuzzes; run.json=\n{doc}"
    );
}
