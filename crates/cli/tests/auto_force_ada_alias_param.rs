// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz: a project that RE-EXPORTS a type of a missing external library under
//! its own name, which is how real Ada projects insulate themselves from a library
//! (`subtype JSON_Value is GNATCOLL.JSON.JSON_Value;` in spat).
//!
//! A child unit then names the type unqualified, and type resolution follows the
//! alias to its EXTERNAL base. Declaring the harness parameter by that base spelling
//! fails — the harness has no `with` for a unit outside the project
//! (`"Vendorx" is not visible`). The in-project spelling is already visible through
//! the unit the harness `with`s to reach the target, so that is the one to use.
//!
//! The body also does arithmetic on a stubbed function's result, which GNAT reports
//! as `invalid operand types for operator` with the two operand types rather than an
//! expected/found pair — a diagnostic shape the stub refiner must also learn from.
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

fn run_auto(force: bool) -> (serde_json::Value, PathBuf, tempfile::TempDir) {
    let fixture = repo_root().join("tests/fixtures/force_fuzz/ada_alias_param");
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-ada-alias-")
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
    let raw = std::fs::read_to_string(work_dir.join("auto/run.json")).unwrap_or_else(|e| {
        panic!(
            "read run.json: {e}\nstdout=\n{}\nstderr=\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let doc = serde_json::from_str(&raw).expect("parse run.json");
    (doc, work_dir, tmp)
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
fn a_parameter_typed_by_a_re_exported_external_type_does_not_build_without_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let (doc, _work, _tmp) = run_auto(false);
    assert_ne!(
        sole_outcome(&doc),
        "built_and_fuzzed",
        "without --force the missing library cannot be stubbed; run.json=\n{doc}"
    );
}

#[test]
fn a_parameter_typed_by_a_re_exported_external_type_builds_and_fuzzes_under_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let (doc, work_dir, _tmp) = run_auto(true);
    assert_eq!(
        sole_outcome(&doc),
        "built_and_fuzzed",
        "with --force the parameter must be declared by a spelling the harness can \
         see, and the stubbed result type learned from the operand diagnostic; \
         run.json=\n{doc}"
    );

    // The declaration must use the IN-PROJECT alias, not the external base: that is
    // the whole point — the harness has no `with` for the missing library's unit.
    let mains: Vec<String> = std::fs::read_dir(work_dir.join("harnesses"))
        .expect("harness dir")
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("main.adb")).ok())
        .collect();
    let main = mains
        .iter()
        .find(|text| text.contains("Object :"))
        .unwrap_or_else(|| panic!("no harness declares the opaque parameter: {mains:?}"));
    assert!(
        main.contains("Object : Aliasapp.Handle"),
        "parameter declared by the visible in-project spelling:\n{main}"
    );
    assert!(
        !main.contains("Vendorx.Doc.Handle"),
        "the external base spelling is not visible to the harness:\n{main}"
    );
}
