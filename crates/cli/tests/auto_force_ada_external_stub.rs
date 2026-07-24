// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz: a large, missing, multi-package external Ada library. The project
//! `with`s and calls `Vendorbig.Json`, `Vendorbig.Strings`, and `Vendorbig.Errors`
//! — none of which exist offline. WITHOUT `--force` the missing library cannot be
//! stubbed and the target terminates `unrecoverable_link`. WITH `--force` the Ada
//! external-stub model
//! reconstructs a compilable stub of the *used subset* of every missing package —
//! inferring subprogram profiles from the GNAT type oracle, flipping stub types to
//! String subtypes where string literals are passed, seeding constants and
//! exception handlers, defaulting optional parameters, and threading cross-package
//! type references — so the driveable `Process (String)` target reaches
//! `built_and_fuzzed`.
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

fn walk(dir: &Path) -> String {
    let mut out = String::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            out.push_str(&format!("{}\n", p.display()));
            if p.is_dir() {
                out.push_str(&walk(&p));
            }
        }
    }
    out
}

fn run_auto(force: bool) -> serde_json::Value {
    let fixture = repo_root().join("tests/fixtures/force_fuzz/ada_external_lib");

    // Work-dir OUTSIDE the scanned tree so it is not itself discovered.
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-ada-ext-")
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let run_json = work_dir.join("auto/run.json");
    let raw = std::fs::read_to_string(&run_json).unwrap_or_else(|e| {
        let listing = walk(&work_dir);
        panic!(
            "read {}: {e}; work_dir tree:\n{listing}\nstdout=\n{stdout}\nstderr=\n{stderr}",
            run_json.display()
        )
    });
    serde_json::from_str(&raw).expect("parse run.json")
}

fn sole_outcome(doc: &serde_json::Value) -> String {
    let targets = doc["targets"].as_array().expect("targets array");
    assert_eq!(
        targets.len(),
        1,
        "expected exactly one discovered target; run.json=\n{doc}"
    );
    targets[0]["outcome"]["outcome"]
        .as_str()
        .expect("outcome tag")
        .to_owned()
}

#[test]
fn missing_multi_package_library_does_not_build_fuzz_without_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(false);
    // Without --force the unresolved external library cannot be stubbed, so the
    // target never builds+fuzzes (it terminates unrecoverable at link).
    let outcome = sole_outcome(&doc);
    assert_ne!(
        outcome, "built_and_fuzzed",
        "without --force a missing external library must NOT build+fuzz; \
         run.json=\n{doc}"
    );
    assert_eq!(
        outcome, "unrecoverable_link",
        "without --force the missing external library leaves the target at the \
         unrecoverable-link floor; run.json=\n{doc}"
    );
}

#[test]
fn missing_multi_package_library_builds_and_fuzzes_under_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(true);
    assert_eq!(
        sole_outcome(&doc),
        "built_and_fuzzed",
        "with --force the external-stub model must reconstruct the used subset of \
         every missing package so the target builds + fuzzes; run.json=\n{doc}"
    );
}
