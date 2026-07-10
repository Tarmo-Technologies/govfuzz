// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz Phase 2: a C translation unit that cannot build even with the
//! aggressive diagnostic-driven stubbing `--force` enables (an undefined
//! external type used by-value with member access — an opaque placeholder can't
//! satisfy `.tag`/`.count`). WITHOUT `--force` the target is `failed_build`;
//! WITH `--force` the terminal report-only floor degrades it to `report_only`
//! (a static scan) — `--force` must NEVER hard-fail.
//!
//! Gated on clang being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
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
    let fixture = repo_root().join("tests/fixtures/force_fuzz/unbuildable");

    // Work-dir OUTSIDE the scanned tree so it is not itself discovered.
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-unbuildable-")
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
        .arg("c")
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
fn unbuildable_target_is_failed_build_without_force() {
    if which::which("clang").is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let doc = run_auto(false);
    assert_eq!(
        sole_outcome(&doc),
        "failed_build",
        "without --force the unbuildable target must be a failed_build; \
         run.json=\n{doc}"
    );
}

#[test]
fn unbuildable_target_degrades_to_report_only_under_force() {
    if which::which("clang").is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let doc = run_auto(true);
    let outcome = sole_outcome(&doc);
    // The floor is report-only; a build that force somehow rescued (built_and_fuzzed)
    // would also be acceptable — the invariant is that force NEVER hard-fails.
    assert_ne!(
        outcome, "failed_build",
        "with --force an unbuildable target must NEVER be a failed_build; run.json=\n{doc}"
    );
    assert_eq!(
        outcome, "report_only",
        "with --force the unbuildable target degrades to report_only (static scan); \
         run.json=\n{doc}"
    );
}
