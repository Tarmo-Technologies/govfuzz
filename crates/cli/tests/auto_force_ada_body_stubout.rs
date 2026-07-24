// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz body stub-out: a project's ROOT body (`app.adb`) instantiates a
//! generic package from a MISSING external library, so it cannot compile offline
//! and cannot be stubbed as an external package (a generic-instantiation stub is
//! intractable). Because the root spec declares a subprogram, that body is
//! mandatory and is dragged into every child unit's build — including the
//! driveable util target `App.Util.Double`.
//!
//! WITHOUT `--force` the target can't build (report-only floor). WITH `--force`,
//! once external-library stubbing is exhausted, govfuzz replaces the offline-
//! unbuildable parent body with a synthesized `raise` body derived from its spec,
//! so `Double` reaches `built_and_fuzzed`. The synthesized body's raise carries a
//! marker, so a target that reaches it is NOT reported as a (false) finding — a
//! clean run has zero findings.
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
    let fixture = repo_root().join("tests/fixtures/force_fuzz/ada_body_stubout");
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-body-stubout-")
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
            "read {}: {e}; tree:\n{}\nstderr=\n{}",
            run_json.display(),
            walk(&work_dir),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    serde_json::from_str(&raw).expect("parse run.json")
}

fn target_outcome<'a>(doc: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    doc["targets"]
        .as_array()?
        .iter()
        .find(|t| t["name"].as_str() == Some(name))?["outcome"]["outcome"]
        .as_str()
}

#[test]
fn driveable_child_target_is_blocked_by_unbuildable_parent_body_without_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(false);
    assert_ne!(
        target_outcome(&doc, "double"),
        Some("built_and_fuzzed"),
        "without --force the unbuildable parent body must block the child target; \
         run.json=\n{doc}"
    );
}

#[test]
fn body_stubout_builds_and_fuzzes_child_target_under_force() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let doc = run_auto(true);
    assert_eq!(
        target_outcome(&doc, "double"),
        Some("built_and_fuzzed"),
        "with --force the parent body is stubbed out so the child target builds + \
         fuzzes; run.json=\n{doc}"
    );
    // The synthesized stub body's raise is marked and suppressed, so reaching it
    // is not a fault: a clean overflow-free target yields zero findings.
    assert_eq!(
        doc["summary"]["findings"].as_u64(),
        Some(0),
        "stub-body raises must be suppressed (no false findings); run.json=\n{doc}"
    );
}
