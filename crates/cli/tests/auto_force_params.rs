// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz Phase 2: a C function whose only parameters are types the
//! type-directed decoders REJECT — an opaque (incomplete) struct pointer and a
//! function pointer. WITHOUT `--force` the target is `unsupported_params`
//! (skipped); WITH `--force` the best-effort parameter drivers synthesize a
//! compiling harness, so the target reaches `built_and_fuzzed`.
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
    let fixture = repo_root().join("tests/fixtures/force_fuzz/opaque_param");

    // Work-dir OUTSIDE the scanned tree so it is not itself discovered.
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-params-")
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
fn opaque_and_funcptr_params_are_skipped_without_force() {
    if which::which("clang").is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let doc = run_auto(false);
    assert_eq!(
        sole_outcome(&doc),
        "unsupported_params",
        "without --force the opaque/function-pointer target must be skipped; \
         run.json=\n{doc}"
    );
}

#[test]
fn opaque_and_funcptr_params_build_and_fuzz_under_force() {
    if which::which("clang").is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let doc = run_auto(true);
    assert_eq!(
        sole_outcome(&doc),
        "built_and_fuzzed",
        "with --force the best-effort parameter drivers must build + fuzz the \
         target; run.json=\n{doc}"
    );
}
