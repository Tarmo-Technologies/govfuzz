// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz Phase 2, Task 2: `auto --force` bypasses the pre-build skip gates.
//!
//! The gate exercised here is the C++ ".cpp-only class" pre-skip: a class defined
//! only in a `.cpp` translation unit (never declared in any header) is an undefined
//! type in the generated harness's translation unit, so its methods are normally
//! pre-skipped as `unsupported_params` WITHOUT burning a build. (The C `static`
//! gate does not apply for a single-TU C function — the C path can paste the
//! defining source into the harness — so this test uses the C++ class gate to
//! demonstrate the bypass, as the task permits.)
//!
//! WITHOUT `--force`: `Parser::scan` -> `unsupported_params` (the gate fires).
//! WITH `--force`:    the gate is bypassed, so `Parser::scan` reaches the
//!                    build+repair path — its outcome is NOT `unsupported_params`
//!                    (here `failed_build`, since the never-hard-fail floor is a
//!                    later Phase-2 task).
//!
//! Gated on the C++ toolchain being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

/// Run `govfuzz auto` on the cpp-only-class fixture, optionally with `--force`,
/// and return the parsed `run.json`.
fn run_auto(force: bool, work_dir: &Path) -> serde_json::Value {
    let fixture = repo_root().join("tests/fixtures/force_fuzz/cpp_only_class");

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    cmd.arg("auto")
        .arg(&fixture)
        .arg("--work-dir")
        .arg(work_dir)
        .arg("--languages")
        .arg("cpp")
        .arg("--per-target-time")
        .arg("2")
        .arg("--no-discovery-cache");
    if force {
        cmd.arg("--force");
    }

    let output = cmd.output().expect("spawn govfuzz auto");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let run_json = work_dir.join("auto/run.json");
    let raw = std::fs::read_to_string(&run_json).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; stdout=\n{stdout}\nstderr=\n{stderr}",
            run_json.display()
        )
    });
    serde_json::from_str(&raw).expect("parse run.json")
}

/// The `Parser::scan` target's outcome kind, identified by the class name that the
/// pre-skip reason embeds (skipped/degraded outcomes carry the candidate name only
/// inside `outcome.reason`) or, once it reaches the build path, by there being
/// exactly one non-`gf_parser_version` target. We locate it structurally: the
/// fixture has exactly two targets, and `gf_parser_version` always builds+fuzzes,
/// so the OTHER target is `Parser::scan`.
fn parser_scan_outcome(doc: &serde_json::Value) -> String {
    let targets = doc["targets"].as_array().expect("targets array");
    assert_eq!(
        targets.len(),
        2,
        "expected exactly two discovered targets (Parser::scan + gf_parser_version); \
         run.json=\n{doc:#}"
    );

    // gf_parser_version is a free function that always builds+fuzzes; Parser::scan
    // is the gated one. Pick the target that is NOT the plain built_and_fuzzed free
    // function by matching the gate reason when present, else by elimination.
    for t in targets {
        let outcome = &t["outcome"]["outcome"];
        let reason = t["outcome"]["reason"].as_str().unwrap_or("");
        if reason.contains("Parser::scan") || reason.contains("class 'Parser'") {
            return outcome.as_str().unwrap_or("").to_owned();
        }
    }
    // No reason names Parser::scan -> the gate was bypassed and it reached the build
    // path. Return the single target whose outcome is not the free function's.
    let non_bf: Vec<&serde_json::Value> = targets
        .iter()
        .filter(|t| t["outcome"]["outcome"].as_str() != Some("built_and_fuzzed"))
        .collect();
    if let Some(t) = non_bf.first() {
        return t["outcome"]["outcome"].as_str().unwrap_or("").to_owned();
    }
    // Both built and fuzzed: Parser::scan built too (still a bypass, not a skip).
    "built_and_fuzzed".to_owned()
}

#[test]
fn force_bypasses_cpp_only_class_pre_skip_gate() {
    if which::which("clang").is_err() && which::which("clang++").is_err() {
        eprintln!("skipping: no clang");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-static-")
        .tempdir()
        .expect("tempdir");

    // WITHOUT --force: the gate fires -> unsupported_params.
    let default_work = tmp.path().join("default_work");
    let default_doc = run_auto(false, &default_work);
    let default_outcome = parser_scan_outcome(&default_doc);
    assert_eq!(
        default_outcome, "unsupported_params",
        "without --force, Parser::scan must be pre-skipped as unsupported_params \
         (the .cpp-only-class gate); got {default_outcome}; run.json=\n{default_doc:#}"
    );

    // WITH --force: the gate is bypassed -> Parser::scan reaches build+repair, so
    // its outcome is NOT unsupported_params.
    let force_work = tmp.path().join("force_work");
    let force_doc = run_auto(true, &force_work);
    let force_outcome = parser_scan_outcome(&force_doc);
    assert_ne!(
        force_outcome, "unsupported_params",
        "with --force, the pre-skip gate must be bypassed so Parser::scan reaches \
         the build path (built_and_fuzzed / failed_build / report_only), not \
         unsupported_params; got {force_outcome}; run.json=\n{force_doc:#}"
    );
}
