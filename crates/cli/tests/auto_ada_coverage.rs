// SPDX-License-Identifier: Apache-2.0
//! Regression for #412: Ada targets must fuzz coverage-guided, not blind.
//!
//! GNAT/GCC does not support `-fsanitize-coverage=trace-pc-guard` (the C/C++
//! driver's flag), so the Ada lane reported `coverage_edges = 0` on every pass —
//! the engine fuzzed blind. Worse, with no coverage feedback the corpus persister
//! kept ~every executed input, blowing up to hundreds-of-thousands of files.
//!
//! The fix instruments the Ada target+harness compile with
//! `-fsanitize-coverage=trace-pc` and links the AdaFuzz trace-pc callback (which
//! writes the GOVFUZZ_COV_SHM edge bitmap), and bounds corpus persistence.
//!
//! This drives the real `govfuzz auto` against a small Ada fixture and asserts:
//!  - AC1: at least one pass reports `coverage_edges > 0`.
//!  - AC3: the persisted corpus queue stays bounded (`< 10_000` files).
//!
//! Gated on the Ada toolchain being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<repo>/crates/cli`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn have_ada_toolchain() -> bool {
    which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok()
}

fn copy_ada_sources(fixture: &Path, dest: &Path) {
    for entry in std::fs::read_dir(fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        let is_ada = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "ads" || e == "adb");
        if is_ada {
            std::fs::copy(&path, dest.join(path.file_name().unwrap())).expect("copy ada source");
        }
    }
}

#[test]
fn ada_target_fuzzes_coverage_guided_with_bounded_corpus() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-412-ada-coverage-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/build_recovery/fixtures/ada_basic");
    copy_ada_sources(&fixture, &srcroot);

    let work_dir = srcroot.join("govfuzz_work");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("3")
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

    // The Ada target must actually build+fuzz — instrumenting with trace-pc must
    // not break the build. (If it does not build, AC1 is meaningless.)
    let built = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed"))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "no Ada target built+fuzzed; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let passes = built["outcome"]["passes"].as_array().expect("passes array");

    // AC1: at least one pass must report non-zero edge coverage (was 0 every pass).
    let max_edges = passes
        .iter()
        .filter_map(|p| p["coverage_edges"].as_u64())
        .max()
        .unwrap_or(0);
    assert!(
        max_edges > 0,
        "Ada coverage_edges must be > 0 (#412); passes={passes:?}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // AC3: the persisted corpus queue must stay bounded (< 10k files), not the
    // 402k-file blowup from before the fix.
    let corpus_root = work_dir.join("corpus");
    let mut total_queue_files = 0usize;
    if let Ok(harness_dirs) = std::fs::read_dir(&corpus_root) {
        for harness in harness_dirs.flatten() {
            let queue = harness.path().join("queue");
            if let Ok(files) = std::fs::read_dir(&queue) {
                let count = files.flatten().count();
                assert!(
                    count < 10_000,
                    "corpus/{:?}/queue must be bounded (#412), got {count} files",
                    harness.file_name()
                );
                total_queue_files += count;
            }
        }
    }
    // Sanity: a coverage-producing run persists a (bounded) non-empty corpus.
    assert!(
        total_queue_files >= 1,
        "expected a non-empty persisted corpus, got {total_queue_files}",
    );
}
