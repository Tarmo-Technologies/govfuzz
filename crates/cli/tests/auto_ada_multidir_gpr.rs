// SPDX-License-Identifier: Apache-2.0
//! §27.7 / #450 increment 2(c): end-to-end multi-directory Ada build.
//!
//! A governing `.gpr` enumerates two sibling `Source_Dirs`. A fuzz target scanned
//! in one directory (`src/parser/line_parser.adb`) depends on a unit that lives in
//! the OTHER (`src/core/core_checks.adb`). `govfuzz auto`, scanning only the
//! `src/parser` subdir, must resolve the governing project's default-scenario
//! Source_Dirs (`active_source_dirs`) and instrument the sibling `src/core` so the
//! cross-package dependency builds — instead of failing `missing_ada_symbol`.
//!
//! Asserts the `parse_line` target `built_and_fuzzed` AND that the sibling unit
//! (`core_checks`) was actually pulled into the instrumented source set (the
//! built-target delta the increment-1 unit tests could not exercise).
//!
//! Gated on the Ada toolchain being installed; skipped (with a notice) otherwise.

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

/// Recursively copy a directory tree (the fixture has subdirectories + a `.gpr`,
/// so the flat `.ads`/`.adb` copy the other Ada tests use does not suffice).
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir dst");
    for entry in std::fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).expect("copy file");
        }
    }
}

#[test]
fn ada_multidir_gpr_pulls_sibling_source_dir_into_build() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-450-ada-multidir-")
        .tempdir()
        .expect("tempdir");
    let tree = tmp.path().join("tree");
    copy_tree(&repo_root().join("tests/fixtures/ada_multidir_gpr"), &tree);

    // Scan ONLY the parser subdir; the governing multidir.gpr sits in `tree` (a
    // parent), and the dependency lives in the sibling src/core. The work dir is
    // kept OUTSIDE the scanned tree so it is not itself discovered as source and so
    // prepare_layout does not pick up the project's own .gpr.
    let scan_root = tree.join("src/parser");
    let work_dir = tmp.path().join("work");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&scan_root)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("2")
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

    let parse_target = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("parse_line"))
        .unwrap_or_else(|| {
            panic!(
                "no `parse_line` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        parse_target["outcome"]["outcome"].as_str(),
        Some("built_and_fuzzed"),
        "the cross-package target must build+fuzz once the sibling Source_Dir is \
         pulled in; target={parse_target}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The built-target delta: the sibling unit from `src/core` must have been
    // instrumented (proving the governing .gpr's Source_Dirs were resolved and
    // added, not just the scanned `src/parser`).
    let instrumented_core = work_dir.join("src_instrumented/core_checks.adb");
    assert!(
        instrumented_core.exists(),
        "sibling src/core unit must be instrumented into {}; \nstderr=\n{}",
        instrumented_core.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}
