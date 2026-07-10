// SPDX-License-Identifier: Apache-2.0
//! Force-fuzz Phase 1: a legacy Win32 C++ file that references Win32 typedefs
//! (`BOOL`, `PUCHAR`, `DWORD`) without any Windows headers present must build and
//! fuzz — NOT get pre-skipped to report-only, and NOT `unsupported_params`.
//!
//! Two mechanisms cooperate:
//!   1. the build-repair loop injects a synthesized `windows.h` (`win32_pack`
//!      repair) so the translation unit type-checks, and
//!   2. the C/C++ parameter decoder normalizes the standard Win32 scalar/pointer
//!      typedefs to their underlying C types up front, so params like `PUCHAR data`
//!      and `DWORD len` get a byte-buffer / scalar decoder instead of being
//!      rejected as opaque types.
//!
//! Gated on the C++ toolchain being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[test]
fn win32_cpp_target_builds_and_fuzzes_via_repair_pack() {
    if which::which("clang").is_err() && which::which("clang++").is_err() {
        eprintln!("skipping: no clang");
        return;
    }

    let fixture = repo_root().join("tests/fixtures/force_fuzz/win32_mfc");

    // Work-dir OUTSIDE the scanned tree so it is not itself discovered.
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-force-win32-")
        .tempdir()
        .expect("tempdir");
    let work_dir = tmp.path().join("auto_work");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&fixture)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--languages")
        .arg("cpp")
        .arg("--per-target-time")
        .arg("2")
        .arg("--no-discovery-cache")
        .output()
        .expect("spawn govfuzz auto");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let run_json = work_dir.join("auto/run.json");
    let raw = std::fs::read_to_string(&run_json).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; stdout=\n{stdout}\nstderr=\n{stderr}",
            run_json.display()
        )
    });
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse run.json");

    let targets = doc["targets"].as_array().expect("targets array");
    assert_eq!(
        targets.len(),
        1,
        "expected exactly one discovered target; run.json=\n{raw}"
    );

    let outcome = &targets[0]["outcome"]["outcome"];
    assert_eq!(
        outcome.as_str(),
        Some("built_and_fuzzed"),
        "Win32 C++ target must build and fuzz (not report_only / unsupported_params); \
         outcome={outcome}; stdout=\n{stdout}\nstderr=\n{stderr}"
    );

    // The build only succeeds because the repair loop injected the synthesized
    // windows.h — assert the win32_pack repair actually fired.
    let repairs = targets[0]["outcome"]["repairs"]
        .as_array()
        .expect("repairs array");
    assert!(
        repairs
            .iter()
            .any(|r| r["kind"].as_str() == Some("win32_pack")),
        "expected a win32_pack repair; repairs={repairs:?}"
    );
}
