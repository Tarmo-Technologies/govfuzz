// SPDX-License-Identifier: Apache-2.0
//! Campaign regression: an Ada subprogram whose parameter is a cross-package
//! `Ada.Strings.Bounded.Generic_Bounded_Length` instance's `Bounded_String`
//! (`Str_Defs.Bounded_750_Type.Bounded_String`). The AST does not model the
//! instantiation, so this used to skip with "named type ... is not declared in
//! the parsed source set and has no synthesizable constructor". The decoder now
//! recognizes the standard `Bounded_String` leaf and builds the argument via the
//! instance's `To_Bounded_String (.., Ada.Strings.Right)`.
//!
//! Drives the real `govfuzz auto` against the bundled fixture and asserts the
//! `process` target built+fuzzed under GNAT (the emitted harness compiles) and
//! that the harness constructs the value through `To_Bounded_String`.
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

#[test]
fn bounded_string_param_builds_via_to_bounded_string() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-bounded-string-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/ada_bounded_string");
    for entry in std::fs::read_dir(&fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        let is_ada = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "ads" || e == "adb");
        if is_ada {
            std::fs::copy(&path, srcroot.join(path.file_name().unwrap())).expect("copy ada source");
        }
    }

    let work_dir = srcroot.join("govfuzz_work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&srcroot)
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

    let process = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("process"))
        .unwrap_or_else(|| {
            panic!(
                "no `process` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        process["outcome"]["outcome"].as_str(),
        Some("built_and_fuzzed"),
        "the Bounded_String param must decode via To_Bounded_String and build; \
         target={process}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let harness_id = process["harness_id"].as_str().expect("harness_id");
    let main_adb =
        std::fs::read_to_string(work_dir.join("harnesses").join(harness_id).join("main.adb"))
            .expect("read harness main.adb");
    assert!(
        main_adb.contains("To_Bounded_String") && main_adb.contains("Ada.Strings.Right"),
        "the bounded-string arg must be built with a truncating To_Bounded_String:\n{main_adb}"
    );
}
