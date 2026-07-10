// SPDX-License-Identifier: Apache-2.0
//! Campaign (json-ada): a generic package whose operation takes a PRIVATE type
//! built through constructor functions that also live in the generic.
//!
//! govfuzz already instantiates such a generic and qualifies the operation and
//! the parameter TYPE through the synthesised instance
//! (`Govfuzz_Generic_Instance.Get`, `Govfuzz_Generic_Instance.Value`). The bug
//! this guards: the synthesised value-decoder built the `Object` argument by
//! calling the constructor functions through the *uninstantiated generic package*
//! (`Value_Pkg.Create_Null`), which GNAT rejects with
//! "prefix must not be a generic package", so 20 json-ada harnesses failed to
//! build. The constructors must be reached through the instance too.
//!
//! This drives the real `govfuzz auto` against the bundled fixture and asserts:
//!   - the `get` target actually `built_and_fuzzed` under GNAT (the emitted
//!     harness compiles — no "prefix must not be a generic package"), and
//!   - its harness names the constructors through the instance, never through the
//!     uninstantiated generic package.
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
fn generic_package_operation_with_private_ctor_param_builds_through_instance() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-jsonada-generic-ctor-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/ada_generic_private_ctor");
    copy_ada_sources(&fixture, &srcroot);

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

    // The `get` target takes a private `Value` declared in the generic package,
    // so its argument is built via the generic's `Create_Null`/`Create_Boolean`
    // constructors. If those were named through the uninstantiated generic
    // (`Value_Pkg.Create_Null`), GNAT would reject the harness with "prefix must
    // not be a generic package" and the target would be `failed_build`. A
    // `built_and_fuzzed` outcome proves the constructors are reached through the
    // instance instead.
    let get_target = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("get"))
        .unwrap_or_else(|| {
            panic!(
                "no `get` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        get_target["outcome"]["outcome"].as_str(),
        Some("built_and_fuzzed"),
        "the generic-package `get` target must build+fuzz (constructors named \
         through the instance, no \"prefix must not be a generic package\"); \
         target={get_target}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // And its harness must name BOTH the target and the value constructors
    // through the synthesised instance, never through the uninstantiated generic.
    let harness_id = get_target["harness_id"]
        .as_str()
        .expect("get target harness_id");
    let main_adb_path = work_dir.join("harnesses").join(harness_id).join("main.adb");
    let main_adb = std::fs::read_to_string(&main_adb_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", main_adb_path.display()));

    assert!(
        main_adb.contains("Govfuzz_Generic_Instance.Create_Null"),
        "the value decoder must reach the constructor through the instance:\n{main_adb}"
    );
    // The constructor must NOT be named through the uninstantiated generic
    // package (case-insensitive: Ada folds case, and the parser may record the
    // unit lowercase).
    let lowered = main_adb.to_ascii_lowercase();
    assert!(
        !lowered.contains("value_pkg.create_null") && !lowered.contains("value_pkg.create_boolean"),
        "the constructor must not be named through the uninstantiated generic \
         package (\"prefix must not be a generic package\"):\n{main_adb}"
    );
    assert!(
        main_adb.contains("Govfuzz_Generic_Instance.get"),
        "the target must be called through the instance:\n{main_adb}"
    );
}
