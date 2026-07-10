// SPDX-License-Identifier: Apache-2.0
//! §27.8 / #457: Ada access-type opaque-handle lifecycle EMISSION end-to-end.
//!
//! A target consuming an access-type opaque handle (`Parse (Ctx :
//! Context_Access; Data : String)`) whose type exposes a Create/Destroy
//! lifecycle must have its harness BUILD the handle through the constructor and
//! tear it down after the call (`Ctx := Create; .. ; Destroy (Ctx);`) instead of
//! passing the null/slot value the callee would dereference. This drives the real
//! `govfuzz auto` against the bundled fixture and asserts:
//!   - the `Parse` target actually `built_and_fuzzed` under GNAT (the emitted
//!     lifecycle Ada compiles), and
//!   - its generated harness contains the Create -> call -> Destroy sequence
//!     (not the `Slots_*` null/slot decoder).
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
fn ada_access_handle_target_builds_with_create_destroy_lifecycle() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-457-ada-lifecycle-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/ada_access_lifecycle");
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

    // The `Parse` target (Context_Access opaque handle + String) must build+fuzz:
    // if the emitted lifecycle Ada did not compile, it would not be built_and_fuzzed.
    let parse_target = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("parse"))
        .unwrap_or_else(|| {
            panic!(
                "no `parse` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        parse_target["outcome"]["outcome"].as_str(),
        Some("built_and_fuzzed"),
        "the access-handle `parse` target must build+fuzz with its Create/Destroy \
         lifecycle; target={parse_target}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // And its harness must use the lifecycle sequence, not the null/slot decoder.
    let harness_id = parse_target["harness_id"]
        .as_str()
        .expect("parse target harness_id");
    let main_adb_path = work_dir.join("harnesses").join(harness_id).join("main.adb");
    let main_adb = std::fs::read_to_string(&main_adb_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", main_adb_path.display()));

    let create_pos = main_adb
        .find("Ctx := Parser_Ctx.Create;")
        .unwrap_or_else(|| panic!("missing Create init in harness:\n{main_adb}"));
    let call_pos = main_adb
        .find("Parser_Ctx.Parse (Ctx,")
        .unwrap_or_else(|| panic!("missing Parse call in harness:\n{main_adb}"));
    let destroy_pos = main_adb
        .find("Parser_Ctx.Destroy (Ctx);")
        .unwrap_or_else(|| panic!("missing Destroy cleanup in harness:\n{main_adb}"));
    assert!(
        create_pos < call_pos && call_pos < destroy_pos,
        "expected Create -> Parse -> Destroy ordering in harness:\n{main_adb}"
    );
    assert!(
        !main_adb.contains("Slots_Ctx"),
        "the null/slot access decoder must not be used when a lifecycle exists:\n{main_adb}"
    );
}
