// SPDX-License-Identifier: Apache-2.0
//! Campaign regression: a source tree with a same-stem Ada body and C source
//! (`sxxx.adb` + `sxxx.c`). Both compile to `sxxx.o`, and gprbuild rejects the
//! whole project with "... have the same object file name", so the Ada harness
//! failed to build. govfuzz now excludes the colliding C file from the generated
//! project (`for Excluded_Source_Files use ("sxxx.c");`) so the Ada unit — the
//! harness target — wins and the build succeeds.
//!
//! Drives the real `govfuzz auto` against the bundled fixture and asserts the Ada
//! `run` target built+fuzzed and the generated `govfuzz_build.gpr` excludes the C.
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
fn same_stem_c_source_excluded_so_ada_harness_builds() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-object-collision-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/ada_c_object_collision");
    for entry in std::fs::read_dir(&fixture).expect("read fixture dir") {
        let path = entry.expect("dir entry").path();
        let keep = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "ads" || e == "adb" || e == "c");
        if keep {
            std::fs::copy(&path, srcroot.join(path.file_name().unwrap())).expect("copy source");
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

    let run_target = run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| {
            t["name"].as_str() == Some("run")
                && t["source"].as_str().is_some_and(|s| s.ends_with(".ads"))
        })
        .unwrap_or_else(|| {
            panic!(
                "no Ada `run` target discovered; run.json={run_json}\nstderr=\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        run_target["outcome"]["outcome"].as_str(),
        Some("built_and_fuzzed"),
        "the Ada harness must build despite the same-stem C collision; \
         target={run_target}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The generated project must have dropped the colliding C file.
    let harness_id = run_target["harness_id"].as_str().expect("harness_id");
    let gpr = std::fs::read_to_string(
        work_dir
            .join("build")
            .join(harness_id)
            .join("govfuzz_build.gpr"),
    )
    .expect("read govfuzz_build.gpr");
    assert!(
        gpr.contains("for Excluded_Source_Files use (\"sxxx.c\");"),
        "the colliding C source must be excluded:\n{gpr}"
    );
}
