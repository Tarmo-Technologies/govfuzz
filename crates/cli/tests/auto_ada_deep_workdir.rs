// SPDX-License-Identifier: Apache-2.0
//! Regression for #411: `govfuzz auto` must not abort a buildable Ada
//! harness just because a user `.gpr` in the source root `with`s
//! govfuzz's own bundled `ada_runtime/adafuzz.gpr`.
//!
//! `prepare_layout` forwards the `with` clauses of top-level user gprs
//! into the generated `govfuzz_build.gpr`. That file lives several
//! directories deeper (`<work_dir>/build/<id>/`) than the source gpr,
//! and gprbuild resolves a `with` relative to the *importing* project's
//! own directory — so a clause kept relative resolved against the wrong
//! base, and govfuzz reported its own runtime as a missing GPR import
//! (`unrecoverable_link`, work-dir-depth dependent). The bundled
//! `adafuzz.gpr` is now never re-forwarded (the build-local
//! `adafuzz_runtime.gpr` already provides those units), and any other
//! forwarded relative import is absolutized so it stays depth-correct.
//!
//! Gated on the Ada toolchain being installed; skipped (with a notice)
//! otherwise.

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
fn ada_target_builds_when_user_gpr_withs_bundled_adafuzz_in_deep_workdir() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-411-deep-workdir-")
        .tempdir()
        .expect("tempdir");
    // A source root buried several levels deep and in a completely
    // different filesystem subtree than the govfuzz install — the
    // condition under which #411 mis-computed the `../` depth.
    let srcroot = tmp.path().join("a/b/c/d/srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");

    let fixture = repo_root().join("tests/fixtures/build_recovery/fixtures/ada_basic");
    copy_ada_sources(&fixture, &srcroot);

    // A user harness project that `with`s govfuzz's bundled runtime via
    // a relative path. Before the fix this clause was forwarded verbatim
    // into govfuzz_build.gpr (deeper in the tree), where the relative
    // path no longer resolves — gprbuild reported `adafuzz.gpr` as a
    // missing import and every Ada target became `unrecoverable_link`.
    std::fs::write(
        srcroot.join("harness_proj.gpr"),
        "--  SPDX-License-Identifier: Apache-2.0\n\
         with \"../adafuzz_runtime_not_shipped/adafuzz.gpr\";\n\
         project Harness_Proj is\n\
         \u{20}\u{20}\u{20}for Languages use (\"Ada\");\n\
         \u{20}\u{20}\u{20}for Source_Dirs use (\".\");\n\
         \u{20}\u{20}\u{20}for Object_Dir use \"obj\";\n\
         \u{20}\u{20}\u{20}for Main use (\"harness.adb\");\n\
         end Harness_Proj;\n",
    )
    .expect("write harness_proj.gpr");

    // work_dir.parent() (= srcroot) is where prepare_layout scans for
    // user gprs, so the work dir lives directly under the source root.
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

    let summary = &run_json["summary"];
    let built_and_fuzzed = summary["built_and_fuzzed"].as_u64().unwrap_or(0);
    let unrecoverable_link = summary["unrecoverable_link"].as_u64().unwrap_or(0);

    // Acceptance criterion 3: deep work-dir -> built_and_fuzzed >= 1.
    assert!(
        built_and_fuzzed >= 1,
        "expected >=1 Ada target built+fuzzed, got summary={summary}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        unrecoverable_link, 0,
        "no Ada target should hit unrecoverable_link after #411 fix; summary={summary}",
    );

    // govfuzz's own bundled runtime must never be reported as a missing
    // import.
    let empty = Vec::new();
    let missing_gpr = run_json["needed_for_build"]["missing_gpr_imports"]
        .as_array()
        .unwrap_or(&empty);
    assert!(
        !missing_gpr.iter().any(|e| e["name"]
            .as_str()
            .is_some_and(|n| n.ends_with("adafuzz.gpr"))),
        "bundled adafuzz.gpr must not appear in missing_gpr_imports: {missing_gpr:?}",
    );
}
