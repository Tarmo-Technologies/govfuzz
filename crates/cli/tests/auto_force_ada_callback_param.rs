// SPDX-License-Identifier: Apache-2.0

//! A parameter satisfied with `X'Access` — a callback — was recorded as a closed
//! boundary for `--force` stubbing. The claim was that such a profile is always
//! written in CLIENT types a stub cannot name without a circular unit dependency.
//!
//! A real consumer showed the premise is usually false: a library's callback is
//! written in the LIBRARY's own types, which the stub declares itself. This is
//! that shape, driven through real GNAT.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

fn gnat_available() -> bool {
    which::which("gprbuild").is_ok() && which::which("gnatmake").is_ok()
}

fn outcome_for(fixture: &Path, work_dir: &Path, force: bool) -> String {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    command
        .arg("auto")
        .arg(fixture)
        .arg("--work-dir")
        .arg(work_dir)
        .arg("--per-target-time")
        .arg("1")
        .arg("--no-discovery-cache");
    if force {
        command.arg("--force");
    }
    let output = command.output().expect("spawn govfuzz auto");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let raw = std::fs::read_to_string(work_dir.join("auto/run.json"))
        .unwrap_or_else(|e| panic!("read run.json: {e}; stderr=\n{stderr}"));
    let run: serde_json::Value = serde_json::from_str(&raw).expect("run.json parses");
    run["targets"][0]["outcome"]["outcome"]
        .as_str()
        .unwrap_or("<none>")
        .to_owned()
}

#[test]
fn a_callback_parameter_of_a_missing_library_builds_and_fuzzes_under_force() {
    if !gnat_available() {
        eprintln!("skipping: no GNAT toolchain");
        return;
    }
    let fixture = repo_root().join("tests/fixtures/force_fuzz/ada_callback_lib");
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-callback-")
        .tempdir()
        .expect("tempdir");

    let outcome = outcome_for(&fixture, &tmp.path().join("work"), true);

    assert_eq!(
        outcome, "built_and_fuzzed",
        "a callback whose profile is written in the missing library's own types \
         must be stubbable"
    );

    // The synthesized parameter must be an ANONYMOUS access-to-subprogram. Ada
    // rejects `X'Access` when X is nested more deeply than the access type, and
    // the fixture's callback is declared inside the body that passes it — so a
    // named library-level access type compiles in isolation and then fails here
    // with "subprogram must not be deeper than access type".
    let stub = std::fs::read_to_string(
        tmp.path()
            .join("work")
            .join("ada_external_stubs")
            .join("vendorcb.ads"),
    )
    .expect("the missing library was reconstructed");
    assert!(
        stub.contains("access procedure (Name : Field_Name; Value : Field_Value)"),
        "the callback parameter must carry the client's profile: {stub}"
    );
    assert!(
        !stub.contains("is access procedure"),
        "a NAMED access type would reintroduce the accessibility rejection: {stub}"
    );
}

#[test]
fn the_same_target_does_not_build_without_force() {
    if !gnat_available() {
        eprintln!("skipping: no GNAT toolchain");
        return;
    }
    let fixture = repo_root().join("tests/fixtures/force_fuzz/ada_callback_lib");
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-callback-noforce-")
        .tempdir()
        .expect("tempdir");

    let outcome = outcome_for(&fixture, &tmp.path().join("work"), false);

    assert_ne!(
        outcome, "built_and_fuzzed",
        "without --force the missing library is not reconstructed at all, so this \
         must not appear to succeed"
    );
}
