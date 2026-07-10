// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Builds the M4-instrumented swallowed-constraint-error fixture when GNAT is
/// available. CI currently lacks GNAT, so this test skips cleanly there.
#[test]
fn build_succeeds_for_instrumented_swallowed_ce_when_gnat_available() {
    if which::which("gprbuild").is_err() && which::which("gnatmake").is_err() {
        eprintln!("skipping: no Ada compiler on PATH");
        return;
    }

    let temp = temp_dir("m6-swallowed-ce");
    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ada_parser/tests/golden/ada95/swallowed_constraint_error/src.adb");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "instrument",
            source.to_str().expect("fixture path is utf-8"),
            "--output",
            instrumented_dir
                .to_str()
                .expect("instrumented path is utf-8"),
        ]),
        0
    );
    fs::rename(
        instrumented_dir.join("src.adb"),
        instrumented_dir.join("pkg.adb"),
    )
    .expect("instrumented package body is renamed to GNAT filename");
    fs::write(
        instrumented_dir.join("pkg.ads"),
        "--  SPDX-License-Identifier: Apache-2.0\npragma Ada_95;\npackage Pkg is\n   function Parse (S : String) return Integer;\nend Pkg;\n",
    )
    .expect("package spec is written");

    let instrumented_source = instrumented_dir.join("pkg.adb");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "generate-harness",
            instrumented_source
                .to_str()
                .expect("instrumented source path is utf-8"),
            "--target",
            "Parse",
            "--output",
            harness_root.to_str().expect("harness root path is utf-8"),
            "--id",
            "H-TEST",
        ]),
        0
    );

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-TEST",
        ]),
        0
    );
    assert!(work_dir.join("build/H-TEST/obj/main").exists());
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}
