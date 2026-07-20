// SPDX-License-Identifier: Apache-2.0
//! Ada candidates share the run-level `src_instrumented` staging directory.
//! `--jobs > 1` must therefore serialize Ada attempts instead of letting one
//! worker replace source files while another gprbuild process reads them.

use std::path::Path;

fn have_ada_toolchain() -> bool {
    which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok()
}

#[test]
fn parallel_auto_serializes_ada_staging_and_builds_both_targets() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed - Ada lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-ada-parallel-")
        .tempdir()
        .expect("tempdir");
    let source = tmp.path().join("source");
    std::fs::create_dir_all(&source).expect("mkdir source");
    std::fs::write(
        source.join("parallel_ops.ads"),
        r#"package Parallel_Ops is
   function Parse_A (Value : Integer) return Integer;
   function Parse_B (Value : Integer) return Integer;
end Parallel_Ops;
"#,
    )
    .expect("write spec");
    std::fs::write(
        source.join("parallel_ops.adb"),
        r#"package body Parallel_Ops is
   function Parse_A (Value : Integer) return Integer is (Value + 1);
   function Parse_B (Value : Integer) return Integer is (Value - 1);
end Parallel_Ops;
"#,
    )
    .expect("write body");

    let work = tmp.path().join("work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(&source)
        .arg("--work-dir")
        .arg(&work)
        .arg("--profile")
        .arg("external-tools")
        .arg("--deps-only")
        .arg("--languages")
        .arg("ada")
        .arg("--max-targets")
        .arg("2")
        .arg("--jobs")
        .arg("2")
        .output()
        .expect("spawn govfuzz auto");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Ada targets share the staged source layout and will build serially"),
        "the operator must be told that Ada is serialized:\n{stderr}"
    );
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join(Path::new("auto/run.json"))).unwrap_or_else(|error| {
            panic!(
                "read run.json: {error}; exit={:?}\nstderr:\n{stderr}",
                output.status.code()
            )
        }),
    )
    .expect("parse run.json");
    let targets = run["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 2, "run={run}");
    for target in targets {
        assert_eq!(
            target["outcome"]["outcome"].as_str(),
            Some("built"),
            "both Ada targets must build under --jobs 2; target={target}; stderr:\n{stderr}"
        );
    }
}
