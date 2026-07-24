// SPDX-License-Identifier: Apache-2.0

//! Offline-legacy audit regression tests: end-to-end proof that the audit fixes
//! restore fuzzing on shapes that previously failed silently.
//!  - #1: a LIBRARY-project Ada repo builds + enters the target (was a hard
//!    "a project extending a library project must specify an attribute
//!    Library_Dir" failure — zero executions).
//!  - #5: a mixed K&R + ANSI C translation unit discovers BOTH functions (the
//!    ANSI-prototyped parser was silently dropped when any K&R def was present).

use std::path::Path;
use std::process::Command;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-legacy-audit-{tag}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_auto(root: &Path, work: &Path, extra: &[&str]) -> serde_json::Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    cmd.arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass");
    for arg in extra {
        cmd.arg(arg);
    }
    let output = cmd.output().expect("spawn govfuzz auto");
    let bytes = std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
        panic!(
            "read run.json: {e}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    serde_json::from_slice(&bytes).expect("parse run.json")
}

#[test]
fn library_project_ada_repo_builds_and_enters_the_target() {
    if which::which("gnatmake").is_err() || which::which("gprbuild").is_err() {
        eprintln!("SKIP: GNAT/gprbuild not on PATH");
        return;
    }
    let root = tmpdir("ada-lib");
    std::fs::create_dir_all(root.join("src")).unwrap();
    // A library project cannot be EXTENDED without declaring Library_Dir (and can't
    // hold the harness Main). The fix builds a standalone project over the
    // instrumented source overlay instead.
    std::fs::write(
        root.join("lib.gpr"),
        "library project Lib is\n\
         \x20  for Source_Dirs use (\"src\");\n\
         \x20  for Library_Name use \"lib\";\n\
         \x20  for Library_Kind use \"static\";\n\
         \x20  for Library_Dir use \"libdir\";\n\
         \x20  for Object_Dir use \"obj\";\n\
         end Lib;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/lib_parser.ads"),
        "package Lib_Parser is\n   function Parse (Data : String) return Integer;\nend Lib_Parser;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/lib_parser.adb"),
        "package body Lib_Parser is\n\
         \x20  function Parse (Data : String) return Integer is\n\
         \x20  begin\n\
         \x20     if Data'Length >= 3 and then Data (Data'First) = 'L' then\n\
         \x20        return 1;\n\
         \x20     end if;\n\
         \x20     return 0;\n\
         \x20  end Parse;\n\
         end Lib_Parser;\n",
    )
    .unwrap();
    let work = tmpdir("ada-lib-work");
    let run = run_auto(&root, &work, &["--target", "Parse"]);
    let targets = run["targets"].as_array().expect("targets array");
    let parse = targets
        .iter()
        .find(|t| t["name"] == "parse" || t["name"] == "Parse")
        .expect("Parse target present");
    assert_eq!(
        parse["outcome"]["outcome"], "built_and_fuzzed",
        "a library-project Ada target must build and fuzz (not fail on Library_Dir): {parse:#}"
    );
    let entered = parse["outcome"]["passes"]
        .as_array()
        .map(|passes| passes.iter().any(|p| p["target_entry_observed"] == true))
        .unwrap_or(false);
    assert!(entered, "the target must be entered: {parse:#}");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn mixed_knr_and_ansi_c_discovers_both_functions() {
    let root = tmpdir("knr-ansi");
    // One old-style K&R helper + one ANSI-prototyped parser (the real fuzz target).
    // Before the fix, the whole file was classified K&R and the ANSI function was
    // dropped from the candidate set entirely.
    std::fs::write(
        root.join("legacy.c"),
        "#include <stddef.h>\n\
         int oldstyle(a, b)\n\
         int a;\n\
         int b;\n\
         { return a + b; }\n\
         int parse_packet(const unsigned char *data, unsigned long len)\n\
         { if (len >= 4 && data[0] == 'P' && data[1] == 'K') return 1; return 0; }\n",
    )
    .unwrap();
    let work = tmpdir("knr-ansi-work");
    let run = run_auto(&root, &work, &[]);
    let names: Vec<String> = run["targets"]
        .as_array()
        .map(|targets| {
            targets
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        names.iter().any(|n| n.contains("parse_packet")),
        "the ANSI-prototyped parser must be discovered in a mixed K&R file: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("oldstyle")),
        "the K&R helper must still be discovered: {names:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}
