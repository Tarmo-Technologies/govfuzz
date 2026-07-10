// SPDX-License-Identifier: Apache-2.0
//
// M3.1 native Python lane: the `python_lane` fixture is discovered + ranked by
// `govfuzz auto`, built into a framed CPython launcher, fuzzed by the builtin
// engine, and the planted uncontrolled-recursion bug surfaces as a CWE-674
// finding. The end-to-end portion skips cleanly when no `python3` is installed
// (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/python_lane")
        .canonicalize()
        .expect("canonicalize python_lane fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn have_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn discovers_and_ranks_python_targets() {
    let candidates = discover(&fixture()).expect("discover python_lane fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();

    assert!(
        candidates.iter().all(|c| c.lang == Lang::Python),
        "every candidate from the Python fixture is tagged Lang::Python: {names:?}"
    );
    assert!(
        names.contains(&"parse_record"),
        "public byte-channel entry `parse_record` discovered: {names:?}"
    );
    assert!(
        !names.contains(&"_walk"),
        "private helper `_walk` must be dropped by the ranker: {names:?}"
    );

    let parse = candidates
        .iter()
        .find(|c| c.name == "parse_record")
        .expect("parse_record discovered");
    assert!(
        parse.harness_id.starts_with("H-P"),
        "Python harness id prefix is H-P: {}",
        parse.harness_id
    );
}

#[test]
fn auto_builds_fuzzes_and_finds_recursion_cwe674() {
    if !have_python() {
        eprintln!("skipping: no python3 on PATH (GNAT-less rule)");
        return;
    }
    // Run from a temp copy OUTSIDE the repo so project-root detection doesn't
    // escape upward into the workspace.
    let src = std::env::temp_dir().join(format!("gf_pylane_it_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        fixture().join("recordparser.py"),
        src.join("recordparser.py"),
    )
    .unwrap();
    let work = std::env::temp_dir().join(format!("gf_pylane_itwork_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let out = Command::new(govfuzz_bin())
        .args([
            "auto",
            "--per-target-time",
            "10",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    assert!(
        out.status.success(),
        "govfuzz auto exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap_or_default();
    assert!(
        // cwe column carries the bare number (`674`), no `CWE-` prefix.
        csv.contains(",674;") || csv.contains(",674,"),
        "expected a CWE-674 uncontrolled-recursion finding in findings.csv:\n{csv}"
    );
    assert!(
        csv.contains("parse_record"),
        "the finding should point at parse_record:\n{csv}"
    );
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
}
