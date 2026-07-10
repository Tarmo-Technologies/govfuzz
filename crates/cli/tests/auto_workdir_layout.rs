// SPDX-License-Identifier: Apache-2.0

//! `govfuzz auto` should keep generated per-target harness artifacts under a
//! dedicated harnesses directory, leaving `auto/` for campaign reports.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-layout-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

#[test]
fn auto_writes_generated_harnesses_under_harnesses_dir() {
    if !support::libfuzzer_toolchain_available("layout") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("probe.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return (int)(n + (d ? 0 : 0)); }\n",
    )
    .unwrap();
    let work = root.join("work");

    let output = support::govfuzz_cargo_command()
        .current_dir(&root)
        .args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            "--max-targets",
            "1",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    assert!(
        output.status.success() || output.status.code() == Some(1),
        "govfuzz auto should complete far enough to emit harness artifacts; status={:?}\nstderr=\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let harness_root = work.join("harnesses");
    let harness_dirs = subdirs(&harness_root);
    assert_eq!(
        harness_dirs.len(),
        1,
        "expected exactly one generated harness under {}; stderr=\n{}",
        harness_root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let harness_dir = &harness_dirs[0];
    let harness_id = harness_dir.file_name().unwrap().to_string_lossy();
    assert!(harness_dir.join("main.c").is_file(), "{harness_dir:?}");
    assert!(harness_dir.join("Makefile").is_file(), "{harness_dir:?}");
    assert!(harness_dir.join("repairs").is_dir(), "{harness_dir:?}");

    assert!(
        !work.join("auto").join(harness_id.as_ref()).exists(),
        "per-target generated artifacts should not be mixed into the report directory"
    );
    assert!(work.join("auto").join("run.json").is_file());

    let summary = fs::read_to_string(work.join("auto").join("summary.txt")).unwrap();
    assert!(
        summary.contains(&format!(
            "harnesses: {}/<harness-id>/",
            harness_root.display()
        )),
        "summary should point users at the harnesses directory:\n{summary}"
    );
}
