// SPDX-License-Identifier: Apache-2.0
//
// A JS/TS harness can BUILD and still be unable to run: the module loads and the
// export resolves, but constructing the receiver for a `Class#method` throws
// because the class wants an environment that is not here. The driver died in its
// load path, the engine recorded a harness that ran ZERO inputs, and the run
// reported `built, no fuzz pass ran` — a row naming nothing, on 58 targets across
// the 500-project sweep (gstack's `BrowseClient` wants a live daemon port).
//
// The gate is LOAD-ONLY on purpose. A finding halts the driver with a nonzero
// exit, so "run one input and see if it exits cleanly" would have skipped exactly
// the targets that crash — which is why this fixture also carries a fuzzable
// sibling with a planted throw, and why the test asserts that one still fuzzes.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/js_unconstructible")
        .canonicalize()
        .expect("canonicalize js_unconstructible fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn have_node() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn an_unconstructible_receiver_skips_with_its_reason_and_its_sibling_still_fuzzes() {
    if !have_node() {
        eprintln!("skipping: no node runtime on PATH (GNAT-less rule)");
        return;
    }
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }

    // Copy outside the repo: the fixture lives under `tests/`, which discovery
    // excludes as a non-library directory when it is not the scan root.
    let src = std::env::temp_dir().join(format!("gf_js_unconstructible_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    for entry in std::fs::read_dir(fixture()).unwrap().flatten() {
        std::fs::copy(entry.path(), src.join(entry.file_name())).unwrap();
    }
    let work = std::env::temp_dir().join(format!("gf_js_unconstructible_w_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let out = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--per-target-time",
            "5",
            "--single-pass",
            "--jobs",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto on js_unconstructible fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !combined.contains("built, no fuzz pass ran"),
        "a harness that cannot be prepared must say so, not report an anonymous \
         build:\n{combined}"
    );
    assert!(
        combined.contains("cannot find daemon port"),
        "the reason must be the constructor's own error:\n{combined}"
    );

    // The fuzzable sibling is untouched: it builds, runs, and its planted throw
    // is found. This is what a run-one-input gate would have broken.
    assert!(
        combined.contains("1 built+fuzzed") || combined.contains("built+fuzzed"),
        "the fuzzable sibling must still fuzz:\n{combined}"
    );
    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap_or_default();
    assert!(
        csv.contains("parseThing"),
        "the planted throw in the sibling must still be found:\n{csv}\n{combined}"
    );

    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
}
