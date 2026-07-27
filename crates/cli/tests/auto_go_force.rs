// SPDX-License-Identifier: Apache-2.0
//
// `auto --force` on the Go lane. Both fixture targets are undrivable by the
// type-directed generator — one is a METHOD (needs a receiver), one takes a MAP
// (no byte decoder) — so without the flag they are a clean `unsupported_params`
// skip, which is the residual blocker on 116 Go targets in the sweep.
//
// Forced, each is called on a synthesized zero value and reaches its planted
// out-of-bounds read. Because the value is fabricated, the run must ALSO mark the
// target `forced` and floor its findings to `low`: a nil map or zero receiver can
// panic on its own account, and such a crash may never read as a confirmed defect.
//
// Skips cleanly when no `go` toolchain is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_force")
        .canonicalize()
        .expect("canonicalize go_force fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn have_go() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(tag: &str, force: bool) -> (PathBuf, serde_json::Value) {
    let src = std::env::temp_dir().join(format!("gf_goforce_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work = std::env::temp_dir().join(format!("gf_goforce_w_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let mut cmd = Command::new(govfuzz_bin());
    cmd.args([
        "auto",
        "--per-target-time",
        "8",
        "--single-pass",
        "--jobs",
        "1",
        "--work-dir",
        work.to_str().unwrap(),
        src.to_str().unwrap(),
    ]);
    if force {
        cmd.arg("--force");
    }
    // The exit status is not asserted: a run where NOTHING fuzzed exits non-zero by
    // design, and the unforced arm is exactly that run. What is under test is the
    // recorded outcome, so read run.json either way.
    let out = cmd.output().expect("run govfuzz auto");
    assert!(
        work.join("auto/run.json").is_file(),
        "no run.json written: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).expect("run.json"))
            .expect("parse run.json");
    let _ = std::fs::remove_dir_all(&src);
    (work, json)
}

#[test]
fn unforced_go_method_and_undrivable_param_skip_cleanly() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let (work, json) = run("plain", false);
    assert_eq!(
        json["summary"]["unsupported_params"], 2,
        "both targets are undrivable without --force: {json}"
    );
    assert_eq!(json["summary"]["built_and_fuzzed"], 0);
    let reasons = json["targets"].to_string();
    assert!(
        reasons.contains("needs a receiver value"),
        "the method must say what is missing: {reasons}"
    );
    assert!(
        reasons.contains("unsupported Go parameter type"),
        "the map parameter must say what is missing: {reasons}"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn forced_go_targets_build_fuzz_and_are_marked_forced() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let (work, json) = run("forced", true);
    assert_eq!(
        json["summary"]["built_and_fuzzed"], 2,
        "both targets fuzz once forced: {json}"
    );
    // Every forced target is counted as such, so N forced targets are never read
    // as N confirmed campaigns.
    assert_eq!(json["summary"]["forced"], 2, "{json}");

    // The synthesized value is recorded on the target, naming what was fabricated.
    let targets = json["targets"].to_string();
    assert!(
        targets.contains("forced_synthetic_params"),
        "the forced synthesis must be on the repair ledger: {targets}"
    );
    assert!(
        targets.contains("receiver tgt.Decoder"),
        "the receiver synthesis must name the type: {targets}"
    );

    // The planted CWE-125 reads are found, and every row is floored to `low` with
    // the forced caveat — the fabricated value makes any crash a maybe.
    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).expect("findings.csv");
    let header: Vec<&str> = csv.lines().next().expect("header").split(',').collect();
    let confidence = header.iter().position(|c| *c == "confidence").unwrap();
    let mut rows = 0usize;
    for row in csv.lines().skip(1) {
        rows += 1;
        let cells: Vec<&str> = row.split(',').collect();
        assert_eq!(
            cells[confidence], "low",
            "a forced finding must be low-confidence: {row}"
        );
        assert!(
            row.contains("stub artifact"),
            "a forced finding must carry the caveat note: {row}"
        );
    }
    assert!(rows > 0, "the planted panics must be found:\n{csv}");
    assert!(
        csv.contains(",125;") || csv.contains(",125,"),
        "expected a CWE-125 index-out-of-bounds finding:\n{csv}"
    );
    let _ = std::fs::remove_dir_all(&work);
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}
