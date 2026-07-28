// SPDX-License-Identifier: Apache-2.0
//
// A Go target under `internal/` is reachable. Go decides "outside the internal
// tree" from the IMPORT PATH, so a harness module named `govfuzzharness` was
// outside every project and could not import such a package at all — `use of
// internal package … not allowed`, reported as a failed BUILD rather than as the
// naming problem it was. Eight targets in three of the 500-project sweep's Go
// repos, and `internal/` is where a great deal of real Go code lives.
//
// The fixture is the `go_lane` parser moved under `internal/`, so the planted
// index-out-of-range panic (CWE-125) proves the harness both COMPILED against
// the internal package and ran it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_internal")
        .canonicalize()
        .expect("canonicalize go_internal fixture")
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

#[test]
fn a_target_under_internal_builds_and_fuzzes() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let src = std::env::temp_dir().join(format!("gf_gointernal_it_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work = std::env::temp_dir().join(format!("gf_gointernal_w_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let out = Command::new(govfuzz_bin())
        .args([
            "auto",
            "--per-target-time",
            "8",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("use of internal package"),
        "the harness module must be inside the tree that may import it:\n{combined}"
    );

    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap_or_default();
    assert!(
        csv.contains(",125;") || csv.contains(",125,"),
        "expected a CWE-125 finding from the internal package:\n{csv}\n{combined}"
    );
    assert!(
        csv.contains("ParseRecord"),
        "the finding should point at ParseRecord:\n{csv}"
    );
    let _ = std::fs::remove_dir_all(&src);
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
            std::fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}
