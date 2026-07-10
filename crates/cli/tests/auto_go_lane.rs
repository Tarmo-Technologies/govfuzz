// SPDX-License-Identifier: Apache-2.0
//
// M3.3 native Go lane: the `go_lane` fixture module is discovered + ranked, built
// into a framed harness binary, fuzzed by the builtin engine, and the planted
// index-out-of-range panic surfaces as a CWE-125 finding. The end-to-end portion
// skips cleanly when no `go` toolchain is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_lane")
        .canonicalize()
        .expect("canonicalize go_lane fixture")
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
fn discovers_and_ranks_go_functions() {
    let candidates = discover(&fixture()).expect("discover go_lane fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    assert!(
        candidates.iter().all(|c| c.lang == Lang::Go),
        "every candidate is Lang::Go: {names:?}"
    );
    assert!(
        names.contains(&"ParseRecord"),
        "exported []byte parser discovered: {names:?}"
    );
    let p = candidates
        .iter()
        .find(|c| c.name == "ParseRecord")
        .expect("ParseRecord discovered");
    assert!(
        p.harness_id.starts_with("H-G"),
        "Go id prefix H-G: {}",
        p.harness_id
    );
}

#[test]
fn auto_builds_fuzzes_and_finds_index_oob_cwe125() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    // Run from a temp copy of the whole module (go.mod + package) outside the repo.
    let src = std::env::temp_dir().join(format!("gf_golane_it_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work = std::env::temp_dir().join(format!("gf_golane_w_{}", std::process::id()));
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
    assert!(
        out.status.success(),
        "govfuzz auto exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap_or_default();
    assert!(
        // cwe column carries the bare number (`125`), no `CWE-` prefix.
        csv.contains(",125;") || csv.contains(",125,"),
        "expected a CWE-125 index-out-of-bounds finding in findings.csv:\n{csv}"
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
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}
