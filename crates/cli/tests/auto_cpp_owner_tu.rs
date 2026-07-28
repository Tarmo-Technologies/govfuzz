// SPDX-License-Identifier: Apache-2.0
//
// A C++ target defined in a header that CANNOT compile standalone is still
// drivable, by falling back to the translation unit that owns the header.
//
// `scanner.hpp` uses `std::size_t` and `ScannerLimit` without including or
// declaring either; only `scanner.cpp` establishes that context before
// including it. Preflighting the header alone fails, which used to end the
// target as report-only with `blocked_by_non_self_contained_header` — the
// largest C++ residual class in the 500-project sweep (49 targets, plus 10
// in C).
//
// The owner TU is adopted only when it preflight-COMPILES, so a wrong
// candidate is rejected rather than guessed at.
//
// Second regression, from the same fixture: `ScannerLimit` is an enumerator
// defined in `scanner.cpp`. The repair loop used to answer the harness's
// "undeclared identifier" with `#define ScannerLimit …`, which is force-included
// ahead of every TU and rewrote the enum's own body to `{ 1 = 4 }` —
// "expected identifier", a build broken by its own repair.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/cpp_owner_tu")
        .canonicalize()
        .expect("canonicalize cpp_owner_tu fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

#[test]
fn a_target_in_a_non_self_contained_header_builds_via_its_owner_tu() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }

    // Copy outside the repo: the fixture lives under `tests/`, which discovery
    // excludes as a non-library directory when it is not the scan root.
    let src = std::env::temp_dir().join(format!("gf_cpp_owner_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    for entry in std::fs::read_dir(fixture()).unwrap().flatten() {
        std::fs::copy(entry.path(), src.join(entry.file_name())).unwrap();
    }
    let work = std::env::temp_dir().join(format!("gf_cpp_owner_w_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let seeds = std::env::temp_dir().join(format!("gf_cpp_owner_s_{}", std::process::id()));
    std::fs::create_dir_all(&seeds).unwrap();
    std::fs::write(seeds.join("trigger"), b"G\x00\x00\x00\x00\x00\x00\x00").unwrap();

    let out = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--per-target-time",
            "10",
            "--jobs",
            "1",
            "--seed-dir",
            seeds.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto on cpp_owner_tu fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !combined.contains("not self-contained"),
        "the header's owner TU supplies the missing context, so the target must \
         not end as blocked-by-non-self-contained-header:\n{combined}"
    );

    // The planted out-of-bounds read sits behind a byte gate inside the header's
    // function, so finding it proves the header was really compiled and driven —
    // not merely that something linked.
    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap_or_default();
    assert!(
        csv.contains("GF-201"),
        "the out-of-bounds read in the header target must be found:\n{csv}\n{combined}"
    );

    // The enumerator veto. `scan_twice` does not build here — its harness includes
    // the non-self-contained sibling header, which is a different path from the
    // header-target one fixed above. What must NOT happen is govfuzz making that
    // worse: `#define ScannerLimit …` is force-included ahead of every TU and
    // rewrites the enum's own body to `{ 1 = 4 }`, so the repair breaks a source
    // that compiled fine before. The honest `missing_macro` is the correct outcome.
    let run = std::fs::read_to_string(work.join("auto/run.json")).unwrap_or_default();
    assert!(
        !run.contains("\"name\": \"ScannerLimit\", \"as_value\": true, \"function_like\": false}"),
        "no repair may `#define` over an enumerator the project defines:\n{run}"
    );
    assert!(
        !combined.contains("scanner.cpp:7"),
        "a `#define ScannerLimit` corrupts the enum's own definition at \
         scanner.cpp:7 — a build broken by its own repair:\n{combined}"
    );

    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_dir_all(&seeds);
}
