// SPDX-License-Identifier: Apache-2.0
//
// A target whose opaque-handle parameter is defined only in its OWN translation
// unit is drivable. `parser.h` forward-declares `pv_session`; `struct pv_session`
// is complete only in `parser.c`, beside the target — the shape antirez/ds4 has,
// and the one that used to end in "opaque handle … is incomplete in the harness's
// included headers … cannot stack-allocate it — skipping".
//
// The lifecycle path stack-allocates the handle, which needs a COMPLETE type. The
// definition is right there in the TU the target lives in, so the harness takes
// the whole-TU include already used for static targets. The planted
// out-of-bounds read is behind a byte gate, so finding it proves the handle was
// really allocated and passed rather than merely that the harness compiled.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/c_private_handle")
        .canonicalize()
        .expect("canonicalize c_private_handle fixture")
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
fn an_opaque_handle_defined_only_in_the_target_tu_is_drivable() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }

    // Copy outside the repo: the fixture lives under `tests/`, which discovery
    // excludes as a non-library directory when it is not the scan root.
    let src = std::env::temp_dir().join(format!("gf_c_private_handle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    for entry in std::fs::read_dir(fixture()).unwrap().flatten() {
        std::fs::copy(entry.path(), src.join(entry.file_name())).unwrap();
    }
    let work = std::env::temp_dir().join(format!("gf_c_private_handle_w_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let seeds = std::env::temp_dir().join(format!("gf_c_private_handle_s_{}", std::process::id()));
    std::fs::create_dir_all(&seeds).unwrap();
    std::fs::write(seeds.join("trigger"), b"G\x00\x00\x00\x00\x00\x00\x00").unwrap();

    let out = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--per-target-time",
            "10",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--seed-dir",
            seeds.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto on c_private_handle fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !combined.contains("incomplete in the harness's included headers"),
        "the handle's definition is in the target's own TU, so it must not be \
         reported incomplete:\n{combined}"
    );
    assert!(
        combined.contains("built+fuzzed"),
        "the target must build and fuzz:\n{combined}"
    );

    let csv = std::fs::read_to_string(work.join("auto/findings.csv")).unwrap_or_default();
    assert!(
        csv.contains("pv_session_scan"),
        "the planted out-of-bounds read is reached only through the stack-allocated \
         handle, so finding it is the proof:\n{csv}\n{combined}"
    );

    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_dir_all(&seeds);
}
