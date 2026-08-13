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

/// The Go lane advertises "real edge coverage" of the TARGET. `go build -cover`
/// instruments only the packages being built, which is just the generated
/// harness `main` — the target module arrives as a dependency through the
/// module `replace`, so without `-coverpkg` the lane measures the harness
/// fuzzing itself and reports it as target coverage.
#[test]
fn go_coverage_instruments_the_target_module_not_just_the_harness() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let src = std::env::temp_dir().join(format!("gf_golane_cov_s_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work = std::env::temp_dir().join(format!("gf_golane_cov_w_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let out = Command::new(govfuzz_bin())
        .args([
            "auto",
            "--per-target-time",
            "5",
            "--max-targets",
            "1",
            "--single-pass",
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

    // Go embeds one coverage-meta entry per instrumented source file. The
    // fixture module's own files must be there; if only the harness were
    // instrumented, none would be.
    let mut binaries = Vec::new();
    for entry in std::fs::read_dir(work.join("harnesses")).expect("harnesses dir") {
        let bin = entry.expect("harness entry").path().join("main");
        if bin.is_file() {
            binaries.push(std::fs::read(&bin).expect("read harness binary"));
        }
    }
    assert!(
        !binaries.is_empty(),
        "no built Go harness binary to inspect"
    );
    // The coverage metadata spells each instrumented file as a STANDALONE
    // NUL-delimited string `<import path>/<file>.go`. The bare import path
    // appears in any build (it is the package reference), so the file-suffixed
    // form is what distinguishes instrumented from merely linked.
    let instrumented = binaries.iter().any(|bytes| {
        let needle = b"govfuzz.example/recordlib/recordparser/parser.go";
        bytes.windows(needle.len()).any(|window| window == needle)
    });
    assert!(
        instrumented,
        "the target module's files are absent from the coverage metadata, so \
         -coverpkg did not reach it and the lane is measuring only the harness"
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
