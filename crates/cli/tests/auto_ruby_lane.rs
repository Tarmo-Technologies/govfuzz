// SPDX-License-Identifier: Apache-2.0
//
// M3.9 native Ruby lane: the `ruby_lane` fixture is discovered, built into a framed
// `ruby` launcher (TracePoint edge coverage), fuzzed by the builtin engine, and the
// planted divide-by-zero surfaces as a CWE-369 finding. The end-to-end portion skips
// cleanly when no `ruby` is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/ruby_lane")
        .canonicalize()
        .expect("canonicalize ruby_lane fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn have_ruby() -> bool {
    Command::new("ruby")
        .arg("-e")
        .arg("1")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn discovers_ruby_methods() {
    let candidates = discover(&fixture()).expect("discover ruby_lane fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    assert!(
        candidates.iter().all(|c| c.lang == Lang::Ruby),
        "every candidate is Lang::Ruby: {names:?}"
    );
    assert!(
        names.contains(&"RecordParser.parse_record"),
        "module self-method discovered with receiver qualification: {names:?}"
    );
    let p = candidates
        .iter()
        .find(|c| c.name == "RecordParser.parse_record")
        .expect("parse_record discovered");
    assert!(
        p.harness_id.starts_with("H-U"),
        "Ruby id prefix H-U: {}",
        p.harness_id
    );
}

#[test]
fn auto_builds_fuzzes_and_finds_divide_by_zero_cwe369() {
    if !have_ruby() {
        eprintln!("skipping: no ruby on PATH (GNAT-less rule)");
        return;
    }
    let src = std::env::temp_dir().join(format!("gf_rubylane_it_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        fixture().join("record_parser.rb"),
        src.join("record_parser.rb"),
    )
    .unwrap();
    let work = std::env::temp_dir().join(format!("gf_rubylane_w_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);

    let out = Command::new(govfuzz_bin())
        .args([
            "auto",
            "--per-target-time",
            "20",
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
        // cwe column carries the bare number (`369`), no `CWE-` prefix.
        csv.contains(",369;") || csv.contains(",369,"),
        "expected a CWE-369 arithmetic finding in findings.csv:\n{csv}"
    );
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
}
