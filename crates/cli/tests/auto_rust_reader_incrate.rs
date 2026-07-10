// SPDX-License-Identifier: Apache-2.0
//
// §27.1 / §27.10 end-to-end: the native Rust lane builds + fuzzes a `pub trait`
// reader method (byteorder's `ReadBytesExt` class) through a synthesised
// `std::io::Cursor` receiver, and builds + fuzzes a `pub` type in a PRIVATE module
// via the IN-CRATE build mode (the harness injected as a module of a copy of the
// target crate). Both fixtures plant a crash so we prove a real, executing harness,
// not just a clean skip. The tests self-skip without a `cargo +nightly` toolchain
// (the native lane needs nightly for `-Zsanitizer`, the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize fixture {name}: {e}"))
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn has_cargo_nightly() -> bool {
    Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `govfuzz auto` on `fixture_dir` and return (combined stdout+stderr, run.json).
fn run_auto(
    fixture_dir: &Path,
    work: &Path,
    per_target: &str,
    max_targets: &str,
) -> (String, serde_json::Value) {
    let output = Command::new(govfuzz_bin())
        .args([
            "auto",
            fixture_dir.to_str().unwrap(),
            "--per-target-time",
            per_target,
            "--max-targets",
            max_targets,
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run_json = work.join("auto").join("run.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&run_json).expect("read run.json"))
            .expect("parse run.json");
    (combined, json)
}

fn attempts(json: &serde_json::Value) -> &Vec<serde_json::Value> {
    json.get("targets")
        .or_else(|| json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array")
}

fn find_attempt<'a>(json: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    attempts(json)
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(name))
        .unwrap_or_else(|| panic!("attempt `{name}` not present in run.json"))
}

/// Total findings across an attempt's passes, asserting it built (has passes).
fn attempt_findings(attempt: &serde_json::Value, name: &str) -> usize {
    let passes = attempt
        .get("outcome")
        .and_then(|o| o.get("passes"))
        .and_then(|p| p.as_array())
        .unwrap_or_else(|| panic!("`{name}` did not build+fuzz (no passes): {attempt}"));
    passes
        .iter()
        .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
        .map(|f| f.len())
        .sum()
}

#[test]
fn reader_trait_method_builds_fuzzes_and_finds_planted_crash() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("govfuzz-reader-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (combined, json) = run_auto(&fixture("rust_reader_trait"), &tmp, "8", "4");

    // The reader-trait methods built+fuzzed through the synthesised Cursor receiver.
    assert!(
        combined.contains("built+fuzzed"),
        "a reader-trait method must build+fuzz; got:\n{combined}"
    );
    // `read_tag` hides a planted panic reachable through the Cursor receiver —
    // proving a real, executing harness (not a skip).
    let read_tag = find_attempt(&json, "read_tag");
    assert!(
        attempt_findings(read_tag, "read_tag") > 0,
        "the planted reader-trait crash in read_tag must be FOUND; output:\n{combined}"
    );
    // The generated harness shows the synthesised receiver + trait import.
    let harness_id = read_tag
        .get("harness_id")
        .and_then(|h| h.as_str())
        .expect("read_tag has a harness_id");
    let harness_rs = tmp
        .join("harnesses")
        .join(harness_id)
        .join("rust_harness/src/lib.rs");
    let text = std::fs::read_to_string(&harness_rs).expect("read generated harness");
    assert!(
        text.contains("std::io::Cursor::new(") && text.contains("recv.read_tag()"),
        "harness must use a Cursor receiver:\n{text}"
    );
    assert!(
        text.contains("ReadNumExt as _;"),
        "harness must import the reader trait:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn private_module_target_builds_and_fuzzes_in_crate() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("govfuzz-incrate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (combined, json) = run_auto(&fixture("rust_incrate"), &tmp, "12", "4");

    assert!(
        combined.contains("built+fuzzed"),
        "the in-crate target must build+fuzz; got:\n{combined}"
    );
    // `Parser::parse` lives in a PRIVATE module — an external harness can't reach
    // it (E0603). It built+fuzzed only via the in-crate mode, AND found the planted
    // out-of-bounds crash behind the magic gate.
    let parse = find_attempt(&json, "parse");
    assert!(
        attempt_findings(parse, "parse") > 0,
        "the planted OOB crash in the private-module Parser::parse must be FOUND \
         (proving in-crate build reached + drove a private item); output:\n{combined}"
    );
    // The in-crate harness was injected as a module reaching `crate::internal`.
    let harness_id = parse
        .get("harness_id")
        .and_then(|h| h.as_str())
        .expect("parse has a harness_id");
    let module = tmp
        .join("harnesses")
        .join(harness_id)
        .join("incrate/src/__govfuzz_harness.rs");
    let text = std::fs::read_to_string(&module).expect("read injected in-crate harness module");
    assert!(
        text.contains("crate::internal::Parser"),
        "the in-crate harness must reach the private module by its `crate::` path:\n{text}"
    );
    // The crashing input reproduces against the built in-crate binary.
    let main_bin = tmp.join("harnesses").join(harness_id).join("main");
    assert!(
        main_bin.is_file(),
        "in-crate `main` binary exists: {}",
        main_bin.display()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
