// SPDX-License-Identifier: Apache-2.0
//
// M1.1 Rust discovery lane: the `rust_discovery` fixture is parsed, ranked, and
// listed by `govfuzz auto`, then pre-skipped cleanly at attempt time (the
// harness/build/engine lane lands in M1.2).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::{discover, discover_with_dir_filter, DirFilter};

fn fixture() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<repo>/crates/cli`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_discovery")
        .canonicalize()
        .expect("canonicalize rust_discovery fixture")
}

fn govfuzz_bin() -> PathBuf {
    // The integration-test binary lives in target/<profile>/deps; the CLI binary
    // is two levels up at target/<profile>/govfuzz.
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

#[test]
fn discovers_and_ranks_rust_lib_targets() {
    // Default filter excludes the `fuzz/` dir (C/C++ convention: it holds driver
    // glue), so this exercises only `src/lib.rs`.
    let candidates = discover(&fixture()).expect("discover rust fixture");

    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    assert!(
        candidates.iter().all(|c| c.lang == Lang::Rust),
        "every candidate from the Rust fixture is tagged Lang::Rust: {names:?}"
    );

    // The byte-channel parse entries are discovered.
    for expected in ["parse_header", "decode_record", "parse_raw", "from_bytes"] {
        assert!(
            names.contains(&expected),
            "expected parse entry `{expected}` in {names:?}"
        );
    }
    // The module-private helper is never externally callable -> skipped.
    assert!(
        !names.contains(&"secret_helper"),
        "private fn must be skipped: {names:?}"
    );

    // The harness_id prefix marks the engine lane.
    let parse_header = candidates
        .iter()
        .find(|c| c.name == "parse_header")
        .expect("parse_header discovered");
    assert!(
        parse_header.harness_id.starts_with("H-R"),
        "Rust harness id prefix is H-R: {}",
        parse_header.harness_id
    );
    assert_eq!(
        parse_header.input_reachability,
        Some(target_rank::InputReachability::AttackerReachable),
        "a `&[u8]` parser is attacker-reachable"
    );

    // The byte-channel parsers out-rank the getter.
    let score = |name: &str| {
        candidates
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.score)
            .unwrap_or_else(|| panic!("{name} not discovered"))
    };
    assert!(
        score("parse_header") > score("get_version"),
        "a byte-channel parser must out-rank a getter: parse_header={} get_version={}",
        score("parse_header"),
        score("get_version"),
    );
    // `parse_raw` is an unsafe/raw-pointer surface -> promoted above a plain getter.
    assert!(
        score("parse_raw") > score("get_version"),
        "the unsafe/raw-pointer surface must out-rank a getter"
    );
}

#[test]
fn existing_fuzz_target_is_found_when_fuzz_dir_included() {
    // `--include-dir fuzz` opts the existing cargo-fuzz harness back in; it is the
    // highest-value Rust discovery (already compiles, declares intent).
    let filter = DirFilter::new(&[], &["fuzz".into()]);
    let candidates = discover_with_dir_filter(&fixture(), &filter).expect("discover with fuzz dir");

    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    // The `fuzz_targets/existing.rs` file contains no `function_item` (the body is
    // a `fuzz_target!` macro token tree), so it contributes no named candidate —
    // but the lib-level parse entries are still discovered alongside it, proving
    // the fuzz dir was walked (it would otherwise be excluded by default).
    assert!(
        names.contains(&"parse_header"),
        "lib parse entries still discovered with fuzz dir included: {names:?}"
    );
    assert!(
        candidates.iter().all(|c| c.lang == Lang::Rust),
        "all Rust: {names:?}"
    );
}

/// The M1.2 end-to-end native fuzzing fixture (`tests/fixtures/rust_fuzz`): a
/// real `&[u8]` parser with a planted OOB-index bug behind a magic gate.
fn rust_fuzz_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_fuzz")
        .canonicalize()
        .expect("canonicalize rust_fuzz fixture")
}

/// Whether a usable `cargo +nightly` toolchain is installed. The native Rust
/// lane needs nightly for `-Zsanitizer`; with none it skips cleanly (the
/// GNAT-less rule), so the build+fuzz test below self-skips too rather than
/// failing on a machine without nightly.
fn has_cargo_nightly() -> bool {
    Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn rust_target_builds_and_fuzzes_natively_and_finds_planted_crash() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("govfuzz-rust-m12-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let output = Command::new(&bin)
        .args([
            "auto",
            rust_fuzz_fixture().to_str().unwrap(),
            // Enough wall to get past the `AB` magic + version gate via the
            // value-profile/cmplog mutator. The planted bug is hit in the first
            // ~120 execs once the gate is solved, so this is comfortable.
            "--per-target-time",
            "12",
            "--max-targets",
            "2",
            "--work-dir",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto on rust_fuzz fixture");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Native build+fuzz reached BuiltAndFuzzed (the run summary says so).
    assert!(
        combined.contains("built+fuzzed"),
        "Rust target must build+fuzz natively; got:\n{combined}"
    );

    // run.json proves: real coverage (>0 edges) AND real executions (>0) on a
    // generated (not stub) harness, AND the planted crash was FOUND.
    let run_json = tmp.join("auto").join("run.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&run_json).expect("read run.json"))
            .expect("parse run.json");

    // Locate parse_packet's attempt and inspect its passes.
    let attempts = json
        .get("targets")
        .or_else(|| json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has targets/attempts array");
    let parse_packet = attempts
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("parse_packet"))
        .expect("parse_packet attempt present");
    let outcome = parse_packet
        .get("outcome")
        .expect("parse_packet has an outcome");
    let passes = outcome
        .get("passes")
        .and_then(|p| p.as_array())
        .expect("parse_packet built+fuzzed with passes");

    let max_edges = passes
        .iter()
        .filter_map(|p| p.get("coverage_edges").and_then(|e| e.as_u64()))
        .max()
        .unwrap_or(0);
    assert!(
        max_edges > 0,
        "native Rust fuzzing must record real coverage edges (>0), got {max_edges}"
    );
    let total_execs: u64 = passes
        .iter()
        .filter_map(|p| p.get("executions").and_then(|e| e.as_u64()))
        .sum();
    assert!(
        total_execs > 0,
        "native Rust fuzzing must record real executions (>0), got {total_execs}"
    );
    let total_findings: usize = passes
        .iter()
        .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
        .map(|f| f.len())
        .sum();
    assert!(
        total_findings > 0,
        "the planted OOB-index crash in parse_packet must be FOUND by the native \
         engine (got 0 findings over {total_execs} execs, {max_edges} edges); \
         output:\n{combined}"
    );

    // The crash is the planted index-out-of-bounds panic (GF-201), and a crashing
    // testcase reproduces deterministically against the built harness.
    let findings_dir = tmp.join("findings");
    let mut found_gf201 = false;
    let mut a_reproducing_testcase = None;
    if let Ok(entries) = std::fs::read_dir(&findings_dir) {
        for e in entries.flatten() {
            let fj = e.path().join("finding.json");
            if let Ok(text) = std::fs::read_to_string(&fj) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let rule = v
                        .pointer("/actionability/sink/line")
                        .and_then(|l| l.as_u64());
                    // The planted bug is at lib.rs:37 (the v1 OOB index loop).
                    if rule == Some(37) {
                        found_gf201 = true;
                    }
                }
            }
            let tc = e.path().join("testcase.bin");
            if tc.is_file() {
                a_reproducing_testcase = Some(tc);
            }
        }
    }
    assert!(
        found_gf201,
        "the finding must localize to the planted bug (lib.rs:37); output:\n{combined}"
    );

    // Replay the crashing input through parse_packet's built harness: it must
    // abort (the Rust panic surfaces as a crash), confirming the finding is real.
    if let Some(tc) = a_reproducing_testcase {
        let harness_id = parse_packet
            .get("harness_id")
            .and_then(|h| h.as_str())
            .expect("parse_packet has a harness_id");
        let main_bin = tmp.join("harnesses").join(harness_id).join("main");
        assert!(
            main_bin.is_file(),
            "the native sancov+ASan harness binary exists at harnesses/<id>/main: {}",
            main_bin.display()
        );
        let replay = Command::new(&main_bin)
            .arg(&tc)
            .output()
            .expect("replay crashing input");
        assert!(
            !replay.status.success(),
            "the crashing input must reproduce (non-zero exit) on replay"
        );
    }

    // Cargo target trees are compiler intermediates, not user output. The final
    // replay binary above must survive while the per-harness caches are gone.
    for attempt in attempts {
        let Some(harness_id) = attempt.get("harness_id").and_then(|value| value.as_str()) else {
            continue;
        };
        let harness = tmp.join("harnesses").join(harness_id);
        assert!(
            !harness.join("rust_harness/target").exists(),
            "external Rust Cargo cache must be cleaned: {}",
            harness.display()
        );
        assert!(
            !harness.join("incrate/target").exists(),
            "in-crate Rust Cargo cache must be cleaned: {}",
            harness.display()
        );
    }
    assert!(tmp.join("FINDINGS.md").is_file());
    assert!(tmp.join("findings.csv").is_file());

    let _ = std::fs::remove_dir_all(&tmp);
}
