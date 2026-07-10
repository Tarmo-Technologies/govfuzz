// SPDX-License-Identifier: Apache-2.0

//! Cold-solve gate for the input-to-state (RedQueen) cmplog mutator (#400).
//!
//! Runs the built-in engine cold (no trigger seed) on the `redqueen_int` fixture,
//! whose only crash is gated behind an INTEGER comparison against a per-input,
//! len-derived magic. That gate is reachable only by capturing the comparison
//! operand via SanitizerCoverage trace-cmp and splicing it into the input at the
//! offset it was compared — #400's contribution. Every pre-existing path (the
//! mem/str-only LD_PRELOAD shim cmplog, the static dictionary, uniform fill,
//! arithmetic, blind mutation, repetition/structured mutators) cannot reach it.
//!
//! The test is the discriminator the issue asked for: with per-input capture ON
//! the bug is solved cold; with it disabled (`GOVFUZZ_DISABLE_REDQUEEN=1`, the
//! dictionary-only path) it is NOT — within the same budget. `#[ignore]` because
//! it is slow and needs clang+make; run it on demand / nightly.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/engine_parity/redqueen_int/redqueen_int.c")
}

fn tmpdir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-rq-cold-{tag}-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Count findings that are real crashes (sanitizer/unhandled faults), excluding
/// oracle hits — only a genuine memory-safety crash means the gate was cleared.
fn count_crash_findings(work: &std::path::Path) -> usize {
    let findings_dir = work.join("govfuzz_work/findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return 0;
    };
    let mut crashes = 0;
    for entry in entries.flatten() {
        let finding = entry.path().join("finding.json");
        let Ok(bytes) = std::fs::read(&finding) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        // Oracle hits (insecure-temp-file, TOCTOU, …) are not the gate crash; the
        // planted OOB surfaces as a sanitizer/"unhandled" classification.
        if value["classification"].as_str() != Some("oracle_hit") {
            crashes += 1;
        }
    }
    crashes
}

/// Run `auto` on the fixture cold and return the number of crash findings.
/// `redqueen` selects per-input cmplog capture (true) or the dictionary-only
/// baseline (false, via `GOVFUZZ_DISABLE_REDQUEEN=1`).
fn run(tag: &str, redqueen: bool, budget_secs: &str) -> usize {
    let work = tmpdir(tag);
    std::fs::copy(fixture(), work.join("redqueen_int.c")).unwrap();
    let mut cmd = support::govfuzz_cargo_command();
    cmd.current_dir(&work)
        .args(["auto", ".", "--per-target-time", budget_secs]);
    if !redqueen {
        cmd.env("GOVFUZZ_DISABLE_REDQUEEN", "1");
    }
    let status = cmd.status().expect("run govfuzz auto");
    assert!(
        status.success() || status.code() == Some(1),
        "govfuzz auto crashed unexpectedly ({:?})",
        status.code()
    );
    count_crash_findings(&work)
}

#[test]
#[ignore = "slow cold-solve discriminator; needs clang+make — run on demand / nightly"]
fn redqueen_int_gate_solved_only_with_per_input_cmplog() {
    if !support::libfuzzer_toolchain_available("redqueen") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let budget = std::env::var("GOVFUZZ_RQ_SECS").unwrap_or_else(|_| "15".to_owned());

    // Dictionary-only baseline must NOT solve the integer gate in the budget.
    let baseline = run("off", false, &budget);
    assert_eq!(
        baseline, 0,
        "dictionary-only path unexpectedly solved the integer gate ({baseline} crashes) — \
         the discriminator no longer isolates per-input cmplog"
    );

    // Per-input cmplog must solve it cold. Retry once to absorb a transient
    // build/run blip (the existing parity sweep does the same).
    let mut solved = run("on", true, &budget);
    if solved == 0 {
        solved = run("on-retry", true, &budget);
    }
    assert!(
        solved > 0,
        "per-input cmplog (#400) failed to solve the integer gate cold within {budget}s — \
         RedQueen capture/splice regression"
    );
}
