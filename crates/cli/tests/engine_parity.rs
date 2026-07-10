// SPDX-License-Identifier: Apache-2.0

//! Engine-parity benchmark + gate (#384): run the built-in engine cold (no
//! trigger seed) on the planted-bug fixtures under `tests/fixtures/engine_parity/`,
//! record time-to-first-crash + executions per case, and assert each is solved
//! cold. The #399 fork-server driver gives generated C harnesses the throughput
//! this needs (per-spawn ~tens of execs/s -> tens of thousands), so all gap
//! classes now solve cold.
//!
//! The sweep is `#[ignore]` (slow + clang-gated) so it runs on demand / nightly
//! rather than per-commit; the `parity_outcome` parser is unit-tested in the
//! default suite.

use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

mod support;

/// Parse a `run.json` value into `(built_and_fuzzed, executions, findings)`
/// summed across the run's targets/passes — the per-fixture parity measurement.
fn parity_outcome(run_json: &serde_json::Value) -> (bool, u64, usize) {
    let mut built = false;
    let mut executions = 0u64;
    let mut findings = 0usize;
    if let Some(targets) = run_json["targets"].as_array() {
        for target in targets {
            let outcome = &target["outcome"];
            if outcome["outcome"].as_str() == Some("built_and_fuzzed") {
                built = true;
            }
            if let Some(passes) = outcome["passes"].as_array() {
                for pass in passes {
                    executions += pass["executions"].as_u64().unwrap_or(0);
                    findings += pass["findings"].as_array().map(|f| f.len()).unwrap_or(0);
                }
            }
        }
    }
    (built, executions, findings)
}

#[test]
fn parity_outcome_sums_executions_and_findings_across_passes() {
    let run = serde_json::json!({
        "targets": [{
            "outcome": {
                "outcome": "built_and_fuzzed",
                "passes": [
                    { "executions": 200, "findings": [] },
                    { "executions": 445, "findings": ["F-0001-aa"] }
                ]
            }
        }]
    });
    assert_eq!(parity_outcome(&run), (true, 645, 1));

    // A target that never built contributes nothing and is not "built".
    let unbuilt = serde_json::json!({
        "targets": [{ "outcome": { "outcome": "failed_build", "passes": [] } }]
    });
    assert_eq!(parity_outcome(&unbuilt), (false, 0, 0));
}

const CASES: &[&str] = &["magic_byte", "const_gate", "len_field"];

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/engine_parity")
}

fn tmpdir(case: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-parity-{case}-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Cold-solve sweep: runs the built-in engine on each planted-bug fixture and
/// prints a TTFC table. `#[ignore]` (slow, clang-gated) — a tracking tool, not
/// a CI gate, until #399 gives generated C harnesses fork-server throughput.
#[test]
#[ignore = "slow cold-solve sweep; tracking tool until #399 throughput fix"]
fn engine_parity_cold_solve_sweep() {
    if !support::libfuzzer_toolchain_available("parity") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let budget_secs = std::env::var("GOVFUZZ_PARITY_SECS").unwrap_or_else(|_| "8".to_owned());
    println!("\nengine-parity TTFC sweep (cold, no trigger seed, {budget_secs}s total/target):");
    println!("  {:<12} {:>6} {:>10}  result", "case", "execs", "findings");

    for case in CASES {
        let started = Instant::now();
        // Fuzzing is stochastic and a transient build/run hiccup can yield zero
        // executions; retry a non-solve once before failing so the gate reflects
        // real engine capability, not a one-off blip.
        let mut last = (false, 0u64, 0usize);
        for _attempt in 0..2 {
            last = run_parity_case(case, &budget_secs);
            if last.2 > 0 {
                break;
            }
        }
        let (built, execs, findings) = last;
        let result = if findings > 0 {
            format!("SOLVED cold in {:?}", started.elapsed())
        } else {
            "UNSOLVED".to_owned()
        };
        println!("  {case:<12} {execs:>6} {findings:>10}  {result}");

        assert!(built, "fixture {case} did not build+fuzz");
        assert!(execs > 0, "fixture {case} produced no executions");
        // Cold-solve gate (#384, unblocked by the #399 fork-server driver): the
        // engine must find each planted bug cold, with no trigger seed. A
        // regression here means parity throughput/feedback broke. The default
        // budget leaves a wide margin (tens of thousands of execs); bump
        // GOVFUZZ_PARITY_SECS on a slow host.
        assert!(
            findings > 0,
            "fixture {case} was not solved cold within budget ({execs} execs) — \
             engine-parity regression (#376/#399)"
        );
    }
}

/// Run one fixture cold through `govfuzz auto` and return `(built, execs, findings)`.
fn run_parity_case(case: &str, budget_secs: &str) -> (bool, u64, usize) {
    let src = fixture_root().join(case).join(format!("{case}.c"));
    assert!(src.is_file(), "missing fixture {}", src.display());
    let work = tmpdir(case);
    std::fs::copy(&src, work.join(format!("{case}.c"))).unwrap();

    let status = support::govfuzz_cargo_command()
        .current_dir(&work)
        .args(["auto", ".", "--per-target-time", budget_secs])
        .status()
        .expect("run govfuzz auto");
    assert!(
        status.success() || status.code() == Some(1),
        "govfuzz auto crashed on {case} ({:?})",
        status.code()
    );

    let run_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("govfuzz_work/auto/run.json")).unwrap())
            .unwrap();
    parity_outcome(&run_json)
}
