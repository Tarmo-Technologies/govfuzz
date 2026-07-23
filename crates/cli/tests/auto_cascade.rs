// SPDX-License-Identifier: Apache-2.0

//! Verify the three-pass cascade actually runs three passes against
//! a built target and tags findings with the pass that produced them.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-cascade-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn three_pass_cascade_records_each_pass() {
    if !support::libfuzzer_toolchain_available("cascade") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }
    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("probe.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    .unwrap();
    // #405 AC3: time the whole run with an INDEPENDENT external clock so the
    // reported fuzz wall can be cross-checked against it (not just against its
    // own derivation).
    let external_start = std::time::Instant::now();
    let status = support::govfuzz_cargo_command()
        .current_dir(&root)
        .args(["auto", ".", "--per-target-time", "2"])
        .status()
        .expect("run govfuzz auto");
    let external_wall = external_start.elapsed().as_secs_f64();
    assert!(status.success() || status.code() == Some(1));

    let run_json: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("govfuzz_work/auto/run.json")).unwrap())
            .unwrap();
    let targets = run_json["targets"].as_array().unwrap();
    let built = targets
        .iter()
        .find(|t| t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed"))
        .unwrap_or_else(|| panic!("no built target in {run_json}"));
    let passes = built["outcome"]["passes"].as_array().expect("passes array");
    let names: Vec<&str> = passes.iter().filter_map(|p| p["pass"].as_str()).collect();
    assert_eq!(names, vec!["empty", "rng", "fuzz_driven"]);
    assert!(
        passes.iter().any(|pass| {
            pass["target_entry_observed"].as_bool() == Some(true)
                && pass["executions"].as_u64().unwrap_or(0) > 0
        }),
        "driver executions must include an independent selected-target entry proof: {built}"
    );

    assert!(
        built["outcome"]["executions_per_sec"].as_f64().is_some(),
        "target aggregate executions_per_sec missing: {built}"
    );

    // #405 AC3 / B: cross-check the reported fuzz wall against an INDEPENDENT
    // external clock AND the per-target budget. `--per-target-time` is the
    // per-TARGET TOTAL fuzz wall, split across the passes under ONE shared
    // deadline — so the summed per-pass elapsed_secs must (a) fit inside the
    // whole subprocess wall, (b) be ≈ the 2s budget and NOT 3× it (the passes
    // share the deadline; this is the regression guard for the budget model),
    // and (c) be a substantial fraction of that budget (catches a bogus
    // near-zero elapsed_secs). This is a genuine external reference, not the
    // executions/elapsed self-consistency check below.
    let per_target_budget = 2.0_f64; // matches `--per-target-time 2` above
    let total_fuzz: f64 = passes
        .iter()
        .map(|p| p["elapsed_secs"].as_f64().expect("elapsed_secs"))
        .sum();
    assert!(total_fuzz > 0.0, "no fuzz wall recorded: {built}");
    assert!(
        total_fuzz <= external_wall + 0.5,
        "reported fuzz wall {total_fuzz}s exceeds external wall {external_wall}s"
    );
    assert!(
        total_fuzz <= per_target_budget + 1.5,
        "reported fuzz wall {total_fuzz}s exceeds the per-target budget \
         {per_target_budget}s — passes must SHARE one deadline, not each get the full budget"
    );
    assert!(
        total_fuzz >= per_target_budget * 0.3,
        "reported fuzz wall {total_fuzz}s implausibly small vs the {per_target_budget}s budget"
    );

    // Each pass's exec/s is internally consistent with executions / elapsed_secs
    // — this validates the rate arithmetic (the external bracket above validates
    // the wall measurement itself).
    for p in passes {
        let execs = p["executions"].as_f64().expect("executions");
        let elapsed = p["elapsed_secs"].as_f64().expect("elapsed_secs");
        let eps = p["executions_per_sec"]
            .as_f64()
            .expect("executions_per_sec");
        assert!(elapsed >= 0.0 && eps >= 0.0, "negative metric in {p}");
        if execs > 0.0 && elapsed > 0.0 {
            let expect = execs / elapsed;
            assert!(
                (eps - expect).abs() <= expect * 0.01 + 1.0,
                "pass exec/s {eps} != executions {execs} / elapsed {elapsed}"
            );
        }
    }

    // run.md surfaces the per-pass exec/s segment for human comparison.
    let md = fs::read_to_string(root.join("govfuzz_work/auto/run.md")).unwrap();
    assert!(md.contains("exec_s"), "run.md missing exec/s figure: {md}");
}
