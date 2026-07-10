// SPDX-License-Identifier: Apache-2.0

//! End-to-end test for Slice C's replay-with-runtime_mode flow:
//!
//!   1. A target whose crash is gated on getenv("ACME_REPLAY_TRIGGER")
//!      returning non-NULL.
//!   2. govfuzz auto cascade: pass 1 (Empty mode) logs the env miss,
//!      pass 2 (Rng) injects ACME_REPLAY_TRIGGER and the harness
//!      crashes deterministically.
//!   3. The crash's finding.json carries runtime_mode = { pass: "rng",
//!      env_injected: { ACME_REPLAY_TRIGGER: "/tmp/govfuzz/fake_env/..." } }.
//!   4. govfuzz replay reads the stamp, reconstructs the env, re-execs
//!      the harness, sees the same crash, prints MATCH (exit 0).

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-replay-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn replay_reproduces_env_triggered_crash_via_runtime_mode_stamp() {
    if !support::libfuzzer_toolchain_available("replay") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }

    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();

    // Harness: crashes ONLY when ACME_REPLAY_TRIGGER is set.
    // Pass::Empty: getenv returns NULL -> no crash, runtrace logs the miss.
    // Pass::Rng:  getenv returns the injected value -> NULL deref -> ASan
    //              SEGV_ON_UNKNOWN_ADDRESS -> GF-206.
    fs::write(
        src.join("probe.c"),
        "#include <stdlib.h>\n\
         #include <string.h>\n\
         int parse_input(const unsigned char *d, unsigned long n) {\n\
             const char *t = getenv(\"ACME_REPLAY_TRIGGER\");\n\
             if (t) {\n\
                 /* deterministic NULL deref: target sees the injected\n\
                  * env value, then crashes the same way every time. */\n\
                 volatile int *boom = (volatile int *)0;\n\
                 return *boom;\n\
             }\n\
             return (int)n;\n\
         }\n",
    )
    .unwrap();

    // Phase 1: drive govfuzz auto. The cascade injects ACME_REPLAY_TRIGGER
    // and produces a finding stamped with runtime_mode.pass = "rng".
    let status = support::govfuzz_cargo_command()
        .current_dir(&root)
        .args(["auto", ".", "--per-target-time", "3"])
        .status()
        .expect("run govfuzz auto");
    // Auto may exit 0 (built+findings) or 1 (built but findings missing
    // due to env quirks). 0 is the expected path; we hard-require it for
    // this test since the crash is deterministic.
    assert!(
        status.success(),
        "govfuzz auto exited non-zero ({:?}); see {}/govfuzz_work/auto/run.md",
        status.code(),
        root.display()
    );

    // Locate the finding the rng pass produced.
    let run_json: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("govfuzz_work/auto/run.json")).unwrap())
            .unwrap();
    let target = run_json["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed"))
        .expect("expected at least one built_and_fuzzed target");
    let passes = target["outcome"]["passes"].as_array().unwrap();
    let rng_pass = passes
        .iter()
        .find(|p| p["pass"].as_str() == Some("rng"))
        .expect("rng pass run missing");
    let finding_ids = rng_pass["findings"].as_array().unwrap();
    assert!(
        !finding_ids.is_empty(),
        "rng pass produced no findings; cascade summary: {target}"
    );
    let finding_id = finding_ids[0].as_str().unwrap().to_owned();

    // Phase 2: read finding.json, verify the stamp.
    let finding_path = root
        .join("govfuzz_work/findings")
        .join(&finding_id)
        .join("finding.json");
    let finding_dir = finding_path.parent().expect("finding path has parent");
    let finding: serde_json::Value =
        serde_json::from_slice(&fs::read(&finding_path).unwrap()).unwrap();
    let runtime_mode = finding["runtime_mode"]
        .as_object()
        .expect("finding.json missing runtime_mode stamp");
    assert_eq!(
        runtime_mode.get("pass").and_then(|v| v.as_str()),
        Some("rng")
    );
    let env_injected = runtime_mode
        .get("env_injected")
        .and_then(|v| v.as_object())
        .expect("runtime_mode.env_injected absent");
    assert!(
        env_injected.contains_key("ACME_REPLAY_TRIGGER"),
        "ACME_REPLAY_TRIGGER not in env_injected: {runtime_mode:?}"
    );

    // Phase 3: invoke govfuzz replay with the stamped finding.
    let harness_binary = root
        .join("govfuzz_work/harnesses")
        .join(target["harness_id"].as_str().unwrap())
        .join("main");
    assert!(
        harness_binary.is_file(),
        "harness binary missing at {}",
        harness_binary.display()
    );
    let replay_status = support::govfuzz_cargo_command()
        .current_dir(&root)
        .args([
            "replay",
            "--harness",
            harness_binary.to_str().unwrap(),
            "--finding",
            finding_dir.to_str().unwrap(),
        ])
        .status()
        .expect("run govfuzz replay");
    assert!(
        replay_status.success(),
        "replay exited non-zero ({:?}); stamp may not have reconstructed env",
        replay_status.code()
    );
}
