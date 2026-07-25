// SPDX-License-Identifier: Apache-2.0

//! When several targets share a build closure that cannot be built, the repair
//! cascade must run once — not once per target reaching the same verdict.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-closure-memo-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// A source whose closure cannot be satisfied offline, carrying several entry
/// points so the sweep attempts more than one.
///
/// The blocker is an object of an INCOMPLETE class type. A missing header or an
/// undefined function is not enough — the repair loop synthesizes a placeholder
/// header and blind-stubs the symbols, and the target builds and fuzzes. A type
/// that is declared but never defined is the documented unsynthesizable case:
/// nothing govfuzz can write completes it, so the cascade genuinely exhausts.
const UNBUILDABLE_WITH_SIBLINGS: &str = "\
class MissingExternalType;

int parse_alpha(const unsigned char *d, unsigned long n) {
    MissingExternalType m;
    return (int)(n + (d ? 0 : 0));
}
int parse_beta(const unsigned char *d, unsigned long n) {
    MissingExternalType m;
    return (int)(n + (d ? 1 : 0));
}
int parse_gamma(const unsigned char *d, unsigned long n) {
    MissingExternalType m;
    return (int)(n + (d ? 2 : 0));
}
";

#[test]
fn a_sibling_target_inherits_the_closure_verdict_instead_of_repeating_the_cascade() {
    if !support::libfuzzer_toolchain_available("closure-memo") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("broken.cpp"), UNBUILDABLE_WITH_SIBLINGS).unwrap();
    let work = root.join("work");

    let output = support::govfuzz_cargo_command()
        .current_dir(&root)
        .args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "1",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    let memo_path = work.join("closure_failures.json");
    assert!(
        memo_path.is_file(),
        "an exhausted cascade must leave a verdict for its siblings; stderr=\n{stderr}"
    );
    let memo: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&memo_path).unwrap()).expect("memo is JSON");
    let entries = memo["entries"].as_object().expect("memo has entries");
    assert_eq!(
        entries.len(),
        1,
        "one closure, one verdict — not one per target: {entries:?}"
    );

    let run_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let targets = run_json["targets"].as_array().expect("targets array");
    assert!(
        targets.len() >= 2,
        "the fixture must produce siblings for the memo to matter: {} target(s)",
        targets.len()
    );
    // Every sibling still reports the same honest outcome it would have reached
    // the slow way. The memo changes what work is done, never what is reported.
    for target in targets {
        let outcome = target["outcome"]["outcome"].as_str().unwrap_or("<none>");
        assert_eq!(
            outcome, "report_only",
            "a memo hit must report exactly what the sibling that ran the full \
             cascade reported — it substitutes for the work, not the verdict"
        );
    }
}

#[test]
fn a_verdict_does_not_survive_a_change_in_project_repair_state() {
    if !support::libfuzzer_toolchain_available("closure-memo-invalidate") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("invalidate");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("broken.cpp"), UNBUILDABLE_WITH_SIBLINGS).unwrap();
    let work = root.join("work");

    let run = || {
        support::govfuzz_cargo_command()
            .current_dir(&root)
            .args([
                "auto",
                "--work-dir",
                work.to_str().unwrap(),
                "--per-target-time",
                "1",
                src.to_str().unwrap(),
            ])
            .output()
            .expect("run govfuzz auto")
    };
    run();
    assert!(work.join("closure_failures.json").is_file());

    // A fresh run refreshes regenerable state, so a verdict reached by an older
    // binary — or under a poorer repair model — can never cap a later sweep.
    let stderr = String::from_utf8_lossy(&run().stderr).into_owned();
    let memo: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("closure_failures.json")).expect("memo exists"),
    )
    .expect("memo is JSON");
    assert!(
        memo["entries"].as_object().is_some_and(|e| !e.is_empty()),
        "the second run must re-derive the verdict rather than inherit a stale \
         one silently; stderr=\n{stderr}"
    );
}
