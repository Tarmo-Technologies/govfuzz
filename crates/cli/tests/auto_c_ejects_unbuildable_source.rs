// SPDX-License-Identifier: Apache-2.0

//! The repair loop pulls in a project source to supply an undefined symbol. When
//! that source cannot compile on its own, it used to stay on the command line and
//! poison every later round, losing a target whose own code is perfectly fine.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-eject-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn a_target_survives_a_recovered_source_that_cannot_compile() {
    if !support::libfuzzer_toolchain_available("eject") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();

    // The target calls a helper defined in a sibling file, so the repair loop
    // recovers that file to close the link.
    fs::write(
        src.join("parser.c"),
        "extern int mission_helper(int v);\n\
         \n\
         int parse_record(const unsigned char *d, unsigned long n) {\n\
         \x20   int total = 0;\n\
         \x20   unsigned long i;\n\
         \x20   for (i = 0; i < n; i++) { total += mission_helper(d[i]); }\n\
         \x20   return total;\n\
         }\n",
    )
    .unwrap();

    // ...but that sibling cannot compile here at all. The blocker is an object of
    // an INCOMPLETE type: a missing header or an undefined macro would not do,
    // because the repair loop synthesizes a placeholder for either and the file
    // then compiles fine. A type that is declared and never defined is the
    // documented unsynthesizable case, so adding this file can never help and
    // keeping it blocks the target forever.
    fs::write(
        src.join("mission_helper.c"),
        "struct never_defined_anywhere;\n\
         \n\
         int mission_helper(int v) {\n\
         \x20   struct never_defined_anywhere blocker;\n\
         \x20   return v + (int)sizeof(blocker);\n\
         }\n",
    )
    .unwrap();

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

    let outcome = outcome_of_target(&work, "parse_record");
    assert!(
        matches!(outcome.as_str(), "built_and_fuzzed" | "built"),
        "the target's own code compiles; an unbuildable recovered sibling must \
         not sink it, got {outcome}; stderr=\n{stderr}"
    );
    // Prove the ejection is what saved it, rather than the fixture happening to
    // build for some other reason.
    assert!(
        stderr.contains("does not compile in isolation"),
        "the recovered sibling must actually have been ejected; stderr=\n{stderr}"
    );
    // The sibling is still reported honestly on its own account — ejecting it
    // from one target's link says nothing good about it as a target.
    assert_eq!(
        outcome_of_target(&work, "mission_helper"),
        "report_only",
        "stderr=\n{stderr}"
    );
}

fn outcome_of_target(work: &Path, name: &str) -> String {
    let run_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    run_json["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|target| target["name"].as_str() == Some(name))
        .map(|target| {
            target["outcome"]["outcome"]
                .as_str()
                .unwrap_or("<none>")
                .to_owned()
        })
        .unwrap_or_else(|| format!("<no target named {name}>"))
}
