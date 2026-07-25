// SPDX-License-Identifier: Apache-2.0

//! From the first repair round on, the C/C++ lane asks the compiler to analyse
//! without generating code or linking. That must not change what the repair loop
//! can fix: a target needing repairs still has to converge, and undefined symbols
//! — which a syntax-only pass cannot see — must still be found by the real build.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-syntaxcheck-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn run_auto(root: &Path, src: &Path, work: &Path) -> String {
    let output = support::govfuzz_cargo_command()
        .current_dir(root)
        .args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "1",
            "--max-targets",
            "1",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_target_needing_repair_still_converges_with_check_rounds() {
    if !support::libfuzzer_toolchain_available("syntaxcheck") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("repair");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // The missing header makes round 0 fail, so rounds 1+ run under the
    // syntax-only path. The repair loop synthesizes a placeholder header and the
    // target must still reach a real, linked harness.
    fs::write(
        src.join("parse.c"),
        "#include \"generated_config.h\"\n\
         int parse_input(const unsigned char *d, unsigned long n) {\n\
         \x20   if (n > 3 && d[0] == 'A') return 1;\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    let stderr = run_auto(&root, &src, &work);

    let run_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let outcome = run_json["targets"][0]["outcome"]["outcome"]
        .as_str()
        .unwrap_or("<none>")
        .to_owned();
    assert_eq!(
        outcome, "built_and_fuzzed",
        "a repairable target must still converge when repair rounds are \
         syntax-only; stderr=\n{stderr}"
    );

    // The linked binary is the proof that a clean check never stood in for a
    // real build.
    let harness_id = run_json["targets"][0]["harness_id"].as_str().unwrap();
    assert!(
        work.join("harnesses")
            .join(harness_id)
            .join("main")
            .is_file(),
        "a syntax-only pass links nothing, so success must still produce a binary"
    );
}

#[test]
fn the_generated_makefile_checks_without_linking_prebuilt_objects() {
    if !support::libfuzzer_toolchain_available("syntaxcheck-makefile") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("makefile");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("probe.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return (int)(n + (d ? 0 : 0)); }\n",
    )
    .unwrap();
    let work = root.join("work");
    let stderr = run_auto(&root, &src, &work);

    let harness_dir = fs::read_dir(work.join("harnesses"))
        .expect("harnesses dir exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .unwrap_or_else(|| panic!("a harness was generated; stderr=\n{stderr}"));
    let makefile = fs::read_to_string(harness_dir.join("Makefile")).expect("Makefile exists");

    let recipe = makefile
        .lines()
        .skip_while(|line| !line.starts_with("syntaxcheck:"))
        .nth(1)
        .unwrap_or_else(|| panic!("Makefile has no syntaxcheck recipe:\n{makefile}"));
    assert!(
        recipe.contains("-fsyntax-only"),
        "the check target must actually skip code generation: {recipe}"
    );
    // Passing a prebuilt object to -fsyntax-only is an error, and nothing is
    // linked here, so the object variables must stay out of the recipe.
    assert!(
        !recipe.contains("CONTEXT_MAIN_OBJECTS"),
        "prebuilt objects must not reach the check recipe: {recipe}"
    );
    assert!(
        !recipe.contains("govfuzz_driver.o"),
        "the driver object is a link input, not a check input: {recipe}"
    );

    // And the target must actually run.
    let status = std::process::Command::new("make")
        .arg("syntaxcheck")
        .current_dir(&harness_dir)
        .output()
        .expect("run make syntaxcheck");
    assert!(
        status.status.success(),
        "make syntaxcheck failed on a target that builds:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
}
