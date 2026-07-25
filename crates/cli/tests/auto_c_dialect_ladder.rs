// SPDX-License-Identifier: Apache-2.0

//! C had no dialect ladder: a modern default rejects pre-standard constructs and
//! the target simply failed. C++ has laddered for a long time; this is the same
//! treatment for C, and it must stay invisible to code that compiles as-is.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-c-ladder-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// The outcome recorded for a named target. Looked up by NAME rather than by
/// position: discovery ranks what it finds, and a fixture can legitimately yield
/// more than one target (a nested helper is itself a candidate), so index 0 is
/// not reliably the one under test.
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
fn an_ordinary_c_target_carries_no_std_flag_at_all() {
    if !support::libfuzzer_toolchain_available("c-ladder-default") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("default");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("probe.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return (int)(n + (d ? 0 : 0)); }\n",
    )
    .unwrap();
    let work = root.join("work");
    let stderr = run_auto(&root, &src, &work);

    assert_eq!(
        outcome_of_target(&work, "parse_input"),
        "built_and_fuzzed",
        "stderr=\n{stderr}"
    );

    // The ladder is opt-in: an ordinary build must be byte-identical to what it
    // always was, which means no `-std` reaches the compiler unless a rung was
    // actually selected.
    let harness_dir = fs::read_dir(work.join("harnesses"))
        .expect("harnesses dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("a harness was generated");
    let makefile = fs::read_to_string(harness_dir.join("Makefile")).expect("Makefile");
    assert!(
        makefile.contains("C_STD ?=\n"),
        "the C standard must default to empty:\n{makefile}"
    );
    assert!(
        makefile.contains("C_STD_FLAG := $(if $(C_STD),-std=$(C_STD),)"),
        "an empty C_STD must expand to no flag at all:\n{makefile}"
    );
}

#[test]
fn a_legacy_c_target_builds_by_laddering_to_an_older_standard() {
    if !support::libfuzzer_toolchain_available("c-ladder-legacy") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("legacy");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // `gets` was removed from the C library in C11 and clang rejects the implicit
    // declaration outright under its modern default; `gnu89` accepts it. The
    // parsing function itself is ordinary, so the ONLY thing standing between
    // this target and a harness is the dialect.
    fs::write(
        src.join("legacy.c"),
        "extern char *gets(char *);\n\
         \n\
         int parse_record(const unsigned char *d, unsigned long n) {\n\
         \x20   register int i;\n\
         \x20   int total = 0;\n\
         \x20   for (i = 0; i < (int)n; i++) { total += d[i]; }\n\
         \x20   return total;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    let stderr = run_auto(&root, &src, &work);

    assert_eq!(
        outcome_of_target(&work, "parse_record"),
        "built_and_fuzzed",
        "a target whose only problem is its vintage must still fuzz; \
         stderr=\n{stderr}"
    );
}

#[test]
fn a_target_only_gcc_accepts_is_built_by_falling_back_to_it() {
    if !support::libfuzzer_toolchain_available("c-ladder-gcc") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }
    if which::which("gcc").is_err() {
        eprintln!("skipping: no gcc to fall back to");
        return;
    }

    let root = tmpdir("gcc-only");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // Nested functions are a GNU C extension that gcc implements and clang has
    // always refused. Nothing else here is unusual, so the compiler is the only
    // thing between this target and a harness.
    fs::write(
        src.join("nested.c"),
        "int parse_record(const unsigned char *d, unsigned long n) {\n\
         \x20   int scale(int v) { return v * 3; }\n\
         \x20   int total = 0;\n\
         \x20   unsigned long i;\n\
         \x20   for (i = 0; i < n; i++) { total += scale(d[i]); }\n\
         \x20   return total;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    let stderr = run_auto(&root, &src, &work);

    // What the fallback is responsible for is that the target BUILDS. What a
    // one-second fuzz budget then manages to execute — and therefore whether the
    // target-entry checkpoint is observed — depends on host load, so asserting on
    // that would make this test flaky about something it is not testing.
    let outcome = outcome_of_target(&work, "parse_record");
    assert!(
        matches!(
            outcome.as_str(),
            "built_and_fuzzed" | "built" | "built_not_entered"
        ),
        "a target the default compiler rejects and the other accepts must not be \
         lost, got {outcome}; stderr=\n{stderr}"
    );
    // The choice is remembered so the rest of the run does not re-probe it.
    assert_eq!(
        fs::read_to_string(work.join("c_compiler.txt"))
            .unwrap_or_default()
            .trim(),
        "gcc",
        "the winning compiler must be cached for the run"
    );
}
