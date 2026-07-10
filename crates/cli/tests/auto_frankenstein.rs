// SPDX-License-Identifier: Apache-2.0

//! End-to-end sanity check: a tiny mixed-quality source tree that
//! exercises both successful repair and unrecoverable cases.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-auto-frank-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn auto_sweep_handles_mixed_quality_tree() {
    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("frankenstein") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();

    // Compiles cleanly.
    fs::write(
        src.join("clean.c"),
        "int clean_parse(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    .unwrap();

    // Missing header -> HeaderPlaceholder repair should fire.
    fs::write(
        src.join("brokenhdr.c"),
        "#include \"vendor/missing.h\"\n\
         int parse_with_missing_hdr(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    .unwrap();

    // Undefined symbol with extern decl in the same TU -> StubDeclared repair should fire.
    fs::write(
        src.join("declared.c"),
        "extern int vendor_helper(const unsigned char *, unsigned long);\n\
         int parse_with_extern(const unsigned char *d, unsigned long n) {\n\
             return vendor_helper(d, n);\n\
         }\n",
    )
    .unwrap();

    // Compile via cargo run so we don't depend on a pre-built binary.
    let status = support::govfuzz_cargo_command()
        .current_dir(&root)
        .args(["auto", ".", "--per-target-time", "2"])
        .status()
        .expect("run govfuzz auto");
    // Some targets may not build on a sandbox without a complete libFuzzer
    // runtime - accept exit 0 (all built) or 1 (some built, some didn't).
    assert!(
        status.success() || status.code() == Some(1),
        "govfuzz auto exited with unexpected status: {status:?}"
    );

    let run_json: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("govfuzz_work/auto/run.json")).unwrap())
            .unwrap();
    let summary = &run_json["summary"];
    assert!(
        summary["discovered"].as_u64().unwrap() >= 3,
        "summary: {summary}"
    );
    assert!(
        summary["built"].as_u64().unwrap() >= 1,
        "summary: {summary}"
    );

    let headers = &run_json["needed_for_build"]["synthesized_headers"];
    assert!(
        headers
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["name"] == "vendor/missing.h"),
        "synthesized_headers: {headers}"
    );
    let declared = &run_json["needed_for_build"]["stubbed_symbols_declared"];
    assert!(
        declared
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["name"] == "vendor_helper"),
        "stubbed_symbols_declared: {declared}"
    );
}
