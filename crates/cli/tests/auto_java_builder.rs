// SPDX-License-Identifier: Apache-2.0
//
// #459 native Java receiver synthesis end-to-end: the `java_builder` fixture's
// `BuilderParser` has only a PRIVATE constructor, so its instance method
// `parse(byte[])` is reachable solely through the fluent builder. `govfuzz auto`
// must synthesise the receiver `com.acme.BuilderParser.builder().build()`,
// compile the harness, and drive the planted ArrayIndexOutOfBoundsException
// (GF-201) — proving the emitted builder-receiver source compiles AND executes.
// Before #459 this target skipped with "no no-arg constructor".

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_builder")
        .canonicalize()
        .expect("canonicalize java_builder fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

/// A usable JDK (`javac` + `java`) — the native Java lane needs it; with none it
/// skips cleanly (the GNAT-less rule), so this test self-skips too.
fn has_jdk() -> bool {
    Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok()
}

#[test]
fn java_builder_only_class_synthesises_receiver_and_finds_crash() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-java-builder-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let work = tmp.join("work");
    let seeds = tmp.join("seeds");
    std::fs::create_dir_all(&seeds).unwrap();
    // 'G'-prefixed (len >= 2) input trips the planted out-of-bounds read fast.
    std::fs::write(seeds.join("trigger"), b"G\x00\x00\x00\x00\x00\x00\x00").unwrap();

    let output = Command::new(&bin)
        .args([
            "auto",
            fixture().to_str().unwrap(),
            // 30s, not 10s: the seed above is designed to trip the planted read on
            // its first execution, so the budget only has to cover JVM and Jazzer
            // startup. On a loaded CI runner that startup ate most of a 10s budget
            // and the run finished having fuzzed the target but found nothing —
            // an intermittent failure that says "no finding" when it means "no
            // time". Raising the ceiling changes nothing about what is tested.
            "--per-target-time",
            "30",
            "--max-targets",
            "1",
            "--seed-dir",
            seeds.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto on java_builder fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The builder-only instance method was harnessed (receiver synthesised), built,
    // and fuzzed — not skipped for "no no-arg constructor".
    assert!(
        combined.contains("built+fuzzed"),
        "builder-only Java target should build + fuzz natively (receiver synthesised), got:\n{combined}"
    );

    // The planted GF-201 ArrayIndexOutOfBoundsException was found through the
    // builder-constructed receiver.
    let findings = work.join("findings");
    let mut found_gf201 = false;
    if let Ok(entries) = std::fs::read_dir(&findings) {
        for entry in entries.flatten() {
            if let Ok(fj) = std::fs::read_to_string(entry.path().join("finding.json")) {
                if fj.contains("GF-201") && fj.contains("ArrayIndexOutOfBounds") {
                    found_gf201 = true;
                }
            }
        }
    }
    assert!(
        found_gf201,
        "expected a GF-201 finding under {} (reached via builder().build()), output:\n{combined}",
        findings.display()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
