// SPDX-License-Identifier: Apache-2.0
//
// M2.1b/d end-to-end native Java fuzzing: `govfuzz auto` discovers + ranks the
// `java_fuzz` fixture, compiles it with javac, generates + compiles a govfuzz
// harness, and drives a persistent JVM under govfuzz's OWN bytecode coverage agent
// over the framed fork-server protocol — finding + classifying the planted
// ArrayIndexOutOfBoundsException (GF-201). No Jazzer, no libFuzzer.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_fuzz")
        .canonicalize()
        .expect("canonicalize java_fuzz fixture")
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
fn java_target_builds_and_fuzzes_natively_and_finds_planted_crash() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-java-m21d-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let work = tmp.join("work");
    let seeds = tmp.join("seeds");
    std::fs::create_dir_all(&seeds).unwrap();
    // Seed a 'G'-prefixed input so the planted single-byte-gate crash is found
    // deterministically + fast in CI; the no-seed coverage-guided path also finds
    // it (verified manually), but seeding keeps the test robust on slow machines.
    std::fs::write(seeds.join("trigger"), b"G\x00\x00\x00\x00\x00\x00\x00").unwrap();

    let output = Command::new(&bin)
        .args([
            "auto",
            fixture().to_str().unwrap(),
            "--per-target-time",
            "10",
            "--max-targets",
            "1",
            "--seed-dir",
            seeds.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto on java_fuzz fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        combined.contains("built+fuzzed"),
        "Java target should build + fuzz natively, got:\n{combined}"
    );

    // A GF-201 ArrayIndexOutOfBoundsException finding was recorded, with the
    // 'G'-prefixed crash input.
    let findings = work.join("findings");
    let mut found_gf201 = false;
    let mut crash_starts_with_g = false;
    if let Ok(entries) = std::fs::read_dir(&findings) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if let Ok(fj) = std::fs::read_to_string(dir.join("finding.json")) {
                if fj.contains("GF-201") && fj.contains("ArrayIndexOutOfBounds") {
                    found_gf201 = true;
                }
            }
            if let Ok(tc) = std::fs::read(dir.join("testcase.bin")) {
                if tc.first() == Some(&b'G') {
                    crash_starts_with_g = true;
                }
            }
        }
    }
    assert!(
        found_gf201,
        "expected a GF-201 ArrayIndexOutOfBoundsException finding under {}, output:\n{combined}",
        findings.display()
    );
    assert!(
        crash_starts_with_g,
        "the crashing input should start with the gate byte 'G'"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
