// SPDX-License-Identifier: Apache-2.0
//
// A tree using a language PREVIEW feature is not an unbuildable tree. The
// `java_preview` fixture uses an unnamed variable (`var _ = …`), preview on JDK
// 21 and standard only from 22, so it fails at THREE points unless the flag is
// carried through: the target compile, the harness compile (javac refuses to read
// preview class files without it), and the JVM that loads them.
//
// RxJava and spring-framework failed exactly this way in the 500-project sweep —
// 11 targets reporting "unnamed variables are a preview feature and are disabled
// by default", which is javac naming the flag it wants.
//
// The planted GF-201 is behind a byte gate, so finding it proves the harness
// really ran rather than merely compiling.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_preview")
        .canonicalize()
        .expect("canonicalize java_preview fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn has_jdk() -> bool {
    Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok()
}

/// Whether this JDK actually needs the flag for the fixture. On JDK 22+ unnamed
/// variables are standard, so the fixture compiles either way and the test has
/// nothing to prove — it still must PASS there, just without exercising the
/// retry, so assert the outcome rather than the flag.
#[test]
fn a_preview_language_feature_is_compiled_and_run_with_the_flag_it_asks_for() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-java-preview-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let work = tmp.join("work");
    let seeds = tmp.join("seeds");
    std::fs::create_dir_all(&seeds).unwrap();
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
        .expect("run govfuzz auto on java_preview fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        combined.contains("built+fuzzed"),
        "a preview-using tree must build and fuzz, not report an unbuildable \
         project, got:\n{combined}"
    );
    assert!(
        !combined.contains("preview feature"),
        "javac named the flag it needed; it must not survive as the reason:\n{combined}"
    );

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
        "the gated crash proves the JVM LOADED the preview class files, which it \
         refuses to do without the flag; none under {}, output:\n{combined}",
        findings.display()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
