// SPDX-License-Identifier: Apache-2.0
//
// A `java.io.File` parameter is a byte channel, not an unsupported type. The
// `java_file_param` fixture's only target is `parse(File)`; before the file
// channel it skipped with "parameter #0 has an unsupported type `File`", which
// closed off the classic Java parse entry point (`ImageIO.read(File)`,
// `CSVParser.parse(File, …)`, `new ZipFile(File)`).
//
// The planted GF-201 sits behind a single-byte gate INSIDE the file the target
// opens, so finding it proves three things at once: the harness compiled with the
// synthesized temp-file helper, the fuzz bytes reached the file, and the target
// read them back.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_file_param")
        .canonicalize()
        .expect("canonicalize java_file_param fixture")
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
fn java_file_parameter_is_driven_through_a_temp_file_and_finds_the_planted_crash() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-java-fileparam-{}", std::process::id()));
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
        .expect("run govfuzz auto on java_file_param fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        combined.contains("built+fuzzed"),
        "a File-parameter Java target must build + fuzz, not skip as unsupported, got:\n{combined}"
    );
    assert!(
        !combined.contains("unsupported type"),
        "the File parameter must no longer be reported unsupported:\n{combined}"
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
        "the gated crash lives behind bytes the target read BACK from the file, so \
         finding it is the proof the channel works; none under {}, output:\n{combined}",
        findings.display()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
