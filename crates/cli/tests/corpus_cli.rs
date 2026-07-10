// SPDX-License-Identifier: Apache-2.0

//! End-to-end checks that `govfuzz corpus import|export|merge`
//! round-trips bytes through the bridge correctly.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn tempdir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-corpus-cli-{prefix}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn corpus_import_afl_dir_writes_govfuzz_dir() {
    let src = tempdir("import-afl-src");
    let dst = tempdir("import-afl-dst");
    fs::write(src.join("id:000000,orig:a"), b"hello").unwrap();
    fs::write(src.join("id:000001,orig:b"), b"world").unwrap();
    fs::write(src.join("id:000002,orig:c"), b"hello").unwrap(); // duplicate

    let out = Command::new(govfuzz_bin())
        .args([
            "corpus",
            "import",
            "--from",
            "afl",
            "--in",
            src.to_str().unwrap(),
            "--out",
            dst.to_str().unwrap(),
        ])
        .output()
        .expect("spawn govfuzz corpus import");
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("imported 2 unique"));
    assert!(stdout.contains("1 duplicates"));
    assert!(stdout.contains("afl -> govfuzz"));

    let written: Vec<_> = fs::read_dir(&dst).unwrap().collect();
    assert_eq!(written.len(), 2);
    for entry in written {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(name.ends_with(".bin"), "govfuzz output: {name}");
    }
}

#[test]
fn corpus_merge_dedups_across_inputs() {
    let src1 = tempdir("merge-cli-src1");
    let src2 = tempdir("merge-cli-src2");
    let dst = tempdir("merge-cli-dst");
    fs::write(src1.join("a.bin"), b"alpha").unwrap();
    fs::write(src1.join("b.bin"), b"beta").unwrap();
    fs::write(src2.join("c.bin"), b"alpha").unwrap(); // dup of src1/a.bin
    fs::write(src2.join("d.bin"), b"gamma").unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "corpus",
            "merge",
            "--out",
            dst.to_str().unwrap(),
            src1.to_str().unwrap(),
            src2.to_str().unwrap(),
        ])
        .output()
        .expect("spawn govfuzz corpus merge");
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("merged 3 unique"));
    assert!(stdout.contains("1 duplicates"));

    let written: Vec<_> = fs::read_dir(&dst).unwrap().collect();
    assert_eq!(written.len(), 3);
}

#[test]
fn corpus_export_to_libfuzzer_uses_40_char_names() {
    let src = tempdir("export-lf-src");
    let dst = tempdir("export-lf-dst");
    fs::write(src.join("a.bin"), b"alpha").unwrap();
    fs::write(src.join("b.bin"), b"beta").unwrap();

    let out = Command::new(govfuzz_bin())
        .args([
            "corpus",
            "export",
            "--to",
            "libfuzzer",
            "--in",
            src.to_str().unwrap(),
            "--out",
            dst.to_str().unwrap(),
        ])
        .output()
        .expect("spawn govfuzz corpus export");
    assert!(out.status.success());
    for entry in fs::read_dir(&dst).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert_eq!(
            name.len(),
            40,
            "libfuzzer name should be 40 hex chars: {name}"
        );
        assert!(name.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
