// SPDX-License-Identifier: Apache-2.0

//! #103: `govfuzz bug-report --bundle X.tar.gz` produces an offline, scrubbed
//! diagnostic archive whose self-test refuses to leak host secrets, and
//! `--preview` shows the inventory without writing an archive.

use std::path::Path;
use std::process::Command;

fn govfuzz() -> Command {
    Command::new(env!("CARGO_BIN_EXE_govfuzz"))
}

fn have_clang() -> bool {
    which::which("clang").is_ok() || which::which("cc").is_ok()
}

/// A work directory whose absolute path embeds a unique, secret-looking token, so
/// a leak of the real work path into the bundle is detectable by grep.
fn secret_workspace(secret: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{secret}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn populate_work_dir(base: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let src = base.join("src");
    let work = base.join("work");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("lib.c"),
        "#include <stddef.h>\n#include <stdint.h>\nint decode(const uint8_t*d,size_t n){return n&&d[0]=='Z';}\n",
    )
    .unwrap();
    let status = govfuzz()
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass")
        .arg("--max-targets")
        .arg("1")
        .status()
        .expect("run govfuzz auto");
    assert!(status.success() || work.join("auto/run.json").is_file());
    (src, work)
}

#[test]
fn bundle_is_offline_scrubbed_and_self_tested_against_host_secrets() {
    if !have_clang() {
        eprintln!("SKIP: no C compiler on PATH");
        return;
    }
    // The unique token lives in the work-dir path; the bundle must not leak it.
    let secret = "govfuzzSECRETUSERxyz";
    let base = secret_workspace(secret);
    let (_src, work) = populate_work_dir(&base);

    let out = base.join("govfuzz-bug-report.tar.gz");
    let output = govfuzz()
        .arg("bug-report")
        .arg(&work)
        .arg("--bundle")
        .arg(&out)
        .output()
        .expect("run govfuzz bug-report --bundle");
    assert!(
        output.status.success(),
        "bug-report --bundle failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.is_file(), "the bundle archive must be written");

    // Extract and assert: the mandatory fields exist, and the planted secret path
    // token appears NOWHERE in the archive contents.
    let extract = base.join("extract");
    std::fs::create_dir_all(&extract).unwrap();
    let untar = Command::new("tar")
        .arg("-xzf")
        .arg(&out)
        .arg("-C")
        .arg(&extract)
        .status()
        .expect("extract bundle");
    assert!(untar.success());
    let root = extract.join("govfuzz-bug-report");
    for field in ["support-report.txt", "MANIFEST.txt", "SELF-TEST.txt"] {
        assert!(root.join(field).is_file(), "bundle must contain {field}");
    }
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !content.contains(secret),
            "{}: leaked the work-dir secret token",
            path.display()
        );
    }
    let self_test = std::fs::read_to_string(root.join("SELF-TEST.txt")).unwrap();
    assert!(self_test.contains("PASS"), "self-test must record PASS");

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn preview_prints_inventory_without_writing_an_archive() {
    if !have_clang() {
        eprintln!("SKIP: no C compiler on PATH");
        return;
    }
    let base = secret_workspace("govfuzzPREVIEW");
    let (_src, work) = populate_work_dir(&base);
    let out = base.join("should-not-exist.tar.gz");

    let output = govfuzz()
        .arg("bug-report")
        .arg(&work)
        .arg("--preview")
        .output()
        .expect("run govfuzz bug-report --preview");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bundle preview") && stdout.contains("self-test: PASS"),
        "preview must print the inventory + self-test result; got:\n{stdout}"
    );
    assert!(!out.exists(), "--preview must not write any archive");
    let _ = std::fs::remove_dir_all(&base);
}
