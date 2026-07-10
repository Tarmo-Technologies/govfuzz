// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `govfuzz snippet`: paste ONE function with no project,
//! build, or dependencies present and get a fuzz verdict. Verifies the wrapper
//! detects the language, synthesizes a one-file project, and drives the full
//! `auto` pipeline to a real finding on a classic overflow — from both a file
//! argument and a stdin paste.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn govfuzz() -> Command {
    Command::new(env!("CARGO_BIN_EXE_govfuzz"))
}

/// A stack overflow: copies an attacker-controlled length into a fixed buffer.
const BUGGY_C: &str = "\
#include <string.h>
int parse_header(const char *data, unsigned int len) {
    char buf[16];
    memcpy(buf, data, len);
    return buf[0];
}
";

#[test]
fn snippet_from_file_fuzzes_a_bare_c_function() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("gf-snippet-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let snippet = tmp.join("fn.c");
    std::fs::write(&snippet, BUGGY_C).unwrap();
    let work = tmp.join("work");

    let output = govfuzz()
        .arg("snippet")
        .arg(&snippet)
        .arg("--per-target-time")
        .arg("8")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run govfuzz snippet");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("detected c"),
        "snippet should detect C; stderr:\n{stderr}"
    );
    assert!(
        finding_count(&work) >= 1,
        "snippet should surface the overflow; stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn snippet_from_stdin_detects_language() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("gf-snippet-stdin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let work = tmp.join("work");

    let mut child = govfuzz()
        .arg("snippet")
        .arg("--per-target-time")
        .arg("8")
        .arg("--work-dir")
        .arg(&work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn govfuzz snippet");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(BUGGY_C.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Content sniffer must pin C from the paste alone (no filename).
    assert!(
        stderr.contains("detected c"),
        "stdin snippet should detect C from content; stderr:\n{stderr}"
    );
    assert!(
        finding_count(&work) >= 1,
        "stdin snippet should surface the overflow; stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Count `findings/*/finding.json` written under a snippet work dir.
fn finding_count(work: &Path) -> usize {
    let dir = work.join("findings");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.path().join("finding.json").is_file())
        .count()
}
