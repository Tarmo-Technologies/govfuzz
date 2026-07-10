// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
#[test]
fn binary_fuzz_finds_replayable_stdin_and_file_crashes() {
    let root = temp_dir("stdin-file");
    let stdin_bin = root.join("crash-stdin.sh");
    write_executable(
        &stdin_bin,
        "#!/bin/sh\ninput=$(cat)\nif [ \"$input\" = \"CRASH\" ]; then echo binary-crash >&2; exit 42; fi\nexit 0\n",
    );
    let file_bin = root.join("crash-file.sh");
    write_executable(
        &file_bin,
        "#!/bin/sh\nif [ -n \"$1\" ] && grep -q CRASH \"$1\"; then echo file-crash >&2; exit 43; fi\nexit 0\n",
    );

    let work = root.join("work");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "binary-fuzz",
                stdin_bin.to_str().unwrap(),
                "--work-dir",
                work.to_str().unwrap(),
                "--input-mode",
                "stdin",
                "--seed-input",
                "CRASH",
                "--env",
                "GOVFUZZ_TEST_ENV=1",
                "--timeout-ms",
                "1000",
            ])
            .output()
            .unwrap(),
    );
    let stdin_finding_dir = work.join("findings/BF-0001");
    let stdin_finding = read_json(&stdin_finding_dir.join("finding.json"));
    assert_eq!(stdin_finding["kind"], "binary_crash");
    assert_eq!(stdin_finding["input"]["mode"], "stdin");
    assert_eq!(stdin_finding["crash"]["exit_code"], 42);
    assert_eq!(stdin_finding["env"]["GOVFUZZ_TEST_ENV"], "1");
    assert_eq!(
        stdin_finding["binary"]["sha256"].as_str().unwrap().len(),
        64
    );

    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "replay",
                stdin_finding_dir.to_str().unwrap(),
                "--harness",
                stdin_bin.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "minimize",
                stdin_finding_dir.to_str().unwrap(),
                "--harness",
                stdin_bin.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let minimized = read_json(&stdin_finding_dir.join("finding.json"));
    assert_eq!(minimized["minimal_reproducer"], "min_testcase.bin");

    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "binary-fuzz",
                file_bin.to_str().unwrap(),
                "--work-dir",
                work.to_str().unwrap(),
                "--input-mode",
                "file",
                "--seed-input",
                "CRASH",
                "--timeout-ms",
                "1000",
            ])
            .output()
            .unwrap(),
    );
    let file_finding = read_json(&work.join("findings/BF-0002/finding.json"));
    assert_eq!(file_finding["input"]["mode"], "file");
    assert_eq!(file_finding["crash"]["exit_code"], 43);
}

#[test]
fn ci_fails_on_binary_crash_findings() {
    let root = temp_dir("ci");
    let work = root.join("work");
    let finding = work.join("findings/BF-0001");
    fs::create_dir_all(&finding).unwrap();
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&json!({
            "id": "BF-0001",
            "kind": "binary_crash",
            "severity": "high",
            "rule_id": "GF-501"
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(govfuzz_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "1",
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn write_executable(path: &Path, source: &str) {
    fs::write(path, source).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-binary-fuzz-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
