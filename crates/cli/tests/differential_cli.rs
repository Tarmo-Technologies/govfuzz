// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that `govfuzz differential` finds output
//! divergences between two harness binaries.

use std::fs;
use std::os::unix::fs::PermissionsExt;
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
    let dir = std::env::temp_dir().join(format!("govfuzz-diff-cli-{prefix}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_harness(dir: &std::path::Path, name: &str, script: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, script).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

#[test]
fn identical_harnesses_produce_zero_divergences() {
    let work = tempdir("identical");
    let inputs = work.join("inputs");
    fs::create_dir_all(&inputs).unwrap();
    fs::write(inputs.join("a.bin"), b"hello").unwrap();
    fs::write(inputs.join("b.bin"), b"world").unwrap();

    let harness_a = write_harness(&work, "harness_a", "#!/bin/sh\ncat \"$1\"\n");
    let harness_b = write_harness(&work, "harness_b", "#!/bin/sh\ncat \"$1\"\n");
    let out_dir = work.join("out");

    let out = Command::new(govfuzz_bin())
        .args([
            "differential",
            "--harness-a",
            harness_a.to_str().unwrap(),
            "--harness-b",
            harness_b.to_str().unwrap(),
            "--inputs",
            inputs.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("spawn differential");
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("2 inputs"));
    assert!(stdout.contains("0 divergences"));
}

#[test]
fn divergent_harnesses_emit_findings_and_nonzero_exit() {
    let work = tempdir("divergent");
    let inputs = work.join("inputs");
    fs::create_dir_all(&inputs).unwrap();
    fs::write(inputs.join("a.bin"), b"hello").unwrap();
    fs::write(inputs.join("b.bin"), b"world").unwrap();
    fs::write(inputs.join("c.bin"), b"!!").unwrap();

    let harness_a = write_harness(&work, "harness_a", "#!/bin/sh\ncat \"$1\"\n");
    // Harness B reverses; for ASCII content these will differ.
    let harness_b = write_harness(&work, "harness_b", "#!/bin/sh\nrev \"$1\"\n");
    let out_dir = work.join("out");

    let out = Command::new(govfuzz_bin())
        .args([
            "differential",
            "--harness-a",
            harness_a.to_str().unwrap(),
            "--harness-b",
            harness_b.to_str().unwrap(),
            "--inputs",
            inputs.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("spawn differential");
    assert_eq!(
        out.status.code(),
        Some(1),
        "differential should exit 1 on divergences; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let findings_dir = out_dir.join("findings");
    let count = fs::read_dir(&findings_dir).unwrap().count();
    assert!(count >= 1, "expected at least one finding directory");

    let any_finding = fs::read_dir(&findings_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let finding_json: serde_json::Value =
        serde_json::from_slice(&fs::read(any_finding.path().join("finding.json")).unwrap())
            .unwrap();
    assert_eq!(finding_json["rule_id"], "GF-301");
    assert_eq!(finding_json["classification"], "divergence");
    assert_eq!(
        finding_json["oracle"]["name"],
        "differential-output-runtime"
    );
    assert_eq!(finding_json["oracle"]["rule_id"], "GF-301");
    assert_eq!(finding_json["oracle"]["api"], "govfuzz differential");
    assert!(finding_json["differential"]["stdout_a_preview"].is_string());
    assert!(finding_json["differential"]["stdout_b_preview"].is_string());
}

#[test]
fn metamorphic_transform_emits_oracle_finding() {
    let work = tempdir("metamorphic");
    let inputs = work.join("inputs");
    fs::create_dir_all(&inputs).unwrap();
    fs::write(inputs.join("a.bin"), b"abc").unwrap();

    let harness = write_harness(&work, "harness", "#!/bin/sh\nwc -c < \"$1\"\n");
    let out_dir = work.join("out");

    let out = Command::new(govfuzz_bin())
        .args([
            "differential",
            "--harness",
            harness.to_str().unwrap(),
            "--metamorphic-transform",
            "append-newline",
            "--inputs",
            inputs.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("spawn metamorphic differential");
    assert_eq!(
        out.status.code(),
        Some(1),
        "metamorphic relation violation should exit 1; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let findings_dir = out_dir.join("findings");
    let count = fs::read_dir(&findings_dir).unwrap().count();
    assert_eq!(count, 1, "expected exactly one metamorphic finding");

    let finding_entry = fs::read_dir(&findings_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let finding_json: serde_json::Value =
        serde_json::from_slice(&fs::read(finding_entry.path().join("finding.json")).unwrap())
            .unwrap();
    assert_eq!(finding_json["rule_id"], "GF-307");
    assert_eq!(finding_json["classification"], "metamorphic_violation");
    assert_eq!(
        finding_json["oracle"]["name"],
        "metamorphic-relation-runtime"
    );
    assert_eq!(finding_json["oracle"]["rule_id"], "GF-307");
    assert_eq!(
        finding_json["oracle"]["api"],
        "govfuzz differential metamorphic"
    );
    assert_eq!(finding_json["metamorphic"]["transform"], "append-newline");
    assert_eq!(
        finding_json["paths"]["transformed_testcase"],
        "testcase_transformed.bin"
    );
}
