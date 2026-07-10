// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn binary_adapter_normalizes_mock_contract_and_error_reports() {
    let root = temp_dir("mock");
    let target = root.join("sample.elf");
    write_elf64_x86_64(&target);
    let mock = root.join("mock-adapter.json");
    fs::write(
        &mock,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.binary.adapter.mock.v1",
            "adapter": "mock-disasm",
            "status": "ok",
            "functions": [{ "name": "parse", "address": "0x1000", "signature": "int parse(char *)" }],
            "call_graph": [{ "caller": "main", "callee": "parse" }],
            "strings": [{ "address": "0x2000", "value": "usage: legacy" }],
            "xrefs": [{ "from": "0x1000", "to": "0x2000", "kind": "data" }]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = root.join("out-ok");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "binary-adapter",
                target.to_str().unwrap(),
                "--adapter",
                "mock",
                "--mock-output",
                mock.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let report = read_json(&out.join("binary-adapter-report.json"));
    assert_eq!(report["schema_version"], "govfuzz.binary.adapter.v1");
    assert_eq!(report["evidence_kind"], "adapter_derived");
    assert_eq!(report["adapter"]["kind"], "mock");
    assert_eq!(report["functions"][0]["name"], "parse");
    assert_eq!(report["call_graph"][0]["callee"], "parse");
    assert_eq!(report["strings"][0]["value"], "usage: legacy");
    assert_eq!(report["xrefs"][0]["kind"], "data");

    let mock_error = root.join("mock-error.json");
    fs::write(
        &mock_error,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "govfuzz.binary.adapter.mock.v1",
            "adapter": "mock-disasm",
            "status": "error",
            "error": "adapter timeout"
        }))
        .unwrap(),
    )
    .unwrap();
    let out_error = root.join("out-error");
    let output = Command::new(govfuzz_bin())
        .args([
            "binary-adapter",
            target.to_str().unwrap(),
            "--adapter",
            "mock",
            "--mock-output",
            mock_error.to_str().unwrap(),
            "--out",
            out_error.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error_report = read_json(&out_error.join("binary-adapter-report.json"));
    assert_eq!(error_report["status"], "error");
    assert_eq!(error_report["errors"][0]["message"], "adapter timeout");
}

#[test]
fn binary_adapter_blocks_real_adapters_by_default_and_skips_missing_tools_when_opted_in() {
    let root = temp_dir("policy");
    let target = root.join("sample.elf");
    write_elf64_x86_64(&target);
    let missing_tool = root.join("missing-rizin").to_string_lossy().into_owned();

    let blocked = Command::new(govfuzz_bin())
        .args([
            "binary-adapter",
            target.to_str().unwrap(),
            "--adapter",
            "rizin",
            "--tool",
            &missing_tool,
            "--out",
            root.join("blocked").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(blocked.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("not allowed"));

    let out = root.join("skipped");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "--profile",
                "external-tools",
                "binary-adapter",
                target.to_str().unwrap(),
                "--adapter",
                "rizin",
                "--tool",
                &missing_tool,
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let report = read_json(&out.join("binary-adapter-report.json"));
    assert_eq!(report["adapter"]["kind"], "rizin");
    assert_eq!(report["status"], "skipped");
    assert_eq!(report["errors"][0]["reason"], "tool_not_found");
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

fn write_elf64_x86_64(path: &Path) {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-binary-adapter-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
