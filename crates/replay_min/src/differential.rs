// SPDX-License-Identifier: Apache-2.0

use corpus::Signature;
use serde::Serialize;

use crate::replay::{signatures_for_input_with_runner, HarnessRunner, ReplayError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompilerIdentity {
    pub id: String,
    pub version: String,
}

impl CompilerIdentity {
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DifferentialHarness {
    pub compiler: CompilerIdentity,
    pub signatures: Vec<Signature>,
}

impl DifferentialHarness {
    pub fn new(compiler: CompilerIdentity, signatures: Vec<Signature>) -> Self {
        Self {
            compiler,
            signatures,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DifferentialMismatch {
    pub left: DifferentialHarness,
    pub right: DifferentialHarness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DifferentialRunResult {
    Consistent {
        left: DifferentialHarness,
        right: DifferentialHarness,
    },
    Mismatch(DifferentialMismatch),
}

pub fn run_differential_harnesses(
    left_compiler: CompilerIdentity,
    left_runner: &HarnessRunner,
    right_compiler: CompilerIdentity,
    right_runner: &HarnessRunner,
    input: &[u8],
) -> Result<DifferentialRunResult, ReplayError> {
    let left = DifferentialHarness::new(
        left_compiler,
        signatures_for_input_with_runner(left_runner, input)?,
    );
    let right = DifferentialHarness::new(
        right_compiler,
        signatures_for_input_with_runner(right_runner, input)?,
    );

    Ok(compare_differential_signatures(&left, &right))
}

pub fn compare_differential_signatures(
    left: &DifferentialHarness,
    right: &DifferentialHarness,
) -> DifferentialRunResult {
    if left.signatures == right.signatures {
        DifferentialRunResult::Consistent {
            left: left.clone(),
            right: right.clone(),
        }
    } else {
        DifferentialRunResult::Mismatch(DifferentialMismatch {
            left: left.clone(),
            right: right.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_harness_signatures_are_consistent() {
        let left = DifferentialHarness::new(
            CompilerIdentity::new("FSF GNAT", "13.2.0"),
            vec![signature("aaa")],
        );
        let right = DifferentialHarness::new(
            CompilerIdentity::new("FSF GNAT", "14.1.0"),
            vec![signature("aaa")],
        );

        let result = compare_differential_signatures(&left, &right);

        assert!(matches!(result, DifferentialRunResult::Consistent { .. }));
    }

    #[test]
    fn mismatching_harness_signatures_report_both_compilers() {
        let left = DifferentialHarness::new(
            CompilerIdentity::new("FSF GNAT", "13.2.0"),
            vec![signature("aaa")],
        );
        let right = DifferentialHarness::new(
            CompilerIdentity::new("AdaCore GNAT Pro", "24.0"),
            vec![signature("bbb")],
        );

        let result = compare_differential_signatures(&left, &right);

        let DifferentialRunResult::Mismatch(mismatch) = result else {
            panic!("expected mismatch");
        };
        assert_eq!(mismatch.left.compiler.id, "FSF GNAT");
        assert_eq!(mismatch.right.compiler.id, "AdaCore GNAT Pro");
        assert_eq!(mismatch.left.signatures, vec![signature("aaa")]);
        assert_eq!(mismatch.right.signatures, vec![signature("bbb")]);
    }

    #[test]
    fn differential_runner_executes_two_harnesses_and_reports_mismatch() {
        let root = temp_dir("runner-mismatch");
        let left_path = compile_line_harness(&root, "left", 9);
        let right_path = compile_line_harness(&root, "right", 10);

        let result = run_differential_harnesses(
            CompilerIdentity::new("FSF GNAT", "13.2.0"),
            &crate::HarnessRunner::direct(left_path),
            CompilerIdentity::new("AdaCore GNAT Pro", "24.0"),
            &crate::HarnessRunner::direct(right_path),
            b"input",
        )
        .expect("differential harness run succeeds");

        assert!(matches!(result, DifferentialRunResult::Mismatch(_)));
    }

    fn signature(hex: &str) -> corpus::Signature {
        let byte = hex.as_bytes()[0];
        corpus::Signature([byte; 32])
    }

    fn compile_line_harness(root: &std::path::Path, name: &str, line: u32) -> std::path::PathBuf {
        let source_path = root.join(format!("{name}.rs"));
        let harness_path = root.join(name);
        std::fs::write(
            &source_path,
            format!(
                r#"
use std::io::Read;

fn main() -> std::io::Result<()> {{
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let event_path = std::env::var("GOVFUZZ_EVENTS_PATH").map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    push_begin(&mut bytes, 1);
    push_target(&mut bytes, 0x42);
    push_crumb(&mut bytes, 1);
    push_handler(&mut bytes);
    push_end(&mut bytes, 0);
    std::fs::write(event_path, bytes)
}}

fn push_begin(bytes: &mut Vec<u8>, testcase_id: u64) {{
    bytes.push(1);
    bytes.extend_from_slice(&testcase_id.to_le_bytes());
}}

fn push_end(bytes: &mut Vec<u8>, result_class: u8) {{
    bytes.push(2);
    bytes.push(result_class);
}}

fn push_crumb(bytes: &mut Vec<u8>, id: u32) {{
    bytes.push(3);
    bytes.extend_from_slice(&id.to_le_bytes());
}}

fn push_target(bytes: &mut Vec<u8>, id: u32) {{
    bytes.push(4);
    bytes.extend_from_slice(&id.to_le_bytes());
}}

fn push_handler(bytes: &mut Vec<u8>) {{
    bytes.push(5);
    push_string(bytes, "CONSTRAINT_ERROR");
    push_string(bytes, "bad input");
    push_string(bytes, "pkg.adb");
    bytes.extend_from_slice(&{line}_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0x42_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
}}

fn push_string(bytes: &mut Vec<u8>, value: &str) {{
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}}
"#
            ),
        )
        .expect("harness source is written");
        let output = std::process::Command::new("rustc")
            .arg(&source_path)
            .arg("-o")
            .arg(&harness_path)
            .output()
            .expect("rustc runs");
        assert!(
            output.status.success(),
            "rustc failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        harness_path
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-differential-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).expect("temporary directory is created");
        dir
    }
}
