// SPDX-License-Identifier: Apache-2.0

//! `govfuzz differential` subcommand: replay each input through
//! two harnesses, compare stdout + exit code, emit GF-301 findings
//! on divergence. No mutation or coverage feedback — pure replay.

use finding_rules::oracle_registry::ORACLE_REGISTRY;
use finding_rules::oracle_sdk::{OracleHit, OracleRuntimeEvent};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Error, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, clap::Args)]
pub struct DifferentialArgs {
    /// First harness binary. Receives the input path as argv[1].
    #[arg(long = "harness-a", value_name = "PATH")]
    pub harness_a: Option<PathBuf>,

    /// Second harness binary. Receives the input path as argv[1].
    #[arg(long = "harness-b", value_name = "PATH")]
    pub harness_b: Option<PathBuf>,

    /// Single harness binary for metamorphic mode. Receives the input path as argv[1].
    #[arg(long = "harness", value_name = "PATH")]
    pub harness: Option<PathBuf>,

    /// Metamorphic transform to apply to each input before replaying the same harness.
    #[arg(long = "metamorphic-transform", value_enum, value_name = "NAME")]
    pub metamorphic_transform: Option<MetamorphicTransform>,

    /// Directory of input files to replay through both harnesses.
    #[arg(long, value_name = "DIR")]
    pub inputs: PathBuf,

    /// Findings output directory.
    #[arg(long, value_name = "DIR", default_value = "findings_differential")]
    pub out: PathBuf,

    /// Per-side timeout in seconds.
    #[arg(long, default_value_t = 5)]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MetamorphicTransform {
    #[value(name = "append-newline")]
    AppendNewline,
}

impl MetamorphicTransform {
    fn as_str(self) -> &'static str {
        match self {
            MetamorphicTransform::AppendNewline => "append-newline",
        }
    }

    fn apply(self, input: &[u8]) -> Vec<u8> {
        match self {
            MetamorphicTransform::AppendNewline => {
                let mut transformed = input.to_vec();
                transformed.push(b'\n');
                transformed
            }
        }
    }
}

#[derive(Debug, Clone)]
enum RunMode {
    Differential {
        harness_a: PathBuf,
        harness_b: PathBuf,
    },
    Metamorphic {
        harness: PathBuf,
        transform: MetamorphicTransform,
    },
}

impl RunMode {
    fn from_args(args: &DifferentialArgs) -> Result<Self, std::io::Error> {
        match args.metamorphic_transform {
            Some(transform) => {
                if args.harness_a.is_some() || args.harness_b.is_some() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "--metamorphic-transform uses --harness, not --harness-a/--harness-b",
                    ));
                }
                let harness = args.harness.clone().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "--metamorphic-transform requires --harness",
                    )
                })?;
                Ok(RunMode::Metamorphic { harness, transform })
            }
            None => {
                if args.harness.is_some() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "--harness requires --metamorphic-transform",
                    ));
                }
                let harness_a = args.harness_a.clone().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidInput, "missing required --harness-a")
                })?;
                let harness_b = args.harness_b.clone().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidInput, "missing required --harness-b")
                })?;
                Ok(RunMode::Differential {
                    harness_a,
                    harness_b,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HarnessOutput {
    stdout: Vec<u8>,
    #[allow(dead_code)]
    // captured for future inclusion in findings; v0.1 keeps stderr out of the divergence predicate
    stderr: Vec<u8>,
    exit_code: i32,
    timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Divergence {
    pub stdout_equal: bool,
    pub exit_equal: bool,
    pub stdout_a_preview: String,
    pub stdout_b_preview: String,
    pub exit_a: i32,
    pub exit_b: i32,
    pub timed_out_a: bool,
    pub timed_out_b: bool,
}

pub fn run(args: DifferentialArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    }
}

fn run_inner(args: DifferentialArgs) -> Result<i32, std::io::Error> {
    let mode = RunMode::from_args(&args)?;
    fs::create_dir_all(&args.out)?;
    let findings_root = args.out.join("findings");
    fs::create_dir_all(&findings_root)?;
    let transformed_root = args.out.join("metamorphic_inputs");
    if matches!(mode, RunMode::Metamorphic { .. }) {
        fs::create_dir_all(&transformed_root)?;
    }

    let mut inputs: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&args.inputs)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            inputs.push(entry.path());
        }
    }
    inputs.sort();

    let timeout = Duration::from_secs(args.timeout_secs);
    let mut divergences = 0usize;
    let mut ordinal = 0u32;

    for (input_index, input_path) in inputs.iter().enumerate() {
        let input_bytes = fs::read(input_path)?;
        match &mode {
            RunMode::Differential {
                harness_a,
                harness_b,
            } => {
                let out_a = run_harness(harness_a, input_path, timeout);
                let out_b = run_harness(harness_b, input_path, timeout);
                if let Some(div) = compare_outputs(&out_a, &out_b) {
                    divergences += 1;
                    write_finding(
                        &findings_root,
                        ordinal,
                        &input_bytes,
                        harness_a,
                        harness_b,
                        &div,
                    )?;
                    ordinal += 1;
                }
            }
            RunMode::Metamorphic { harness, transform } => {
                let transformed_bytes = transform.apply(&input_bytes);
                let transformed_path = transformed_root.join(format!("{input_index:04}.bin"));
                fs::write(&transformed_path, &transformed_bytes)?;
                let original = run_harness(harness, input_path, timeout);
                let transformed = run_harness(harness, &transformed_path, timeout);
                if let Some(div) = compare_outputs(&original, &transformed) {
                    divergences += 1;
                    write_metamorphic_finding(
                        &findings_root,
                        ordinal,
                        &input_bytes,
                        &transformed_bytes,
                        harness,
                        *transform,
                        &div,
                    )?;
                    ordinal += 1;
                }
            }
        }
    }

    println!("{} inputs, {} divergences", inputs.len(), divergences);
    Ok(if divergences > 0 { 1 } else { 0 })
}

fn run_harness(bin: &Path, input: &Path, timeout: Duration) -> HarnessOutput {
    let child = Command::new(bin)
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(error) => {
            return HarnessOutput {
                stdout: Vec::new(),
                stderr: format!("spawn failed: {error}").into_bytes(),
                exit_code: -1,
                timed_out: false,
            };
        }
    };
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    timed_out = true;
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return HarnessOutput {
                    stdout: Vec::new(),
                    stderr: format!("wait failed: {error}").into_bytes(),
                    exit_code: -1,
                    timed_out: false,
                };
            }
        }
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_end(&mut stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_end(&mut stderr);
    }
    let exit_code = if timed_out {
        -1
    } else {
        child.wait().ok().and_then(|s| s.code()).unwrap_or(-1)
    };
    HarnessOutput {
        stdout,
        stderr,
        exit_code,
        timed_out,
    }
}

pub(crate) fn compare_outputs(a: &HarnessOutput, b: &HarnessOutput) -> Option<Divergence> {
    let stdout_equal = a.stdout == b.stdout;
    let exit_equal = a.exit_code == b.exit_code && a.timed_out == b.timed_out;
    if stdout_equal && exit_equal {
        None
    } else {
        Some(Divergence {
            stdout_equal,
            exit_equal,
            stdout_a_preview: truncate_preview(&a.stdout, 4096),
            stdout_b_preview: truncate_preview(&b.stdout, 4096),
            exit_a: a.exit_code,
            exit_b: b.exit_code,
            timed_out_a: a.timed_out,
            timed_out_b: b.timed_out,
        })
    }
}

pub(crate) fn truncate_preview(bytes: &[u8], max: usize) -> String {
    let slice = if bytes.len() > max {
        &bytes[..max]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).into_owned()
}

fn write_finding(
    findings_root: &Path,
    ordinal: u32,
    input_bytes: &[u8],
    harness_a: &Path,
    harness_b: &Path,
    div: &Divergence,
) -> std::io::Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(input_bytes);
    let signature_hex = format!("{:x}", hasher.finalize());
    let oracle_hit = differential_oracle_hit(&signature_hex, div).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "differential oracle did not match a divergent output pair",
        )
    })?;
    let short = signature_hex.chars().take(8).collect::<String>();
    let id = format!("F-{ordinal:04}-{short}");
    let finding_dir = findings_root.join(&id);
    fs::create_dir_all(&finding_dir)?;
    fs::write(finding_dir.join("testcase.bin"), input_bytes)?;
    let record = json!({
        "id": id,
        "signature": signature_hex,
        "rule_id": "GF-301",
        "classification": "divergence",
        "exception": {
            "name": "OUTPUT_DIVERGENCE",
            "message": if div.stdout_equal {
                "exit codes differ"
            } else {
                "stdout bytes differ"
            },
        },
        "differential": {
            "harness_a": harness_a.display().to_string(),
            "harness_b": harness_b.display().to_string(),
            "stdout_equal": div.stdout_equal,
            "exit_equal": div.exit_equal,
            "stdout_a_preview": div.stdout_a_preview,
            "stdout_b_preview": div.stdout_b_preview,
            "exit_a": div.exit_a,
            "exit_b": div.exit_b,
            "timed_out_a": div.timed_out_a,
            "timed_out_b": div.timed_out_b,
        },
        "oracle": oracle_hit_json(&oracle_hit),
        "paths": {
            "testcase": "testcase.bin",
            "finding": "finding.json",
        },
    });
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    Ok(())
}

fn write_metamorphic_finding(
    findings_root: &Path,
    ordinal: u32,
    input_bytes: &[u8],
    transformed_bytes: &[u8],
    harness: &Path,
    transform: MetamorphicTransform,
    div: &Divergence,
) -> std::io::Result<()> {
    let input_sha256 = sha256_hex(input_bytes);
    let transformed_sha256 = sha256_hex(transformed_bytes);
    let signature_hex = metamorphic_signature(transform, input_bytes, transformed_bytes);
    let oracle_hit = metamorphic_oracle_hit(&input_sha256, &transformed_sha256, transform, div)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "metamorphic oracle did not match a relation violation",
            )
        })?;
    let short = signature_hex.chars().take(8).collect::<String>();
    let id = format!("F-{ordinal:04}-{short}");
    let finding_dir = findings_root.join(&id);
    fs::create_dir_all(&finding_dir)?;
    fs::write(finding_dir.join("testcase.bin"), input_bytes)?;
    fs::write(
        finding_dir.join("testcase_transformed.bin"),
        transformed_bytes,
    )?;
    let record = json!({
        "id": id,
        "signature": signature_hex,
        "rule_id": "GF-307",
        "classification": "metamorphic_violation",
        "exception": {
            "name": "METAMORPHIC_RELATION_VIOLATION",
            "message": if div.stdout_equal {
                "exit codes differ after metamorphic transform"
            } else {
                "stdout bytes differ after metamorphic transform"
            },
        },
        "metamorphic": {
            "harness": harness.display().to_string(),
            "transform": transform.as_str(),
            "stdout_equal": div.stdout_equal,
            "exit_equal": div.exit_equal,
            "original_stdout_preview": div.stdout_a_preview,
            "transformed_stdout_preview": div.stdout_b_preview,
            "original_exit": div.exit_a,
            "transformed_exit": div.exit_b,
            "timed_out_original": div.timed_out_a,
            "timed_out_transformed": div.timed_out_b,
        },
        "oracle": oracle_hit_json(&oracle_hit),
        "paths": {
            "testcase": "testcase.bin",
            "transformed_testcase": "testcase_transformed.bin",
            "finding": "finding.json",
        },
    });
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn metamorphic_signature(
    transform: MetamorphicTransform,
    input_bytes: &[u8],
    transformed_bytes: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"metamorphic\0");
    hasher.update(transform.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(input_bytes);
    hasher.update(b"\0");
    hasher.update(transformed_bytes);
    format!("{:x}", hasher.finalize())
}

fn differential_oracle_hit(input_sha256: &str, div: &Divergence) -> Option<OracleHit> {
    let event = OracleRuntimeEvent::Differential {
        api: "govfuzz differential".to_owned(),
        stdout_equal: div.stdout_equal,
        exit_equal: div.exit_equal,
        timed_out_a: div.timed_out_a,
        timed_out_b: div.timed_out_b,
        evidence: vec![("input_sha256".to_owned(), input_sha256.to_owned())],
    };
    ORACLE_REGISTRY
        .iter()
        .find_map(|oracle| oracle.evaluate(&event))
}

fn metamorphic_oracle_hit(
    input_sha256: &str,
    transformed_sha256: &str,
    transform: MetamorphicTransform,
    div: &Divergence,
) -> Option<OracleHit> {
    let event = OracleRuntimeEvent::Metamorphic {
        api: "govfuzz differential metamorphic".to_owned(),
        relation: transform.as_str().to_owned(),
        stdout_equal: div.stdout_equal,
        exit_equal: div.exit_equal,
        timed_out_original: div.timed_out_a,
        timed_out_transformed: div.timed_out_b,
        evidence: vec![
            ("input_sha256".to_owned(), input_sha256.to_owned()),
            (
                "transformed_input_sha256".to_owned(),
                transformed_sha256.to_owned(),
            ),
        ],
    };
    ORACLE_REGISTRY
        .iter()
        .find_map(|oracle| oracle.evaluate(&event))
}

fn oracle_hit_json(hit: &OracleHit) -> serde_json::Value {
    json!({
        "name": hit.oracle_name,
        "rule_id": hit.rule_id,
        "category": hit.category,
        "api": hit.api,
        "message": hit.message,
        "evidence": hit.evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::{compare_outputs, truncate_preview, HarnessOutput};

    fn harness_output(stdout: &[u8], exit_code: i32) -> HarnessOutput {
        HarnessOutput {
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            exit_code,
            timed_out: false,
        }
    }

    #[test]
    fn compare_outputs_returns_none_when_identical() {
        let a = harness_output(b"hello", 0);
        let b = harness_output(b"hello", 0);
        assert!(compare_outputs(&a, &b).is_none());
    }

    #[test]
    fn compare_outputs_flags_stdout_difference() {
        let a = harness_output(b"hello", 0);
        let b = harness_output(b"world", 0);
        let div = compare_outputs(&a, &b).expect("divergent");
        assert!(!div.stdout_equal);
        assert!(div.exit_equal);
    }

    #[test]
    fn compare_outputs_flags_exit_code_difference() {
        let a = harness_output(b"same", 0);
        let b = harness_output(b"same", 1);
        let div = compare_outputs(&a, &b).expect("divergent");
        assert!(div.stdout_equal);
        assert!(!div.exit_equal);
    }

    #[test]
    fn truncate_preview_keeps_first_4096_bytes() {
        let bytes = vec![b'a'; 5000];
        let preview = truncate_preview(&bytes, 4096);
        assert_eq!(preview.len(), 4096);
    }

    #[test]
    fn truncate_preview_produces_lossy_for_binary_input() {
        let preview = truncate_preview(&[0xFF, 0xFE, b'a'], 4096);
        assert!(preview.contains('a'));
    }
}
