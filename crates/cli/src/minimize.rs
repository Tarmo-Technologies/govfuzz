// SPDX-License-Identifier: Apache-2.0

use crate::finding_arg::resolve_finding_arg;
use crate::runner::{detect_harness_engine, harness_runner, HarnessEngine, SandboxModeArg};
use anyhow::{anyhow, Context};
use clap::ValueEnum;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct MinimizeArgs {
    /// Finding directory, or finding ID under ./findings.
    #[arg(
        value_name = "FINDING_DIR",
        required_unless_present = "finding",
        conflicts_with = "finding"
    )]
    pub finding_dir: Option<PathBuf>,

    /// Finding directory, or finding ID under ./findings.
    #[arg(long, value_name = "ID_OR_DIR")]
    pub finding: Option<PathBuf>,

    /// Harness binary path. Required for minimization.
    #[arg(long)]
    pub harness: PathBuf,

    /// qemu-user executable for ELF-Linux cross-target minimization.
    #[arg(long, value_name = "QEMU")]
    pub qemu_user: Option<PathBuf>,

    /// Extra argument passed to qemu-user before the harness path.
    #[arg(
        long = "qemu-arg",
        value_name = "ARG",
        allow_hyphen_values = true,
        requires = "qemu_user"
    )]
    pub qemu_args: Vec<String>,

    /// Sandbox wrapper for harness execution.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    pub sandbox: SandboxModeArg,

    /// Override sandbox wrapper executable.
    #[arg(long, value_name = "PATH", requires = "sandbox")]
    pub sandbox_tool: Option<PathBuf>,

    /// Fail if the requested sandbox tool is unavailable.
    #[arg(long)]
    pub sandbox_strict: bool,

    /// Minimization strategy.
    #[arg(long, value_enum, default_value_t = MinimizeStrategy::Bytes)]
    pub strategy: MinimizeStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinimizeStrategy {
    Bytes,
    Typed,
}

impl MinimizeStrategy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Typed => "typed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MinimizeSummary {
    strategy: MinimizeStrategy,
    original_len: usize,
    minimized_len: usize,
    removed_bytes: usize,
    reduced: bool,
}

/// How a candidate input is delivered to the harness's main().
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CEngineIo {
    /// libFuzzer single-input mode: \`./harness <input-file>\`.
    ArgvFile,
    /// AFL persistent-mode: pipe input bytes via stdin.
    Stdin,
}

/// Minimize a C/C++ harness crash by delta-debugging the recorded
/// testcase. The predicate runs the harness via the engine-specific
/// I/O contract (argv file for libFuzzer, stdin for AFL), parses
/// stderr for a sanitizer report, and accepts the candidate only
/// when it reproduces the same sanitizer rule_id as the original.
fn minimize_c_engine(
    finding_dir: &Path,
    harness: &Path,
    strategy: MinimizeStrategy,
    io: CEngineIo,
) -> anyhow::Result<MinimizeSummary> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    if strategy != MinimizeStrategy::Bytes {
        return Err(anyhow!(
            "minimize --strategy {} is not yet supported for C/C++ harnesses",
            strategy.as_str()
        ));
    }
    let testcase_path = finding_dir.join("testcase.bin");
    let original_input =
        fs::read(&testcase_path).with_context(|| format!("read {}", testcase_path.display()))?;

    let tmp_dir = finding_dir.join("minimize_tmp");
    fs::create_dir_all(&tmp_dir)
        .with_context(|| format!("create minimize temp dir {}", tmp_dir.display()))?;
    let run_once = |bytes: &[u8]| -> anyhow::Result<Option<&'static str>> {
        let mut cmd = Command::new(harness);
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());
        let input_path = match io {
            CEngineIo::ArgvFile => {
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let p = tmp_dir.join(format!("input-{}-{}.bin", std::process::id(), nonce));
                fs::write(&p, bytes).with_context(|| format!("write {}", p.display()))?;
                cmd.arg(&p).stdin(Stdio::null());
                Some(p)
            }
            CEngineIo::Stdin => {
                cmd.stdin(Stdio::piped());
                None
            }
        };
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", harness.display()))?;
        if let CEngineIo::Stdin = io {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(bytes);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait()? {
                Some(_) => break,
                None => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        let output = child.wait_with_output()?;
        if let Some(p) = input_path {
            let _ = fs::remove_file(&p);
        }
        if output.status.success() {
            return Ok(None);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(corpus::parse_sanitizer_report(&stderr).map(|r| r.rule_id))
    };

    let baseline = run_once(&original_input)?.ok_or_else(|| {
        anyhow!(
            "original testcase {} does not reproduce a sanitizer crash against {}",
            testcase_path.display(),
            harness.display()
        )
    })?;

    let result = replay_min::ddmin_bytes(&original_input, |candidate| -> anyhow::Result<bool> {
        Ok(run_once(candidate)?.map(|r| r == baseline).unwrap_or(false))
    })?;

    let _ = fs::remove_dir_all(&tmp_dir);

    let min_path = finding_dir.join("min_testcase.bin");
    fs::write(&min_path, &result.minimized)
        .with_context(|| format!("write minimized testcase to {}", min_path.display()))?;

    let removed = result.original_len.saturating_sub(result.minimized.len());
    let reduced = removed > 0;
    update_finding_record(
        finding_dir,
        &MinimizeOutput {
            strategy,
            original_len: result.original_len,
            minimized: result.minimized.clone(),
            metadata: json!({
                "strategy": strategy.as_str(),
                "original_len": result.original_len,
                "minimized_len": result.minimized.len(),
                "removed_bytes": removed,
                "reduced": reduced,
                "predicate_runs": result.predicate_runs,
                "engine": match io {
                    CEngineIo::ArgvFile => "libfuzzer-c",
                    CEngineIo::Stdin => "afl-c",
                },
            }),
            reduced,
        },
    )?;

    Ok(MinimizeSummary {
        strategy,
        original_len: result.original_len,
        minimized_len: result.minimized.len(),
        removed_bytes: removed,
        reduced,
    })
}

pub fn run(args: MinimizeArgs) -> i32 {
    match run_inner(args) {
        Ok(summary) => {
            println!(
                "MINIMIZED strategy={} original_len={} minimized_len={} removed_bytes={} reduced={} path=min_testcase.bin",
                summary.strategy.as_str(),
                summary.original_len,
                summary.minimized_len,
                summary.removed_bytes,
                summary.reduced
            );
            0
        }
        Err(error) => {
            gfeprintln!("error: {error:#}");
            1
        }
    }
}

fn run_inner(args: MinimizeArgs) -> anyhow::Result<MinimizeSummary> {
    let finding_dir = resolve_finding_arg(args.finding_dir, args.finding);
    if crate::binary_fuzz::is_binary_finding(&finding_dir) {
        let result = crate::binary_fuzz::minimize_binary_finding(
            &finding_dir,
            &args.harness,
            args.strategy,
        )?;
        return Ok(MinimizeSummary {
            strategy: args.strategy,
            original_len: result.original_len,
            minimized_len: result.minimized_len,
            removed_bytes: result.removed_bytes,
            reduced: result.reduced,
        });
    }
    // Dispatch by engine. Both C engines reuse the same delta-debug
    // skeleton but differ in how a candidate input reaches main():
    // libFuzzer takes argv[1], AFL persistent-mode reads stdin (the
    // generated template falls back to `govfuzz_afl_read_stdin`).
    match detect_harness_engine(&args.harness) {
        HarnessEngine::CAfl => {
            return minimize_c_engine(&finding_dir, &args.harness, args.strategy, CEngineIo::Stdin);
        }
        HarnessEngine::CLibFuzzer => {
            return minimize_c_engine(
                &finding_dir,
                &args.harness,
                args.strategy,
                CEngineIo::ArgvFile,
            );
        }
        HarnessEngine::AdaStdin => {}
    }
    let runner = harness_runner(
        args.harness,
        args.qemu_user,
        args.qemu_args,
        args.sandbox,
        args.sandbox_tool,
        args.sandbox_strict,
    );
    let result = minimize(&finding_dir, &runner, args.strategy)?;
    let min_path = finding_dir.join("min_testcase.bin");

    fs::write(&min_path, &result.minimized)
        .with_context(|| format!("write minimized testcase to {}", min_path.display()))?;
    update_finding_record(&finding_dir, &result)?;

    Ok(MinimizeSummary {
        strategy: result.strategy,
        original_len: result.original_len,
        minimized_len: result.minimized.len(),
        removed_bytes: result.original_len.saturating_sub(result.minimized.len()),
        reduced: result.reduced,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MinimizeOutput {
    strategy: MinimizeStrategy,
    original_len: usize,
    minimized: Vec<u8>,
    metadata: serde_json::Value,
    reduced: bool,
}

fn minimize(
    finding_dir: &Path,
    runner: &replay_min::HarnessRunner,
    strategy: MinimizeStrategy,
) -> anyhow::Result<MinimizeOutput> {
    match strategy {
        MinimizeStrategy::Bytes => {
            let result = replay_min::minimize_finding_bytes_with_runner(finding_dir, runner)?;
            let reduced = result.removed_bytes() > 0;
            let metadata = json!({
                "strategy": strategy.as_str(),
                "original_len": result.original_len,
                "minimized_len": result.minimized_len(),
                "removed_bytes": result.removed_bytes(),
                "reduced": reduced,
                "predicate_runs": result.predicate_runs,
            });
            Ok(MinimizeOutput {
                strategy,
                original_len: result.original_len,
                minimized: result.minimized,
                metadata,
                reduced,
            })
        }
        MinimizeStrategy::Typed => {
            let result =
                replay_min::minimize_finding_typed_values_with_runner(finding_dir, runner)?;
            let reduced = result.removed_bytes() > 0;
            let metadata = json!({
                "strategy": strategy.as_str(),
                "original_len": result.original_len,
                "minimized_len": result.minimized_len(),
                "removed_bytes": result.removed_bytes(),
                "reduced": reduced,
                "attempted_replacements": result.attempted_replacements,
                "accepted_replacements": result.accepted_replacements,
            });
            Ok(MinimizeOutput {
                strategy,
                original_len: result.original_len,
                minimized: result.minimized,
                metadata,
                reduced,
            })
        }
    }
}

fn update_finding_record(finding_dir: &Path, result: &MinimizeOutput) -> anyhow::Result<()> {
    let path = finding_dir.join("finding.json");
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} must contain a JSON object", path.display()))?;
    let paths = object.entry("paths").or_insert_with(|| json!({}));
    let paths = paths
        .as_object_mut()
        .ok_or_else(|| anyhow!("{}.paths must contain a JSON object", path.display()))?;

    paths.insert("minimized".to_owned(), json!("min_testcase.bin"));
    object.insert("minimal_reproducer".to_owned(), json!("min_testcase.bin"));
    object.insert("minimization".to_owned(), result.metadata.clone());

    fs::write(&path, serde_json::to_vec_pretty(&value)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
