// SPDX-License-Identifier: Apache-2.0

//! Nyx / what-the-fuzz snapshot-fuzzing adapter.
//!
//! Two backends:
//!
//! - **Software replay** (default): the snapshot_dir contains a
//!   `target` binary that gets spawned per input, mimicking the
//!   one-shot semantics of a snapshot restore. Useful for the
//!   Nyx-API consumer story when libnyx isn't available
//!   (hardware support / CI envs / dev machines).
//! - **Real Nyx** (`nyx-engine` feature): libnyx FFI + QEMU
//!   snapshot restore. Tracked separately because the FFI
//!   bindings depend on host hardware and a real QEMU install.
//!
//! Architecture note: snapshot fuzzing (Nyx, kAFL, what-the-fuzz)
//! is the production version of state virtualization — see the
//! sibling `govfuzz_runtrace_shim` crate for the dependency-faking
//! variant govfuzz ships today. The strategic story is that govfuzz
//! supports both — fake the dependencies (shim) OR fake the process
//! state (this adapter) — and users pick per target.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NyxAdapterConfig {
    /// Path to the Nyx snapshot directory produced by
    /// `libnyx` setup (containing `state.qcow2`, `regs.ymm`, etc.).
    pub snapshot_dir: PathBuf,
    /// Coverage strategy. `IntelPt` requires hardware support;
    /// `SanCov` requires the target to be compiled with
    /// `-fsanitize-coverage=trace-pc-guard`.
    pub coverage: CoverageStrategy,
    /// Maximum per-input wall-clock budget.
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStrategy {
    IntelPt,
    SanCov,
}

#[derive(Debug, thiserror::Error)]
pub enum NyxError {
    #[error(
        "Nyx adapter built without the `nyx-engine` feature; rebuild with `--features nyx-engine` once the real backend lands"
    )]
    NotImplemented,
    #[error("snapshot dir does not exist: {0}")]
    SnapshotMissing(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Open a Nyx snapshot and drive the provided input through it.
/// Returns the standard `EngineFeedback` the builtin engine
/// consumes via `fuzz_engine_builtin::EngineFeedbackTranslator`.
///
/// Software-replay backend: spawn `<snapshot_dir>/target` with
/// the input file path as argv[1]. Used when `nyx-engine` isn't
/// enabled (the default). The exit kind maps process exit status
/// onto Nyx's ExitKind. Coverage edges are empty in software mode
/// — real coverage requires libnyx's Intel-PT decoder.
pub fn run_snapshot_once(config: &NyxAdapterConfig, input: &[u8]) -> Result<RunOutcome, NyxError> {
    if !config.snapshot_dir.is_dir() {
        return Err(NyxError::SnapshotMissing(config.snapshot_dir.clone()));
    }
    #[cfg(feature = "nyx-engine")]
    {
        unreachable!(
            "nyx-engine feature is set but the real libnyx integration has not landed yet; remove the feature flag to suppress this build until then"
        );
    }
    #[cfg(not(feature = "nyx-engine"))]
    {
        run_software_replay(config, input)
    }
}

#[cfg(not(feature = "nyx-engine"))]
fn run_software_replay(config: &NyxAdapterConfig, input: &[u8]) -> Result<RunOutcome, NyxError> {
    let target = config.snapshot_dir.join("target");
    if !target.is_file() {
        return Err(NyxError::SnapshotMissing(target));
    }
    let input_file = config.snapshot_dir.join(format!(
        "input-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&input_file, input)?;

    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(&target)
        .arg(&input_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let timeout = Duration::from_millis(config.timeout_ms);
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    timed_out = true;
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    let mut stdout = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        use std::io::Read;
        let _ = s.read_to_end(&mut stdout);
    }
    let exit_kind = if timed_out {
        ExitKind::Timeout
    } else {
        let status = child.wait()?;
        if status.success() {
            ExitKind::Ok
        } else {
            ExitKind::Crash
        }
    };
    let _ = std::fs::remove_file(&input_file);
    Ok(RunOutcome {
        exit_kind,
        coverage_edges: Vec::new(),
        stdout,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub exit_kind: ExitKind,
    pub coverage_edges: Vec<u32>,
    pub stdout: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    Ok,
    Crash,
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tempdir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-nyx-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn run_snapshot_once_returns_snapshot_missing_when_target_absent() {
        let dir = tempdir("no-target");
        let config = NyxAdapterConfig {
            snapshot_dir: dir,
            coverage: CoverageStrategy::SanCov,
            timeout_ms: 1000,
        };
        let result = run_snapshot_once(&config, b"input");
        assert!(matches!(result, Err(NyxError::SnapshotMissing(_))));
    }

    #[cfg(unix)]
    #[test]
    fn run_snapshot_once_software_replay_against_bin_true() {
        use std::os::unix::fs::symlink;
        let dir = tempdir("sw-true");
        symlink("/bin/true", dir.join("target")).unwrap();
        let config = NyxAdapterConfig {
            snapshot_dir: dir,
            coverage: CoverageStrategy::SanCov,
            timeout_ms: 5000,
        };
        let outcome = run_snapshot_once(&config, b"hello").unwrap();
        assert_eq!(outcome.exit_kind, ExitKind::Ok);
    }

    #[cfg(unix)]
    #[test]
    fn run_snapshot_once_software_replay_against_bin_false() {
        use std::os::unix::fs::symlink;
        let dir = tempdir("sw-false");
        symlink("/bin/false", dir.join("target")).unwrap();
        let config = NyxAdapterConfig {
            snapshot_dir: dir,
            coverage: CoverageStrategy::SanCov,
            timeout_ms: 5000,
        };
        let outcome = run_snapshot_once(&config, b"hello").unwrap();
        assert_eq!(outcome.exit_kind, ExitKind::Crash);
    }

    #[test]
    fn run_snapshot_once_rejects_missing_snapshot_dir() {
        let config = NyxAdapterConfig {
            snapshot_dir: PathBuf::from("/nonexistent/snapshot/path"),
            coverage: CoverageStrategy::IntelPt,
            timeout_ms: 1000,
        };
        let result = run_snapshot_once(&config, b"input");
        assert!(matches!(result, Err(NyxError::SnapshotMissing(_))));
    }

    #[test]
    fn coverage_strategy_is_copy_and_eq() {
        let a = CoverageStrategy::IntelPt;
        let b = a;
        assert_eq!(a, b);
    }
}
