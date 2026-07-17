// SPDX-License-Identifier: Apache-2.0

//! CLI wiring for [`crash_diag`]: a durable, low-overhead diagnostics session
//! that brackets every `govfuzz` invocation.
//!
//! The panic path is already covered by [`crate::auto::bug_report`]. This adds
//! coverage for the death mode that previously left only `Killed` in the
//! terminal — the process (or a fuzz worker) being SIGKILLed by the OOM killer,
//! which cannot be caught in-process:
//!
//! - a `session_start` record (pid, argv, version, memory limit) and a matching
//!   `session_end` written only on a clean return. A log with a start and no
//!   end is the fingerprint of a killed run.
//! - for memory-heavy commands (`auto`, `fuzz`, `ci`, `differential`, binary
//!   fuzz), a background memory-watermark heartbeat, so the last surviving line
//!   shows RSS climbing toward the limit and a `WARN` fires as it nears it.
//!
//! Destination is controlled by `GOVFUZZ_LOG` (a path, or `off` to disable);
//! the default is `<tmp>/govfuzz/govfuzz.log`.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crash_diag::{DiagLog, Heartbeat};

/// A diagnostics session spanning one CLI invocation. Dropping it without
/// calling [`Session::finish`] still stops the heartbeat but records nothing —
/// which is exactly the "killed before finish" signal we rely on.
pub struct Session {
    log: Arc<DiagLog>,
    heartbeat: Option<Heartbeat>,
    start: Instant,
    finished: bool,
}

impl Session {
    /// Open the log, record `session_start`, and (for `heavy` commands) start the
    /// memory heartbeat.
    pub fn start(argv: &[OsString], label: &str, heavy: bool) -> Self {
        // The diagnostics log is file-only: records must never leak into stderr,
        // where they could pollute machine-read output or golden-test contracts.
        // Live crash visibility comes from the orchestrator's own worker-death
        // messages, not from echoing this log.
        let log = match crash_diag::resolve_log_path(crash_diag::default_log_path()) {
            Some(path) => match DiagLog::open(&path, false) {
                Ok(log) => {
                    // Point interactive users at the log for heavy commands, but
                    // never when stderr is captured (pipes / CI / golden tests).
                    if heavy && std::io::IsTerminal::is_terminal(&std::io::stderr()) {
                        eprintln!("govfuzz: diagnostics log: {}", path.display());
                    }
                    Arc::new(log)
                }
                Err(error) => {
                    eprintln!("govfuzz: could not open diagnostics log {path:?}: {error}");
                    Arc::new(DiagLog::disabled(false))
                }
            },
            None => Arc::new(DiagLog::disabled(false)),
        };
        Self::with_log(log, argv, label, heavy)
    }

    /// Build a session around an already-open log. Records `session_start` and
    /// starts the heartbeat for `heavy` commands.
    fn with_log(log: Arc<DiagLog>, argv: &[OsString], label: &str, heavy: bool) -> Self {
        let argv_str = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let mut fields = vec![
            ("label", label.to_owned()),
            ("version", env!("CARGO_PKG_VERSION").to_owned()),
            ("argv", argv_str),
        ];
        if let Some(limit) = crash_diag::cgroup_memory_limit_bytes() {
            fields.push(("mem_limit_kib", (limit / 1024).to_string()));
        }
        log.info("session_start", "govfuzz invocation started", &fields);

        let heartbeat = if heavy {
            Some(Heartbeat::start(
                Arc::clone(&log),
                Duration::from_secs(5),
                label,
            ))
        } else {
            None
        };

        Self {
            log,
            heartbeat,
            start: Instant::now(),
            finished: false,
        }
    }

    /// Record `session_end` with the exit code and elapsed time. An abnormal
    /// exit code is logged at `WARN` so it also reaches stderr.
    pub fn finish(mut self, exit_code: i32) {
        // Stop the heartbeat before the final record so the last memory sample is
        // flushed and the thread is joined.
        self.heartbeat.take();
        let elapsed_ms = self.start.elapsed().as_millis().to_string();
        let peak = crash_diag::peak_rss_kib()
            .map(|kib| kib.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        let fields = [
            ("exit_code", exit_code.to_string()),
            ("elapsed_ms", elapsed_ms),
            ("peak_kib", peak),
        ];
        if exit_code == 0 {
            self.log
                .info("session_end", "govfuzz invocation completed", &fields);
        } else {
            self.log.warn(
                "session_end",
                "govfuzz invocation exited non-zero",
                &fields,
            );
        }
        self.finished = true;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Ensure the heartbeat thread is always stopped/joined, even on the
        // "no finish" (killed / early-return) path.
        self.heartbeat.take();
        let _ = self.finished;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests inject an explicit `DiagLog` via `with_log` rather than the
    // process-global `GOVFUZZ_LOG` env var, so they are safe under the parallel
    // test runner.

    fn temp_log(name: &str) -> (std::path::PathBuf, Arc<DiagLog>) {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz_diag_{name}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("govfuzz.log");
        let log = Arc::new(DiagLog::open(&path, false).unwrap());
        (path, log)
    }

    #[test]
    fn session_start_and_finish_bracket_the_log() {
        let (path, log) = temp_log("sess");
        let argv: Vec<OsString> = vec!["govfuzz".into(), "auto".into(), "src".into()];
        Session::with_log(log, &argv, "auto", false).finish(0);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("session_start:"));
        assert!(text.contains("argv=\"govfuzz auto src\""));
        assert!(text.contains("session_end:"));
        assert!(text.contains("exit_code=0"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn nonzero_finish_is_recorded_as_warn() {
        let (path, log) = temp_log("warn");
        let argv: Vec<OsString> = vec!["govfuzz".into(), "fuzz".into()];
        Session::with_log(log, &argv, "fuzz", false).finish(2);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("WARN"));
        assert!(text.contains("exit_code=2"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
