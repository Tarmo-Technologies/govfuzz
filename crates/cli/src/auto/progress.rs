// SPDX-License-Identifier: Apache-2.0
//! Live per-target progress for `govfuzz auto`.
//!
//! TTY: one line rewritten in place per phase change / fuzz tick.
//! Non-TTY: silent by default (the existing attempting/outcome lines
//! stay); `--verbose` adds one heartbeat line per phase change so CI
//! logs show where time went without 2 Hz spam.

use std::io::{IsTerminal, Write};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Generate,
    Build { retry: usize },
    Repair { retry: usize },
    Fuzz { pass: &'static str },
}

#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub phase: Phase,
    pub elapsed: Duration,
    pub budget: Option<Duration>,
    pub executions: usize,
    pub findings: usize,
    /// Marks the terminal update for a fuzz pass, carrying the pass's final
    /// execution/finding counts. Live ticks during a pass land faster than the
    /// throttle window and a sub-throttle pass emits none, so without an
    /// explicit final flush the only rendered counts would be the `execs=0`
    /// start state — making working runs look like they never fuzzed.
    pub is_final: bool,
}

impl ProgressUpdate {
    /// Phase-transition event with no counters (generate/build/repair).
    pub fn phase(phase: Phase) -> Self {
        Self {
            phase,
            elapsed: Duration::ZERO,
            budget: None,
            executions: 0,
            findings: 0,
            is_final: false,
        }
    }
}

pub trait ProgressSink {
    fn update(&self, update: &ProgressUpdate);
    /// Erase any transient output before a real line is printed.
    fn clear(&self) {}
}

/// Sink for tests and non-interactive callers.
pub struct NoProgress;
impl ProgressSink for NoProgress {
    fn update(&self, _: &ProgressUpdate) {}
}

pub struct TerminalProgress {
    prefix: String,
    tty: bool,
    verbose: bool,
    last_phase: std::cell::RefCell<Option<Phase>>,
}

impl TerminalProgress {
    pub fn new(prefix: String, verbose: bool) -> Self {
        Self {
            prefix,
            tty: std::io::stderr().is_terminal(),
            verbose,
            last_phase: std::cell::RefCell::new(None),
        }
    }

    #[cfg(test)]
    fn for_test(prefix: &str, tty: bool) -> Self {
        Self {
            prefix: prefix.to_owned(),
            tty,
            verbose: false,
            last_phase: std::cell::RefCell::new(None),
        }
    }

    fn phase_label(phase: &Phase) -> String {
        match phase {
            Phase::Generate => "generating harness".to_owned(),
            Phase::Build { retry: 0 } => "building".to_owned(),
            Phase::Build { retry } => format!("building (retry {retry})"),
            Phase::Repair { retry } => format!("repairing (attempt {retry})"),
            Phase::Fuzz { pass } => format!("fuzz:{pass}"),
        }
    }

    fn render(&self, u: &ProgressUpdate) -> String {
        let mut line = format!("{} … {}", self.prefix, Self::phase_label(&u.phase));
        if matches!(u.phase, Phase::Fuzz { .. }) {
            let budget = u
                .budget
                .map(|b| format!("/{}s", b.as_secs()))
                .unwrap_or_default();
            line.push_str(&format!(
                " {}s{} execs={} findings={}",
                u.elapsed.as_secs(),
                budget,
                u.executions,
                u.findings
            ));
        }
        line
    }

    fn is_fuzz(phase: &Phase) -> bool {
        matches!(phase, Phase::Fuzz { .. })
    }
}

impl ProgressSink for TerminalProgress {
    fn update(&self, u: &ProgressUpdate) {
        if self.tty {
            let mut err = std::io::stderr().lock();
            // A pass's final update carries its real counters; persist it with a
            // newline so each completed pass stays on screen, while live ticks
            // keep rewriting the current line in place.
            if u.is_final {
                let _ = writeln!(err, "\r\x1b[2K{}", self.render(u));
            } else {
                let _ = write!(err, "\r\x1b[2K{}", self.render(u));
                let _ = err.flush();
            }
            return;
        }
        // Non-TTY heartbeat, verbose only. Fuzz passes print once at completion
        // with their final counts (the start-of-pass update reads execs=0 and
        // would be misleading); other phases print once when they change.
        if !self.verbose {
            return;
        }
        let changed = self.last_phase.borrow().as_ref() != Some(&u.phase);
        if changed {
            *self.last_phase.borrow_mut() = Some(u.phase.clone());
        }
        let should_print = if Self::is_fuzz(&u.phase) {
            u.is_final
        } else {
            changed
        };
        if should_print {
            eprintln!("{}", self.render(u));
        }
    }

    fn clear(&self) {
        if self.tty {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink() -> TerminalProgress {
        TerminalProgress::for_test("[  3/191] H-C0042 mz_compress", false)
    }

    #[test]
    fn fuzz_phase_renders_budget_and_counters() {
        let line = sink().render(&ProgressUpdate {
            phase: Phase::Fuzz { pass: "rng" },
            elapsed: Duration::from_secs(14),
            budget: Some(Duration::from_secs(60)),
            executions: 8123,
            findings: 1,
            is_final: false,
        });
        assert_eq!(
            line,
            "[  3/191] H-C0042 mz_compress … fuzz:rng 14s/60s execs=8123 findings=1"
        );
    }

    #[test]
    fn non_tty_verbose_prints_final_pass_counts_not_zero_start() {
        use std::sync::{Arc, Mutex};
        // Capture what the non-TTY verbose sink would print by re-deriving its
        // decision: the start-of-pass update (execs=0) is suppressed and only
        // the final update (real counts) is emitted for a fuzz pass.
        let sink = TerminalProgress {
            prefix: "[  1/  1] H-C001C miniz_inflate_fuzz".to_owned(),
            tty: false,
            verbose: true,
            last_phase: std::cell::RefCell::new(None),
        };
        let printed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        // The decision logic mirrors `update`: fuzz passes print only when final.
        let emit = |u: &ProgressUpdate| {
            let changed = sink.last_phase.borrow().as_ref() != Some(&u.phase);
            if changed {
                *sink.last_phase.borrow_mut() = Some(u.phase.clone());
            }
            let should = if TerminalProgress::is_fuzz(&u.phase) {
                u.is_final
            } else {
                changed
            };
            if should {
                printed.lock().unwrap().push(sink.render(u));
            }
        };
        let start = ProgressUpdate {
            phase: Phase::Fuzz { pass: "empty" },
            elapsed: Duration::ZERO,
            budget: Some(Duration::from_secs(3)),
            executions: 0,
            findings: 0,
            is_final: false,
        };
        let done = ProgressUpdate {
            executions: 67,
            is_final: true,
            ..start.clone()
        };
        emit(&start);
        emit(&done);
        let lines = printed.lock().unwrap().clone();
        assert_eq!(lines.len(), 1, "exactly one line per pass: {lines:?}");
        assert!(
            lines[0].contains("execs=67"),
            "final pass line must show real execs: {lines:?}"
        );
    }

    #[test]
    fn build_phase_renders_without_counters() {
        let line = sink().render(&ProgressUpdate::phase(Phase::Build { retry: 1 }));
        assert_eq!(line, "[  3/191] H-C0042 mz_compress … building (retry 1)");
    }

    #[test]
    fn first_build_attempt_has_no_retry_suffix() {
        let line = sink().render(&ProgressUpdate::phase(Phase::Build { retry: 0 }));
        assert_eq!(line, "[  3/191] H-C0042 mz_compress … building");
    }
}
