// SPDX-License-Identifier: Apache-2.0
//! Keyboard control plane for a live `govfuzz auto` run.
//!
//! Everything here was previously reachable only by killing the run — losing the
//! in-flight targets — and starting over with different flags:
//!
//!   * **stop cleanly** (`q`): stop handing out candidates, let the in-flight
//!     targets finish and be persisted, then write the report and summary. The
//!     opposite of Ctrl-C, which kills the parent mid-sweep and leaves whatever
//!     the workers had already checkpointed.
//!   * **pause / resume** (`p`): the same, but the run stays alive. For "I need
//!     this box back for ten minutes".
//!   * **retune concurrency** (`+` / `-`): the dashboard shows CPU and RSS
//!     against the run's budget, so the natural next move when the box is idle
//!     is to raise `--jobs`.
//!   * **retune the stop condition** (`]` / `[`): raise `--max-targets` when the
//!     sweep is producing findings, or cap a run that is not.
//!   * **retune the per-target budget** (`>` / `<`): the block reports how long
//!     since each target last found a new edge; this is what that number is FOR.
//!   * **add or drop the forced pass** (`f`), and **toggle detail** (`v`).
//!
//! What is deliberately NOT here: anything baked into discovery (the candidate
//! set is already ranked) or into a harness build (`--sanitizers`, `--cxx-std`,
//! `--build-command`). Changing those mid-run would make targets within one
//! report incomparable, which is worse than having to re-run.
//!
//! Every control is read at a point the sweep already passes through — the top of
//! a candidate iteration, or the phase boundary — so nothing interrupts work in
//! flight.
//!
//! Terminal handling keeps `ISIG` enabled: Ctrl-C must still work exactly as it
//! did. Only line-buffering and echo are turned off, so a keypress arrives
//! without the operator having to hit enter and without `q` being echoed into
//! the middle of the sticky block.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::auto::dashboard::Console;
use crate::auto::run_status::RunStatus;

/// What a key does. Split from the I/O so the mapping is testable without a
/// terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    Pause,
    Jobs(i64),
    Cap(i64),
    TargetTime(i64),
    Force,
    Verbose,
    Help,
    Ignore,
}

pub fn action_for(key: u8) -> Action {
    match key {
        b'q' | b'Q' => Action::Quit,
        b'p' | b'P' => Action::Pause,
        // `=` is the unshifted `+` on a US layout: accepting both means the
        // operator does not have to hold shift to add a worker. The same reasoning
        // pairs `[`/`]` with `{`/`}` and `,`/`.` with `<`/`>`.
        b'+' | b'=' => Action::Jobs(1),
        b'-' | b'_' => Action::Jobs(-1),
        b']' | b'}' => Action::Cap(1),
        b'[' | b'{' => Action::Cap(-1),
        b'>' | b'.' => Action::TargetTime(1),
        b'<' | b',' => Action::TargetTime(-1),
        b'f' | b'F' => Action::Force,
        b'v' | b'V' => Action::Verbose,
        b'?' | b'h' | b'H' => Action::Help,
        _ => Action::Ignore,
    }
}

/// Apply an action, returning the line to echo to the operator (`None` for keys
/// that change nothing). Pure with respect to the terminal: the caller prints.
pub fn apply(action: Action, status: &RunStatus) -> Option<String> {
    // Any key other than `?` itself means the operator is done reading.
    if !matches!(action, Action::Help | Action::Ignore) {
        status.close_help();
    }
    match action {
        Action::Quit => {
            if status.quitting() {
                return None;
            }
            status.request_quit();
            Some(
                "govfuzz auto: [q] stopping — no new targets will start; \
                 in-flight targets finish and the report is written"
                    .to_owned(),
            )
        }
        Action::Jobs(delta) => {
            let before = status.jobs();
            let after = status.adjust_jobs(delta);
            if after == before {
                // Say why nothing happened; a key that silently does nothing
                // reads as a broken key.
                let edge = if delta > 0 {
                    format!("already at the ceiling of {}", status.jobs_ceiling())
                } else {
                    "already at 1".to_owned()
                };
                return Some(format!("govfuzz auto: jobs unchanged ({before}) — {edge}"));
            }
            Some(format!(
                "govfuzz auto: jobs {before} → {after} (ceiling {})",
                status.jobs_ceiling()
            ))
        }
        Action::Pause => {
            let paused = status.toggle_pause();
            Some(if paused {
                "govfuzz auto: [p] paused — in-flight targets finish, nothing new starts; \
                 press [p] again to resume"
                    .to_owned()
            } else {
                "govfuzz auto: [p] resumed".to_owned()
            })
        }
        Action::Cap(delta) => {
            let before = status.cap();
            let (after, changed) = status.adjust_cap(delta);
            if !changed {
                return Some(match (before, delta > 0) {
                    (None, true) => "govfuzz auto: no --max-targets cap on this run — every \
                                     candidate is already attempted"
                        .to_owned(),
                    _ => format!(
                        "govfuzz auto: --max-targets unchanged ({})",
                        before.map_or("none".to_owned(), |cap| cap.to_string())
                    ),
                });
            }
            let after = after.expect("a changed cap is always set");
            Some(match before {
                Some(before) => format!("govfuzz auto: --max-targets {before} → {after}"),
                // Capping a previously uncapped run is a bigger change than a
                // nudge, so it says so outright rather than showing "none → 17".
                None => format!(
                    "govfuzz auto: --max-targets set to {after}; the sweep now stops once \
                     {after} target(s) have fuzzed"
                ),
            })
        }
        Action::TargetTime(delta) => {
            if status.budget_locked() {
                return Some(
                    "govfuzz auto: per-target time is set by the --campaign-time / \
                     --min-target-time split on this run and cannot be changed live"
                        .to_owned(),
                );
            }
            let before = status.per_target_time().as_secs();
            let after = status.adjust_per_target_time(delta);
            if after == before {
                return Some(format!(
                    "govfuzz auto: per-target time unchanged ({before}s — already at the floor)"
                ));
            }
            Some(format!(
                "govfuzz auto: --per-target-time {before}s → {after}s (applies from the next \
                 target; the one running keeps its planned budget)"
            ))
        }
        Action::Force => {
            let force = status.toggle_force();
            Some(if force {
                "govfuzz auto: --force ON — a second, forced pass will retry every target this \
                 pass could not fuzz (findings stamped low-confidence)"
                    .to_owned()
            } else {
                "govfuzz auto: --force OFF — no forced pass will run".to_owned()
            })
        }
        Action::Verbose => {
            let verbose = status.toggle_verbose();
            Some(format!(
                "govfuzz auto: --verbose {}",
                if verbose { "on" } else { "off" }
            ))
        }
        // The list lives in the block, not in the scrollback: it can be dismissed,
        // and reading it does not push the live numbers off screen.
        Action::Help => {
            status.toggle_help();
            None
        }
        Action::Ignore => None,
    }
}

/// Live keyboard reader. Restores the terminal on drop, including on the error
/// paths out of a run.
pub struct Controls {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    #[cfg(unix)]
    restore: Option<RawMode>,
}

impl Controls {
    /// Start reading keys, or return `None` when there is no controlling
    /// terminal (CI, `| tee`, a cron run) — where a key reader would both be
    /// useless and risk consuming another process's stdin.
    pub fn start(status: Arc<RunStatus>, console: Arc<Console>) -> Option<Self> {
        Self::start_impl(status, console)
    }

    #[cfg(unix)]
    fn start_impl(status: Arc<RunStatus>, console: Arc<Console>) -> Option<Self> {
        use std::io::Read;

        let tty = std::fs::File::open("/dev/tty").ok()?;
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&tty);
        let restore = RawMode::enter(fd)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_status = Arc::clone(&status);
        let handle = std::thread::Builder::new()
            .name("govfuzz-controls".to_owned())
            .spawn(move || {
                let mut tty = tty;
                let mut buf = [0u8; 1];
                while !thread_stop.load(Ordering::Relaxed) {
                    // VMIN=0/VTIME=1 makes this a 100ms poll, so the thread
                    // notices the run ending instead of blocking on a key that
                    // never comes.
                    match tty.read(&mut buf) {
                        Ok(1) => {
                            if let Some(message) = apply(action_for(buf[0]), &thread_status) {
                                console.println(&message);
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            })
            .ok()?;
        status.set_controls_live(true);
        Some(Self {
            stop,
            handle: Some(handle),
            restore: Some(restore),
        })
    }

    #[cfg(not(unix))]
    fn start_impl(_status: Arc<RunStatus>, _console: Arc<Console>) -> Option<Self> {
        None
    }
}

impl Drop for Controls {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        #[cfg(unix)]
        drop(self.restore.take());
    }
}

/// Terminal mode guard: unbuffered, unechoed reads while alive; the operator's
/// original settings back when dropped.
#[cfg(unix)]
pub struct RawMode {
    fd: std::os::unix::io::RawFd,
    original: libc::termios,
}

#[cfg(unix)]
impl RawMode {
    fn enter(fd: std::os::unix::io::RawFd) -> Option<Self> {
        // SAFETY: `fd` is an open descriptor for /dev/tty for the lifetime of the
        // guard; `termios` is POD and the calls only read/write that struct.
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut original) != 0 {
                return None;
            }
            let mut raw = original;
            // Deliberately NOT cfmakeraw: that clears ISIG too, which would take
            // Ctrl-C away from a user who has always had it. Turn off only line
            // buffering (ICANON) and echo.
            raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            raw.c_cc[libc::VMIN] = 0;
            raw.c_cc[libc::VTIME] = 1;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return None;
            }
            Some(Self { fd, original })
        }
    }
}

#[cfg(unix)]
impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: same descriptor and POD struct as in `enter`.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_map_to_their_actions() {
        assert_eq!(action_for(b'q'), Action::Quit);
        assert_eq!(action_for(b'Q'), Action::Quit);
        assert_eq!(action_for(b'+'), Action::Jobs(1));
        assert_eq!(action_for(b'='), Action::Jobs(1));
        assert_eq!(action_for(b'-'), Action::Jobs(-1));
        assert_eq!(action_for(b'?'), Action::Help);
        assert_eq!(action_for(b'p'), Action::Pause);
        assert_eq!(action_for(b']'), Action::Cap(1));
        assert_eq!(action_for(b'['), Action::Cap(-1));
        // The unshifted keys map to the same actions, so nothing needs shift.
        assert_eq!(action_for(b'.'), Action::TargetTime(1));
        assert_eq!(action_for(b','), Action::TargetTime(-1));
        assert_eq!(action_for(b'>'), Action::TargetTime(1));
        assert_eq!(action_for(b'f'), Action::Force);
        assert_eq!(action_for(b'v'), Action::Verbose);
        assert_eq!(action_for(b'x'), Action::Ignore);
    }

    #[test]
    fn quit_sets_the_flag_once_and_says_what_will_happen() {
        let status = RunStatus::new(3, 8);
        let message = apply(Action::Quit, &status).expect("first quit reports");
        assert!(message.contains("in-flight targets finish"), "{message}");
        assert!(status.quitting());
        // A second press must not spam the log with a promise already made.
        assert_eq!(apply(Action::Quit, &status), None);
    }

    #[test]
    fn jobs_keys_report_the_new_value() {
        let status = RunStatus::new(3, 8);
        let message = apply(Action::Jobs(1), &status).unwrap();
        assert!(message.contains("jobs 3 → 4"), "{message}");
        assert_eq!(status.jobs(), 4);
    }

    #[test]
    fn help_toggles_the_in_block_panel_rather_than_printing_a_line() {
        let status = RunStatus::new(3, 8);
        // No scrolling line: printing the list would push the live numbers off
        // screen, and it could not then be dismissed.
        assert_eq!(apply(Action::Help, &status), None);
        assert!(status.help_open());
        assert_eq!(apply(Action::Help, &status), None);
        assert!(!status.help_open());
    }

    #[test]
    fn any_acting_key_dismisses_the_help_panel() {
        let status = RunStatus::new(3, 8);
        apply(Action::Help, &status);
        assert!(status.help_open());
        // The operator found what they wanted; the panel is now covering the run.
        apply(Action::Jobs(1), &status);
        assert!(!status.help_open());
        // A key that does nothing must not close it — the reader may still be
        // mid-list.
        apply(Action::Help, &status);
        apply(Action::Ignore, &status);
        assert!(status.help_open());
    }

    #[test]
    fn pause_parks_the_sweep_without_ending_it() {
        let status = RunStatus::new(3, 8);
        let message = apply(Action::Pause, &status).unwrap();
        assert!(status.paused());
        assert!(message.contains("in-flight targets finish"), "{message}");
        // Pausing must never look like quitting: the run is still alive.
        assert!(!status.quitting());
        assert!(apply(Action::Pause, &status).unwrap().contains("resumed"));
        assert!(!status.paused());
    }

    #[test]
    fn the_cap_moves_by_a_tenth_of_itself_and_never_below_what_already_fuzzed() {
        let status = RunStatus::new(3, 8);
        status.set_cap(Some(50));
        assert!(apply(Action::Cap(1), &status)
            .unwrap()
            .contains("--max-targets 50 → 55"));
        // Lowering below the fuzzed count would stop the sweep instantly and make
        // the progress bar read as over-full.
        status.seed_resumed(54);
        apply(Action::Cap(-1), &status);
        assert_eq!(status.cap(), Some(54));
    }

    #[test]
    fn an_uncapped_run_can_be_capped_down_but_not_nudged_up() {
        let status = RunStatus::new(3, 8);
        // Nothing to raise: the run already attempts every candidate. Inventing a
        // ceiling here would silently RESTRICT a run the operator asked to be
        // unlimited.
        let message = apply(Action::Cap(1), &status).unwrap();
        assert!(message.contains("no --max-targets cap"), "{message}");
        assert_eq!(status.cap(), None);
        // Capping downward is a real intent ("stop after a few more"), so it is
        // honoured — and stated in full rather than shown as "none → 10".
        let message = apply(Action::Cap(-1), &status).unwrap();
        assert!(message.contains("--max-targets set to 10"), "{message}");
        assert_eq!(status.cap(), Some(10));
    }

    #[test]
    fn per_target_time_moves_by_a_quarter_and_says_when_it_applies() {
        let status = RunStatus::new(3, 8);
        status.set_per_target_time(std::time::Duration::from_secs(60));
        let message = apply(Action::TargetTime(1), &status).unwrap();
        assert!(message.contains("60s → 75s"), "{message}");
        // The in-flight target already planned its pass cascade; promising
        // otherwise would be a lie the operator could measure.
        assert!(message.contains("from the next target"), "{message}");
        assert_eq!(status.per_target_time().as_secs(), 75);
    }

    #[test]
    fn a_campaign_split_owns_the_per_target_budget_and_the_key_refuses() {
        let status = RunStatus::new(3, 8);
        status.set_per_target_time(std::time::Duration::from_secs(40));
        status.set_budget_locked(true);
        let message = apply(Action::TargetTime(1), &status).unwrap();
        assert!(message.contains("cannot be changed live"), "{message}");
        assert_eq!(status.per_target_time().as_secs(), 40, "budget untouched");
    }

    #[test]
    fn force_toggle_also_moves_the_phase_count_the_block_shows() {
        let status = RunStatus::new(3, 8);
        status.set_force(false);
        status.begin_phase(1, false, 10);
        assert_eq!(status.snapshot().phase.unwrap().total, 1);
        let message = apply(Action::Force, &status).unwrap();
        assert!(message.contains("--force ON"), "{message}");
        // The headline must not keep claiming "phase 1/1" once a second phase is
        // going to run.
        assert_eq!(status.snapshot().phase.unwrap().total, 2);
        apply(Action::Force, &status);
        assert_eq!(status.snapshot().phase.unwrap().total, 1);
    }

    #[test]
    fn verbose_toggles_both_ways() {
        let status = RunStatus::new(3, 8);
        assert!(apply(Action::Verbose, &status).unwrap().contains("on"));
        assert!(status.verbose());
        assert!(apply(Action::Verbose, &status).unwrap().contains("off"));
        assert!(!status.verbose());
    }

    #[test]
    fn a_jobs_key_that_cannot_move_says_why() {
        let status = RunStatus::new(8, 8);
        let message = apply(Action::Jobs(1), &status).unwrap();
        assert!(message.contains("already at the ceiling of 8"), "{message}");
        assert_eq!(status.jobs(), 8);

        let status = RunStatus::new(1, 8);
        let message = apply(Action::Jobs(-1), &status).unwrap();
        assert!(message.contains("already at 1"), "{message}");
    }
}
