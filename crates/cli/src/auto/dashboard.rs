// SPDX-License-Identifier: Apache-2.0
//! The sticky progress block, and the console that keeps it from being shredded
//! by the sweep's own log lines.
//!
//! A block redrawn at the bottom of the terminal and a stream of scrolling
//! result lines are the same cursor. A bare `eprintln!` issued while the block is
//! on screen writes INTO it, and the next redraw then erases the wrong rows and
//! walks up the scrollback — observed in a real sweep as wiped warnings and
//! stranded block fragments. So every line the process prints goes through
//! [`Console::println`] (via the crate's `gfeprintln!`), which erases the block,
//! prints, and repaints as one unit — the discipline `indicatif` enforces with
//! `MultiProgress::suspend`.
//!
//! Non-TTY output keeps the historical static lines (CI logs are parsed and
//! diffed) and adds a periodic heartbeat carrying the same run-level facts.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auto::run_status::{self, RunStatus};

/// Redraw cadence. Fast enough that execs/s and the stage clock look live, slow
/// enough that a 24-line block over ssh does not eat the terminal's bandwidth.
const REDRAW_INTERVAL: Duration = Duration::from_millis(250);

/// Non-TTY heartbeat cadence. One line every 30s is enough to see where a CI run
/// spent an hour without burying the result lines that are actually parsed.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Load sampling cadence. CPU percentage is a delta between readings, so this
/// also sets the window it averages over — a second is long enough not to be
/// dominated by one compiler starting.
const LOAD_INTERVAL: Duration = Duration::from_secs(1);

/// Owns stderr while the dashboard is live: the single writer that both the
/// sticky block and the sweep's scrolling lines must go through.
pub struct Console {
    inner: Mutex<ConsoleInner>,
    tty: bool,
}

/// Renders the current block on demand. Set once the run status exists, so a
/// line printed between redraws puts the block back with FRESH numbers rather
/// than replaying the last frame — result lines arrive in bursts, and a burst
/// would otherwise leave several seconds of identical, stale block underneath.
type BlockProvider = Box<dyn Fn() -> Vec<String> + Send + Sync>;

struct ConsoleInner {
    /// Lines currently drawn at the bottom of the terminal, cached so the next
    /// erase knows how many rows to walk back over.
    sticky: Vec<String>,
    provider: Option<BlockProvider>,
}

impl Console {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ConsoleInner {
                sticky: Vec::new(),
                provider: None,
            }),
            tty: std::io::stderr().is_terminal(),
        }
    }

    pub fn is_tty(&self) -> bool {
        self.tty
    }

    pub fn set_block_provider(&self, provider: BlockProvider) {
        self.inner.lock().unwrap().provider = Some(provider);
    }

    /// Print a line that scrolls (a target result, a warning, a phase banner),
    /// stepping around the sticky block.
    pub fn println(&self, line: &str) {
        self.write_through(line, true);
    }

    /// As [`Console::println`] for text that already carries its own newlines.
    pub fn print(&self, text: &str) {
        self.write_through(text, false);
    }

    fn write_through(&self, text: &str, newline: bool) {
        let mut inner = self.inner.lock().unwrap();
        let mut err = std::io::stderr().lock();
        erase(&mut err, inner.sticky.len());
        if newline {
            let _ = writeln!(err, "{text}");
        } else {
            let _ = write!(err, "{text}");
        }
        let sticky = match (self.tty, &inner.provider) {
            (true, Some(provider)) => provider(),
            _ => inner.sticky.clone(),
        };
        draw(&mut err, &sticky, self.tty);
        let _ = err.flush();
        inner.sticky = sticky;
    }

    /// Replace the sticky block.
    pub fn set_sticky(&self, lines: Vec<String>) {
        if !self.tty {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let mut err = std::io::stderr().lock();
        erase(&mut err, inner.sticky.len());
        draw(&mut err, &lines, self.tty);
        let _ = err.flush();
        inner.sticky = lines;
    }

    /// Retire the block for good: erase it AND forget how to draw it.
    ///
    /// Clearing the lines alone is not enough — the provider would repaint the
    /// block under every line of the end-of-run summary, because `println` asks
    /// it for a fresh block on each call. The sweep is over; there is nothing
    /// left to report live.
    pub fn stop_block(&self) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.provider = None;
        }
        self.clear_sticky();
    }

    /// Erase the block for good — before the final summary, and on the way out of
    /// any early return, so the summary is never printed into a live block.
    pub fn clear_sticky(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.sticky.is_empty() {
            return;
        }
        let mut err = std::io::stderr().lock();
        erase(&mut err, inner.sticky.len());
        let _ = err.flush();
        inner.sticky.clear();
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

/// The console the whole process writes through, once a run owns one.
///
/// A global rather than a threaded-through handle because the writes that
/// corrupt the block come from everywhere — the fuzz engine, build probes,
/// repair — and plumbing a console reference into all of them would be a far
/// larger change than the problem warrants. Set once per run; never replaced.
static ACTIVE: std::sync::OnceLock<Arc<Console>> = std::sync::OnceLock::new();

/// Register the run's console. Later calls are ignored (one run, one console).
pub fn set_active(console: Arc<Console>) {
    let _ = ACTIVE.set(console);
}

/// Write one line, through the live console when there is one.
pub fn emit_line(line: &str) {
    match ACTIVE.get() {
        Some(console) => console.println(line),
        None => eprintln!("{line}"),
    }
}

/// Write text verbatim, through the live console when there is one.
pub fn emit(text: &str) {
    match ACTIVE.get() {
        Some(console) => console.print(text),
        None => eprint!("{text}"),
    }
}

/// Walk up over `count` drawn lines, clearing each. The cursor is left at the
/// column 0 of the first line the block occupied, ready to be written over.
fn erase(err: &mut impl Write, count: usize) {
    if count == 0 {
        return;
    }
    let _ = write!(err, "\r");
    for _ in 0..count {
        // Up one line, erase it entirely.
        let _ = write!(err, "\x1b[1A\x1b[2K");
    }
}

fn draw(err: &mut impl Write, lines: &[String], tty: bool) {
    if !tty {
        return;
    }
    let width = terminal_width();
    for line in lines {
        // Truncate rather than let the terminal wrap: a wrapped line occupies two
        // rows, and the erase above counts rows, so one wrap permanently
        // desynchronises the block from the scrollback.
        let _ = writeln!(err, "\x1b[2K{}", truncate(line, width));
    }
}

/// Truncate to `width` columns, counting characters (the block is ASCII plus a
/// handful of box-drawing glyphs, all single-width).
fn truncate(line: &str, width: usize) -> String {
    if width == 0 || line.chars().count() <= width {
        return line.to_owned();
    }
    line.chars().take(width.saturating_sub(1)).collect()
}

/// Terminal columns and rows, re-read on every draw so a resize is picked up
/// without a SIGWINCH handler.
pub fn terminal_size() -> (usize, usize) {
    (terminal_width(), terminal_rows())
}

#[cfg(unix)]
fn terminal_rows() -> usize {
    // SAFETY: as in `terminal_width` — POD struct, ioctl only writes into it.
    unsafe {
        let mut size: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut size) == 0 && size.ws_row > 0 {
            return size.ws_row as usize;
        }
    }
    24
}

#[cfg(not(unix))]
fn terminal_rows() -> usize {
    24
}

#[cfg(unix)]
fn terminal_width() -> usize {
    // SAFETY: `winsize` is a plain POD struct; the ioctl only writes into it, and
    // a failed call leaves the zero-initialised value, which the caller treats as
    // "unknown width" via the fallback below.
    unsafe {
        let mut size: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut size) == 0 && size.ws_col > 0 {
            return size.ws_col as usize;
        }
    }
    120
}

#[cfg(not(unix))]
fn terminal_width() -> usize {
    120
}

/// A single sticky line with a running clock, for a phase that has no per-item
/// progress to report.
///
/// Discovery is the longest silent stretch of a run — minutes on a large tree,
/// with nothing between "discovering targets under X" and the candidate count —
/// and silence is exactly what clig.dev warns reads as a hung process. This does
/// not claim to know how far along it is (it does not); it shows that the run is
/// alive and how long the phase has taken, which is what the operator needs to
/// decide whether to keep waiting.
pub struct PhaseTicker {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    console: Arc<Console>,
}

impl PhaseTicker {
    pub fn start(console: Arc<Console>, label: &str) -> Option<Self> {
        if !console.is_tty() {
            // Piped output gets the existing static line; a clock rewritten 4x a
            // second would be thousands of lines of noise in a CI log.
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_console = Arc::clone(&console);
        let label = label.to_owned();
        let handle = std::thread::Builder::new()
            .name("govfuzz-phase-ticker".to_owned())
            .spawn(move || {
                let started = Instant::now();
                while !thread_stop.load(Ordering::Relaxed) {
                    thread_console.set_sticky(vec![format!(
                        "{label} … {}",
                        run_status::human_duration(started.elapsed())
                    )]);
                    std::thread::sleep(REDRAW_INTERVAL);
                }
            })
            .ok()?;
        Some(Self {
            stop,
            handle: Some(handle),
            console,
        })
    }
}

impl Drop for PhaseTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.console.clear_sticky();
    }
}

/// The renderer thread. Redraws the block on a TTY; emits a periodic heartbeat
/// line otherwise.
pub struct Dashboard {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    console: Arc<Console>,
}

impl Dashboard {
    pub fn start(status: Arc<RunStatus>, console: Arc<Console>, verbose: bool) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_console = Arc::clone(&console);
        let tty = console.is_tty();
        let handle = std::thread::Builder::new()
            .name("govfuzz-dashboard".to_owned())
            .spawn(move || {
                let mut last_heartbeat = Instant::now();
                let mut sampler = crate::auto::load::LoadSampler::default();
                let mut last_sample = Instant::now() - LOAD_INTERVAL;
                while !thread_stop.load(Ordering::Relaxed) {
                    // Load is sampled here rather than on its own thread: it is
                    // only ever read by this renderer, and /proc scans cost more
                    // than a redraw does.
                    if last_sample.elapsed() >= LOAD_INTERVAL {
                        status.set_load(sampler.sample());
                        last_sample = Instant::now();
                    }
                    let snapshot = status.snapshot();
                    if tty {
                        let (cols, rows) = terminal_size();
                        thread_console.set_sticky(run_status::fit_block(
                            run_status::render_block(&snapshot, cols),
                            rows,
                        ));
                        std::thread::sleep(REDRAW_INTERVAL);
                    } else {
                        // A heartbeat before any target has finished would say
                        // nothing; wait for the sweep to actually be under way.
                        if verbose
                            && snapshot.phase.is_some()
                            && last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL
                        {
                            thread_console.println(&run_status::heartbeat_line(&snapshot));
                            last_heartbeat = Instant::now();
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            })
            .expect("spawn dashboard thread");
        Self {
            stop,
            handle: Some(handle),
            console,
        }
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.console.clear_sticky();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_walks_up_exactly_the_drawn_line_count() {
        let mut buf = Vec::new();
        erase(&mut buf, 3);
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out, "\r\x1b[1A\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K");
    }

    #[test]
    fn erase_of_an_empty_block_writes_nothing() {
        let mut buf = Vec::new();
        erase(&mut buf, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn lines_are_truncated_so_a_wrap_cannot_desync_the_block() {
        // 30 columns of terminal, 40 characters of line: one wrapped row would
        // make the next erase eat a line of real scrollback.
        let line = "x".repeat(40);
        assert_eq!(truncate(&line, 30).chars().count(), 29);
        assert_eq!(truncate("short", 30), "short");
    }

    #[test]
    fn non_tty_console_draws_no_sticky_block() {
        let mut buf = Vec::new();
        draw(&mut buf, &["one".to_owned(), "two".to_owned()], false);
        assert!(buf.is_empty());
    }
}
