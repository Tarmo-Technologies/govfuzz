// SPDX-License-Identifier: Apache-2.0

//! Crash & resource diagnostics.
//!
//! GovFuzz runs die in three ways. The Rust panic path is already captured by
//! the CLI's `bug_report` hook. This crate covers the other two — the ones that
//! historically left nothing behind but `Killed` in the terminal:
//!
//! 1. **The process itself is SIGKILLed** — almost always the Linux OOM killer
//!    (or a cgroup/container memory limit) on a memory-hungry fuzz run. SIGKILL
//!    cannot be caught, blocked, or handled, so *nothing in-process can log at
//!    the moment of death*. Instead we make the death identifiable after the
//!    fact:
//!      - a durable, timestamped, pid-tagged log file with a `session_start`
//!        record and a matching `session_end` written only on clean exit — a
//!        start with no end means the process was killed;
//!      - a periodic memory-watermark heartbeat, so the last surviving line
//!        shows RSS climbing toward the limit;
//!      - [`scan_kernel_oom`], a best-effort kernel-log correlation that
//!        confirms an OOM kill by name.
//!
//! 2. **A child harness / fuzz worker is killed by a signal** — the parent must
//!    decode the signal ([`describe_exit`]) instead of collapsing it into an
//!    opaque `None` exit code, and capture the child's own stderr.
//!
//! The crate is dependency-free (std only) and safe to call on any platform;
//! Linux-specific probes degrade to `None` elsewhere.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Environment variable selecting the diagnostics log destination. A path sets
/// (and appends to) the log file; `off`, `0`, `none`, or `false` disable file
/// logging entirely. When unset, callers fall back to a default path.
pub const LOG_ENV: &str = "GOVFUZZ_LOG";

/// Structured decoding of a terminated child process's exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDescription {
    /// Normal exit code, if the process exited normally.
    pub code: Option<i32>,
    /// Terminating signal number, if the process was killed by a signal.
    pub signal: Option<i32>,
    /// Human name for [`Self::signal`], when known (e.g. `SIGKILL`).
    pub signal_name: Option<&'static str>,
    /// True when the terminating signal is `SIGKILL` (9) — on Linux the
    /// overwhelmingly common cause is the OOM killer or a cgroup memory limit.
    pub likely_oom: bool,
}

impl ExitDescription {
    /// True when the process did not exit cleanly with code 0.
    pub fn is_abnormal(&self) -> bool {
        self.signal.is_some() || !matches!(self.code, Some(0))
    }

    /// One-line human summary suitable for a log or terminal message.
    pub fn human(&self) -> String {
        match (self.signal, self.code) {
            (Some(sig), _) => {
                let name = self.signal_name.unwrap_or("signal");
                if self.likely_oom {
                    format!(
                        "killed by signal {sig} ({name}) — likely out-of-memory \
                         (OOM killer or cgroup/container memory limit)"
                    )
                } else {
                    format!("killed by signal {sig} ({name})")
                }
            }
            (None, Some(0)) => "exited cleanly (code 0)".to_owned(),
            (None, Some(code)) => format!("exited with non-zero code {code}"),
            (None, None) => "terminated for an unknown reason".to_owned(),
        }
    }
}

/// Decode a [`std::process::ExitStatus`] into signal / code detail. On non-Unix
/// platforms only the exit code is available.
pub fn describe_exit(status: &ExitStatus) -> ExitDescription {
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;

    ExitDescription {
        code: status.code(),
        signal,
        signal_name: signal.and_then(signal_name),
        likely_oom: signal == Some(9),
    }
}

/// Human name for the common POSIX signals govfuzz cares about.
pub fn signal_name(sig: i32) -> Option<&'static str> {
    Some(match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        _ => return None,
    })
}

/// Current resident-set size of this process in KiB, from `/proc/self/status`
/// (`VmRSS`). `None` off Linux or when the field is unavailable.
pub fn current_rss_kib() -> Option<u64> {
    proc_status_field("VmRSS:")
}

/// Peak resident-set size ("high water mark") of this process in KiB, from
/// `/proc/self/status` (`VmHWM`). This is the value the OOM killer's decision
/// tracks most closely.
pub fn peak_rss_kib() -> Option<u64> {
    proc_status_field("VmHWM:")
}

fn proc_status_field(field: &str) -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            // e.g. "VmHWM:\t  123456 kB"
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

/// Best-effort memory limit (in bytes) applied to this process by a cgroup, so
/// a run can report how much headroom it has before the OOM killer fires. Reads
/// cgroup v2 (`memory.max`) then v1 (`memory.limit_in_bytes`). `None` when
/// unlimited or unreadable.
pub fn cgroup_memory_limit_bytes() -> Option<u64> {
    for path in [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let trimmed = text.trim();
            if trimmed == "max" {
                return None;
            }
            if let Ok(value) = trimmed.parse::<u64>() {
                // v1 reports a sentinel near u64::MAX / page-aligned when unlimited.
                if value >= u64::MAX / 4096 * 4096 || value == u64::MAX {
                    return None;
                }
                return Some(value);
            }
        }
    }
    None
}

/// Best-effort scan of the kernel ring buffer for an OOM-kill line naming
/// `process_name`. Returns the most recent matching line, if any. Tries
/// `dmesg` and falls back to `journalctl -k`; both may be unavailable or
/// require privileges, in which case this quietly returns `None`.
///
/// This is how an OOM death is *confirmed* even though the victim could not log
/// anything at the moment it was SIGKILLed.
pub fn scan_kernel_oom(process_name: &str) -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let needle = process_name.to_ascii_lowercase();
    for (bin, args) in [
        ("dmesg", &["--ctime"][..]),
        ("journalctl", &["-k", "--no-pager", "-n", "2000"][..]),
    ] {
        let Ok(output) = std::process::Command::new(bin).args(args).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut last: Option<String> = None;
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            let is_oom = lower.contains("out of memory")
                || lower.contains("oom-killer")
                || lower.contains("killed process");
            if is_oom && (lower.contains(&needle) || lower.contains("killed process")) {
                last = Some(line.trim().to_owned());
            }
        }
        if last.is_some() {
            return last;
        }
    }
    None
}

/// Severity of a diagnostics record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// Append-only, thread-safe diagnostics log. Writes greppable, timestamped,
/// pid-tagged lines to a file and optionally echoes `WARN`/`ERROR` to stderr.
/// Cheap to hold behind an [`Arc`] and share with the heartbeat thread.
#[derive(Debug)]
pub struct DiagLog {
    file: Option<Mutex<File>>,
    path: Option<PathBuf>,
    echo_stderr: bool,
    pid: u32,
}

impl DiagLog {
    /// Open a log at `path` (creating parent dirs, appending if it exists). When
    /// `echo_stderr` is set, `WARN`/`ERROR` records are also printed to stderr.
    pub fn open(path: &Path, echo_stderr: bool) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Some(Mutex::new(file)),
            path: Some(path.to_path_buf()),
            echo_stderr,
            pid: std::process::id(),
        })
    }

    /// A no-op log (file logging disabled). Still echoes to stderr if requested,
    /// so critical records are never fully silent.
    pub fn disabled(echo_stderr: bool) -> Self {
        Self {
            file: None,
            path: None,
            echo_stderr,
            pid: std::process::id(),
        }
    }

    /// The log file path, if file logging is active.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Write one record. `fields` are appended as `key=value` pairs.
    pub fn event(&self, level: Level, kind: &str, message: &str, fields: &[(&str, String)]) {
        let mut line = format!(
            "{} {} pid={} {kind}: {message}",
            now_iso8601(),
            level.as_str(),
            self.pid
        );
        for (key, value) in fields {
            line.push(' ');
            line.push_str(key);
            line.push('=');
            // Quote values containing spaces so the line stays greppable.
            if value.contains(' ') {
                line.push('"');
                line.push_str(value);
                line.push('"');
            } else {
                line.push_str(value);
            }
        }
        if let Some(file) = &self.file {
            if let Ok(mut guard) = file.lock() {
                let _ = writeln!(guard, "{line}");
                let _ = guard.flush();
            }
        }
        if self.echo_stderr && level != Level::Info {
            eprintln!("govfuzz[diag]: {line}");
        }
    }

    /// Convenience wrapper for an `INFO` record.
    pub fn info(&self, kind: &str, message: &str, fields: &[(&str, String)]) {
        self.event(Level::Info, kind, message, fields);
    }

    /// Convenience wrapper for a `WARN` record.
    pub fn warn(&self, kind: &str, message: &str, fields: &[(&str, String)]) {
        self.event(Level::Warn, kind, message, fields);
    }
}

/// Resolve the diagnostics log path. Honours [`LOG_ENV`]: an explicit path wins;
/// `off`/`0`/`none`/`false` disables file logging (returns `None`); unset falls
/// back to `default`.
pub fn resolve_log_path(default: PathBuf) -> Option<PathBuf> {
    match std::env::var(LOG_ENV) {
        Ok(value) => {
            let lowered = value.trim().to_ascii_lowercase();
            if matches!(lowered.as_str(), "off" | "0" | "none" | "false" | "") {
                None
            } else {
                Some(PathBuf::from(value))
            }
        }
        Err(_) => Some(default),
    }
}

/// The default diagnostics log location: `<tmp>/govfuzz/govfuzz.log`. A single
/// append-only file keeps the trail greppable across runs; every line carries a
/// pid so concurrent runs stay separable.
pub fn default_log_path() -> PathBuf {
    std::env::temp_dir().join("govfuzz").join("govfuzz.log")
}

/// Running background sampler that records the process memory watermark at a
/// fixed interval. Stops and joins its thread when dropped, logging a final
/// sample so the last line before an abrupt kill is as fresh as possible.
pub struct Heartbeat {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Heartbeat {
    /// Start sampling `log` every `interval`. `label` tags each record (e.g. the
    /// command name). A `WARN` is emitted the first time RSS crosses 90% of any
    /// detected cgroup memory limit, so an approaching OOM is visible before the
    /// kill.
    pub fn start(log: Arc<DiagLog>, interval: Duration, label: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let label = label.to_owned();
        let limit = cgroup_memory_limit_bytes();
        let handle = std::thread::Builder::new()
            .name("govfuzz-memwatch".to_owned())
            .spawn(move || {
                let mut warned = false;
                let mut last_peak = 0u64;
                loop {
                    // Sleep in short slices so shutdown is responsive.
                    let mut waited = Duration::ZERO;
                    while waited < interval {
                        if stop_thread.load(Ordering::Relaxed) {
                            sample(&log, &label, limit, &mut warned, &mut last_peak);
                            return;
                        }
                        let slice = Duration::from_millis(200).min(interval - waited);
                        std::thread::sleep(slice);
                        waited += slice;
                    }
                    sample(&log, &label, limit, &mut warned, &mut last_peak);
                }
            })
            .ok();
        Self { stop, handle }
    }
}

fn sample(log: &DiagLog, label: &str, limit: Option<u64>, warned: &mut bool, last_peak: &mut u64) {
    let Some(peak) = peak_rss_kib() else {
        return;
    };
    // Only log when the watermark advances, to keep the trail small on idle runs.
    if peak <= *last_peak {
        return;
    }
    *last_peak = peak;
    let rss = current_rss_kib().unwrap_or(0);
    let mut fields = vec![
        ("label", label.to_owned()),
        ("rss_kib", rss.to_string()),
        ("peak_kib", peak.to_string()),
    ];
    if let Some(limit) = limit {
        let limit_kib = limit / 1024;
        fields.push(("limit_kib", limit_kib.to_string()));
        if limit_kib > 0 && peak * 100 >= limit_kib * 90 && !*warned {
            *warned = true;
            log.warn(
                "memory_pressure",
                "process memory is within 10% of the cgroup limit — an OOM kill is likely imminent",
                &fields,
            );
            return;
        }
    }
    log.info("memory", "memory watermark advanced", &fields);
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Format a `SystemTime::now()` as an ISO-8601 / RFC-3339 UTC string with
/// millisecond precision, without pulling in a date library.
fn now_iso8601() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    format_epoch(dur.as_secs(), dur.subsec_millis())
}

fn format_epoch(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days (Howard Hinnant's algorithm), epoch = 1970-01-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_names_cover_crash_and_kill_signals() {
        assert_eq!(signal_name(9), Some("SIGKILL"));
        assert_eq!(signal_name(11), Some("SIGSEGV"));
        assert_eq!(signal_name(6), Some("SIGABRT"));
        assert_eq!(signal_name(123), None);
    }

    #[test]
    fn exit_description_flags_sigkill_as_likely_oom() {
        let desc = ExitDescription {
            code: None,
            signal: Some(9),
            signal_name: Some("SIGKILL"),
            likely_oom: true,
        };
        assert!(desc.is_abnormal());
        assert!(desc.human().contains("out-of-memory"));
        assert!(desc.human().contains("SIGKILL"));
    }

    #[test]
    fn clean_exit_is_not_abnormal() {
        let desc = ExitDescription {
            code: Some(0),
            signal: None,
            signal_name: None,
            likely_oom: false,
        };
        assert!(!desc.is_abnormal());
        assert_eq!(desc.human(), "exited cleanly (code 0)");
    }

    #[test]
    fn nonzero_exit_is_abnormal() {
        let desc = ExitDescription {
            code: Some(2),
            signal: None,
            signal_name: None,
            likely_oom: false,
        };
        assert!(desc.is_abnormal());
        assert!(desc.human().contains("non-zero code 2"));
    }

    #[cfg(unix)]
    #[test]
    fn describe_exit_decodes_a_real_killed_child() {
        use std::process::Command;
        // `sleep` killed with SIGKILL — the exact "Killed" scenario.
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        // SIGKILL via libc-free path: kill(2) through the shell is heavy; use the
        // std kill which sends SIGKILL.
        child.kill().expect("kill child");
        let status = child.wait().expect("wait child");
        let desc = describe_exit(&status);
        assert_eq!(desc.signal, Some(9));
        assert_eq!(desc.signal_name, Some("SIGKILL"));
        assert!(desc.likely_oom);
    }

    #[test]
    fn resolve_log_path_honours_off_switch() {
        // Guard against a polluted ambient env by setting explicitly.
        std::env::set_var(LOG_ENV, "off");
        assert_eq!(resolve_log_path(PathBuf::from("/tmp/x.log")), None);
        std::env::set_var(LOG_ENV, "/custom/path.log");
        assert_eq!(
            resolve_log_path(PathBuf::from("/tmp/x.log")),
            Some(PathBuf::from("/custom/path.log"))
        );
        std::env::remove_var(LOG_ENV);
        assert_eq!(
            resolve_log_path(PathBuf::from("/tmp/x.log")),
            Some(PathBuf::from("/tmp/x.log"))
        );
    }

    #[test]
    fn diaglog_writes_records_to_file() {
        let dir = std::env::temp_dir().join(format!("crash_diag_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("diag.log");
        let log = DiagLog::open(&path, false).expect("open log");
        log.info("session_start", "boot", &[("argv", "govfuzz auto".to_owned())]);
        log.warn("worker_killed", "worker 3 died", &[("signal", "9".to_owned())]);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("session_start: boot"));
        assert!(text.contains("argv=\"govfuzz auto\""));
        assert!(text.contains("WARN"));
        assert!(text.contains("worker_killed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epoch_formats_known_instant() {
        // 2021-01-01T00:00:00.000Z == 1609459200 seconds since the epoch.
        assert_eq!(format_epoch(1_609_459_200, 0), "2021-01-01T00:00:00.000Z");
        assert_eq!(format_epoch(0, 5), "1970-01-01T00:00:00.005Z");
    }
}
