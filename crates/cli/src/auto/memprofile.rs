// SPDX-License-Identifier: Apache-2.0

//! Memory-consumption replay — uncontrolled resource consumption (CWE-400, GF-558),
//! the MemLock / MemConFuzz idea adapted to govfuzz's replay path.
//!
//! Crash-only fuzzing finds a memory-consumption bug only when it OOM-kills the
//! process; a target that allocates hundreds of megabytes from a few input bytes but
//! stays under the limit is invisible. This pass replays the coverage-guided corpus
//! (each input in a FRESH process, so `wait4`'s `ru_maxrss` is that input's true peak
//! resident set) and flags an input whose peak memory is both far above the harness
//! baseline AND amplified relative to the input size — the signature of an
//! attacker-controlled allocation (`malloc(n * attacker_count)`, an unbounded
//! accumulation, a decompression bomb). A legitimately large input that holds a
//! proportional amount of memory is not flagged.
//!
//! Linux-only (reads `ru_maxrss` in KiB); a non-Linux host or a missing corpus skips
//! cleanly.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Cap the corpus inputs profiled per harness so a huge queue can't stall the run.
const MAX_INPUTS: usize = 512;
/// A candidate input must drive at least this much resident memory ABOVE the harness
/// baseline — filters a parser's normal working set.
const MIN_EXCESS_MB: u64 = 128;
/// ...and the growth must be amplified vs the input: at least this many KiB of
/// resident memory per input byte, so a legitimately large input (which holds a
/// proportional working set) is not flagged.
const MIN_KB_PER_INPUT_BYTE: u64 = 64;
/// A resource-profile replay is diagnostic only. A target that does not terminate
/// is not a useful RSS sample and must not hold the whole auto campaign open.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(10);
const PROFILE_BUDGET: Duration = Duration::from_secs(30);

struct Sample {
    input: std::path::PathBuf,
    input_len: u64,
    peak_kb: u64,
}

/// Profile every C/C++ harness's corpus, writing a GF-558 finding for the worst
/// disproportionate-memory input per harness. Returns the number of findings written.
pub fn run_mem_profile(work_dir: &Path) -> usize {
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return 0;
    };
    let mut written = 0usize;
    let mut index = 0usize;
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        written += profile_one(work_dir, &hdir, &harness_id, &mut index);
    }
    written
}

fn profile_one(work_dir: &Path, hdir: &Path, harness_id: &str, index: &mut usize) -> usize {
    // The ASan `main` built during fuzzing is the replay binary; the govfuzz C/Ada
    // driver replays a single input passed as argv[1].
    let bin = hdir.join("main");
    if !bin.is_file() {
        return 0;
    }
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return 0;
    };

    let deadline = Instant::now() + PROFILE_BUDGET;
    let mut samples: Vec<Sample> = Vec::new();
    for entry in inputs.flatten() {
        if samples.len() >= MAX_INPUTS || Instant::now() >= deadline {
            break;
        }
        let input = entry.path();
        let Ok(meta) = input.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Some(peak_kb) = run_and_peak_rss_kb(&bin, &input) else {
            // A timeout or spawn/reap failure makes this best-effort profile
            // incomplete. Do not multiply the delay across the remaining corpus.
            break;
        };
        samples.push(Sample {
            input,
            input_len: meta.len(),
            peak_kb,
        });
    }

    // Need a baseline (the harness's fixed overhead) to attribute excess to an input.
    if samples.len() < 2 {
        return 0;
    }
    let baseline_kb = samples.iter().map(|s| s.peak_kb).min().unwrap_or(0);

    // The worst amplifying input, if any, is this harness's one finding.
    let worst = samples
        .iter()
        .filter(|s| is_disproportionate(s, baseline_kb))
        .max_by_key(|s| s.peak_kb.saturating_sub(baseline_kb));
    let Some(worst) = worst else {
        return 0;
    };

    let id = format!("F-MEM-{:04}", *index);
    *index += 1;
    if write_mem_finding(work_dir, &id, harness_id, worst, baseline_kb) {
        1
    } else {
        0
    }
}

/// Whether a sample's peak memory is both far above baseline and amplified relative
/// to the input size.
fn is_disproportionate(sample: &Sample, baseline_kb: u64) -> bool {
    let excess_kb = sample.peak_kb.saturating_sub(baseline_kb);
    if excess_kb / 1024 < MIN_EXCESS_MB {
        return false;
    }
    // Empty input driving large memory is maximally amplified; otherwise require the
    // per-byte growth to clear the bar.
    sample.input_len == 0 || excess_kb / sample.input_len.max(1) >= MIN_KB_PER_INPUT_BYTE
}

/// Run `bin input` in a fresh process and return its peak resident set in KiB
/// (`rusage.ru_maxrss`), or `None` if it could not be spawned/reaped. Linux only.
#[cfg(target_os = "linux")]
fn run_and_peak_rss_kb(bin: &Path, input: &Path) -> Option<u64> {
    run_and_peak_rss_kb_with_timeout(bin, input, REPLAY_TIMEOUT)
}

#[cfg(target_os = "linux")]
fn run_and_peak_rss_kb_with_timeout(bin: &Path, input: &Path, timeout: Duration) -> Option<u64> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::Instant;

    let mut command = Command::new(bin);
    command
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // A sanitizer symbolizer or another descendant must not outlive a timed-out
        // replay, so isolate the entire invocation in its own process group.
        .process_group(0);
    let child = command.spawn().ok()?;
    let pid = child.id() as libc::pid_t;
    // Reap via wait4 to read rusage; std's Child does not reap on drop, so there is no
    // double-reap. Keep the Child alive until after wait4 so its pid can't be reused.
    let mut status: libc::c_int = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let deadline = Instant::now() + timeout;
    loop {
        let reaped = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut usage) };
        if reaped == pid {
            drop(child);
            return Some(usage.ru_maxrss.max(0) as u64);
        }
        if reaped < 0 {
            drop(child);
            return None;
        }
        if Instant::now() >= deadline {
            // A negative pid addresses the process group created above.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::wait4(pid, &mut status, 0, &mut usage);
            }
            drop(child);
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(target_os = "linux"))]
fn run_and_peak_rss_kb(_bin: &Path, _input: &Path) -> Option<u64> {
    None
}

fn write_mem_finding(
    work: &Path,
    id: &str,
    harness_id: &str,
    sample: &Sample,
    baseline_kb: u64,
) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let peak_mb = sample.peak_kb / 1024;
    let baseline_mb = baseline_kb / 1024;
    let excess_mb = sample.peak_kb.saturating_sub(baseline_kb) / 1024;
    // One issue per harness (rule + harness), stable 64-hex cluster key.
    let cluster_key_full = hex(&Sha256::digest(format!("GF-558:{harness_id}").as_bytes()));
    // Persist the reproducer so `auto` can minimize / attest it.
    let repro = dir.join("testcase.bin");
    let _ = std::fs::copy(&sample.input, &repro);
    let record = json!({
        "id": id,
        "rule_id": "GF-558",
        "severity": "high",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "minimal_reproducer": repro.to_string_lossy(),
        "exception": {
            "name": "MemoryConsumption",
            "message": format!(
                "input of {} bytes drove {peak_mb} MB resident (baseline {baseline_mb} MB, +{excess_mb} MB) — uncontrolled memory consumption",
                sample.input_len
            ),
        },
        "oracle": { "evidence": [
            { "key": "peak_rss_mb", "value": peak_mb.to_string() },
            { "key": "baseline_rss_mb", "value": baseline_mb.to_string() },
            { "key": "excess_rss_mb", "value": excess_mb.to_string() },
            { "key": "input_bytes", "value": sample.input_len.to_string() },
        ] },
        "analysis": { "engine": "govfuzz.dynamic.memprofile.replay" },
        "actionability": { "cwe": ["CWE-400"], "verdict": "likely_reachable", "confidence": "high" },
    });
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: u64, peak_kb: u64) -> Sample {
        Sample {
            input: std::path::PathBuf::from("x"),
            input_len: len,
            peak_kb,
        }
    }

    #[test]
    fn flags_small_input_with_large_amplified_memory() {
        // 4-byte input, baseline 8 MB, peak 300 MB -> +292 MB, hugely amplified.
        let baseline = 8 * 1024;
        assert!(is_disproportionate(
            &sample(4, baseline + 292 * 1024),
            baseline
        ));
    }

    #[test]
    fn does_not_flag_proportional_large_input() {
        // A 300 MB input holding a ~300 MB working set is proportional, not amplified.
        let baseline = 8 * 1024;
        let big = 300 * 1024 * 1024; // bytes
        assert!(!is_disproportionate(
            &sample(big, baseline + 300 * 1024),
            baseline
        ));
    }

    #[test]
    fn does_not_flag_small_excess() {
        // A few MB above baseline is a normal parser working set, not a finding.
        let baseline = 8 * 1024;
        assert!(!is_disproportionate(
            &sample(4, baseline + 16 * 1024),
            baseline
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hanging_replay_is_killed_at_profile_timeout() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let root = tempfile::tempdir().unwrap();
        let harness = root.path().join("hang.sh");
        std::fs::write(&harness, "#!/bin/sh\nsleep 60\n").unwrap();
        let mut permissions = std::fs::metadata(&harness).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&harness, permissions).unwrap();
        let input = root.path().join("input.bin");
        std::fs::write(&input, b"input").unwrap();

        let started = Instant::now();
        assert_eq!(
            run_and_peak_rss_kb_with_timeout(&harness, &input, Duration::from_millis(100)),
            None
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "profile replay exceeded its wall-clock timeout: {:?}",
            started.elapsed()
        );
    }
}
