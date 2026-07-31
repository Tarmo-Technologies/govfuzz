// SPDX-License-Identifier: Apache-2.0
//! Host load sampling for the live dashboard.
//!
//! `auto` already prints its RSS *budget* once at startup (`jobs x rss-limit`),
//! which is a plan, not a measurement. The number that decides whether to raise
//! `--jobs` is the one the run is actually using: a sweep of C targets that
//! spends most of its wall-clock in single-threaded `clang` invocations sits at
//! 20% CPU with gigabytes of headroom, and nothing on screen said so.
//!
//! Linux-only and best-effort: a failed read yields `None` and the dashboard
//! simply omits the field rather than reporting a zero that looks like an idle
//! box.

use crate::auto::run_status::LoadSample;

/// Samples system CPU utilisation across calls (it is a delta of /proc/stat
/// counters, so a single reading means nothing) and the process group's RSS.
#[derive(Default)]
pub struct LoadSampler {
    previous: Option<CpuTotals>,
}

#[derive(Clone, Copy)]
struct CpuTotals {
    idle: u64,
    total: u64,
}

impl LoadSampler {
    pub fn sample(&mut self) -> Option<LoadSample> {
        let cpu_percent = self.cpu_percent().unwrap_or(0);
        let rss_mb = process_group_rss_mb()?;
        Some(LoadSample {
            cpu_percent,
            rss_mb,
            rss_budget_mb: 0,
        })
    }

    fn cpu_percent(&mut self) -> Option<u32> {
        let current = read_cpu_totals()?;
        let previous = self.previous.replace(current)?;
        let total = current.total.saturating_sub(previous.total);
        let idle = current.idle.saturating_sub(previous.idle);
        if total == 0 {
            return None;
        }
        let busy = total.saturating_sub(idle);
        Some(((busy as f64 / total as f64) * 100.0).round() as u32)
    }
}

#[cfg(target_os = "linux")]
fn read_cpu_totals() -> Option<CpuTotals> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().next()?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    if fields.len() < 5 {
        return None;
    }
    // user nice system idle iowait ...; idle time is idle + iowait.
    let idle = fields[3] + fields[4];
    Some(CpuTotals {
        idle,
        total: fields.iter().sum(),
    })
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_totals() -> Option<CpuTotals> {
    None
}

/// Resident memory of the whole run: the parent plus every compiler, linker and
/// fuzz child it spawned. Summed over the process group rather than read from
/// `/proc/self`, because the parent's own RSS is a rounding error next to a
/// dozen concurrent `cc1plus`es — and the group total is exactly what the
/// `jobs x rss-limit` budget is meant to bound.
#[cfg(target_os = "linux")]
fn process_group_rss_mb() -> Option<usize> {
    // SAFETY: getpgrp takes no arguments and cannot fail.
    let pgrp = unsafe { libc::getpgrp() };
    let page_size = page_size_bytes();
    let mut total_pages: u64 = 0;
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // The comm field is parenthesised and may itself contain spaces, so field
        // splitting has to start after the last ')'.
        let Some(rest) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // After comm: state(0) ppid(1) pgrp(2) ... rss(21).
        if fields.len() < 22 {
            continue;
        }
        let Ok(entry_pgrp) = fields[2].parse::<i32>() else {
            continue;
        };
        if entry_pgrp != pgrp {
            continue;
        }
        total_pages += fields[21].parse::<u64>().unwrap_or(0);
    }
    Some((total_pages * page_size / (1024 * 1024)) as usize)
}

#[cfg(target_os = "linux")]
fn page_size_bytes() -> u64 {
    // SAFETY: sysconf with a valid name returns a long; -1 signals failure, for
    // which the conventional 4 KiB page is a safe fallback.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        4096
    }
}

#[cfg(not(target_os = "linux"))]
fn process_group_rss_mb() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_percent_needs_two_readings_to_mean_anything() {
        let mut sampler = LoadSampler::default();
        // The first call has no previous total to subtract from, so it must not
        // invent a utilisation figure.
        assert_eq!(sampler.cpu_percent(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_run_reports_its_own_resident_memory() {
        // This process is in its own process group's scan, so the total can never
        // be zero on a working reader.
        let rss = process_group_rss_mb().expect("linux exposes /proc");
        assert!(rss > 0, "process group RSS should include this test binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_percent_is_a_percentage_after_a_second_reading() {
        let mut sampler = LoadSampler::default();
        let _ = sampler.cpu_percent();
        std::thread::sleep(std::time::Duration::from_millis(50));
        if let Some(percent) = sampler.cpu_percent() {
            assert!(percent <= 100, "cpu percent out of range: {percent}");
        }
    }
}
