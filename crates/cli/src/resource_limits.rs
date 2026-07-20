// SPDX-License-Identifier: Apache-2.0

//! Memory-aware defaults for retention and capture buffers.
//!
//! These are application safeguards, not OS-enforced quotas. Every public
//! default has an environment override, and Linux derives the default from the
//! smaller of host-available RAM and remaining cgroup memory. This lets an 8 GiB
//! workstation stay conservative without imposing the same limits on a 64 GiB
//! analysis host.

use std::path::Path;

pub(crate) const MIB: usize = 1024 * 1024;

fn read_u64(path: impl AsRef<Path>) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn mem_available_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemAvailable:")?;
        rest.split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
            .map(|kb| kb.saturating_mul(1024))
    })
}

#[cfg(target_os = "linux")]
fn cgroup_available_bytes() -> Option<u64> {
    fn remaining(limit_path: &str, used_path: &str) -> Option<u64> {
        let limit_text = std::fs::read_to_string(limit_path).ok()?;
        let limit_text = limit_text.trim();
        if limit_text == "max" {
            return None;
        }
        let limit = limit_text.parse::<u64>().ok()?;
        // cgroup v1 represents unlimited with a number close to u64::MAX.
        if limit >= (1_u64 << 60) {
            return None;
        }
        let used = read_u64(used_path).unwrap_or(0);
        Some(limit.saturating_sub(used))
    }

    remaining("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current").or_else(|| {
        remaining(
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        )
    })
}

/// Memory currently available to this process. On Linux this respects both the
/// host and the process's cgroup. Other platforms return `None`, causing callers
/// to use their documented conservative fallback unless explicitly configured.
pub(crate) fn available_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        match (mem_available_bytes(), cgroup_available_bytes()) {
            (Some(host), Some(cgroup)) => Some(host.min(cgroup)),
            (host, cgroup) => host.or(cgroup),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub(crate) fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()?
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
}

/// Resolve a byte budget from an explicit environment override or a fraction of
/// currently available memory, clamped to sensible implementation bounds.
pub(crate) fn dynamic_bytes(
    env_name: &str,
    available_divisor: u64,
    minimum: usize,
    fallback: usize,
    maximum: usize,
) -> usize {
    if let Some(configured) = env_usize(env_name) {
        return configured;
    }
    available_memory_bytes()
        .map(|available| {
            usize::try_from(available / available_divisor)
                .unwrap_or(usize::MAX)
                .clamp(minimum, maximum)
        })
        .unwrap_or(fallback.clamp(minimum, maximum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_budget_is_bounded() {
        let value = dynamic_bytes(
            "GOVFUZZ_TEST_NONEXISTENT_MEMORY_LIMIT",
            64,
            4 * MIB,
            8 * MIB,
            32 * MIB,
        );
        assert!((4 * MIB..=32 * MIB).contains(&value));
    }
}
