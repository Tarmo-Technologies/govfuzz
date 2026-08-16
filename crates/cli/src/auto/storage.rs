// SPDX-License-Identifier: Apache-2.0

//! Work-directory accounting and removal of disposable auto-harness artifacts.
//!
//! Findings, reports, corpora, generated harness sources, and the final replayable
//! harness executable are durable outputs. Compiler caches are not: once a final
//! harness has been linked, retaining a private Cargo `target/` tree per target can
//! consume hundreds of MiB for every Rust candidate.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

pub(crate) const DEFAULT_MAX_WORK_DIR_MIB: u64 = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CompactResult {
    pub(crate) before_bytes: u64,
    pub(crate) after_bytes: u64,
    pub(crate) removed_paths: usize,
}

impl CompactResult {
    pub(crate) fn reclaimed_bytes(self) -> u64 {
        self.before_bytes.saturating_sub(self.after_bytes)
    }
}

/// A campaign-wide output ceiling. The check is serialized because parallel
/// workers finish concurrently; without the lock they would all walk the same
/// potentially large work tree at once.
pub(crate) struct WorkDirBudget {
    max_bytes: u64,
    exhausted: AtomicBool,
    last_bytes: AtomicU64,
    check_lock: Mutex<()>,
}

impl WorkDirBudget {
    pub(crate) fn new(work_dir: &Path, max_mib: u64) -> std::io::Result<Self> {
        let max_bytes = max_mib.saturating_mul(1024 * 1024);
        let bytes = work_dir_size_bytes(work_dir)?;
        Ok(Self {
            max_bytes,
            exhausted: AtomicBool::new(max_bytes > 0 && bytes >= max_bytes),
            last_bytes: AtomicU64::new(bytes),
            check_lock: Mutex::new(()),
        })
    }

    /// Re-measure the work directory after a target has been persisted. Returns
    /// true once the ceiling has been reached. A value of zero disables the cap.
    pub(crate) fn checkpoint(&self, work_dir: &Path) -> std::io::Result<bool> {
        if self.max_bytes == 0 || self.exhausted() {
            return Ok(self.exhausted());
        }
        let _guard = self.check_lock.lock().unwrap_or_else(|p| p.into_inner());
        if self.exhausted() {
            return Ok(true);
        }
        let bytes = work_dir_size_bytes(work_dir)?;
        self.last_bytes.store(bytes, Ordering::SeqCst);
        if bytes >= self.max_bytes {
            self.exhausted.store(true, Ordering::SeqCst);
        }
        Ok(self.exhausted())
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted.load(Ordering::SeqCst)
    }

    pub(crate) fn last_bytes(&self) -> u64 {
        self.last_bytes.load(Ordering::SeqCst)
    }

    pub(crate) fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

/// Remove compiler caches that are never needed to replay or explain a completed
/// auto-harness. This also repairs work directories produced by releases that
/// retained one Cargo target tree per Rust harness.
pub(crate) fn compact_build_caches(work_dir: &Path) -> std::io::Result<CompactResult> {
    let before_bytes = work_dir_size_bytes(work_dir)?;
    let mut removed_paths = 0;
    for harness_root in [work_dir.join("harnesses"), work_dir.join("auto")] {
        let Ok(entries) = std::fs::read_dir(harness_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let harness = entry.path();
            if !harness.is_dir() {
                continue;
            }
            for target in [
                harness.join("rust_harness").join("target"),
                harness.join("incrate").join("target"),
            ] {
                if remove_directory_if_owned(&target)? {
                    removed_paths += 1;
                }
            }
        }
    }
    let after_bytes = work_dir_size_bytes(work_dir)?;
    Ok(CompactResult {
        before_bytes,
        after_bytes,
        removed_paths,
    })
}

/// User-requested compaction additionally clears scratch space. It deliberately
/// retains findings, reports, corpora, result.json checkpoints, generated source,
/// and final harness executables.
pub(crate) fn compact_work_dir(work_dir: &Path) -> std::io::Result<CompactResult> {
    let before_bytes = work_dir_size_bytes(work_dir)?;
    let build = compact_build_caches(work_dir)?;
    let mut removed_paths = build.removed_paths;
    for scratch in ["fuzz_scratch", "fuzz_inputs", "events"] {
        if remove_directory_if_owned(&work_dir.join(scratch))? {
            removed_paths += 1;
        }
    }
    let after_bytes = work_dir_size_bytes(work_dir)?;
    Ok(CompactResult {
        before_bytes,
        after_bytes,
        removed_paths,
    })
}

fn remove_directory_if_owned(path: &Path) -> std::io::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(true)
}

/// Allocated size, without following symlinks. On Unix this uses filesystem block
/// counts (so sparse files do not cause a false quota trip); other platforms use
/// logical file length.
pub(crate) fn work_dir_size_bytes(root: &Path) -> std::io::Result<u64> {
    if !root.exists() {
        return Ok(0);
    }
    let mut total = 0_u64;
    let mut pending = vec![PathBuf::from(root)];
    while let Some(path) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            // Parallel builders can unlink an intermediate between read_dir and
            // metadata. It no longer consumes space, so skipping it is exact.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        total = total.saturating_add(allocated_bytes(&metadata));
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let entries = match std::fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            for entry in entries {
                match entry {
                    Ok(entry) => pending.push(entry.path()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(total)
}

#[cfg(unix)]
fn allocated_bytes(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated_bytes(metadata: &std::fs::Metadata) -> u64 {
    metadata.len()
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_removes_rust_targets_but_preserves_evidence_and_replay_binary() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        let harness = work.join("harnesses/H-RUST");
        std::fs::create_dir_all(harness.join("incrate/target/debug")).unwrap();
        std::fs::create_dir_all(harness.join("rust_harness/target/debug")).unwrap();
        std::fs::create_dir_all(work.join("findings/F-1")).unwrap();
        std::fs::write(harness.join("incrate/target/debug/cache"), vec![0_u8; 8192]).unwrap();
        std::fs::write(
            harness.join("rust_harness/target/debug/cache"),
            vec![0_u8; 8192],
        )
        .unwrap();
        std::fs::write(harness.join("main"), "replay").unwrap();
        std::fs::write(harness.join("result.json"), "{}").unwrap();
        std::fs::write(work.join("findings/F-1/finding.json"), "{}").unwrap();

        let result = compact_work_dir(work).unwrap();
        assert_eq!(result.removed_paths, 2);
        assert!(!harness.join("incrate/target").exists());
        assert!(!harness.join("rust_harness/target").exists());
        assert!(harness.join("main").is_file());
        assert!(harness.join("result.json").is_file());
        assert!(work.join("findings/F-1/finding.json").is_file());
        assert!(result.after_bytes < result.before_bytes);
    }

    #[test]
    fn budget_zero_is_disabled_and_positive_budget_trips() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("large"), vec![0_u8; 2 * 1024 * 1024]).unwrap();
        let disabled = WorkDirBudget::new(temp.path(), 0).unwrap();
        assert!(!disabled.checkpoint(temp.path()).unwrap());
        let bounded = WorkDirBudget::new(temp.path(), 1).unwrap();
        assert!(bounded.exhausted());
    }
}
