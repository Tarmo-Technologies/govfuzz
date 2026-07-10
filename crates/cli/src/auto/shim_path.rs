// SPDX-License-Identifier: Apache-2.0

//! Find libgovfuzz_runtrace.so on disk so the auto attempt loop
//! can LD_PRELOAD it. Search order:
//!
//!   1. $GOVFUZZ_RUNTRACE_SHIM (explicit override)
//!   2. Sibling of std::env::current_exe() — same target dir as
//!      cli's build.rs copied it to.
//!   3. Cargo's native sibling cdylib name from direct shim builds.
//!   4. A sibling `govfuzz_runtrace_shim-*` dist archive directory.
//!   5. None — the shim isn't on disk; caller falls back to
//!      audit-disabled mode with a one-line warning.

use std::path::{Path, PathBuf};

pub fn locate() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("GOVFUZZ_RUNTRACE_SHIM") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    locate_next_to_exe(&exe)
}

fn locate_next_to_exe(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    // `libgovfuzz_runtrace.so` is the dist-named copy cli's build.rs makes from
    // the canonical cargo cdylib `libgovfuzz_runtrace_shim.so`. Prefer the copy to
    // preserve packaging intent — BUT cli's build.rs can lag the shim by one build
    // within a single `cargo build` (its rerun-if-changed fingerprint is decided
    // before the shim rebuilds in the same invocation), leaving the copy stale.
    // Loading a stale shim silently runs old instrumentation, so when the
    // canonical artifact is strictly newer than the copy, use the fresh one.
    let dist = dir.join("libgovfuzz_runtrace.so");
    let shim = dir.join("libgovfuzz_runtrace_shim.so");
    match (dist.is_file(), shim.is_file()) {
        (true, true) => Some(if shim_is_strictly_newer(&shim, &dist) {
            shim
        } else {
            dist
        }),
        (true, false) => Some(dist),
        (false, true) => Some(shim),
        (false, false) => locate_in_sibling_dist_dir(dir),
    }
}

/// Whether `shim`'s mtime is strictly newer than `dist`'s. Conservative: any
/// metadata error answers `false`, so an unreadable mtime keeps the dist-name
/// preference rather than risking a spurious switch.
fn shim_is_strictly_newer(shim: &Path, dist: &Path) -> bool {
    match (
        shim.metadata().and_then(|m| m.modified()),
        dist.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(shim_mtime), Ok(dist_mtime)) => shim_mtime > dist_mtime,
        _ => false,
    }
}

fn locate_in_sibling_dist_dir(dir: &Path) -> Option<PathBuf> {
    let parent = dir.parent()?;
    let mut sibling_dirs: Vec<PathBuf> = std::fs::read_dir(parent)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("govfuzz_runtrace_shim-"))
        })
        .collect();
    sibling_dirs.sort();

    sibling_dirs
        .into_iter()
        .map(|path| path.join("libgovfuzz_runtrace_shim.so"))
        .find(|path| path.is_file())
}

/// Convenience: format the LD_PRELOAD value to set, optionally
/// chained behind any existing LD_PRELOAD the user has in env.
///
/// Thin wrapper around [`ld_preload_value_with`] that reads
/// `$LD_PRELOAD` from the process environment.
pub fn ld_preload_value(shim: &Path) -> String {
    ld_preload_value_with(shim, std::env::var("LD_PRELOAD").ok().as_deref())
}

/// Pure variant of [`ld_preload_value`] that takes the existing
/// `LD_PRELOAD` value as a parameter. Kept separate so tests can
/// exercise the chaining logic without touching the global env
/// (which would race under cargo's parallel test runner).
pub fn ld_preload_value_with(shim: &Path, existing: Option<&str>) -> String {
    match existing {
        Some(v) if !v.is_empty() => format!("{}:{}", shim.display(), v),
        _ => shim.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ld_preload_chains_existing_value() {
        let p = ld_preload_value_with(Path::new("/tmp/shim.so"), Some("/tmp/other.so"));
        assert_eq!(p, "/tmp/shim.so:/tmp/other.so");
    }

    #[test]
    fn ld_preload_no_chain_when_empty() {
        // Both `None` and `Some("")` should produce the bare shim path.
        let none = ld_preload_value_with(Path::new("/tmp/shim.so"), None);
        assert_eq!(none, "/tmp/shim.so");
        let empty = ld_preload_value_with(Path::new("/tmp/shim.so"), Some(""));
        assert_eq!(empty, "/tmp/shim.so");
    }

    #[test]
    fn locate_next_to_exe_accepts_cargo_cdylib_name() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("govfuzz");
        let shim = dir.path().join("libgovfuzz_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&shim, "").unwrap();

        assert_eq!(locate_next_to_exe(&exe), Some(shim));
    }

    /// Set a file's mtime so the locator's freshness comparison is deterministic
    /// (writing two files back-to-back gives unreliable mtime ordering).
    fn set_mtime(path: &Path, t: std::time::SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    #[test]
    fn locate_next_to_exe_prefers_dist_name_when_not_older() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("govfuzz");
        let dist_shim = dir.path().join("libgovfuzz_runtrace.so");
        let cargo_shim = dir.path().join("libgovfuzz_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&dist_shim, "").unwrap();
        std::fs::write(&cargo_shim, "").unwrap();
        // Dist copy at least as new as the cargo artifact -> dist preference holds.
        let now = std::time::SystemTime::now();
        set_mtime(&cargo_shim, now - std::time::Duration::from_secs(10));
        set_mtime(&dist_shim, now);

        assert_eq!(locate_next_to_exe(&exe), Some(dist_shim));
    }

    #[test]
    fn locate_next_to_exe_uses_fresh_cargo_artifact_over_stale_copy() {
        // The build-ordering footgun: cli's build.rs lagged, so the dist copy is
        // stale while the canonical cargo cdylib was just rebuilt. The locator
        // must load the fresh artifact, not the stale copy.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("govfuzz");
        let dist_shim = dir.path().join("libgovfuzz_runtrace.so");
        let cargo_shim = dir.path().join("libgovfuzz_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&dist_shim, "").unwrap();
        std::fs::write(&cargo_shim, "").unwrap();
        let now = std::time::SystemTime::now();
        set_mtime(&dist_shim, now - std::time::Duration::from_secs(10));
        set_mtime(&cargo_shim, now);

        assert_eq!(locate_next_to_exe(&exe), Some(cargo_shim));
    }

    #[test]
    fn locate_next_to_exe_accepts_sibling_dist_archive_dir() {
        let dir = tempfile::tempdir().unwrap();
        let govfuzz_dir = dir.path().join("govfuzz-x86_64-unknown-linux-gnu");
        let shim_dir = dir
            .path()
            .join("govfuzz_runtrace_shim-x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&govfuzz_dir).unwrap();
        std::fs::create_dir_all(&shim_dir).unwrap();
        let exe = govfuzz_dir.join("govfuzz");
        let shim = shim_dir.join("libgovfuzz_runtrace_shim.so");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&shim, "").unwrap();

        assert_eq!(locate_next_to_exe(&exe), Some(shim));
    }
}
