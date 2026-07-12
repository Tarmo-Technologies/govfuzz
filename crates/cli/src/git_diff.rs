// SPDX-License-Identifier: Apache-2.0

//! Shared git-diff helpers: compute the set of files changed vs a ref.
//!
//! Extracted from `list_targets` so `ci` (PR-native mode) reuses them. Two
//! change-set flavors are provided:
//!
//! * [`compute_changed_set`] — `git diff --name-only <ref>..HEAD` (two-dot),
//!   the exact behavior `list_targets --changed-since` has always had.
//! * [`compute_changed_set_pr`] — merge-base aware (`<merge-base>..HEAD`), so a
//!   PR branch that is behind its base does not flag the base's own changes.
//!   This is what `govfuzz ci --changed-since` uses.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Absolute path to the git repo root (`git rev-parse --show-toplevel`).
pub fn repo_root() -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .with_context(|| "spawn `git rev-parse --show-toplevel`; is git installed?")?;
    if !out.status.success() {
        bail!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let root = std::str::from_utf8(&out.stdout)
        .with_context(|| "git toplevel output is not utf-8")?
        .trim();
    Ok(PathBuf::from(root))
}

/// Resolve the merge-base of `git_ref` and `HEAD`, falling back to `git_ref`
/// itself when no common ancestor is found (shallow/unrelated history).
pub fn merge_base(repo_root: &Path, git_ref: &str) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["merge-base", git_ref, "HEAD"])
        .output();
    match out {
        Ok(o) if o.status.success() => std::str::from_utf8(&o.stdout)
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| git_ref.to_owned()),
        _ => git_ref.to_owned(),
    }
}

/// Files changed between `<git_ref>` and `HEAD` (two-dot `<ref>..HEAD`). Exact
/// behavior of `list_targets --changed-since`; do not change its semantics.
pub fn compute_changed_set(git_ref: &str) -> Result<HashSet<PathBuf>> {
    let repo_root = repo_root()?;
    diff_name_only(&repo_root, &format!("{git_ref}..HEAD"))
}

/// Files introduced by the PR: merge-base-aware, `<merge-base(ref,HEAD)>..HEAD`.
/// A branch behind its base does not flag the base's own changes.
pub fn compute_changed_set_pr(git_ref: &str) -> Result<HashSet<PathBuf>> {
    let repo_root = repo_root()?;
    let base = merge_base(&repo_root, git_ref);
    diff_name_only(&repo_root, &format!("{base}..HEAD"))
}

fn diff_name_only(repo_root: &Path, range: &str) -> Result<HashSet<PathBuf>> {
    let diff = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--name-only", range])
        .output()
        .with_context(|| "spawn `git diff --name-only`")?;
    if !diff.status.success() {
        bail!(
            "git diff --name-only {range} failed: {}",
            String::from_utf8_lossy(&diff.stderr).trim()
        );
    }
    let stdout =
        std::str::from_utf8(&diff.stdout).with_context(|| "git diff output is not utf-8")?;
    Ok(parse_changed_set(stdout, repo_root))
}

/// Parse `git diff --name-only` output into an absolute-path set rooted at
/// `repo_root`. Blank lines are skipped.
pub fn parse_changed_set(stdout: &str, repo_root: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.insert(repo_root.join(trimmed));
    }
    out
}

/// Whether `path` is in the changed set, tolerant of canonicalization
/// differences (symlinks, `..`, relative vs absolute).
pub fn path_in_changed_set(path: &Path, changed: &HashSet<PathBuf>) -> bool {
    if changed.contains(path) {
        return true;
    }
    if let Ok(canonical) = path.canonicalize() {
        if changed.contains(&canonical) {
            return true;
        }
        for entry in changed {
            if let Ok(entry_canonical) = entry.canonicalize() {
                if entry_canonical == canonical {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_changed_set_joins_against_repo_root_and_skips_blank_lines() {
        let root = Path::new("/repo");
        let set = parse_changed_set("src/a.c\n\nsub/dir/b.rs\n", root);
        assert!(set.contains(&root.join("src/a.c")));
        assert!(set.contains(&root.join("sub/dir/b.rs")));
        assert_eq!(set.len(), 2, "blank line ignored");
    }

    #[test]
    fn parse_changed_set_empty_input_returns_empty_set() {
        assert!(parse_changed_set("", Path::new("/repo")).is_empty());
    }

    #[test]
    fn path_in_changed_set_matches_direct_entry() {
        let root = Path::new("/repo");
        let set = parse_changed_set("src/a.c\n", root);
        assert!(path_in_changed_set(&root.join("src/a.c"), &set));
        assert!(!path_in_changed_set(&root.join("src/z.c"), &set));
    }
}
