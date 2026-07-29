// SPDX-License-Identifier: Apache-2.0

//! Which targets a `--resume` may reuse, decided per SOURCE FILE.
//!
//! A whole-tree fingerprint is the wrong granularity, because a run can
//! invalidate its own tree: fuzzing executes the target, and a target that writes
//! or rewrites a file with a source extension — a code generator, a compiler,
//! anything emitting `.c`/`.py`/`.ts` into the checkout — changes the very digest
//! the next run compares against. `--resume` then concluded "the source changed",
//! discarded every completed target and re-ran the lot; once that target had run
//! again and the file settled, the run after it matched. That is the reported
//! "resume only works the second time".
//!
//! Judging each target by the file it came from makes an unrelated write harmless
//! while still re-attempting exactly the targets whose own source moved.
//!
//! Cost: ONE `HashSet` of the relative paths that are unchanged — not two maps of
//! every file. The hashes themselves come free from the fingerprint walk that
//! already ran, and are dropped as soon as the comparison is made.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct Scope {
    root: PathBuf,
    /// Relative paths whose content is identical to the previous run's record.
    unchanged: HashSet<String>,
    changed: usize,
    /// No previous record at all (first run over this work dir).
    had_prior: bool,
}

static SCOPE: Mutex<Option<Scope>> = Mutex::new(None);

/// Compare this run's per-file hashes against the previous run's record and keep
/// only the verdict. `prior_text` is the `<hex>\t<path>` record written last run.
pub(crate) fn publish(root: &Path, prior_text: &str, current: &[(String, u64)]) {
    let mut prior: HashSet<&str> = HashSet::with_capacity(current.len());
    for line in prior_text.lines() {
        prior.insert(line);
    }
    let mut unchanged = HashSet::with_capacity(current.len());
    for (rel, hash) in current {
        if prior.contains(format!("{hash:016x}\t{rel}").as_str()) {
            unchanged.insert(rel.clone());
        }
    }
    let changed = current.len().saturating_sub(unchanged.len());
    if let Ok(mut slot) = SCOPE.lock() {
        *slot = Some(Scope {
            root: root.to_path_buf(),
            unchanged,
            changed,
            had_prior: !prior_text.is_empty(),
        });
    }
}

/// Whether `source_path` is byte-identical to the previous run's record. `true`
/// when no scope was published (no cache configured), leaving the caller's other
/// guards in charge.
pub(crate) fn file_unchanged(source_path: &Path) -> bool {
    let Ok(slot) = SCOPE.lock() else {
        return false;
    };
    let Some(scope) = slot.as_ref() else {
        return true;
    };
    if !scope.had_prior {
        return false;
    }
    let relative = source_path
        .strip_prefix(&scope.root)
        .unwrap_or(source_path)
        .to_string_lossy();
    scope.unchanged.contains(relative.as_ref())
}

/// How many recorded files changed since the previous run, for reporting.
pub(crate) fn changed_file_count() -> usize {
    SCOPE
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().filter(|s| s.had_prior).map(|s| s.changed))
        .unwrap_or(0)
}
