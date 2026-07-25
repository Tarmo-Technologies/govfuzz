// SPDX-License-Identifier: Apache-2.0

//! Remember that a source's build closure could not be built, so the next target
//! in the same closure does not rediscover it from scratch.
//!
//! The repair manifest is per target and the repairs directory is wiped per
//! target, so when twenty targets live in one file — or in files sharing one
//! unbuildable dependency — the full repair cascade runs twenty times and fails
//! twenty times in exactly the same way. On a sweep with many targets per file
//! that is most of the wall clock, and none of it can change the answer.
//!
//! The correctness risk is the inverse of the saving: the project-level repair
//! state IMPROVES as a sweep runs (the shared Ada external-library model is the
//! main one), and a closure that was terminal under a poorer model can become
//! buildable under a better one. Caching a stale "no" would cap convergence,
//! which is precisely how an earlier attempt at a stall detector destroyed
//! convergence while looking like a large speedup. So the memo is keyed on a
//! fingerprint of that project state and is discarded WHOLESALE the moment it
//! moves — the memo may only ever short-circuit work that would reach the same
//! conclusion with the same inputs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use build_classifier::BuildErrorKind;
use serde::{Deserialize, Serialize};

/// File under the work dir holding the memo.
pub(crate) const MEMO_FILE: &str = "closure_failures.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct ClosureMemo {
    /// Fingerprint of the project-level repair state these verdicts were reached
    /// under. A mismatch invalidates every entry.
    #[serde(default)]
    fingerprint: String,
    /// Source path -> the terminal failure reached for it.
    #[serde(default)]
    entries: BTreeMap<String, MemoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MemoEntry {
    pub(crate) errors: Vec<BuildErrorKind>,
    pub(crate) rounds: usize,
}

impl ClosureMemo {
    /// Load the memo, discarding it if the project's repair state has moved since
    /// it was written.
    pub(crate) fn load(work_dir: &Path, force: bool) -> Self {
        let current = project_fingerprint(work_dir, force);
        let stored: Self = std::fs::read_to_string(memo_path(work_dir))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        if stored.fingerprint == current {
            stored
        } else {
            Self {
                fingerprint: current,
                entries: BTreeMap::new(),
            }
        }
    }

    /// The recorded terminal failure for this source, if the closure has already
    /// been proven unbuildable under the current project state.
    pub(crate) fn terminal_failure_for(&self, source: &Path) -> Option<&MemoEntry> {
        self.entries.get(&source.display().to_string())
    }

    /// Record a terminal failure — one reached after the repair loop ran out of
    /// things to try, not merely an early round that failed.
    ///
    /// Declines anything that is not a property of the CLOSURE. An error in the
    /// generated harness itself says nothing about the next target in the same
    /// file, and memoizing it would write off targets that build perfectly well.
    pub(crate) fn record(&mut self, source: &Path, errors: &[BuildErrorKind], rounds: usize) {
        if errors.is_empty() || !errors_are_closure_scoped(errors) {
            return;
        }
        self.entries.insert(
            source.display().to_string(),
            MemoEntry {
                errors: errors.to_vec(),
                rounds,
            },
        );
    }

    pub(crate) fn save(&self, work_dir: &Path) {
        if let Ok(bytes) = serde_json::to_vec(self) {
            let _ = std::fs::write(memo_path(work_dir), bytes);
        }
    }
}

fn memo_path(work_dir: &Path) -> PathBuf {
    work_dir.join(MEMO_FILE)
}

/// Whether every error describes the project's own closure rather than the
/// generated harness. A harness-specific failure (a parameter the driver could
/// not decode, a mistake in generated code) is particular to ONE target, so it
/// must never speak for its siblings.
fn errors_are_closure_scoped(errors: &[BuildErrorKind]) -> bool {
    const HARNESS_ARTIFACTS: [&str; 5] =
        ["main.c", "main.cpp", "main.adb", "main_afl", "gf_harness"];
    errors.iter().all(|error| match error {
        BuildErrorKind::Other { tail } => !HARNESS_ARTIFACTS
            .iter()
            .any(|artifact| tail.contains(artifact)),
        BuildErrorKind::UndeclaredFunction { file, .. } => !HARNESS_ARTIFACTS
            .iter()
            .any(|artifact| file.contains(artifact)),
        // The remaining kinds name a missing header/type/symbol/unit, which is a
        // property of what the closure needs, not of one generated driver.
        _ => true,
    })
}

/// Fingerprint of the project-level state that can change a build verdict.
///
/// Everything here is shared across targets and grows as a sweep proceeds, so a
/// change to any of it can turn a previously terminal closure buildable. The
/// fingerprint is deliberately coarse: being wrong in the direction of
/// forgetting costs a rebuild, while being wrong in the direction of remembering
/// costs a target.
fn project_fingerprint(work_dir: &Path, force: bool) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Force mode changes what counts as buildable at all.
    force.hash(&mut hasher);
    // The reconstructed external-library model: the single biggest reason a
    // closure that failed for one target succeeds for a later one.
    for relative in [
        crate::auto::attempt::ADA_EXTERNAL_MODEL,
        "c_compat.mk",
        "cxx_dialect.txt",
    ] {
        let path = work_dir.join(relative);
        match std::fs::read(&path) {
            Ok(bytes) => bytes.hash(&mut hasher),
            Err(_) => 0u8.hash(&mut hasher),
        }
    }
    // The rendered external stubs and the staged sources: both are rewritten as
    // the sweep learns more about the project.
    for relative in [
        crate::build::SHARED_ADA_STUBS_DIR,
        "src_instrumented",
        "cxx_dialects",
    ] {
        let dir = work_dir.join(relative);
        let mut names: Vec<(String, u64)> = std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| {
                        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        (entry.file_name().to_string_lossy().into_owned(), len)
                    })
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "govfuzz-closure-memo-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn missing_header(path: &str) -> BuildErrorKind {
        BuildErrorKind::MissingHeader {
            path: path.to_owned(),
        }
    }

    #[test]
    fn a_recorded_failure_is_returned_for_the_same_source() {
        let work = tmpdir("hit");
        let mut memo = ClosureMemo::load(&work, false);
        let source = Path::new("/proj/src/parse.c");
        memo.record(source, &[missing_header("absent.h")], 4);
        memo.save(&work);

        let reloaded = ClosureMemo::load(&work, false);
        let entry = reloaded
            .terminal_failure_for(source)
            .expect("the sibling target must inherit the verdict");
        assert_eq!(entry.rounds, 4);
        assert_eq!(entry.errors.len(), 1);
    }

    #[test]
    fn changing_the_project_repair_state_discards_every_verdict() {
        let work = tmpdir("invalidate");
        let mut memo = ClosureMemo::load(&work, false);
        let source = Path::new("/proj/src/parse.c");
        memo.record(source, &[missing_header("absent.h")], 4);
        memo.save(&work);

        // The sweep learns more of the external library — exactly the case where
        // a closure that could not build before now can.
        std::fs::write(
            work.join(crate::auto::attempt::ADA_EXTERNAL_MODEL),
            b"{\"packages\":{}}",
        )
        .unwrap();

        let reloaded = ClosureMemo::load(&work, false);
        assert!(
            reloaded.terminal_failure_for(source).is_none(),
            "a better model must retire the old verdict, not cap convergence with it"
        );
    }

    #[test]
    fn force_mode_does_not_share_verdicts_with_ordinary_mode() {
        let work = tmpdir("force");
        let mut memo = ClosureMemo::load(&work, false);
        let source = Path::new("/proj/src/parse.c");
        memo.record(source, &[missing_header("absent.h")], 4);
        memo.save(&work);

        let forced = ClosureMemo::load(&work, true);
        assert!(
            forced.terminal_failure_for(source).is_none(),
            "--force can build what ordinary mode cannot; its verdicts are separate"
        );
    }

    #[test]
    fn a_harness_specific_failure_is_never_memoized() {
        let work = tmpdir("harness-scoped");
        let mut memo = ClosureMemo::load(&work, false);
        let source = Path::new("/proj/src/parse.c");
        memo.record(
            source,
            &[BuildErrorKind::Other {
                tail: "main.c:42:7: error: too few arguments to function call".to_owned(),
            }],
            4,
        );
        assert!(
            memo.terminal_failure_for(source).is_none(),
            "an error in the generated driver says nothing about the next target \
             in the same file"
        );
    }

    #[test]
    fn an_empty_error_list_is_not_a_verdict() {
        let work = tmpdir("empty");
        let mut memo = ClosureMemo::load(&work, false);
        let source = Path::new("/proj/src/parse.c");
        memo.record(source, &[], 4);
        assert!(memo.terminal_failure_for(source).is_none());
    }

    #[test]
    fn a_closure_scoped_failure_survives_alongside_harness_noise_being_rejected() {
        // Mixed lists are rejected: one harness-specific error is enough to make
        // the whole verdict unsafe to generalize.
        let work = tmpdir("mixed");
        let mut memo = ClosureMemo::load(&work, false);
        let source = Path::new("/proj/src/parse.c");
        memo.record(
            source,
            &[
                missing_header("absent.h"),
                BuildErrorKind::Other {
                    tail: "main.cpp:9: error: no matching constructor".to_owned(),
                },
            ],
            4,
        );
        assert!(memo.terminal_failure_for(source).is_none());
    }
}
