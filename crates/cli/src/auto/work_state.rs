// SPDX-License-Identifier: Apache-2.0

//! Version and refresh policy for regenerable `govfuzz auto` work-directory state.
//!
//! Corpus and findings are user-valued evidence and are never removed here. Build
//! products, staged sources, generated harnesses, fake dependencies, and dialect
//! choices are derived from the current govfuzz implementation; silently reusing
//! them across a fresh run or an incompatible upgrade makes fixed code appear
//! broken and can build the wrong target.

use serde::{Deserialize, Serialize};
use std::path::Path;

const WORK_STATE_SCHEMA_VERSION: u32 = 1;
/// Bumped to 2: the force-fuzz Ada external-stub model, its rendered sources, and
/// the Ada object directory moved from per-target `repairs/` to run scope, so a
/// work dir produced by an earlier binary holds them in places this one no longer
/// reads.
pub(crate) const GENERATED_STATE_SEMANTIC_VERSION: u32 = 2;
const STATE_FILE: &str = "auto/work-state.json";

const REGENERABLE_DIRECTORIES: &[&str] = &[
    "build",
    "harnesses",
    "generated_harnesses",
    "generated_stubs",
    "fake_corba",
    "src_instrumented",
    "fuzz_runs",
    "fuzz_scratch",
    "afl_out",
    "afl_qemu_out",
    "cxx_dialects",
    // Run-level force-fuzz Ada state: the reconstructed external-library stub
    // sources and the object directory every harness shares. Both are carried
    // ACROSS targets within a run (that is the point — the project's closure and
    // its stub set are project properties, not per-target ones), so they need
    // refreshing at run scope like any other generated artifact.
    crate::build::SHARED_ADA_STUBS_DIR,
    crate::build::SHARED_ADA_OBJ_DIR,
];

const REGENERABLE_FILES: &[&str] = &[
    "c_compat.mk",
    "cxx_dialect.txt",
    crate::auto::attempt::ADA_EXTERNAL_MODEL,
    // Cached "this closure cannot be built" verdicts. Regenerable by definition,
    // and a stale one would suppress a cascade that a new binary might win.
    crate::auto::closure_memo::MEMO_FILE,
    // The run-level Ada dialect the legacy ladder settled on.
    "ada_dialect",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkStateCheckpoint {
    schema_version: u32,
    producer_version: String,
    producer_commit: String,
    generated_state_semantic_version: u32,
    disposition: WorkStateDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkStateDisposition {
    New,
    CompatibleResume,
    FreshRunRefresh,
    IncompatibleMigration,
}

impl std::fmt::Display for WorkStateDisposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::New => "new",
            Self::CompatibleResume => "compatible_resume",
            Self::FreshRunRefresh => "fresh_run_refresh",
            Self::IncompatibleMigration => "incompatible_migration",
        };
        formatter.write_str(value)
    }
}

/// Validate and, when necessary, refresh all regenerable campaign state.
///
/// A compatible explicit `--resume` is the only mode allowed to reuse generated
/// artifacts. A normal run refreshes them even under the same binary. A resume
/// from an older/semantically different producer is migrated to a fresh attempt,
/// while preserving corpus, queues, reports, and findings.
pub(crate) fn prepare(work_dir: &Path, resume: bool) -> std::io::Result<WorkStateDisposition> {
    let state_path = work_dir.join(STATE_FILE);
    let previous = std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<WorkStateCheckpoint>(&bytes).ok());
    let compatible = previous.as_ref().is_some_and(is_compatible);
    let has_regenerable = regenerable_state_exists(work_dir);

    let disposition = if resume && compatible {
        WorkStateDisposition::CompatibleResume
    } else if previous.is_none() && !has_regenerable {
        WorkStateDisposition::New
    } else if compatible {
        refresh_regenerable_state(work_dir)?;
        WorkStateDisposition::FreshRunRefresh
    } else {
        refresh_regenerable_state(work_dir)?;
        WorkStateDisposition::IncompatibleMigration
    };

    let checkpoint = WorkStateCheckpoint {
        schema_version: WORK_STATE_SCHEMA_VERSION,
        producer_version: crate::auto::bug_report::version().to_owned(),
        producer_commit: crate::auto::bug_report::commit().to_owned(),
        generated_state_semantic_version: GENERATED_STATE_SEMANTIC_VERSION,
        disposition,
    };
    let bytes = serde_json::to_vec(&checkpoint).map_err(std::io::Error::other)?;
    crate::auto::report::atomic_write(&state_path, &bytes)?;
    Ok(disposition)
}

fn is_compatible(state: &WorkStateCheckpoint) -> bool {
    state.schema_version == WORK_STATE_SCHEMA_VERSION
        && state.generated_state_semantic_version == GENERATED_STATE_SEMANTIC_VERSION
        && state.producer_version == crate::auto::bug_report::version()
        && state.producer_commit == crate::auto::bug_report::commit()
}

fn regenerable_state_exists(work_dir: &Path) -> bool {
    REGENERABLE_DIRECTORIES
        .iter()
        .chain(REGENERABLE_FILES)
        .any(|relative| work_dir.join(relative).exists())
}

fn refresh_regenerable_state(work_dir: &Path) -> std::io::Result<()> {
    for relative in REGENERABLE_DIRECTORIES {
        let path = work_dir.join(relative);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::remove_dir_all(path)?;
            }
            Ok(_) => std::fs::remove_file(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    for relative in REGENERABLE_FILES {
        let path = work_dir.join(relative);
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_run_refreshes_generated_state_but_preserves_corpus_and_findings() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        assert_eq!(prepare(work, false).unwrap(), WorkStateDisposition::New);

        std::fs::create_dir_all(work.join("src_instrumented")).unwrap();
        std::fs::write(work.join("src_instrumented/stale.ads"), "stale").unwrap();
        std::fs::write(work.join("cxx_dialect.txt"), "gnu++03").unwrap();
        std::fs::create_dir_all(work.join("corpus/H-ONE")).unwrap();
        std::fs::write(work.join("corpus/H-ONE/seed"), b"seed").unwrap();
        std::fs::create_dir_all(work.join("findings/F-ONE")).unwrap();

        assert_eq!(
            prepare(work, false).unwrap(),
            WorkStateDisposition::FreshRunRefresh
        );
        assert!(!work.join("src_instrumented").exists());
        assert!(!work.join("cxx_dialect.txt").exists());
        assert!(work.join("corpus/H-ONE/seed").is_file());
        assert!(work.join("findings/F-ONE").is_dir());
    }

    #[test]
    fn compatible_resume_keeps_generated_state() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        prepare(work, false).unwrap();
        std::fs::create_dir_all(work.join("generated_harnesses/H-ONE")).unwrap();
        std::fs::write(work.join("generated_harnesses/H-ONE/main.adb"), "current").unwrap();

        assert_eq!(
            prepare(work, true).unwrap(),
            WorkStateDisposition::CompatibleResume
        );
        assert!(work.join("generated_harnesses/H-ONE/main.adb").is_file());
    }

    #[test]
    fn incompatible_resume_migrates_generated_state() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        prepare(work, false).unwrap();
        let state_path = work.join(STATE_FILE);
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state["generated_state_semantic_version"] = serde_json::json!(999);
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        std::fs::create_dir_all(work.join("harnesses/H-OLD")).unwrap();

        assert_eq!(
            prepare(work, true).unwrap(),
            WorkStateDisposition::IncompatibleMigration
        );
        assert!(!work.join("harnesses/H-OLD").exists());
    }
}
