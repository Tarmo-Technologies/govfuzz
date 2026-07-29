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

/// Per-target attempt records, which live inside `harnesses/<id>/`. They are the
/// one thing in there that is NOT regenerable: recreating a record means redoing
/// the whole attempt. Wiping them with the build artifacts is what made
/// `--resume` look intermittent — a work dir produced by a different govfuzz
/// version was refreshed on the way in, so the resume that followed found
/// nothing and silently re-ran everything. Killing THAT run left records written
/// by the current binary, so the next `--resume` worked, which is exactly the
/// "works the second time" symptom.
const PRESERVED_IN_HARNESS_DIRS: &str = "result.json";

fn refresh_regenerable_state(work_dir: &Path) -> std::io::Result<()> {
    for relative in REGENERABLE_DIRECTORIES {
        let path = work_dir.join(relative);
        if *relative == "harnesses" {
            refresh_harness_dirs_preserving_records(&path)?;
            continue;
        }
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

/// Clear every generated artifact under `harnesses/` while keeping each target's
/// `result.json`. A target directory left holding only its record is inert: the
/// harness and build products are regenerated on the next attempt.
fn refresh_harness_dirs_preserving_records(harnesses: &Path) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(harnesses) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let target_dir = entry.path();
        if !target_dir.is_dir() {
            std::fs::remove_file(&target_dir)?;
            continue;
        }
        for inner in std::fs::read_dir(&target_dir)?.flatten() {
            if inner.file_name() == PRESERVED_IN_HARNESS_DIRS {
                continue;
            }
            let path = inner.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                std::fs::remove_dir_all(path)?;
            } else {
                std::fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refresh must keep every target's `result.json`. Those records are the
    /// ONLY resume state there is, and they live inside `harnesses/` alongside
    /// genuinely regenerable build products — so wiping the directory wholesale
    /// silently destroyed `--resume`. That is what made resume look intermittent:
    /// the first run after an interrupted one refreshed the work dir, found no
    /// records, and re-ran everything; killing THAT run left records written by
    /// the current binary, so the next `--resume` worked.
    #[test]
    fn a_refresh_keeps_attempt_records_and_drops_only_build_products() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        let target = work.join("harnesses/H-KEEP");
        std::fs::create_dir_all(target.join("obj")).unwrap();
        std::fs::write(target.join("result.json"), r#"{"harness_id":"H-KEEP"}"#).unwrap();
        std::fs::write(target.join("main.c"), "int main(void){return 0;}").unwrap();
        std::fs::write(target.join("obj/main.o"), b"\x7fELF").unwrap();

        refresh_regenerable_state(work).unwrap();

        assert!(
            target.join("result.json").is_file(),
            "the attempt record is not regenerable — recreating it means redoing the work"
        );
        assert!(
            !target.join("main.c").exists() && !target.join("obj").exists(),
            "generated harness and build products must still be cleared"
        );
    }

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
        std::fs::write(work.join("harnesses/H-OLD/main.c"), "stale").unwrap();
        std::fs::write(work.join("harnesses/H-OLD/result.json"), "{}").unwrap();

        assert_eq!(
            prepare(work, true).unwrap(),
            WorkStateDisposition::IncompatibleMigration
        );
        // The generated harness goes; the attempt RECORD stays. It is the only
        // resume state there is, and removing it is what made `--resume` appear
        // to work only on the second try. The caller decides what to do with a
        // record from an older build (successes are kept, failures re-attempted)
        // — but it must still be there to decide about.
        assert!(!work.join("harnesses/H-OLD/main.c").exists());
        assert!(work.join("harnesses/H-OLD/result.json").is_file());
    }
}
