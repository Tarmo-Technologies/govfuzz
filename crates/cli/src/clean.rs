// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct CleanArgs {
    /// Path to the govfuzz work directory.
    pub work_dir: PathBuf,

    /// Remove build outputs.
    #[arg(long)]
    pub build: bool,

    /// Remove disposable compiler caches and scratch files while preserving
    /// findings, reports, corpora, generated harness source, result checkpoints,
    /// and final replayable harness executables.
    #[arg(long)]
    pub compact: bool,

    /// Remove corpus and queue data.
    #[arg(long)]
    pub corpus: bool,

    /// Remove generated reports.
    #[arg(long)]
    pub reports: bool,

    /// Remove findings. Findings are preserved unless this flag or --all is used.
    #[arg(long)]
    pub findings: bool,

    /// Remove all known GovFuzz-owned workdir subtrees.
    #[arg(long)]
    pub all: bool,
}

pub fn run(args: CleanArgs) -> i32 {
    if !args.work_dir.is_dir() {
        gfeprintln!("work directory not found: {}", args.work_dir.display());
        return 3;
    }

    let targets = clean_targets(&args);
    if targets.is_empty() && !args.compact {
        println!("no clean scope selected");
        return 0;
    }

    if (args.compact || args.build) && !args.all {
        match crate::auto::storage::compact_work_dir(&args.work_dir) {
            Ok(result) => println!(
                "compacted {}: reclaimed {} from {} disposable path(s); findings and replay binaries preserved",
                args.work_dir.display(),
                crate::auto::storage::human_bytes(result.reclaimed_bytes()),
                result.removed_paths,
            ),
            Err(error) => {
                gfeprintln!("compact {}: {error}", args.work_dir.display());
                return 1;
            }
        }
    }

    for relative in targets {
        let path = args.work_dir.join(relative);
        match remove_owned_path(&path) {
            Ok(RemoveOutcome::Removed) => println!("removed {}", path.display()),
            Ok(RemoveOutcome::Missing) => {}
            Err(error) => {
                gfeprintln!("clean {}: {error}", path.display());
                return 1;
            }
        }
    }

    0
}

fn clean_targets(args: &CleanArgs) -> Vec<&'static str> {
    if args.all {
        return vec![
            "build",
            "corpus",
            "queue",
            "reports",
            "auto",
            "harnesses",
            "generated_harnesses",
            "generated_stubs",
            "fake_corba",
            "src_instrumented",
            "findings",
            "FINDINGS.md",
            "findings.csv",
            "fuzz_runs",
            "fuzz_scratch",
            "afl_out",
            "afl_qemu_out",
            "capsules",
            "env-capsules",
            "events",
            "java-build-cache",
            "sbom",
            "static-scan",
            "vcs_recovery",
            "c_compat.mk",
            "cxx_dialect.txt",
            "cxx_dialects",
            "discovery-cache.json",
        ];
    }

    let mut targets = Vec::new();
    if args.build {
        targets.push("build");
    }
    if args.corpus {
        targets.push("corpus");
        targets.push("queue");
    }
    if args.reports {
        targets.push("reports");
    }
    if args.findings {
        targets.push("findings");
        targets.push("FINDINGS.md");
        targets.push("findings.csv");
        targets.push("auto/findings.csv");
    }
    targets
}

enum RemoveOutcome {
    Removed,
    Missing,
}

fn remove_owned_path(path: &Path) -> std::io::Result<RemoveOutcome> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RemoveOutcome::Missing);
        }
        Err(error) => return Err(error),
    };

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(RemoveOutcome::Removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_args(work_dir: PathBuf) -> CleanArgs {
        CleanArgs {
            work_dir,
            build: false,
            compact: false,
            corpus: false,
            reports: false,
            findings: false,
            all: true,
        }
    }

    #[test]
    fn all_includes_root_level_caches_and_auto_generated_state() {
        let args = all_args(PathBuf::from("/tmp/work"));
        let targets = clean_targets(&args);
        for expected in [
            "auto",
            "src_instrumented",
            "fake_corba",
            "generated_harnesses",
            "FINDINGS.md",
            "findings.csv",
            "c_compat.mk",
            "cxx_dialect.txt",
            "cxx_dialects",
            "discovery-cache.json",
        ] {
            assert!(
                targets.contains(&expected),
                "missing clean target {expected}"
            );
        }
    }

    #[test]
    fn all_removes_owned_files_and_directories_but_not_siblings() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let sibling = temp.path().join("source-kept");
        std::fs::create_dir_all(work.join("src_instrumented")).unwrap();
        std::fs::write(work.join("src_instrumented/stale.ads"), "stale").unwrap();
        std::fs::write(work.join("cxx_dialect.txt"), "gnu++03").unwrap();
        std::fs::write(work.join("discovery-cache.json"), "{}").unwrap();
        std::fs::write(work.join("FINDINGS.md"), "findings").unwrap();
        std::fs::write(work.join("findings.csv"), "id\n").unwrap();
        std::fs::write(&sibling, "source").unwrap();

        assert_eq!(run(all_args(work.clone())), 0);
        assert!(!work.join("src_instrumented").exists());
        assert!(!work.join("cxx_dialect.txt").exists());
        assert!(!work.join("discovery-cache.json").exists());
        assert!(!work.join("FINDINGS.md").exists());
        assert!(!work.join("findings.csv").exists());
        assert!(sibling.is_file());
    }

    #[test]
    fn compact_preserves_findings_reports_corpus_and_replay_binary() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        std::fs::create_dir_all(work.join("harnesses/H/incrate/target/debug")).unwrap();
        std::fs::create_dir_all(work.join("findings/F-1")).unwrap();
        std::fs::create_dir_all(work.join("corpus/H/queue")).unwrap();
        std::fs::create_dir_all(work.join("auto")).unwrap();
        std::fs::write(work.join("harnesses/H/incrate/target/debug/cache"), "cache").unwrap();
        std::fs::write(work.join("harnesses/H/main"), "binary").unwrap();
        std::fs::write(work.join("findings/F-1/finding.json"), "{}").unwrap();
        std::fs::write(work.join("corpus/H/queue/seed"), "seed").unwrap();
        std::fs::write(work.join("auto/run.json"), "{}").unwrap();

        assert_eq!(
            run(CleanArgs {
                work_dir: work.clone(),
                build: false,
                compact: true,
                corpus: false,
                reports: false,
                findings: false,
                all: false,
            }),
            0
        );
        assert!(!work.join("harnesses/H/incrate/target").exists());
        assert!(work.join("harnesses/H/main").is_file());
        assert!(work.join("findings/F-1/finding.json").is_file());
        assert!(work.join("corpus/H/queue/seed").is_file());
        assert!(work.join("auto/run.json").is_file());
    }

    #[test]
    fn findings_scope_removes_primary_and_compatibility_indexes() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        std::fs::create_dir_all(work.join("findings/F-1")).unwrap();
        std::fs::create_dir_all(work.join("auto")).unwrap();
        std::fs::write(work.join("findings/F-1/finding.json"), "{}").unwrap();
        std::fs::write(work.join("FINDINGS.md"), "findings").unwrap();
        std::fs::write(work.join("findings.csv"), "id\n").unwrap();
        std::fs::write(work.join("auto/findings.csv"), "id\n").unwrap();
        std::fs::write(work.join("auto/run.json"), "{}").unwrap();

        assert_eq!(
            run(CleanArgs {
                work_dir: work.clone(),
                build: false,
                compact: false,
                corpus: false,
                reports: false,
                findings: true,
                all: false,
            }),
            0
        );
        assert!(!work.join("findings").exists());
        assert!(!work.join("FINDINGS.md").exists());
        assert!(!work.join("findings.csv").exists());
        assert!(!work.join("auto/findings.csv").exists());
        assert!(work.join("auto/run.json").is_file());
    }
}
