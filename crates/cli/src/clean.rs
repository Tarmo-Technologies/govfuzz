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
        eprintln!("work directory not found: {}", args.work_dir.display());
        return 3;
    }

    let targets = clean_targets(&args);
    if targets.is_empty() {
        println!("no clean scope selected");
        return 0;
    }

    for relative in targets {
        let path = args.work_dir.join(relative);
        match remove_owned_path(&path) {
            Ok(RemoveOutcome::Removed) => println!("removed {}", path.display()),
            Ok(RemoveOutcome::Missing) => {}
            Err(error) => {
                eprintln!("clean {}: {error}", path.display());
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
            "harnesses",
            "generated_harnesses",
            "generated_stubs",
            "fake_corba",
            "src_instrumented",
            "findings",
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
