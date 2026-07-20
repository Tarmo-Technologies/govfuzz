// SPDX-License-Identifier: Apache-2.0

use std::path::{Component, Path, PathBuf};
use std::process::Command;

const MAX_RECOVERED_FILES: usize = 256;
const MAX_RECOVERED_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECOVERED_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct VcsRecovery {
    pub root: PathBuf,
    pub relative_paths: Vec<PathBuf>,
}

fn repository_root(scan_path: &Path) -> Option<PathBuf> {
    let mut current = scan_path;
    loop {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if raw.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    Some(path.to_path_buf())
}

fn git_output(repo: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
}

/// Materialize tracked files deleted from the current worktree from local
/// `HEAD`, under the GovFuzz work directory. The source tree remains untouched;
/// callers index this shadow as an additional dependency root so ordinary
/// `AddIncludeDir` / `AddSource` / `AddAdaSource` repairs retain their normal
/// provenance.
pub fn materialize_deleted_tracked_files(scan_path: &Path, work_dir: &Path) -> Option<VcsRecovery> {
    let repo = repository_root(scan_path)?;
    let diff = git_output(
        &repo,
        &[
            "diff",
            "--no-renames",
            "--name-only",
            "--diff-filter=D",
            "-z",
            "HEAD",
            "--",
        ],
    )?;
    let names = diff
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .filter_map(|name| std::str::from_utf8(name).ok())
        .filter_map(safe_relative_path)
        .take(MAX_RECOVERED_FILES)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return None;
    }

    let root = work_dir.join("vcs_recovery");
    if root.exists() && std::fs::remove_dir_all(&root).is_err() {
        return None;
    }
    let mut relative_paths = Vec::new();
    let mut total_bytes = 0u64;
    for relative in names {
        let object = format!("HEAD:{}", relative.to_string_lossy().replace('\\', "/"));
        let Some(size_output) = git_output(&repo, &["cat-file", "-s", &object]) else {
            continue;
        };
        let Some(size) = std::str::from_utf8(&size_output.stdout)
            .ok()
            .and_then(|size| size.trim().parse::<u64>().ok())
        else {
            continue;
        };
        if size > MAX_RECOVERED_FILE_BYTES
            || total_bytes.saturating_add(size) > MAX_RECOVERED_TOTAL_BYTES
        {
            continue;
        }
        let Some(blob) = git_output(&repo, &["cat-file", "blob", &object]) else {
            continue;
        };
        if blob.stdout.len() as u64 != size {
            continue;
        }
        let destination = root.join(&relative);
        let Some(parent) = destination.parent() else {
            continue;
        };
        if std::fs::create_dir_all(parent).is_err()
            || std::fs::write(&destination, blob.stdout).is_err()
        {
            continue;
        }
        total_bytes += size;
        relative_paths.push(relative);
    }
    if relative_paths.is_empty() {
        let _ = std::fs::remove_dir_all(&root);
        return None;
    }
    Some(VcsRecovery {
        root,
        relative_paths,
    })
}

#[cfg(test)]
mod tests {
    use super::materialize_deleted_tracked_files;
    use std::path::Path;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("govfuzz-vcs-recovery-{unique}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn git(repo: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn deleted_tracked_file_is_recovered_only_into_work_dir() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let repo = temp_dir();
        assert!(git(&repo, &["init", "--quiet"]));
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/dependency.h"), "#define DEPENDENCY 1\n").unwrap();
        std::fs::write(
            repo.join("src/target.c"),
            "int target(void) { return 1; }\n",
        )
        .unwrap();
        assert!(git(&repo, &["add", "."]));
        assert!(git(
            &repo,
            &[
                "-c",
                "user.name=GovFuzz Test",
                "-c",
                "user.email=govfuzz@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        ));
        std::fs::remove_file(repo.join("src/dependency.h")).unwrap();
        let work = repo.join("work");

        let recovered = materialize_deleted_tracked_files(&repo, &work).unwrap();
        assert_eq!(
            recovered.relative_paths,
            vec![Path::new("src/dependency.h")]
        );
        assert_eq!(
            std::fs::read_to_string(recovered.root.join("src/dependency.h")).unwrap(),
            "#define DEPENDENCY 1\n"
        );
        assert!(!repo.join("src/dependency.h").exists());

        std::fs::remove_dir_all(repo).unwrap();
    }
}
