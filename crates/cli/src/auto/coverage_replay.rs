// SPDX-License-Identifier: Apache-2.0

//! C/C++ line coverage for negative fuzz-confirmation.
//!
//! The interpreted lanes get executed-line sets for free from their tracers; the
//! compiled lanes don't. This builds a source-based-coverage variant of the harness
//! (`make cov` — clang `-fprofile-instr-generate -fcoverage-mapping`), replays the
//! fuzz corpus through it (each input a fresh process, so the profile flushes on
//! exit), merges the profiles with `llvm-profdata`, and exports the covered
//! `(file, line)` set with `llvm-cov`. The set is written to the harness's
//! `covered-lines.txt` — the SAME sidecar the interpreted lanes write — so
//! `confirm::mark_fuzz_exercised_findings` marks a C/C++ static finding whose line
//! the campaign PROVABLY executed (yet never crashed) as `fuzz_exercised`.
//!
//! Best-effort: a missing `llvm-cov`/`llvm-profdata`, a failed coverage build, or an
//! empty corpus all skip cleanly. Never fatal.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const MAX_INPUTS: usize = 2000;
const REPLAY_BUDGET: Duration = Duration::from_secs(30);

/// Build + replay every C/C++ harness's corpus under source coverage, writing each
/// harness's executed `(file:line)` set to `<harness>/covered-lines.txt`. Returns the
/// number of harnesses for which a covered-lines set was written.
pub fn run_coverage_replay(work_dir: &Path) -> usize {
    let (Some(profdata), Some(cov)) = (llvm_tool("llvm-profdata"), llvm_tool("llvm-cov")) else {
        return 0; // no llvm-cov toolchain -> the interpreted-lane path still works.
    };
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return 0;
    };
    let mut wrote = 0usize;
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        if replay_one(work_dir, &hdir, &harness_id, &profdata, &cov) {
            wrote += 1;
        }
    }
    wrote
}

fn replay_one(work_dir: &Path, hdir: &Path, harness_id: &str, profdata: &str, cov: &str) -> bool {
    if !hdir.join("Makefile").is_file() {
        return false;
    }
    // Don't clobber a covered-lines set an interpreted lane already wrote.
    if hdir.join("covered-lines.txt").is_file() {
        return false;
    }
    let built = crate::command_output::output_with_timeout(
        Command::new("make").arg("cov").current_dir(hdir),
        Duration::from_secs(600),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let bin = hdir.join("main_cov");
    if !built || !bin.is_file() {
        return false;
    }
    let deadline = Instant::now() + REPLAY_BUDGET;

    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return false;
    };
    let prof_dir = hdir.join("cov_profraw");
    let _ = std::fs::remove_dir_all(&prof_dir);
    if std::fs::create_dir_all(&prof_dir).is_err() {
        return false;
    }
    let mut replayed = 0usize;
    for (i, input) in inputs.flatten().enumerate() {
        if replayed >= MAX_INPUTS || Instant::now() >= deadline {
            break;
        }
        let path = input.path();
        if !path.is_file() {
            continue;
        }
        replayed += 1;
        // Fresh process per input (argv[1]) so the profile flushes at exit.
        let completed = crate::command_output::output_with_timeout(
            replay_command(&bin).arg(&path).env(
                "LLVM_PROFILE_FILE",
                prof_dir.join(format!("cov-{i}.profraw")),
            ),
            Duration::from_secs(15),
        )
        .map(|output| !matches!(output.status.code(), Some(124 | 137)))
        .unwrap_or(false);
        if !completed {
            return false;
        }
    }
    if replayed == 0 {
        return false;
    }

    // Merge the raw profiles, then export covered lines.
    let merged = hdir.join("cov.profdata");
    let raws: Vec<std::path::PathBuf> = std::fs::read_dir(&prof_dir)
        .map(|d| {
            d.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "profraw"))
                .collect()
        })
        .unwrap_or_default();
    if raws.is_empty() {
        return false;
    }
    let merge_ok = crate::command_output::output_with_timeout(
        Command::new(profdata)
            .arg("merge")
            .arg("-sparse")
            .args(&raws)
            .arg("-o")
            .arg(&merged),
        Duration::from_secs(300),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    if !merge_ok {
        return false;
    }
    let Ok(export) = crate::command_output::output_with_timeout(
        Command::new(cov)
            .args(["export", "--format=lcov"])
            .arg(format!("-instr-profile={}", merged.display()))
            .arg(&bin),
        Duration::from_secs(300),
    ) else {
        return false;
    };
    if !export.status.success() {
        return false;
    }
    let export_text = String::from_utf8_lossy(&export.stdout);
    if export_text.contains("[govfuzz: subprocess output truncated]") {
        eprintln!(
            "govfuzz: llvm-cov output for {harness_id} exceeded the bounded capture; \
             negative-confirmation coverage is partial"
        );
    }
    let covered = parse_lcov_covered(&export_text);
    let _ = std::fs::remove_dir_all(&prof_dir);
    if covered.is_empty() {
        return false;
    }
    std::fs::write(hdir.join("covered-lines.txt"), covered.join("\n")).is_ok()
}

/// Coverage is a best-effort post-pass. Bound every replay so a target that hangs
/// after consuming its input cannot hold the complete auto campaign open.
fn replay_command(bin: &Path) -> Command {
    if which::which("timeout").is_ok() {
        let mut command = Command::new("timeout");
        command.arg("-s").arg("KILL").arg("10").arg(bin);
        command
    } else {
        Command::new(bin)
    }
}

/// Parse an LCOV export into `<file>:<line>` for each line with a non-zero hit count.
/// LCOV: `SF:<file>` opens a file section, `DA:<line>,<count>` is a line record.
fn parse_lcov_covered(lcov: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut file = String::new();
    for line in lcov.lines() {
        if line.contains("[govfuzz: subprocess output truncated]") {
            file.clear();
        } else if let Some(rest) = line.strip_prefix("SF:") {
            file = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("DA:") {
            let mut parts = rest.split(',');
            let (Some(line_no), Some(count)) = (parts.next(), parts.next()) else {
                continue;
            };
            let hit = count.trim().parse::<u64>().unwrap_or(0);
            if hit > 0 && !file.is_empty() {
                out.push(format!("{file}:{}", line_no.trim()));
            }
        }
    }
    out
}

/// Resolve an llvm tool, preferring the versioned name available in this image
/// (`llvm-cov-18`) and falling back to the unversioned one.
fn llvm_tool(base: &str) -> Option<String> {
    [format!("{base}-18"), base.to_owned()]
        .into_iter()
        .find(|name| which::which(name).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcov_export_yields_only_executed_lines() {
        let lcov = "\
TN:\n\
SF:/proj/parse.c\n\
DA:4,0\n\
DA:5,12\n\
DA:6,3\n\
end_of_record\n\
SF:/proj/other.c\n\
DA:1,0\n\
end_of_record\n";
        let covered = parse_lcov_covered(lcov);
        assert_eq!(covered, vec!["/proj/parse.c:5", "/proj/parse.c:6"]);
    }
}
