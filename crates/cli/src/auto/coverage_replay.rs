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

/// Aggregate coverage across the harnesses a replay measured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageTotals {
    pub harnesses: usize,
    pub covered_lines: usize,
    pub instrumented_lines: usize,
}

impl CoverageTotals {
    /// Fraction of instrumented lines the campaign executed, or `None` when
    /// nothing was instrumented — which is a different statement from 0%, and
    /// must not be reported as one.
    pub fn fraction(&self) -> Option<f64> {
        (self.instrumented_lines > 0)
            .then(|| self.covered_lines as f64 / self.instrumented_lines as f64)
    }
}

/// Build + replay every C/C++ harness's corpus under source coverage, writing each
/// harness's executed `(file:line)` set to `<harness>/covered-lines.txt` and its
/// covered/instrumented counts to `coverage-summary.json`. Returns the totals.
pub fn run_coverage_replay(work_dir: &Path) -> CoverageTotals {
    let (Some(profdata), Some(cov)) = (llvm_tool("llvm-profdata"), llvm_tool("llvm-cov")) else {
        // no llvm-cov toolchain -> the interpreted-lane path still works.
        return CoverageTotals::default();
    };
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return CoverageTotals::default();
    };
    let mut totals = CoverageTotals::default();
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        if let Some((covered, instrumented)) =
            replay_one(work_dir, &hdir, &harness_id, &profdata, &cov)
        {
            totals.harnesses += 1;
            totals.covered_lines += covered;
            totals.instrumented_lines += instrumented;
        }
    }
    totals
}

fn replay_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    profdata: &str,
    cov: &str,
) -> Option<(usize, usize)> {
    if !hdir.join("Makefile").is_file() {
        return None;
    }
    // Don't clobber a covered-lines set an interpreted lane already wrote.
    if hdir.join("covered-lines.txt").is_file() {
        return None;
    }
    let built = crate::command_output::output_with_timeout(
        Command::new("make").arg("cov").current_dir(hdir),
        Duration::from_secs(600),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let bin = hdir.join("main_cov");
    if !built || !bin.is_file() {
        return None;
    }
    let deadline = Instant::now() + REPLAY_BUDGET;

    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return None;
    };
    let prof_dir = hdir.join("cov_profraw");
    let _ = std::fs::remove_dir_all(&prof_dir);
    if std::fs::create_dir_all(&prof_dir).is_err() {
        return None;
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
            return None;
        }
    }
    if replayed == 0 {
        return None;
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
        return None;
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
        return None;
    }
    let Ok(export) = crate::command_output::output_with_timeout(
        Command::new(cov)
            .args(["export", "--format=lcov"])
            .arg(format!("-instr-profile={}", merged.display()))
            .arg(&bin),
        Duration::from_secs(300),
    ) else {
        return None;
    };
    if !export.status.success() {
        return None;
    }
    let export_text = String::from_utf8_lossy(&export.stdout);
    if export_text.contains("[govfuzz: subprocess output truncated]") {
        gfeprintln!(
            "govfuzz: llvm-cov output for {harness_id} exceeded the bounded capture; \
             negative-confirmation coverage is partial"
        );
    }
    let (covered, instrumented) = parse_lcov(&export_text);
    let _ = std::fs::remove_dir_all(&prof_dir);
    if covered.is_empty() {
        return None;
    }
    // The denominator, next to the covered set. `1,400 lines covered` says
    // nothing without knowing whether the target has 2,000 or 200,000; the
    // zero-hit `DA:` records that carry it are dropped from the covered set, so
    // the count is recorded here, at the only place that sees them.
    let _ = std::fs::write(
        hdir.join("coverage-summary.json"),
        format!(
            "{{\n  \"harness_id\": \"{harness_id}\",\n  \"covered_lines\": {},\n  \
             \"instrumented_lines\": {instrumented}\n}}\n",
            covered.len()
        ),
    );
    std::fs::write(hdir.join("covered-lines.txt"), covered.join("\n"))
        .ok()
        .map(|()| (covered.len(), instrumented))
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

/// Parse an LCOV export into the covered `<file>:<line>` set plus the number of
/// lines INSTRUMENTED — every `DA:` record, hit or not.
///
/// LCOV: `SF:<file>` opens a file section, `DA:<line>,<count>` is a line record.
///
/// Without the second number a coverage figure has no denominator: "1,400 lines"
/// is uninterpretable without knowing whether the target has 2,000 or 200,000.
/// The zero-hit records that carry it are exactly the ones the covered set
/// drops, so they are counted here, at the only place that sees them.
fn parse_lcov(lcov: &str) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut instrumented = 0usize;
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
            if file.is_empty() {
                continue;
            }
            instrumented += 1;
            let hit = count.trim().parse::<u64>().unwrap_or(0);
            if hit > 0 {
                out.push(format!("{file}:{}", line_no.trim()));
            }
        }
    }
    (out, instrumented)
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
        let (covered, instrumented) = parse_lcov(lcov);
        assert_eq!(covered, vec!["/proj/parse.c:5", "/proj/parse.c:6"]);
        // The denominator counts every instrumented line, including the zero-hit
        // records the covered set drops. Without it, "2 lines covered" cannot be
        // turned into a coverage figure.
        assert_eq!(
            instrumented, 4,
            "all four DA records are instrumented lines, hit or not"
        );
    }

    #[test]
    fn a_wholly_unexecuted_file_still_contributes_to_the_denominator() {
        // The pathological case the old covered-only parse hid: a target whose
        // corpus reached nothing at all reported an empty set and no scale, so
        // "0 lines" and "no coverage build" were indistinguishable.
        let lcov = "\
TN:\n\
SF:/proj/never.c\n\
DA:1,0\n\
DA:2,0\n\
DA:3,0\n\
end_of_record\n";
        let (covered, instrumented) = parse_lcov(lcov);
        assert!(covered.is_empty());
        assert_eq!(instrumented, 3);
    }

    #[test]
    fn a_fraction_needs_a_denominator() {
        // "0%" and "nothing was instrumented" are different statements, and
        // reporting the second as the first is how a broken coverage build gets
        // mistaken for a target the fuzzer failed to reach.
        let nothing = CoverageTotals::default();
        assert_eq!(nothing.fraction(), None);

        let measured = CoverageTotals {
            harnesses: 2,
            covered_lines: 589,
            instrumented_lines: 2458,
        };
        let fraction = measured.fraction().expect("instrumented lines present");
        assert!((fraction - 0.2396).abs() < 0.001, "got {fraction}");
    }
}
