// SPDX-License-Identifier: Apache-2.0

//! `auto --differential A:B` post-pass — two-compiler differential fuzzing.
//!
//! After the normal run builds and fuzzes each C/C++ target, this rebuilds the
//! SAME harness source under a second compiler (e.g. `clang` and `gcc`) via the
//! portable `make diff` target, then replays the fuzz corpus through both
//! binaries and flags any input on which the two builds' exit/crash behavior
//! diverges — a codegen- or UB-dependent bug one compiler exposes and the other
//! hides. Each distinct divergence becomes a GF-301 finding, so it flows through
//! the same report/confirmation path as any fuzz crash.
//!
//! Comparison is on **exit status** (including crash signals and timeout), not
//! stdout: govfuzz harnesses suppress the target's stdout under the fork-server
//! driver, so exit divergence is the reliable signal. (The standalone `govfuzz
//! differential` subcommand compares stdout for arbitrary user harnesses.)
//!
//! Best-effort: a harness whose second-compiler build fails (a flag the other
//! compiler rejects, a dialect mismatch) is logged and skipped. Missing
//! `make`/corpus skips cleanly.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Cap corpus inputs replayed per harness so a huge queue can't stall the run.
const MAX_INPUTS: usize = 2000;
/// Cap distinct divergence findings per harness.
const MAX_FINDINGS_PER_HARNESS: usize = 10;
/// Per-input, per-side replay timeout.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(5);

/// Two compilers to build each C/C++ harness under, parsed from `A:B`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialSpec {
    pub cc_a: String,
    pub cxx_a: String,
    pub cc_b: String,
    pub cxx_b: String,
}

/// Parse a `--differential A:B` spec (two C-compiler names). The C++ counterpart
/// is derived (`clang`→`clang++`, `gcc`→`g++`, `cc`→`c++`, otherwise unchanged).
pub fn parse_spec(spec: &str) -> Result<DifferentialSpec, String> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 2 || parts[0].trim().is_empty() || parts[1].trim().is_empty() {
        return Err(format!(
            "invalid --differential spec {spec:?}; expected two compilers like `clang:gcc`"
        ));
    }
    let a = parts[0].trim();
    let b = parts[1].trim();
    if a == b {
        return Err(format!(
            "--differential spec {spec:?} names the same compiler twice; use two different ones"
        ));
    }
    Ok(DifferentialSpec {
        cc_a: a.to_owned(),
        cxx_a: cxx_for(a),
        cc_b: b.to_owned(),
        cxx_b: cxx_for(b),
    })
}

fn cxx_for(cc: &str) -> String {
    match cc {
        "clang" => "clang++".to_owned(),
        "gcc" => "g++".to_owned(),
        "cc" => "c++".to_owned(),
        other => other.to_owned(),
    }
}

/// Run the differential post-pass over every C/C++ harness. Returns the number
/// of GF-301 findings written.
pub fn run_differential(work_dir: &Path, spec: &DifferentialSpec) -> usize {
    let Ok(harnesses) = std::fs::read_dir(work_dir.join("harnesses")) else {
        return 0;
    };
    let mut written = 0usize;
    let mut index = 0usize;
    for entry in harnesses.flatten() {
        let hdir = entry.path();
        let Some(harness_id) = hdir
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        written += differential_one(work_dir, &hdir, &harness_id, spec, &mut index);
    }
    written
}

fn differential_one(
    work_dir: &Path,
    hdir: &Path,
    harness_id: &str,
    spec: &DifferentialSpec,
    index: &mut usize,
) -> usize {
    if !hdir.join("Makefile").is_file() {
        return 0;
    }
    let is_cpp = hdir.join("main.cpp").is_file();
    // Only C/C++ harnesses have the `diff` Makefile target.
    if !is_cpp && !hdir.join("main.c").is_file() {
        return 0;
    }

    let bin_a = match build_side(hdir, is_cpp, &spec.cc_a, &spec.cxx_a, "a") {
        Some(bin) => bin,
        None => {
            gfeprintln!(
                "govfuzz auto: differential — {harness_id}: build under {} failed; skipping",
                if is_cpp { &spec.cxx_a } else { &spec.cc_a }
            );
            return 0;
        }
    };
    let bin_b = match build_side(hdir, is_cpp, &spec.cc_b, &spec.cxx_b, "b") {
        Some(bin) => bin,
        None => {
            gfeprintln!(
                "govfuzz auto: differential — {harness_id}: build under {} failed; skipping",
                if is_cpp { &spec.cxx_b } else { &spec.cc_b }
            );
            return 0;
        }
    };

    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return 0;
    };
    // One record per distinct (exit_a, exit_b) divergence; keep the first input
    // that produced it so the finding is reproducible.
    let mut divergences: BTreeMap<(i32, bool, i32, bool), PathBuf> = BTreeMap::new();
    let mut replayed = 0usize;
    for input in inputs.flatten() {
        if replayed >= MAX_INPUTS || divergences.len() >= MAX_FINDINGS_PER_HARNESS {
            break;
        }
        let path = input.path();
        if !path.is_file() {
            continue;
        }
        replayed += 1;
        let a = run_one(&bin_a, &path);
        let b = run_one(&bin_b, &path);
        if a.exit != b.exit || a.timed_out != b.timed_out {
            divergences
                .entry((a.exit, a.timed_out, b.exit, b.timed_out))
                .or_insert(path);
        }
    }

    let mut written = 0usize;
    for ((exit_a, to_a, exit_b, to_b), input) in divergences {
        let id = format!("F-DIFF-{:04}", *index);
        *index += 1;
        let side_a = if is_cpp { &spec.cxx_a } else { &spec.cc_a };
        let side_b = if is_cpp { &spec.cxx_b } else { &spec.cc_b };
        if write_finding(
            work_dir, &id, harness_id, side_a, side_b, exit_a, to_a, exit_b, to_b, &input,
        ) {
            written += 1;
        }
    }
    written
}

/// Build the `main_diff` target under a specific compiler and copy it to a
/// side-tagged path (`main_diff.<tag>`). Returns the binary path on success.
fn build_side(hdir: &Path, is_cpp: bool, cc: &str, cxx: &str, tag: &str) -> Option<PathBuf> {
    let mut cmd = Command::new("make");
    cmd.arg("-B").arg("diff").current_dir(hdir);
    if is_cpp {
        cmd.arg(format!("DIFF_CXX={cxx}"));
    } else {
        cmd.arg(format!("DIFF_CC={cc}"));
    }
    let ok = crate::command_output::output_with_timeout(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let produced = hdir.join("main_diff");
    if !ok || !produced.is_file() {
        return None;
    }
    let tagged = hdir.join(format!("main_diff.{tag}"));
    if std::fs::copy(&produced, &tagged).is_err() {
        return None;
    }
    Some(tagged)
}

struct Run {
    exit: i32,
    timed_out: bool,
}

/// Replay a single input through a harness binary (input path as argv[1]),
/// suppressing stdout/stderr, with a hard timeout. Returns its exit status.
fn run_one(bin: &Path, input: &Path) -> Run {
    let child = Command::new(bin)
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        // A binary that will not even spawn is treated as a hard error exit so a
        // side that cannot run at all still registers as different from one that does.
        Err(_) => {
            return Run {
                exit: -3,
                timed_out: false,
            }
        }
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Run {
                    exit: exit_code(&status),
                    timed_out: false,
                }
            }
            Ok(None) => {
                if start.elapsed() >= REPLAY_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Run {
                        exit: -1,
                        timed_out: true,
                    };
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                return Run {
                    exit: -2,
                    timed_out: false,
                }
            }
        }
    }
}

/// Exit code, mapping a fatal signal to `128 + signo` (so SIGSEGV=139, SIGABRT=134).
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    -2
}

#[allow(clippy::too_many_arguments)]
fn write_finding(
    work: &Path,
    id: &str,
    harness_id: &str,
    side_a: &str,
    side_b: &str,
    exit_a: i32,
    to_a: bool,
    exit_b: i32,
    to_b: bool,
    input: &Path,
) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    // Preserve the reproducing input alongside the finding.
    if let Ok(bytes) = std::fs::read(input) {
        let _ = std::fs::write(dir.join("testcase.bin"), &bytes);
    }
    let a_desc = describe(exit_a, to_a);
    let b_desc = describe(exit_b, to_b);
    let message =
        format!("differential: {side_a} -> {a_desc}, {side_b} -> {b_desc} on the same input");
    // One issue per distinct (harness, divergence shape) so repeat inputs collapse.
    let cluster_key_full = hex(&Sha256::digest(
        format!("GF-301:{harness_id}:{exit_a}:{to_a}:{exit_b}:{to_b}").as_bytes(),
    ));
    let record = json!({
        "id": id,
        "rule_id": "GF-301",
        "classification": "divergence",
        "severity": "medium",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": harness_id, "source_path": harness_id, "line": 0 },
        "exception": { "name": "OUTPUT_DIVERGENCE", "message": message },
        "differential": {
            "compiler_a": side_a,
            "compiler_b": side_b,
            "exit_a": exit_a,
            "exit_b": exit_b,
            "timed_out_a": to_a,
            "timed_out_b": to_b,
        },
        "oracle": { "evidence": [
            { "key": "compilers", "value": format!("{side_a} vs {side_b}") },
            { "key": "outcome", "value": format!("{a_desc} vs {b_desc}") },
        ] },
        "analysis": { "engine": "govfuzz.dynamic.differential.replay" },
        "actionability": { "cwe": ["CWE-758"], "verdict": "likely_reachable", "confidence": "medium" },
    });
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
}

fn describe(exit: i32, timed_out: bool) -> String {
    if timed_out {
        return "hung (timeout)".to_owned();
    }
    match exit {
        0 => "exit 0".to_owned(),
        139 => "SIGSEGV".to_owned(),
        134 => "SIGABRT".to_owned(),
        132 => "SIGILL".to_owned(),
        136 => "SIGFPE".to_owned(),
        c if c > 128 => format!("signal {}", c - 128),
        c => format!("exit {c}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spec_splits_and_derives_cxx() {
        let s = parse_spec("clang:gcc").unwrap();
        assert_eq!(s.cc_a, "clang");
        assert_eq!(s.cxx_a, "clang++");
        assert_eq!(s.cc_b, "gcc");
        assert_eq!(s.cxx_b, "g++");
    }

    #[test]
    fn parse_spec_rejects_malformed_and_identical() {
        assert!(parse_spec("clang").is_err());
        assert!(parse_spec("clang:").is_err());
        assert!(parse_spec(":gcc").is_err());
        assert!(
            parse_spec("gcc:gcc").is_err(),
            "same compiler twice is useless"
        );
    }

    #[test]
    fn cxx_for_maps_known_and_passes_through() {
        assert_eq!(cxx_for("clang"), "clang++");
        assert_eq!(cxx_for("gcc"), "g++");
        assert_eq!(cxx_for("cc"), "c++");
        assert_eq!(cxx_for("clang-17"), "clang-17");
    }

    #[test]
    fn describe_names_signals_and_exits() {
        assert_eq!(describe(0, false), "exit 0");
        assert_eq!(describe(139, false), "SIGSEGV");
        assert_eq!(describe(134, false), "SIGABRT");
        assert_eq!(describe(3, false), "exit 3");
        assert_eq!(describe(0, true), "hung (timeout)");
    }
}
