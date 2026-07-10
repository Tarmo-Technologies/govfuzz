// SPDX-License-Identifier: Apache-2.0

//! ThreadSanitizer corpus replay — data races (CWE-362, GF-556) that ASan/UBSan do
//! not detect.
//!
//! TSan cannot be combined with ASan, so instead of a second fuzz loop govfuzz builds
//! a SEPARATE TSan-instrumented binary (`make tsan`, C only — the C++ Makefile has no
//! `tsan` target) and replays the ASan pass's saved corpus through it. An input that
//! drove a data race becomes a GF-556 runtime finding — so it flows through the same
//! confirmation/attestation path as any fuzz crash.
//!
//! A race only surfaces when the target itself spawns threads while processing one
//! input; a single-threaded target simply reports none, so this is best-effort and,
//! like the MSan replay, FP-gated: only a report whose FAULTING frame lands in a
//! target source (not the govfuzz driver, the C runtime, or a system library) is
//! emitted. Missing `make`/corpus, a failed TSan build, or a C++ harness all skip
//! cleanly.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// Cap the number of corpus inputs replayed per harness so a huge queue can't stall
/// the run; the coverage-diverse queue front is what matters for race detection.
const MAX_INPUTS: usize = 2000;

/// Extra attempts to re-run a single input under TSan when a run aborts
/// abnormally with no race report. Under heavy concurrent sanitizer load, TSan's
/// large shadow-memory reservation can transiently fail to map, so the process
/// aborts at init before ever running the target — losing a real race to
/// scheduling luck. Retrying the transient (not a clean no-race run) makes the
/// replay robust (regression: auto_tsan_replay flaked under the parallel suite).
const TSAN_RUN_RETRIES: usize = 4;

/// Replay every C harness's corpus through its TSan build, writing a GF-556 finding
/// per distinct data-race site. Returns the number of findings written.
pub fn run_tsan_replay(work_dir: &Path) -> usize {
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
        written += replay_one(work_dir, &hdir, &harness_id, &mut index);
    }
    written
}

fn replay_one(work_dir: &Path, hdir: &Path, harness_id: &str, index: &mut usize) -> usize {
    if !hdir.join("Makefile").is_file() {
        return 0;
    }
    // Build the TSan variant. C++ harnesses have no `tsan` target -> make fails ->
    // skip. A genuine TSan build error also skips.
    let built = Command::new("make")
        .arg("tsan")
        .current_dir(hdir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let bin = hdir.join("main_tsan");
    if !built || !bin.is_file() {
        return 0;
    }

    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let Ok(inputs) = std::fs::read_dir(&queue) else {
        return 0;
    };
    let mut sites: BTreeSet<(String, u64)> = BTreeSet::new();
    let mut replayed = 0usize;
    for input in inputs.flatten() {
        if replayed >= MAX_INPUTS {
            break;
        }
        let path = input.path();
        if !path.is_file() {
            continue;
        }
        replayed += 1;
        // The govfuzz C driver replays a single input passed as argv[1]. Retry a
        // transient TSan-init abort (abnormal exit with no "data race" report)
        // under concurrent-sanitizer load; a clean no-race run (exit 0) is a real
        // result and is not retried. See TSAN_RUN_RETRIES.
        for _ in 0..=TSAN_RUN_RETRIES {
            let Ok(out) = Command::new(&bin)
                .arg(&path)
                .env("TSAN_OPTIONS", "halt_on_error=1:exitcode=86")
                .output()
            else {
                break;
            };
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("data race") {
                if let Some(site) = first_target_frame(&stderr, hdir) {
                    sites.insert(site);
                }
                break;
            }
            // No race report: a clean exit is a genuine no-race run (stop); an
            // abnormal exit is the shadow-mapping transient (retry).
            if out.status.success() {
                break;
            }
        }
    }

    let mut written = 0usize;
    for (file, line) in sites {
        let id = format!("F-TSAN-{:04}", *index);
        *index += 1;
        if write_tsan_finding(work_dir, &id, harness_id, &file, line) {
            written += 1;
        }
    }
    written
}

/// The first stack frame in a TSan report that lands in a TARGET source — not the
/// govfuzz driver (`main.c` under the harness dir), the bundled C runtime, or a
/// system library. That frame is the race's real site; if there is none, the report
/// is dropped.
fn first_target_frame(stderr: &str, hdir: &Path) -> Option<(String, u64)> {
    let hdir_str = hdir.to_string_lossy();
    for line in stderr.lines() {
        let line = line.trim();
        if !line.starts_with('#') {
            continue;
        }
        // Unlike MSan, a TSan frame ends with `(module+0xoffset)`, so the
        // `file:line:col` locator is NOT the last token — scan every token for the
        // first that parses as a source locator.
        let Some((file, line_no)) = line.split_whitespace().find_map(parse_locator) else {
            continue;
        };
        if is_noise_frame(&file, &hdir_str) {
            continue;
        }
        return Some((file, line_no));
    }
    None
}

/// Parse a `file:line:col` (or `file:line`) locator token, rejecting the
/// `(module+0xoffset)` suffix and bare symbol names. The file part must look like a
/// source path (a `/` or a `.` extension) so a module or plain word is dropped.
fn parse_locator(token: &str) -> Option<(String, u64)> {
    let token = token.trim_matches(|c| c == '(' || c == ')');
    // Try `file:line:col`.
    let mut triple = token.rsplitn(3, ':');
    let _col = triple.next();
    if let (Some(line), Some(file)) = (triple.next(), triple.next()) {
        if let Ok(line_no) = line.parse::<u64>() {
            if looks_like_source(file) {
                return Some((file.to_owned(), line_no));
            }
        }
    }
    // Try `file:line`.
    if let Some((file, line)) = token.rsplit_once(':') {
        if let Ok(line_no) = line.parse::<u64>() {
            if looks_like_source(file) {
                return Some((file.to_owned(), line_no));
            }
        }
    }
    None
}

/// Whether a token looks like a source-file path rather than a module name or a
/// bare symbol — it contains a path separator or a filename extension dot.
fn looks_like_source(file: &str) -> bool {
    file.contains('/') || file.contains('.')
}

/// Whether a frame's file is govfuzz scaffolding, the C runtime, or a system library
/// rather than the analysed target.
fn is_noise_frame(file: &str, hdir: &str) -> bool {
    file.starts_with(hdir)
        || file.contains("/c_runtime/")
        || file.contains("govfuzz_decode")
        || file.starts_with("/usr/")
        || file.starts_with("/lib")
        || file.starts_with("/build")
        || file.contains("sysdeps")
        || file.contains("csu/")
        || file == "main.c"
}

/// Persist one TSan finding as a runtime crash (`classification: unhandled`) so the
/// confirmation join + attestation treat it like any other fuzz-found defect.
fn write_tsan_finding(work: &Path, id: &str, harness_id: &str, file: &str, line: u64) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_owned());
    // One issue per distinct data-race site (rule + file:line), as a stable 64-hex
    // cluster key so the report collapses repeat inputs into one row.
    let cluster_key_full = hex(&Sha256::digest(format!("GF-556:{file}:{line}").as_bytes()));
    let record = json!({
        "id": id,
        "rule_id": "GF-556",
        "classification": "unhandled",
        "severity": "high",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": name, "source_path": file, "line": line },
        "exception": {
            "name": "ThreadSanitizer",
            "message": "data race (TSan corpus replay)",
            "stack": [ { "function": "", "file": file, "line": line } ],
        },
        "oracle": { "evidence": [ { "key": "source", "value": format!("{file}:{line}") } ] },
        "analysis": { "engine": "govfuzz.dynamic.tsan.replay" },
        "actionability": { "cwe": ["CWE-362"], "verdict": "likely_reachable", "confidence": "high" },
    });
    std::fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )
    .is_ok()
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
    fn parses_first_target_frame_skipping_scaffolding_and_module_suffix() {
        let hdir = "/w/harnesses/H-C0001";
        // TSan frames carry a trailing `(module+0xoffset)` the parser must skip.
        let report = "\
==================\n\
WARNING: ThreadSanitizer: data race (pid=1)\n\
  Write of size 4 at 0x7b04 by thread T1:\n\
    #0 worker /proj/src/race.c:12:7 (main_tsan+0x4a1b2)\n\
    #1 govfuzz_run_one /w/harnesses/H-C0001/main.c:44:13 (main_tsan+0x1000)\n\
  Previous read of size 4 at 0x7b04 by main thread:\n\
    #0 main /w/harnesses/H-C0001/main.c:531:5 (main_tsan+0x2000)\n";
        assert_eq!(
            first_target_frame(report, Path::new(hdir)),
            Some(("/proj/src/race.c".to_owned(), 12))
        );
    }

    #[test]
    fn drops_report_with_only_system_and_driver_frames() {
        let hdir = "/w/harnesses/H-C0002";
        let report = "\
WARNING: ThreadSanitizer: data race (pid=1)\n\
    #0 memcpy /usr/lib/x86_64-linux-gnu/libc.so (libc.so+0x99)\n\
    #1 govfuzz_run_one /w/harnesses/H-C0002/main.c:44:13 (main_tsan+0x1000)\n";
        assert_eq!(first_target_frame(report, Path::new(hdir)), None);
    }

    #[test]
    fn locator_rejects_module_offset_and_bare_symbol() {
        assert_eq!(parse_locator("(main_tsan+0x4a1b2)"), None);
        assert_eq!(parse_locator("worker"), None);
        assert_eq!(
            parse_locator("/proj/src/race.c:12:7"),
            Some(("/proj/src/race.c".to_owned(), 12))
        );
        assert_eq!(
            parse_locator("/proj/src/race.c:12"),
            Some(("/proj/src/race.c".to_owned(), 12))
        );
    }
}
