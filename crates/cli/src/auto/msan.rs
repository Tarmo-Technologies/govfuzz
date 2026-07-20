// SPDX-License-Identifier: Apache-2.0

//! MemorySanitizer corpus replay — uninitialized-memory reads (CWE-457/908, GF-212)
//! that ASan/UBSan do not detect.
//!
//! MSan cannot be combined with ASan, so instead of a second fuzz loop govfuzz
//! builds a SEPARATE MSan-instrumented binary (`make msan`, C only — the C++ Makefile
//! has no `msan` target, and C++ MSan needs an instrumented libc++) and replays the
//! ASan pass's saved corpus through it. An input that drove a read of uninitialized
//! memory becomes a GF-212 runtime finding — so it flows through the same
//! confirmation/attestation path as any fuzz crash.
//!
//! Best-effort and FP-gated: only a report whose FAULTING frame lands in a target
//! source (not the govfuzz driver, the C runtime, or a system library) is emitted,
//! so noise from uninstrumented libc paths is dropped. Missing `make`/corpus, a
//! failed MSan build, or a C++ harness all skip cleanly.

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Cap the number of corpus inputs replayed per harness so a huge queue can't
/// stall the run; the coverage-diverse queue front is what matters for MSan.
const MAX_INPUTS: usize = 2000;

/// Replay every C harness's corpus through its MSan build, writing a GF-212 finding
/// per distinct uninitialized-read site. Returns the number of findings written.
pub fn run_msan_replay(work_dir: &Path) -> usize {
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
    // Build the MSan variant. C++ harnesses have no `msan` target -> make fails ->
    // skip. A genuine MSan build error (missing instrumented dep) also skips.
    let built = crate::command_output::output_with_timeout(
        Command::new("make").arg("msan").current_dir(hdir),
        Duration::from_secs(600),
    )
    .map(|o| o.status.success())
    .unwrap_or(false);
    let bin = hdir.join("main_msan");
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
        // The govfuzz C driver replays a single input passed as argv[1].
        let Ok(out) = crate::command_output::output_with_timeout(
            Command::new(&bin)
                .arg(&path)
                .env("MSAN_OPTIONS", "halt_on_error=1:exitcode=86:print_stats=0"),
            Duration::from_secs(30),
        ) else {
            continue;
        };
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.contains("MemorySanitizer") {
            continue;
        }
        if let Some(site) = first_target_frame(&stderr, hdir) {
            sites.insert(site);
        }
    }

    let mut written = 0usize;
    for (file, line) in sites {
        let id = format!("F-MSAN-{:04}", *index);
        *index += 1;
        if write_msan_finding(work_dir, &id, harness_id, &file, line) {
            written += 1;
        }
    }
    written
}

/// The first stack frame in an MSan report that lands in a TARGET source — not the
/// govfuzz driver (`main.c` under the harness dir), the bundled C runtime, or a
/// system library. That frame is the uninitialized read's real site; if there is
/// none (the read is purely inside uninstrumented libc), the report is dropped.
fn first_target_frame(stderr: &str, hdir: &Path) -> Option<(String, u64)> {
    let hdir_str = hdir.to_string_lossy();
    for line in stderr.lines() {
        let line = line.trim();
        if !line.starts_with('#') {
            continue;
        }
        // `#N 0x... in <symbol> <file>:<line>:<col>` — take the last whitespace token
        // as the `file:line:col` locator.
        let Some(locator) = line.split_whitespace().last() else {
            continue;
        };
        let mut parts = locator.rsplitn(3, ':');
        let _col = parts.next();
        let Some(line_no) = parts.next().and_then(|l| l.parse::<u64>().ok()) else {
            continue;
        };
        let Some(file) = parts.next() else {
            continue;
        };
        if is_noise_frame(file, &hdir_str) {
            continue;
        }
        return Some((file.to_owned(), line_no));
    }
    None
}

/// Whether a frame's file is govfuzz scaffolding, the C runtime, or a system
/// library rather than the analysed target.
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

/// Persist one MSan finding as a runtime crash (`classification: unhandled`) so the
/// confirmation join + attestation treat it like any other fuzz-found defect.
fn write_msan_finding(work: &Path, id: &str, harness_id: &str, file: &str, line: u64) -> bool {
    let dir = work.join("findings").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_owned());
    // One issue per distinct uninitialized-read site (rule + file:line), as a stable
    // 64-hex cluster key so the report collapses repeat inputs into one row.
    let cluster_key_full = hex(&Sha256::digest(format!("GF-212:{file}:{line}").as_bytes()));
    let record = json!({
        "id": id,
        "rule_id": "GF-212",
        "classification": "unhandled",
        "severity": "high",
        "harness_id": harness_id,
        "cluster_key_full": cluster_key_full,
        "target": { "name": name, "source_path": file, "line": line },
        "exception": {
            "name": "MemorySanitizer",
            "message": "use of uninitialized memory (MSan corpus replay)",
            "stack": [ { "function": "", "file": file, "line": line } ],
        },
        "oracle": { "evidence": [ { "key": "source", "value": format!("{file}:{line}") } ] },
        "analysis": { "engine": "govfuzz.dynamic.msan.replay" },
        "actionability": { "cwe": ["CWE-457"], "verdict": "likely_reachable", "confidence": "high" },
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
    fn parses_first_target_frame_skipping_scaffolding() {
        let hdir = "/w/harnesses/H-C0001";
        let report = "\
==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n\
    #0 0x55 in classify /proj/src/uninit.c:8:5\n\
    #1 0x55 in govfuzz_run_one /w/harnesses/H-C0001/main.c:44:13\n\
    #2 0x55 in main /w/harnesses/H-C0001/main.c:531:5\n\
    #3 0x7f in __libc_start_main csu/../csu/libc-start.c:360:3\n";
        assert_eq!(
            first_target_frame(report, Path::new(hdir)),
            Some(("/proj/src/uninit.c".to_owned(), 8))
        );
    }

    #[test]
    fn drops_report_with_only_system_and_driver_frames() {
        let hdir = "/w/harnesses/H-C0002";
        let report = "\
==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n\
    #0 0x55 in memcpy /usr/lib/x86_64-linux-gnu/libc.so\n\
    #1 0x55 in govfuzz_run_one /w/harnesses/H-C0002/main.c:44:13\n";
        assert_eq!(first_target_frame(report, Path::new(hdir)), None);
    }
}
