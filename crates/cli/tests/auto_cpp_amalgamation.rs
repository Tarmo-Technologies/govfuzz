// SPDX-License-Identifier: Apache-2.0

//! #408 regression: C++ single-file (amalgamated) targets must get real edge
//! coverage from the govfuzz driver. Before the fix the C++ build linked
//! libFuzzer's own `main` and emitted no `-fsanitize-coverage` runtime, so
//! `coverage_edges` was 0 on every pass, the coverage-guided `fuzz_driven` pass
//! collapsed, govfuzz MISSED reachable bugs, and the libFuzzer-main mis-drive
//! fabricated empty-testcase findings.
//!
//! Coverage of the four acceptance criteria:
//! - AC1 (coverage>0 + live fuzz_driven): `cpp_amalgamation_reports_nonzero_coverage`
//!   and the passthrough variant.
//! - AC2 (detect the reachable bug) + AC4 (the crash testcase is non-empty):
//!   `cpp_amalgamation_detects_planted_bug_with_nonempty_testcase`.
//! - AC3 (benign => 0 findings): `cpp_amalgamation_benign_target_reports_no_findings`.
//! - passthrough arm compiles + instruments: `cpp_passthrough_libfuzzer_amalgamation_reports_nonzero_coverage`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

/// True when this host can build a C++ sanitizer target the way `govfuzz auto`
/// does: clang++ present and a libstdc++ the linker can find. We deliberately do
/// NOT probe `-fsanitize=fuzzer` — the #408 fix drives the C++ harness WITHOUT
/// libFuzzer's main, so a fuzzer-runtime gate would wrongly skip on hosts where
/// the fix works. When this is true, a failed build is a real regression, not a
/// toolchain gap, so the tests assert rather than skip.
fn cpp_toolchain_capable() -> bool {
    let clang = Command::new("clang++")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let libstdcxx = support::libstdcxx_search_path_from_dirs(
        [
            "/usr/lib/gcc/x86_64-linux-gnu/14",
            "/usr/lib/gcc/x86_64-linux-gnu/13",
            "/usr/lib/gcc/x86_64-linux-gnu/12",
            "/usr/lib/gcc/aarch64-linux-gnu/14",
            "/usr/lib/gcc/aarch64-linux-gnu/13",
            "/usr/lib/gcc/aarch64-linux-gnu/12",
        ]
        .into_iter()
        .map(Path::new),
    )
    .is_some();
    clang && libstdcxx
}

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-cpp-amalg-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// A benign single-file C++ "amalgamation": one free function with a clear
/// 4-byte magic branch (so the edge bitmap is non-trivial) and NO memory bug.
const BENIGN_AMALGAMATION: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include <cstddef>
int amalg_parse(const char *p, unsigned long n) {
    if (n >= 4 && p[0] == 'F' && p[1] == 'U' && p[2] == 'Z' && p[3] == 'Z') {
        int s = 0;
        for (unsigned long i = 0; i < n && i < 16; i++) s += p[i];
        return s;
    }
    return (int)n;
}
"#;

/// A single-file C++ amalgamation with a REACHABLE heap-buffer-overflow: a
/// variable-length copy into a fixed 4-byte buffer. The memcpy size is
/// input-derived, so -O1 does not elide it (the #400 fixture lesson), and ASan
/// fires on any input longer than 4 bytes — trivially reachable once the engine
/// grows the input past the seeds. Before #408 (coverage_edges=0, libFuzzer
/// mis-drive) govfuzz missed this class of bug; now it must find it.
const BUGGY_AMALGAMATION: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include <cstddef>
#include <cstring>
int buggy_parse(const char *p, unsigned long n) {
    char *buf = new char[4];
    memcpy(buf, p, n);
    int r = buf[0] ^ buf[1];
    delete[] buf;
    return r;
}
"#;

/// A project-supplied libFuzzer entrypoint in a single .cc — exercises the
/// PASSTHROUGH arm of the driver template (target name == LLVMFuzzerTestOneInput),
/// which carries its own value-profile runtime distinct from the generated arm.
const PASSTHROUGH_LIBFUZZER: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        volatile int s = 0;
        for (size_t i = 0; i < size && i < 16; i++) s += data[i];
        return s;
    }
    return 0;
}
"#;

/// A passthrough libFuzzer target whose ASan heap-buffer-overflow only fires on
/// the FIRST input a fresh process sees (`calls == 0`), modelling the general
/// class of fault that the persistent fork-server MASKS: a crash gated on
/// accumulated per-process state (lazy-init globals, allocator / container-
/// annotation state — the jsoncpp container-overflow that motivated #416). Run
/// warm in the long-lived fork-server (`calls > 0`) the input survives and the
/// server credits its coverage; run cold in a fresh process it aborts. The
/// `size >= 8` branch is fresh edge coverage, so the engine enqueues the input —
/// which is exactly when it must re-verify it in a fresh process. The memcpy
/// size is input-derived so -O1 cannot elide it (the #400 fixture lesson).
const STATE_MASKED_PASSTHROUGH: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include <cstddef>
#include <cstring>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int calls = 0;
    int call = calls++;
    if (size >= 8) {
        if (call == 0) {
            char *buf = new char[4];
            memcpy(buf, data, size);          // heap-buffer-overflow when size > 4
            volatile char c = buf[0]; (void)c;
            delete[] buf;
        }
        volatile unsigned long s = 0;
        for (size_t i = 0; i < size; i++) s += (unsigned)data[i] * 7u;
        return (int)s;
    }
    return 0;
}
"#;

fn run_auto(root: &Path, per_target_time: &str) -> std::process::ExitStatus {
    support::govfuzz_cargo_command()
        .current_dir(root)
        .args(["auto", "src", "--per-target-time", per_target_time])
        .status()
        .expect("run govfuzz auto")
}

fn read_run_json(root: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(root.join("govfuzz_work/auto/run.json")).unwrap()).unwrap()
}

fn built_target(run_json: &serde_json::Value) -> serde_json::Value {
    run_json["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed"))
        .cloned()
        .unwrap_or_else(|| panic!("C++ target did not build+fuzz: {run_json}"))
}

#[test]
fn cpp_amalgamation_reports_nonzero_coverage() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("cov");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("amalg.cpp"), BENIGN_AMALGAMATION).unwrap();

    let status = run_auto(&root, "3");
    assert!(status.success() || status.code() == Some(1));

    // On a capable toolchain the C++ amalgamation MUST build+fuzz — if it does
    // not, that is a #408 regression, not a skip.
    let built = built_target(&read_run_json(&root));
    let passes = built["outcome"]["passes"].as_array().expect("passes array");
    // #408 AC1: the engine must see non-zero edge coverage on a C++ amalgamation
    // (was 0 every pass), and the coverage-guided fuzz_driven pass must run.
    let max_edges = passes
        .iter()
        .filter_map(|p| p["coverage_edges"].as_u64())
        .max()
        .unwrap_or(0);
    assert!(
        max_edges > 0,
        "C++ amalgamation coverage_edges must be > 0 (#408): {built}"
    );
    let fuzz_driven = passes
        .iter()
        .find(|p| p["pass"].as_str() == Some("fuzz_driven"))
        .expect("fuzz_driven pass present");
    assert!(
        fuzz_driven["executions"].as_u64().unwrap_or(0) > 0,
        "fuzz_driven (coverage-guided) pass must execute on a C++ amalgamation: {built}"
    );
}

#[test]
fn cpp_amalgamation_detects_planted_bug_with_nonempty_testcase() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("bug");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("buggy.cpp"), BUGGY_AMALGAMATION).unwrap();

    let status = run_auto(&root, "8");
    assert!(status.success() || status.code() == Some(1));

    let run_json = read_run_json(&root);
    let _ = built_target(&run_json);
    // #408 AC2: with real coverage restored, the reachable heap-overflow must be
    // FOUND (it was missed when C++ coverage was 0). The OOB triggers on any
    // input > 4 bytes, so the coverage-guided cascade reaches it well within the
    // budget.
    let findings = run_json["summary"]["findings"].as_u64().unwrap_or(0);
    assert!(
        findings > 0,
        "govfuzz must detect the reachable C++ heap-overflow (#408 AC2): {run_json}"
    );
    // #408 AC4 (the real intent): a genuine crash must carry a NON-EMPTY
    // reproducing testcase — never the empty-testcase artifact the broken driver
    // used to fabricate. Every emitted finding's testcase must be non-empty.
    let findings_dir = root.join("govfuzz_work/findings");
    let mut checked = 0usize;
    for entry in fs::read_dir(&findings_dir).expect("findings dir exists once a bug is found") {
        let tc = entry.unwrap().path().join("testcase.bin");
        if let Ok(meta) = fs::metadata(&tc) {
            assert!(
                meta.len() > 0,
                "crash finding emitted an EMPTY testcase (#408 FP regression): {}",
                tc.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "expected at least one finding with a testcase.bin"
    );
}

#[test]
fn cpp_amalgamation_benign_target_reports_no_findings() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("benign");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("amalg.cpp"), BENIGN_AMALGAMATION).unwrap();

    let status = run_auto(&root, "3");
    assert!(status.success() || status.code() == Some(1));

    // #408 AC3: a benign C++ amalgamation (no memory error) must yield ZERO
    // findings — no spurious GF-206 from a mis-driven libFuzzer binary. This
    // assertion always runs (unlike a findings-dir scan, which is vacuous when
    // no findings are emitted).
    let run_json = read_run_json(&root);
    let _ = built_target(&run_json);
    assert_eq!(
        run_json["summary"]["findings"].as_u64().unwrap_or(0),
        0,
        "benign C++ amalgamation must produce no findings (#408 AC3): {run_json}"
    );
}

#[test]
fn cpp_passthrough_libfuzzer_amalgamation_reports_nonzero_coverage() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("passthrough");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // A project-supplied LLVMFuzzerTestOneInput selects the passthrough arm of
    // the driver template — its own runtime block, never compiled by the
    // generated-arm tests above. This is the compile-and-instrument guard.
    fs::write(src.join("fuzz.cc"), PASSTHROUGH_LIBFUZZER).unwrap();

    let status = run_auto(&root, "3");
    assert!(status.success() || status.code() == Some(1));

    let built = built_target(&read_run_json(&root));
    let passes = built["outcome"]["passes"].as_array().expect("passes array");
    let max_edges = passes
        .iter()
        .filter_map(|p| p["coverage_edges"].as_u64())
        .max()
        .unwrap_or(0);
    assert!(
        max_edges > 0,
        "passthrough C++ libFuzzer amalgamation coverage_edges must be > 0 (#408): {built}"
    );
}

/// First `<root>/<id>/<name>` in the govfuzz_work layout (one `<id>` subdir).
fn find_named(root: &Path, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()?.flatten() {
        let candidate = entry.path().join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn fork_server_state_masked_crash_is_caught_by_fresh_reverify() {
    // #416: the persistent fork-server ran a crashing input, credited its
    // coverage, enqueued it, and reported 0 findings — because the warm process
    // masked a per-process-state-gated ASan abort that a fresh process detects.
    // The engine now re-verifies every coverage-novel fork-server input in a
    // fresh per-spawn process, so the masked crash becomes a finding and the
    // crashing input is kept OUT of the clean coverage corpus.
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("masked");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("fuzz.cc"), STATE_MASKED_PASSTHROUGH).unwrap();

    let status = run_auto(&root, "8");
    assert!(status.success() || status.code() == Some(1));

    let run_json = read_run_json(&root);
    let _ = built_target(&run_json); // must build+fuzz on a capable host

    // AC1/AC2: the masked ASan abort MUST surface as a finding — pre-#416 the
    // fork-server `Ran` path silently dropped it (findings == 0 while the same
    // input sat coverage-credited in the corpus).
    let findings = run_json["summary"]["findings"].as_u64().unwrap_or(0);
    assert!(
        findings > 0,
        "fork-server-masked ASan crash must be reported as a finding (#416): {run_json}"
    );

    // AC2: every crash finding carries a real, non-empty reproducing testcase.
    let findings_dir = root.join("govfuzz_work/findings");
    let mut crash_inputs: Vec<Vec<u8>> = Vec::new();
    for entry in fs::read_dir(&findings_dir).expect("findings dir exists once a crash is found") {
        let tc = entry.unwrap().path().join("testcase.bin");
        if let Ok(bytes) = fs::read(&tc) {
            assert!(
                !bytes.is_empty(),
                "crash finding emitted an EMPTY testcase: {}",
                tc.display()
            );
            crash_inputs.push(bytes);
        }
    }
    assert!(
        !crash_inputs.is_empty(),
        "expected at least one finding testcase.bin"
    );

    // The engine's OWN built binary must abort on the reported testcase in a
    // fresh process — the exact evidence from the issue (the engine missed a
    // crash that its own build detects standalone).
    let main =
        find_named(&root.join("govfuzz_work/harnesses"), "main").expect("built harness binary");
    let mut reproduced = false;
    for (i, bytes) in crash_inputs.iter().enumerate() {
        let input_path = root.join(format!("repro-{i}.bin"));
        fs::write(&input_path, bytes).unwrap();
        let out = Command::new(&main)
            .arg(&input_path)
            .env("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0")
            .env("DEBUGINFOD_URLS", "")
            .output()
            .expect("run built harness standalone");
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && stderr.contains("AddressSanitizer") {
            reproduced = true;
        }
    }
    assert!(
        reproduced,
        "the reported testcase must abort the engine's own binary standalone (#416)"
    );

    // AC3: the crashing input must NOT linger in the clean coverage corpus — it
    // is a finding, not a benign coverage seed.
    if let Some(queue) = find_named(&root.join("govfuzz_work/corpus"), "queue") {
        for entry in fs::read_dir(&queue).into_iter().flatten().flatten() {
            if let Ok(bytes) = fs::read(entry.path()) {
                assert!(
                    !crash_inputs.contains(&bytes),
                    "a crashing input must not be enqueued into the clean corpus (#416 AC3): {}",
                    entry.path().display()
                );
            }
        }
    }
}
