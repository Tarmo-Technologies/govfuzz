// SPDX-License-Identifier: Apache-2.0

//! #421 laf-intel comparison-progress: the DRIVER path's trace-cmp callbacks
//! already see every `(a, b)` operand pair (`-fsanitize-coverage=trace-cmp`).
//! Instead of a clang LLVM split pass, the driver synthesizes laf-intel's
//! gradient ENGINE-SIDE: for each compare it records, per hashed call site, this
//! exec's MAX number of matching LEADING bytes into a parallel per-exec map
//! (`GOVFUZZ_CMP_PROGRESS_SHM`). The engine folds a newly-reached leading-match
//! LEVEL into a virgin map (the same machinery as the #420 hit-count buckets) so
//! an input that gets one more byte of a multi-byte gate correct is retained and
//! energized — the gradient a whole-compare edge cannot give.
//!
//! This is the deterministic DRIVER-runtime proof: a 4-byte integer gate, run
//! standalone at two leading-match depths, must record STRICTLY more total
//! comparison-progress for the deeper-matching input. Edge presence cannot see
//! this (both inputs fail the gate and hit the same edges); only the per-site
//! leading-byte-match map can.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

/// Size (bytes) of the driver's comparison-progress map. MUST match
/// `GOVFUZZ_CMPP_BITS` in the driver templates and the `CoverageTracker` reader.
const GOVFUZZ_CMPP_BITS: usize = 1 << 16;

/// True when this host can build a C sanitizer/libFuzzer target the way
/// `govfuzz auto` does. When true, a failed build is a real regression.
fn c_toolchain_capable() -> bool {
    support::libfuzzer_toolchain_available("cmpp")
}

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-cmpp-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// A passthrough libFuzzer target whose only interesting behavior is a single
/// 4-byte integer gate against a constant. The number of matching LEADING bytes
/// of `v` against the magic is the laf-intel gradient: input `0x41,..` matches 1
/// low byte, `0x41,0x42,0x43,..` matches 3. Every non-passing input hits the same
/// edges, so edge presence is constant; only the leading-byte-match differs.
const MAGIC_GATE: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
#include <stddef.h>
#include <string.h>
/* A normal library parse entry, NOT a pre-written `LLVMFuzzerTestOneInput`:
   discovery deliberately excludes files defining the libFuzzer entry (they are
   existing/generated harnesses, not libraries to harness — see discovery.rs),
   so `govfuzz auto` would discover 0 candidates and exit non-zero. A plain
   `(const uint8_t*, size_t)` function is discovered, and govfuzz wraps it in a
   generated driver whose magic gate is what we measure. */
int magic_gate_parse(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    uint32_t v;
    memcpy(&v, data, 4);
    if (v == 0x44434241u) {            /* 'A','B','C','D' little-endian */
        volatile int sink = data[0];   /* post-gate marker (no crash needed) */
        (void)sink;
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

/// Run the built driver standalone on `input` with a FRESH comparison-progress
/// map, and return the total recorded progress (sum of per-site leading-byte-
/// match levels) for that single exec. The driver's trace-cmp runtime opens the
/// map from the env and `max`-writes each compare site's leading-byte-match.
fn standalone_progress_sum(main: &Path, work: &Path, tag: &str, input: &[u8]) -> u64 {
    let cmpp = work.join(format!("cmpp-{tag}.shm"));
    let _ = fs::remove_file(&cmpp);
    let input_path = work.join(format!("input-{tag}.bin"));
    fs::write(&input_path, input).unwrap();

    let status = Command::new(main)
        .arg(&input_path)
        .env("GOVFUZZ_CMP_PROGRESS_SHM", &cmpp)
        .env("ASAN_OPTIONS", "detect_leaks=0")
        // Defensive: never let an inherited env put the driver into framed mode.
        .env_remove("GOVFUZZ_FRAMED")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run built driver standalone");
    assert!(
        status.success(),
        "benign standalone run must exit cleanly (tag {tag})"
    );

    let bytes = fs::read(&cmpp).expect("driver must create the #421 comparison-progress map");
    assert_eq!(
        bytes.len(),
        GOVFUZZ_CMPP_BITS,
        "progress map must be GOVFUZZ_CMPP_BITS-sized"
    );
    bytes.iter().map(|&b| u64::from(b)).sum()
}

#[test]
fn comparison_progress_rewards_more_leading_bytes_matched() {
    if !c_toolchain_capable() {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let root = tmpdir("gate");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("fuzz.c"), MAGIC_GATE).unwrap();

    // 1s budget: we only need the build to produce the `main` driver binary.
    let status = run_auto(&root, "1");
    assert!(status.success() || status.code() == Some(1));

    // The built harness binary lives at `govfuzz_work/harnesses/<id>/main`
    // (`find_named` looks one level down, at `<root>/<id>/main`).
    let main = find_named(&root.join("govfuzz_work/harnesses"), "main")
        .expect("built harness binary (C toolchain capable host)");

    // Two same-length inputs differing only in how many LEADING bytes of the
    // 4-byte magic they match: `low` matches 1 (byte0='A'), `high` matches 3
    // (bytes 0..3 = 'A','B','C'). Same length => identical harness-internal
    // compare behavior, so the ONLY differing recorded site is the magic gate.
    let low = standalone_progress_sum(main.as_path(), &root, "low", &[0x41, 0xFF, 0xFF, 0xFF]);
    let high = standalone_progress_sum(main.as_path(), &root, "high", &[0x41, 0x42, 0x43, 0xFF]);

    // The partial-match input recorded SOME leading-byte progress (the channel is
    // live), and matching more leading bytes records strictly more progress — the
    // gradient laf-intel adds and edge presence cannot.
    assert!(
        low >= 1,
        "a 1-leading-byte match must record comparison progress (#421): low={low}"
    );
    assert!(
        high > low,
        "matching more leading bytes of the gate must record strictly more \
         comparison progress (#421): low(1 byte)={low} high(3 bytes)={high}"
    );
}
