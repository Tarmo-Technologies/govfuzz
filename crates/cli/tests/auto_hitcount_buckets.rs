// SPDX-License-Identifier: Apache-2.0

//! #420 regression: AFL-style hit-count coverage buckets for the DRIVER /
//! fork-server path (C/C++ trace-pc-guard). The driver's edge bitmap is
//! presence-only — `presence_map[idx] = 1` — so it cannot tell a loop run 3×
//! from one run 300×. #420 adds a SEPARATE, PARALLEL per-exec hit-COUNT map
//! (`GOVFUZZ_COV_CNT_SHM`): the runtime saturating-increments each edge per exec,
//! the engine zeroes it before each exec and folds the per-exec count into AFL
//! logarithmic buckets (1,2,3,4-7,8-15,16-31,32-127,128+) so a deeper loop
//! registers as new coverage across a bucket boundary that edge-presence misses.
//!
//! The fixture is an input-LENGTH-controlled loop with a STRAIGHT-LINE body (no
//! data-dependent branches), which makes it the clean isolation case:
//! - Every non-empty input hits the SAME edges (entry / loop-header / loop-body /
//!   exit), so edge PRESENCE is saturated after the first non-empty seed and can
//!   NEVER distinguish loop depth. Any retained NON-seed corpus input therefore
//!   proves the hit-count bucket channel — not presence — drove corpus growth.
//! - A standalone run at two depths shows IDENTICAL presence bitmaps but
//!   DIVERGENT per-edge counts that cross AFL bucket boundaries — exactly the
//!   signal #420 adds and edge-presence cannot.
//!
//! Coverage of the acceptance criteria:
//! - AC1 (progressively higher n registers new coverage / new buckets):
//!   `hitcount_buckets_distinguish_loop_depth_and_grow_corpus` — the standalone
//!   count-map divergence + the bucket-driven corpus retention.
//! - AC2 (bucket transitions register, within-bucket noise does not): the
//!   deterministic CoverageTracker unit test in `crates/cli/src/fuzz.rs`
//!   (`coverage_tracker_buckets_register_transitions_not_within_bucket_noise`).
//! - AC3 (the in-process builtin engine already has this; this is the DRIVER
//!   path only): no in-process duplication — this exercises the C++ driver
//!   runtime + the CoverageTracker count reader.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

/// Size (bytes) of the driver's shared edge bitmap AND the #420 count map. MUST
/// match `GOVFUZZ_COV_BITS` in the driver templates and the CoverageTracker
/// reader.
const GOVFUZZ_COV_BITS: usize = 1 << 16;

/// True when this host can build a C++ sanitizer target the way `govfuzz auto`
/// does (clang++ present + a discoverable libstdc++). Mirrors the gate in
/// `auto_cpp_amalgamation.rs`: when true, a failed build is a real regression,
/// not a toolchain gap.
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

/// Replica of the canonical AFL log-bucket table (`count_to_bucket` in
/// `crates/fuzz_engine/builtin/src/coverage.rs` and `crates/cli/src/fuzz.rs`).
/// Kept here only to assert a bucket CROSSING between two observed depths.
fn count_to_bucket(count: u32) -> u8 {
    match count {
        0 | 1 => 0,
        2 => 1,
        3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=127 => 6,
        _ => 7,
    }
}

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-hitcount-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// A benign passthrough libFuzzer target whose ONLY interesting behavior is an
/// input-LENGTH-controlled loop with a straight-line body. The `volatile`
/// accumulator forces every iteration to execute (no closed-form elision at the
/// `-O1` the harness Makefile uses, and no vectorization across the volatile
/// RMW). Presence coverage is the SAME for every non-empty input; only the loop
/// edges' hit COUNT scales with input length.
const DEEPENING_LOOP: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    volatile unsigned long acc = 0;
    for (size_t i = 0; i < size; i++) {
        acc += data[i];   // single straight-line block, executed `size` times
    }
    (void)acc;
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

/// Run the built driver binary standalone on `input`, with a FRESH presence map
/// and #420 count map, and return `(set-edge offsets, per-edge counts)` for that
/// single exec. The driver's trace-pc-guard runtime opens both maps from the env
/// and (presence bit + saturating count) records this one input's footprint.
fn standalone_footprint(
    main: &Path,
    work: &Path,
    tag: &str,
    input: &[u8],
) -> (BTreeSet<usize>, Vec<u8>) {
    let cov = work.join(format!("cov-{tag}.shm"));
    let cnt = work.join(format!("cnt-{tag}.shm"));
    let _ = fs::remove_file(&cov);
    let _ = fs::remove_file(&cnt);
    let input_path = work.join(format!("input-{tag}.bin"));
    fs::write(&input_path, input).unwrap();

    let status = Command::new(main)
        .arg(&input_path)
        .env("GOVFUZZ_COV_SHM", &cov)
        .env("GOVFUZZ_COV_CNT_SHM", &cnt)
        .env("ASAN_OPTIONS", "detect_leaks=0")
        .env("DEBUGINFOD_URLS", "")
        // Defensive: never let an inherited env put the driver into framed mode.
        .env_remove("GOVFUZZ_FRAMED")
        .status()
        .expect("run built driver standalone");
    assert!(
        status.success(),
        "benign standalone run must exit cleanly (tag {tag})"
    );

    let cnt_bytes = fs::read(&cnt).expect("driver must create the #420 count map");
    assert_eq!(
        cnt_bytes.len(),
        GOVFUZZ_COV_BITS,
        "count map must be GOVFUZZ_COV_BITS-sized"
    );
    let cov_bytes = fs::read(&cov).expect("driver must create the presence map");
    let presence: BTreeSet<usize> = cov_bytes
        .iter()
        .enumerate()
        .filter(|(_, &b)| b != 0)
        .map(|(i, _)| i)
        .collect();
    (presence, cnt_bytes)
}

#[test]
fn hitcount_buckets_distinguish_loop_depth_and_grow_corpus() {
    if !cpp_toolchain_capable() {
        eprintln!("skipping: clang++/libstdc++ toolchain unavailable");
        return;
    }
    let root = tmpdir("loop");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("fuzz.cc"), DEEPENING_LOOP).unwrap();

    // 5s budget: enough for the mutator to grow inputs past the seeds and for the
    // bucket channel to retain deeper loops.
    let status = run_auto(&root, "5");
    assert!(status.success() || status.code() == Some(1));

    let run_json = read_run_json(&root);
    let _ = built_target(&run_json); // must build+fuzz on a capable host

    // --- Driver-runtime proof (deterministic): the #420 count map records
    // per-input loop depth that edge-presence cannot. Two depths, standalone. ---
    let main =
        find_named(&root.join("govfuzz_work/harnesses"), "main").expect("built harness binary");
    let (shallow_edges, shallow_counts) =
        standalone_footprint(&main, &root, "shallow", &[0x41u8; 8]);
    let (deep_edges, deep_counts) = standalone_footprint(&main, &root, "deep", &[0x41u8; 240]);

    let shallow_max = shallow_counts.iter().copied().max().unwrap_or(0);
    let deep_max = deep_counts.iter().copied().max().unwrap_or(0);

    // A multi-iteration loop was actually counted (not just presence-flagged).
    assert!(
        deep_max >= 2,
        "the deep loop must record a per-edge hit count > 1 (#420): deep_max={deep_max}"
    );
    // Deeper loop => strictly higher max per-edge count.
    assert!(
        deep_max > shallow_max,
        "a deeper loop must record higher hit counts (#420): shallow_max={shallow_max} deep_max={deep_max}"
    );
    // ...and the two depths land in DIFFERENT AFL buckets — i.e. the engine's
    // input_grew_buckets() would register the deeper input as novel coverage.
    let shallow_bucket = count_to_bucket(u32::from(shallow_max));
    let deep_bucket = count_to_bucket(u32::from(deep_max));
    assert!(
        deep_bucket > shallow_bucket,
        "loop depths must cross an AFL bucket boundary (#420): \
         shallow={shallow_max}(bucket {shallow_bucket}) deep={deep_max}(bucket {deep_bucket})"
    );
    // The whole point: edge PRESENCE cannot tell the two depths apart — the
    // straight-line loop hits exactly the same edges at every depth.
    assert_eq!(
        shallow_edges, deep_edges,
        "edge-presence must be identical across loop depths (only hit-count differs) (#420)"
    );

    // --- Engine end-to-end proof: because presence is saturated after the first
    // non-empty seed, ANY retained NON-seed corpus input was kept ONLY because it
    // crossed a hit-count bucket. The seeds are lengths {0,1,8}; a persisted queue
    // entry of any other length is bucket-driven retention. ---
    let queue = find_named(&root.join("govfuzz_work/corpus"), "queue")
        .expect("coverage corpus queue must be persisted");
    let seed_lengths: BTreeSet<usize> = [0usize, 1, 8].into_iter().collect();
    let mut retained_lengths: BTreeSet<usize> = BTreeSet::new();
    let mut bucket_driven: BTreeSet<usize> = BTreeSet::new();
    for entry in fs::read_dir(&queue).expect("queue dir readable").flatten() {
        if let Ok(bytes) = fs::read(entry.path()) {
            retained_lengths.insert(bytes.len());
            if !seed_lengths.contains(&bytes.len()) {
                bucket_driven.insert(bytes.len());
            }
        }
    }
    assert!(
        !bucket_driven.is_empty(),
        "the bucket channel must retain at least one deeper (non-seed-length) loop input \
         in the corpus — presence alone never would (#420). retained lengths={retained_lengths:?}"
    );
}
