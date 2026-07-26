// SPDX-License-Identifier: Apache-2.0

//! #94: `--max-targets` is a cap on targets that reach the FUZZ phase, not on
//! candidates inspected. Unsupported params / build failures must not consume the
//! cap, so the viable endpoints are backfilled instead of being starved.

use std::path::Path;
use std::process::Command;

fn run_auto(root: &Path, work: &Path, extra: &[&str]) -> serde_json::Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    command
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass");
    command.args(extra);
    let output = command.output().expect("spawn govfuzz auto");
    let run_path = work.join("auto/run.json");
    let bytes = std::fs::read(&run_path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; status={:?}\nstderr:\n{}",
            run_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    serde_json::from_slice(&bytes).expect("parse run.json")
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-maxtargets-{tag}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn have_clang() -> bool {
    which::which("clang").is_ok() || which::which("cc").is_ok()
}

/// A tree mixing UNSUPPORTED endpoints with viable byte-buffer endpoints.
/// `--max-targets 2` must fuzz BOTH viable ones — the unsupported candidates
/// never consume the success cap.
///
/// The unsupported endpoints used to be function-pointer params. They are not
/// unsupported any more: govfuzz drives C callbacks, so every function in the
/// old fixture built and fuzzed and the tree had nothing non-viable left in it.
/// A pointer to a type the tree never defines has no byte-buffer decoder and no
/// constructor to find, which is what "cannot be driven" means today.
fn write_mixed_tree(root: &Path) {
    std::fs::write(
        root.join("lib.c"),
        r#"
#include <stddef.h>
#include <stdint.h>

/* Unsupported: an incomplete type has no byte-buffer decoder and no in-tree
 * constructor, so auto reports UnsupportedParams — these must NOT consume the
 * cap. (A function-POINTER parameter no longer belongs here: govfuzz drives
 * those, and using them left this fixture with nothing non-viable in it.) */
struct opaque_handle;
union opaque_variant;
int parse_with_handle_a(struct opaque_handle *h) { return h ? 1 : 0; }
int parse_with_handle_b(union opaque_variant *v) { return v ? 2 : 0; }
int parse_with_handle_c(struct opaque_handle *h, size_t n) { return h ? (int)n : 0; }

/* Viable: a byte-buffer endpoint auto can drive directly. */
int decode_alpha(const uint8_t *data, size_t len) {
    if (len >= 2 && data[0] == 'A' && data[1] == 'Z') return 1;
    return 0;
}
int decode_beta(const uint8_t *data, size_t len) {
    if (len >= 3 && data[0] == 'B' && data[1] == 'E' && data[2] == 'T') return 2;
    return 0;
}
"#,
    )
    .unwrap();
}

fn count_outcome(run: &serde_json::Value, outcome: &str) -> usize {
    run["targets"]
        .as_array()
        .map(|targets| {
            targets
                .iter()
                .filter(|t| t["outcome"]["outcome"] == outcome)
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn max_targets_backfills_past_unsupported_and_fuzzes_the_viable_ones() {
    if !have_clang() {
        eprintln!("SKIP: no C compiler on PATH");
        return;
    }
    let root = tmpdir("backfill");
    write_mixed_tree(&root);
    let work = tmpdir("backfill-work");

    // `--jobs 1`: the cap is only EXACT when attempts are serial. A parallel
    // sweep stops handing out candidates once the cap is reached but lets the
    // up-to `jobs-1` attempts already in flight finish, so it can fuzz a few
    // more — documented and deliberate. Asserting an exact count without
    // pinning jobs was asserting the serial contract against a parallel run,
    // and on a multi-core box it read 4 where it wanted 2.
    let run = run_auto(&root, &work, &["--max-targets", "2", "--jobs", "1"]);
    // Both viable byte-buffer endpoints must reach the fuzz phase; the
    // unsupported candidates never consume the success cap.
    let fuzzed = count_outcome(&run, "built_and_fuzzed");
    assert_eq!(
        fuzzed, 2,
        "--max-targets 2 must fuzz exactly two targets; run.json targets: {}",
        run["targets"]
    );
    // ...and they must be the VIABLE ones, not an unsupported candidate counted
    // as a success. This is the property #94 is about.
    let fuzzed_names: Vec<&str> = run["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .filter(|t| t["outcome"]["outcome"] == "built_and_fuzzed")
        .filter_map(|t| t["name"].as_str())
        .collect();
    for viable in ["decode_alpha", "decode_beta"] {
        assert!(
            fuzzed_names.contains(&viable),
            "the viable endpoint '{viable}' must be one of the {fuzzed} fuzzed \
             targets, got {fuzzed_names:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn max_attempts_bounds_the_number_of_candidates_inspected() {
    if !have_clang() {
        eprintln!("SKIP: no C compiler on PATH");
        return;
    }
    let root = tmpdir("attempts");
    write_mixed_tree(&root);
    let work = tmpdir("attempts-work");

    // --max-attempts is a hard ceiling on candidates INSPECTED (built/attempted),
    // independent of how many fuzz.
    let run = run_auto(&root, &work, &["--max-attempts", "2"]);
    let attempted = run["targets"].as_array().map(Vec::len).unwrap_or(0);
    assert!(
        attempted <= 2,
        "--max-attempts 2 must inspect at most 2 candidates, inspected {attempted}"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}
