// SPDX-License-Identifier: Apache-2.0
//! `--force` is a SECOND phase, not a different way to run the first one.
//!
//! Measured over 126 real projects, applying force from the start of the sweep
//! reached 13 FEWER targets than not passing it at all (214 → 201) and bought one
//! extra fuzz finding: a forced attempt costs ~36% more, so inside a fixed
//! `--campaign-time` fewer candidates were attempted and viable targets were never
//! reached. git/git went from 10 attempted / 5 fuzzed to 1 attempted / 0 fuzzed.
//!
//! So the contract is:
//!   1. phase 1 is always unforced — bit-for-bit the run you'd get without the flag
//!   2. phase 2 forces only what phase 1 could not fuzz
//!   3. therefore `--force` can never lower the fuzzed count
//!   4. `--resume --force` over a finished campaign keeps what fuzzed and forces
//!      only what did not, without repeating the unforced attempt it already has
//!
//! Gated on a C toolchain; skipped with a notice otherwise.

use std::path::Path;
use std::process::Command;

/// A tree with two endpoints govfuzz can drive from bytes and one it cannot (a
/// pointer to a type the tree never defines — no decoder, no constructor).
const TREE: &str = r#"
#include <stddef.h>
#include <stdint.h>
struct opaque_handle;
int parse_handle(struct opaque_handle *h, const uint8_t *d, size_t n) {
    if (!h) return -1;
    if (n >= 2 && d[0] == 'O' && d[1] == 'K') return 1;
    return 0;
}
int decode_alpha(const uint8_t *d, size_t n) {
    if (n >= 2 && d[0] == 'A' && d[1] == 'Z') return 1;
    return 0;
}
int decode_beta(const uint8_t *d, size_t n) {
    if (n >= 3 && d[0] == 'B') return 2;
    return 0;
}
"#;

fn have_c() -> bool {
    (which::which("clang").is_ok() || which::which("cc").is_ok()) && which::which("make").is_ok()
}

fn run(root: &Path, work: &Path, extra: &[&str]) -> (serde_json::Value, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    command
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass")
        .arg("--jobs")
        .arg("1");
    command.args(extra);
    let out = command.output().expect("spawn govfuzz auto");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let path = work.join("auto/run.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}\nstderr:\n{stderr}", path.display()));
    (
        serde_json::from_slice(&bytes).expect("parse run.json"),
        stderr,
    )
}

fn fuzzed_names(run: &serde_json::Value) -> Vec<String> {
    run["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .filter(|t| t["outcome"]["outcome"] == "built_and_fuzzed")
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn force_only_adds_reach_and_never_removes_it() {
    if !have_c() {
        eprintln!("SKIP: no C toolchain");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("gf-force-phase-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path().join("src");
    std::fs::create_dir_all(&root).expect("mkdir");
    std::fs::write(root.join("lib.c"), TREE).expect("write");

    // Unforced: the two byte-buffer endpoints fuzz, the opaque one does not.
    let (plain, _) = run(&root, &tmp.path().join("w-plain"), &[]);
    let mut plain_fuzzed = fuzzed_names(&plain);
    plain_fuzzed.sort();
    assert_eq!(
        plain_fuzzed,
        vec!["decode_alpha", "decode_beta"],
        "unforced baseline: run.json={plain}"
    );

    // Forced: a superset. Phase 1 must still fuzz both viable endpoints — they
    // cannot be starved by work spent forcing the third — and phase 2 rescues it.
    let (forced, stderr) = run(&root, &tmp.path().join("w-forced"), &["--force"]);
    let mut forced_fuzzed = fuzzed_names(&forced);
    forced_fuzzed.sort();
    for viable in &plain_fuzzed {
        assert!(
            forced_fuzzed.contains(viable),
            "--force must never LOSE a target the unforced run fuzzed; \
             missing {viable}, got {forced_fuzzed:?}\nstderr:\n{stderr}"
        );
    }
    assert!(
        forced_fuzzed.len() >= plain_fuzzed.len(),
        "forcing must be monotonic in reach: {forced_fuzzed:?} vs {plain_fuzzed:?}"
    );
    assert!(
        stderr.contains("phase 2 — retrying 1 target(s)"),
        "the forced pass must be a second phase over only what phase 1 missed:\n{stderr}"
    );
    assert!(
        stderr.contains("rescued 1 target(s)"),
        "and it should rescue the opaque-pointer target here:\n{stderr}"
    );
    assert!(
        forced_fuzzed.contains(&"parse_handle".to_owned()),
        "forcing should drive the undrivable parameter: {forced_fuzzed:?}"
    );
}

#[test]
fn resume_force_keeps_what_fuzzed_and_forces_only_the_rest() {
    if !have_c() {
        eprintln!("SKIP: no C toolchain");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("gf-force-resume-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path().join("src");
    std::fs::create_dir_all(&root).expect("mkdir");
    std::fs::write(root.join("lib.c"), TREE).expect("write");
    let work = tmp.path().join("w");

    // A plain campaign first.
    let (first, _) = run(&root, &work, &[]);
    assert_eq!(fuzzed_names(&first).len(), 2, "first campaign: {first}");

    // Now force over the SAME work dir. The two that fuzzed must be RELOADED, not
    // re-attempted, and the one that did not must go straight to the forced phase
    // rather than repeating an unforced attempt whose answer is already recorded.
    let (second, stderr) = run(&root, &work, &["--resume", "--force"]);
    assert!(
        stderr.contains("keeping 2 target(s) that already fuzzed and forcing only the 1"),
        "resume+force must name what it kept and what it is forcing:\n{stderr}"
    );
    assert_eq!(
        stderr.matches("… attempting").count(),
        1,
        "exactly ONE attempt (the forced retry) — the unforced result for that \
         target is already on disk, and the other two are reloaded:\n{stderr}"
    );
    let mut fuzzed = fuzzed_names(&second);
    fuzzed.sort();
    assert_eq!(
        fuzzed,
        vec!["decode_alpha", "decode_beta", "parse_handle"],
        "resume+force ends with everything fuzzed: run.json={second}"
    );
}
