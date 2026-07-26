// SPDX-License-Identifier: Apache-2.0
//! `--force` must get past the non-self-contained-header gate.
//!
//! That gate runs BEFORE any build, so refusing there made `--force` a no-op for
//! the whole class: 42 C++ targets in the 126-project measurement came back
//! `blocked_by_non_self_contained_header` with forcing on, having never shown the
//! repair loop a single compiler error. The flag promises the opposite — attempt
//! it anyway and stub whatever the compiler reports.
//!
//! Real case (nicbarker/clay): the preflight compiles the header under flags the
//! library rejects (`#error "Clay requires C99, C++20, or MSVC"`), while the real
//! harness build uses the dialect ladder and compiles it fine. Forcing past the
//! gate took that project from 0 to 3 `built_and_fuzzed`, all three with
//! `stub_only=false` and target entry observed — real code, not stubs.
//!
//! Gated on a C++ toolchain; skipped with a notice otherwise.

use std::path::Path;
use std::process::Command;

/// A header that refuses to compile below C++20, exactly like clay.h. The
/// standalone preflight uses the recovered flags; the harness build climbs the
/// dialect ladder, so forcing past the gate is what lets it build.
const HEADER: &str = r#"// SPDX-License-Identifier: Apache-2.0
#pragma once
#if !defined(__cplusplus) || __cplusplus < 202002L
#error "this library requires C++20"
#endif
#include <cstddef>
#include <cstdint>
inline int scan_prefix(const uint8_t *data, size_t len) {
    if (len >= 3 && data[0] == 'G' && data[1] == 'F' && data[2] == 'Z') {
        return 1;
    }
    return 0;
}
"#;

fn have_cpp() -> bool {
    which::which("clang++").is_ok() && which::which("make").is_ok()
}

fn run(root: &Path, work: &Path, force: bool) -> (serde_json::Value, String) {
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
    if force {
        command.arg("--force");
    }
    let out = command.output().expect("spawn govfuzz auto");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let bytes = std::fs::read(work.join("auto/run.json"))
        .unwrap_or_else(|e| panic!("read run.json: {e}\nstderr:\n{stderr}"));
    (
        serde_json::from_slice(&bytes).expect("parse run.json"),
        stderr,
    )
}

fn count(run: &serde_json::Value, outcome: &str) -> usize {
    run["targets"]
        .as_array()
        .map(|t| {
            t.iter()
                .filter(|t| t["outcome"]["outcome"] == outcome)
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn force_attempts_a_header_the_preflight_rejects() {
    if !have_cpp() {
        eprintln!("SKIP: no C++ toolchain");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("gf-force-nsc-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path().join("src");
    std::fs::create_dir_all(&root).expect("mkdir");
    std::fs::write(root.join("scan.hpp"), HEADER).expect("write");

    let (plain, plain_err) = run(&root, &tmp.path().join("w-plain"), false);
    let blocked = plain_err.contains("blocked_by_non_self_contained_header")
        || count(&plain, "report_only") > 0;
    if !blocked {
        // The gate did not fire in this environment (its default dialect already
        // satisfies the header), so there is nothing for forcing to get past and
        // asserting on the bypass would be testing nothing.
        eprintln!(
            "SKIP: the standalone preflight accepted this header here, so the gate \
             under test never fired"
        );
        return;
    }

    let (forced, forced_err) = run(&root, &tmp.path().join("w-forced"), true);
    assert!(
        forced_err.contains("attempting it anyway"),
        "--force must say it is proceeding past the gate:\n{forced_err}"
    );
    assert!(
        count(&forced, "built_and_fuzzed") >= 1,
        "forcing past the gate must actually FUZZ the target, not re-label it: \
         run.json={forced}\nstderr:\n{forced_err}"
    );
    // And what it fuzzed must be the project's own code, not blind stubs —
    // otherwise forcing has bought a number, not a test.
    let real = forced["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .filter(|t| t["outcome"]["outcome"] == "built_and_fuzzed")
        .any(|t| t["stub_execution"]["stub_only"] == serde_json::Value::Bool(false));
    assert!(
        real,
        "a forced rescue must exercise real code (stub_only=false): {forced}"
    );
}
