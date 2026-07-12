// SPDX-License-Identifier: Apache-2.0
//! End-to-end: `govfuzz auto --differential clang:gcc` flags a cross-compiler
//! divergence as a GF-301 finding.
//!
//! The fixture's function traps only under gcc (`#if !defined(__clang__)`), so
//! the normal (clang) run survives and builds a corpus, while the gcc build
//! crashes on those same inputs — a deterministic exit-code divergence the
//! post-pass must catch. (A target that crashed under the primary compiler would
//! leave an empty corpus queue and is already caught as an ordinary crash.)
//! Gated on clang + gcc + make; skipped otherwise.

use std::path::Path;
use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tempdir(name: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-diff-e2e-{name}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Read every finding.json under `<work>/findings/` and return the parsed values.
fn read_findings(work: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(work.join("findings")) else {
        return out;
    };
    for entry in entries.flatten() {
        let f = entry.path().join("finding.json");
        if let Ok(bytes) = std::fs::read(&f) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                out.push(v);
            }
        }
    }
    out
}

#[test]
fn auto_differential_flags_cross_compiler_divergence() {
    if !have("clang") || !have("gcc") || !have("make") {
        eprintln!("skip: needs clang + gcc + make");
        return;
    }
    let src = tempdir("src");
    // Traps only under gcc: the normal clang run survives (building a corpus),
    // the gcc differential build crashes (SIGILL) on the same inputs.
    std::fs::write(
        src.join("probe.c"),
        "#include <stddef.h>\n\
         int probe(const unsigned char* d, size_t n) {\n\
         #if !defined(__clang__)\n\
             __builtin_trap();\n\
         #endif\n\
             return (n > 0) ? (int)d[0] : 0;\n\
         }\n",
    )
    .unwrap();

    let work = tempdir("work");
    let out = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .args(["auto", src.to_str().unwrap()])
        .args(["--languages", "c"])
        .args(["--per-target-time", "2"])
        .args(["--differential", "clang:gcc"])
        .arg("--no-discovery-cache")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("spawn govfuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);

    let findings = read_findings(&work);
    let diff: Vec<_> = findings
        .iter()
        .filter(|f| {
            f["rule_id"] == "GF-301"
                && f["analysis"]["engine"] == "govfuzz.dynamic.differential.replay"
        })
        .collect();
    assert!(
        !diff.is_empty(),
        "expected a GF-301 differential finding (clang traps, gcc does not).\nstderr:\n{stderr}"
    );
    // The finding names both compilers and preserves the reproducing input.
    let f = diff[0];
    assert_eq!(f["differential"]["compiler_a"], "clang");
    assert_eq!(f["differential"]["compiler_b"], "gcc");
}
