// SPDX-License-Identifier: Apache-2.0

//! Regression test for #418: `govfuzz auto` on an autotools-style C tree whose
//! public header pulls in a configure-generated header (absent until
//! `./configure` runs) must NOT produce an opaque `failed_build` with an empty
//! missing-dependency manifest. Every failed target has to leave at least one
//! actionable manifest entry naming WHAT blocked it, with remediation.
//!
//! End-to-end (shells the built `govfuzz` binary). Gated on clang + make so a
//! toolchain-less CI lane skips cleanly rather than failing.

use std::path::Path;
use std::process::Command;

fn toolchain_available() -> bool {
    if which::which("clang").is_err() {
        eprintln!("skipping auto_autotools_manifest: clang not on PATH");
        return false;
    }
    if which::which("make").is_err() {
        eprintln!("skipping auto_autotools_manifest: make not on PATH");
        return false;
    }
    true
}

/// Write a minimal autotools-shaped project: a public header that includes a
/// configure-generated header (`gencfg.h`, materialised only from `gencfg.h.in`
/// by `./configure`, which we deliberately never run) and `#error`s out when the
/// generated build macro is absent. clang therefore fails the build the way a
/// real unconfigured c-ares tree does.
fn write_fixture(root: &Path) {
    std::fs::write(
        root.join("gencfg.h.in"),
        "#define LIBFOO_CONFIGURED 1\n#define LIBFOO_SIZE_T unsigned long\n",
    )
    .unwrap();
    std::fs::write(
        root.join("foo.h"),
        "#ifndef FOO_H\n#define FOO_H\n\
         #include \"gencfg.h\"   /* configure-generated; absent without ./configure */\n\
         #ifndef LIBFOO_CONFIGURED\n\
         #  error \"libfoo is not configured: run ./configure to generate the build header\"\n\
         #endif\n\
         int foo_parse(const unsigned char *data, unsigned long len);\n\
         #endif\n",
    )
    .unwrap();
    std::fs::write(
        root.join("foo.c"),
        "#include \"foo.h\"\n\
         int foo_parse(const unsigned char *data, unsigned long len) {\n\
         \x20   int acc = 0;\n\
         \x20   for (unsigned long i = 0; i < len; i++) acc ^= data[i];\n\
         \x20   return acc;\n\
         }\n",
    )
    .unwrap();
}

#[test]
fn autotools_failed_build_has_actionable_manifest_not_opaque() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-418-autotools-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_fixture(root);
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn govfuzz auto");

    let run_json_path = work.join("auto/run.json");
    let run_bytes = std::fs::read(&run_json_path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; govfuzz auto exit={:?}\nstderr:\n{}",
            run_json_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let run: serde_json::Value = serde_json::from_slice(&run_bytes).expect("parse run.json");

    // The fixture must actually fail to build (no ./configure was run).
    let failed_build = run["summary"]["failed_build"].as_u64().unwrap_or(0);
    assert!(
        failed_build >= 1,
        "fixture should produce a failed_build; summary={}",
        run["summary"]
    );

    // The manifest must NOT be empty / opaque.
    let manifest_path = work.join("auto/missing-deps.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("read missing-deps.json"))
            .expect("parse missing-deps.json");
    let entries = manifest["entries"]
        .as_array()
        .expect("manifest.entries is an array");
    assert_eq!(manifest["complete"].as_bool(), Some(true), "{manifest:#}");
    assert!(
        manifest["completed_targets"].as_u64().unwrap_or(0) >= 1,
        "{manifest:#}"
    );
    assert!(
        !entries.is_empty(),
        "#418: a failed_build must not leave an EMPTY missing-deps manifest"
    );

    // AC2: every failed target leaves at least one referencing manifest entry —
    // no silent/opaque failure.
    let entry_refs = |id: &str| -> bool {
        entries.iter().any(|e| {
            e["referenced_by"]
                .as_array()
                .map(|rs| rs.iter().any(|r| r.as_str() == Some(id)))
                .unwrap_or(false)
        })
    };
    let mut failed_ids = Vec::new();
    for t in run["targets"].as_array().unwrap() {
        // Outcome is an internally-tagged enum keyed on "outcome".
        if t["outcome"]["outcome"].as_str() == Some("failed_build") {
            let id = t["harness_id"].as_str().unwrap().to_owned();
            assert!(
                entry_refs(&id),
                "#418 AC2: failed target {id} has no manifest entry; manifest:\n{}",
                serde_json::to_string_pretty(&manifest).unwrap()
            );
            failed_ids.push(id);
        }
    }
    assert!(!failed_ids.is_empty());

    // AC2: at least one STILL-BLOCKING entry — the manifest must not cheerfully
    // claim "0 still blocking / build continued" for a build that failed.
    let blocking: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|e| e["stubbed"].as_bool() == Some(false))
        .collect();
    assert!(
        !blocking.is_empty(),
        "#418: failed_build must surface >= 1 STILL-BLOCKING entry; manifest:\n{}",
        serde_json::to_string_pretty(&manifest).unwrap()
    );

    // AC1: the configure-generated header is named, with configure-oriented
    // remediation (never a dead-end apt-file pointer).
    let gencfg = entries
        .iter()
        .find(|e| e["name"].as_str() == Some("gencfg.h"))
        .expect("the configure-generated header must appear in the manifest");
    assert_eq!(
        gencfg["kind"].as_str(),
        Some("generated_source"),
        "generated output must be in the first-class offline requirements section"
    );
    let hint = gencfg["acquisition_hint"].as_str().unwrap_or("");
    assert!(
        hint.contains("configure"),
        "AC1: gencfg.h remediation must name the configure step, got: {hint:?}"
    );
    assert!(
        !hint.contains("apt-file"),
        "AC1: a configure-generated header must not get a dead-end apt hint: {hint:?}"
    );

    // The real blocker (the #error telling the user to run configure) is surfaced
    // rather than dropped behind an opaque failure.
    let text = std::fs::read_to_string(work.join("auto/missing-deps.txt")).unwrap();
    assert!(
        text.contains("not configured") || text.contains("configure"),
        "the configure blocker must be visible in missing-deps.txt:\n{text}"
    );
    assert!(
        text.contains("Required toolchains, runtimes, generated and vendor source"),
        "the offline handoff section must be first-class:\n{text}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let last = stderr.lines().last().unwrap_or_default();
    assert!(
        last.contains("govfuzz auto: requirements:")
            && last.contains("auto/missing-deps.txt")
            && last.contains("final"),
        "last terminal line must point at the final requirement list, got {last:?}\n{stderr}"
    );
}
