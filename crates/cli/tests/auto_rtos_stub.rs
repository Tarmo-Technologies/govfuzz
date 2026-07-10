// SPDX-License-Identifier: Apache-2.0

//! End-to-end: `govfuzz auto` on UNGUARDED RTOS application code — the dominant
//! real-world shape for radar/avionics software, which simply `#include
//! <vxWorks.h>` and is built only by the vendor toolchain in production. On a
//! Linux lab host those platform headers are absent, so the host harness build
//! first fails with `'vxWorks.h' file not found`. govfuzz must recover: the
//! repair loop fills the missing RTOS headers with a rich type surface (STATUS,
//! SEM_ID, OK/ERROR, …) and the placeholder dir is searched with `-idirafter`
//! so the ANGLED `<...>` includes resolve — the target then builds + fuzzes
//! stub-isolated on the host with the builtin engine.
//!
//! Shells the built `govfuzz` binary. Gated on clang so a toolchain-less CI lane
//! skips cleanly rather than failing.

use std::path::Path;
use std::process::Command;

fn toolchain_available() -> bool {
    if which::which("clang").is_err() {
        eprintln!("skipping auto_rtos_stub: clang not on PATH");
        return false;
    }
    true
}

/// A representative unguarded VxWorks translation unit: it pulls in three vendor
/// headers and uses their type surface (STATUS / SEM_ID / OK / ERROR) in the
/// algorithmic body govfuzz should fuzz.
fn write_fixture(root: &Path) {
    std::fs::write(
        root.join("radar_track.c"),
        "#include <vxWorks.h>\n\
         #include <semLib.h>\n\
         #include <msgQLib.h>\n\
         \n\
         static SEM_ID track_lock;\n\
         \n\
         /* Parse a radar track message. Built only by the vendor toolchain in\n\
            production; govfuzz stubs the RTOS headers to fuzz it on the host. */\n\
         int parse_track_msg(const unsigned char *buf, unsigned len)\n\
         {\n\
         \x20   STATUS s = OK;\n\
         \x20   unsigned i, checksum = 0;\n\
         \x20   if (len < 4) return ERROR;\n\
         \x20   for (i = 0; i < len; i++) {\n\
         \x20       checksum += buf[i];\n\
         \x20       if (buf[i] == 0xFF && i + 1 < len && buf[i + 1] == 0xFE)\n\
         \x20           s = ERROR;\n\
         \x20   }\n\
         \x20   return s == OK ? (int)(checksum & 0x7fff) : ERROR;\n\
         }\n",
    )
    .unwrap();
}

#[test]
fn unguarded_vxworks_code_builds_stub_isolated_and_fuzzes() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-rtos-vxworks-")
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

    // The whole point: the RTOS target must reach built_and_fuzzed on the host,
    // NOT failed_build. Without the rich RTOS header packs + the -idirafter
    // fallback it would die on `'vxWorks.h' file not found`.
    let built_and_fuzzed = run["summary"]["built_and_fuzzed"].as_u64().unwrap_or(0);
    assert!(
        built_and_fuzzed >= 1,
        "unguarded VxWorks code must build+fuzz stub-isolated; summary={}\nstderr:\n{}",
        run["summary"],
        String::from_utf8_lossy(&output.stderr)
    );

    // And specifically the radar parser, with no opaque failed_build left behind.
    let targets = run["targets"].as_array().expect("targets array");
    assert!(
        targets
            .iter()
            .any(|t| t["name"].as_str() == Some("parse_track_msg")
                && t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed")),
        "parse_track_msg should be built_and_fuzzed; targets={targets:#?}"
    );
}

/// A translation unit whose fuzzable entry point exists ONLY inside a
/// `#ifdef __vxworks` branch — invisible on a Linux host unless govfuzz detects
/// the platform guard, defines it, and stub-isolates the platform headers. This
/// exercises the discovery→`foreign_platform_stub`→`apply_platform_stub` route
/// (the parser tags the guard; the build defines `__vxworks` + supplies the
/// header pack), distinct from the unguarded repair-loop route above.
fn write_guarded_fixture(root: &Path) {
    std::fs::write(
        root.join("sonar.c"),
        "#include <vxWorks.h>\n\
         #include <semLib.h>\n\
         \n\
         #ifdef __vxworks\n\
         int sonar_decode(const unsigned char *ping, unsigned len)\n\
         {\n\
         \x20   STATUS s = OK;\n\
         \x20   unsigned i, energy = 0;\n\
         \x20   if (len < 8) return ERROR;\n\
         \x20   for (i = 0; i < len; i++) {\n\
         \x20       energy += ping[i];\n\
         \x20       if (ping[i] == 0xDE && i + 1 < len && ping[i + 1] == 0xAD)\n\
         \x20           s = ERROR;\n\
         \x20   }\n\
         \x20   return s == OK ? (int)(energy % 1024) : ERROR;\n\
         }\n\
         #endif\n",
    )
    .unwrap();
}

#[test]
fn guarded_vxworks_branch_is_made_visible_and_fuzzed_stub_isolated() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-rtos-guarded-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_guarded_fixture(root);
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

    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
            panic!(
                "read run.json: {e}; exit={:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        }),
    )
    .expect("parse run.json");

    // The guard-only function must be discovered, made visible, and fuzzed.
    let targets = run["targets"].as_array().expect("targets array");
    assert!(
        targets
            .iter()
            .any(|t| t["name"].as_str() == Some("sonar_decode")
                && t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed")),
        "guard-only sonar_decode should be built_and_fuzzed; targets={targets:#?}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // It routed through the stub-isolated platform path (not a plain native
    // build), and govfuzz flagged the reduced fidelity in its output.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("STUB-ISOLATED") && stderr.to_lowercase().contains("vxworks"),
        "must report the stub-isolated vxworks build; stderr:\n{stderr}"
    );
}
