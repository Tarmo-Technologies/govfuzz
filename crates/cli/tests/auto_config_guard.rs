// SPDX-License-Identifier: Apache-2.0
//
// A configure-style `#error` guard must not end the build. Reading the residual
// blockers of the forced sweep, ten of the sampled unbuilt harnesses died on a
// header's own `#error` — libssh's "no strtoull function found" / "Your system
// must provide a __func__ macro", ImageMagick's "you should set
// MAGICKCORE_QUANTUM_DEPTH". Nothing is MISSING from those trees, so no
// header/type/symbol repair applies: the project's build system was supposed to
// define the macro the guard tests, and offline govfuzz has to supply it.
//
// The fixture reproduces the shape exactly, with a planted out-of-bounds read
// behind the guarded macro so a build that really recovers also fuzzes.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/config_guard")
        .canonicalize()
        .expect("canonicalize config_guard fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

#[test]
fn a_config_guard_hash_error_is_repaired_by_defining_what_it_tests() {
    let work = std::env::temp_dir().join(format!("gf_cfgguard_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let out = Command::new(govfuzz_bin())
        .args([
            "auto",
            "--per-target-time",
            "5",
            "--single-pass",
            "--jobs",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
            fixture().to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto");
    assert!(
        out.status.success(),
        "govfuzz auto exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).expect("run.json"))
            .expect("parse run.json");
    assert_eq!(
        json["summary"]["built_and_fuzzed"], 1,
        "the guarded target must build and fuzz: {json}"
    );

    // The repair says exactly what was recovered and with what value — a
    // feature-test macro a real configure would write as 1, not 0 (which satisfies
    // `#ifdef X` but fails the equally common `#if X`).
    let repairs = json["targets"][0]["outcome"]["repairs"].to_string();
    assert!(
        repairs.contains("config_guard_define") && repairs.contains("HAVE_STRTOULL"),
        "the guard's macro must be on the repair ledger: {repairs}"
    );
    let defines = std::fs::read_dir(work.join("harnesses"))
        .expect("harnesses dir")
        .flatten()
        .find_map(|entry| std::fs::read_to_string(entry.path().join("repairs/auto_defines.h")).ok())
        .expect("auto_defines.h");
    assert!(
        defines.contains("#define HAVE_STRTOULL 1"),
        "auto_defines.h: {defines}"
    );

    let _ = std::fs::remove_dir_all(&work);
}
