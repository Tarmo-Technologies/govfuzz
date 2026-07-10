// SPDX-License-Identifier: Apache-2.0

//! GAP 2 (campaign: yaml-cpp) — the §26.1 SECONDARY whole-library fallback:
//! compile+link the library's FULL recovered translation-unit set when no prebuilt
//! `*.a` exists and the harness link fails with undefined externals across sibling
//! TUs.
//!
//! yaml-cpp is a header + many `src/*.cpp` built via CMake `file(GLOB)`, with no
//! shipped static archive. A harness for a function whose definition references
//! sibling translation units links only the target's own `.cpp` and fails with
//! undefined references; the §26.1 archive fallback has no archive to link, and the
//! per-symbol `AddSource` cascade is slow/incomplete. The fix links the whole
//! library's recovered TU set in one shot.
//!
//! This fixture is a multi-TU C++ library WITH a `compile_commands.json` and NO
//! prebuilt archive: `process()` (the fuzzable buffer+len target) is defined in
//! `src/process.cpp` and calls SIX `helperN()` defined across the sibling
//! `src/helpers_a.cpp` / `src/helpers_b.cpp`. The target harness links only
//! `process.cpp`, fails on six undefined externals (a genuine library-wide link
//! failure, past `WHOLE_LIBRARY_TU_MIN_UNDEFINED`), and is closed by linking the
//! full TU set recovered from the compile database — whereas a single missing
//! helper stays on the precise per-symbol `AddSource` path.
//!
//! Shells the built `govfuzz` binary; gated on clang++ so a toolchain-less lane
//! skips cleanly.

use std::path::Path;
use std::process::Command;

fn clangxx_available() -> bool {
    if which::which("clang++").is_err() {
        eprintln!("skipping auto_full_tu_link: clang++ not on PATH");
        return false;
    }
    true
}

fn write_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("include")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    // A genuine library-wide link failure: the target references SIX sibling
    // symbols across two TUs, so the harness link misses well past
    // WHOLE_LIBRARY_TU_MIN_UNDEFINED and the one-shot full-TU-set link is the
    // right fallback (a single missing helper stays on the precise per-symbol
    // AddSource path — see auto_attempt's per-symbol tests).
    std::fs::write(
        root.join("include/lib.h"),
        "#pragma once\n\
         int process(const unsigned char *data, unsigned len);\n\
         int helper1(int x); int helper2(int x); int helper3(int x);\n\
         int helper4(int x); int helper5(int x); int helper6(int x);\n",
    )
    .unwrap();
    // The fuzzable target: defined here, references SIX sibling-TU helpers.
    std::fs::write(
        root.join("src/process.cpp"),
        "#include \"lib.h\"\n\
         int process(const unsigned char *data, unsigned len)\n\
         {\n\
         \x20   int acc = 0;\n\
         \x20   for (unsigned i = 0; i < len; i++) {\n\
         \x20       int v = (int)data[i];\n\
         \x20       acc += helper1(v) + helper2(v) + helper3(v)\n\
         \x20            + helper4(v) + helper5(v) + helper6(v);\n\
         \x20   }\n\
         \x20   return acc;\n\
         }\n",
    )
    .unwrap();
    // Sibling TUs whose symbols the harness link would otherwise miss.
    std::fs::write(
        root.join("src/helpers_a.cpp"),
        "#include \"lib.h\"\n\
         int helper1(int x) { return (x * 7) ^ 0x5a; }\n\
         int helper2(int x) { return (x + 3) * 2; }\n\
         int helper3(int x) { return x ^ 0x33; }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/helpers_b.cpp"),
        "#include \"lib.h\"\n\
         int helper4(int x) { return (x << 1) | 1; }\n\
         int helper5(int x) { return (x * 11) & 0xff; }\n\
         int helper6(int x) { return ~x; }\n",
    )
    .unwrap();
    // A compile database listing ALL library TUs (the recovery source). NO `*.a`.
    let db = format!(
        r#"[
  {{"directory":"{root}","file":"src/process.cpp","arguments":["clang++","-Iinclude","-c","src/process.cpp"]}},
  {{"directory":"{root}","file":"src/helpers_a.cpp","arguments":["clang++","-Iinclude","-c","src/helpers_a.cpp"]}},
  {{"directory":"{root}","file":"src/helpers_b.cpp","arguments":["clang++","-Iinclude","-c","src/helpers_b.cpp"]}}
]"#,
        root = root.display()
    );
    std::fs::write(root.join("compile_commands.json"), db).unwrap();
}

#[test]
fn full_tu_set_link_closes_a_multi_tu_library_without_an_archive() {
    if !clangxx_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-full-tu-")
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
            panic!(
                "read run.json: {e}; govfuzz auto exit={:?}\nstderr:\n{stderr}",
                output.status.code(),
            )
        }),
    )
    .expect("parse run.json");
    let built_and_fuzzed = run["summary"]["built_and_fuzzed"].as_u64().unwrap_or(0);

    // The full-TU-set fallback must have closed the link...
    assert!(
        stderr.contains("full recovered TU set"),
        "the §26.1 full-TU-set whole-library fallback must fire for the multi-TU target;\nstderr:\n{stderr}"
    );
    // ...and the target must build + fuzz as a result.
    assert!(
        built_and_fuzzed >= 1,
        "target must build+fuzz via the full-TU-set link; summary={}\nstderr:\n{stderr}",
        run["summary"],
    );
}
