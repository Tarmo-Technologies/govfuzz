// SPDX-License-Identifier: Apache-2.0

//! Multi-TU source recovery for a library with no prebuilt archive.
//!
//! yaml-cpp is a header + many `src/*.cpp` built via CMake `file(GLOB)`, with no
//! shipped static archive. A harness for a function whose definition references
//! sibling translation units links only the target's own `.cpp` and fails with
//! undefined references. The definition index should map those symbols to the two
//! exact sibling sources instead of sweeping every translation unit into the link.
//!
//! This fixture is a multi-TU C++ library WITH a `compile_commands.json` and NO
//! prebuilt archive: `process()` (the fuzzable buffer+len target) is defined in
//! `src/process.cpp` and calls SIX `helperN()` defined across the sibling
//! `src/helpers_a.cpp` / `src/helpers_b.cpp`. The target harness links only
//! `process.cpp`, fails on six undefined externals (a genuine library-wide link
//! failure), and is closed by adding the two definition-bearing sources recovered
//! from the compile database.
//!
//! Shells the built `govfuzz` binary; gated on g++ so a toolchain-less lane
//! skips cleanly.

use std::path::Path;
use std::process::Command;

fn gxx_available() -> bool {
    if which::which("g++").is_err() {
        eprintln!("skipping auto_full_tu_link: g++ not on PATH");
        return false;
    }
    true
}

fn write_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("include")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    // A genuine multi-TU link failure: the target references SIX sibling symbols
    // whose exact definitions live across two source files.
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
  {{"directory":"{root}","file":"src/process.cpp","arguments":["g++","-Iinclude","-c","src/process.cpp"]}},
  {{"directory":"{root}","file":"src/helpers_a.cpp","arguments":["g++","-Iinclude","-c","src/helpers_a.cpp"]}},
  {{"directory":"{root}","file":"src/helpers_b.cpp","arguments":["g++","-Iinclude","-c","src/helpers_b.cpp"]}}
]"#,
        root = root.display()
    );
    std::fs::write(root.join("compile_commands.json"), db).unwrap();
}

#[test]
fn precise_source_repairs_close_a_multi_tu_library_without_an_archive() {
    if !gxx_available() {
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
    let process = run["targets"]
        .as_array()
        .and_then(|targets| targets.iter().find(|target| target["name"] == "process"))
        .unwrap_or_else(|| panic!("process target missing from run.json; stderr:\n{stderr}"));
    let repaired_sources: Vec<&str> = process["outcome"]["repairs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|repair| repair["kind"] == "add_source")
        .filter_map(|repair| repair["source_path"].as_str())
        .collect();

    assert!(
        process["outcome"]["outcome"] == "built_and_fuzzed",
        "process must build and fuzz after precise source repair; outcome={}\nstderr:\n{stderr}",
        process["outcome"],
    );
    for expected in ["helpers_a.cpp", "helpers_b.cpp"] {
        assert!(
            repaired_sources
                .iter()
                .any(|source| Path::new(source).ends_with(expected)),
            "expected exact source repair for {expected}; got {repaired_sources:?}; stderr:\n{stderr}",
        );
    }
    assert!(
        !stderr.contains("full recovered TU set"),
        "exact definition sources should prevent a whole-library sweep; stderr:\n{stderr}",
    );
}
