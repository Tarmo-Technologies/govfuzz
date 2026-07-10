// SPDX-License-Identifier: Apache-2.0

//! GAP 1 (campaign: fmt) — the harness build must FILTER compile flags that are
//! incompatible with govfuzz's standalone single-translation-unit harness compile.
//!
//! fmt's CMake declares `target_compile_options(<lib> PUBLIC -fmodules-ts)` (C++20
//! modules). govfuzz recovers a project's compile wiring from its CMakeLists when
//! there is no compile database, and used to forward EVERY `-f…` flag verbatim —
//! so `-fmodules-ts` reached the harness `clang++`, which rejects it with
//! `error: unknown argument: '-fmodules-ts'`, breaking ALL of fmt's harness builds.
//!
//! This fixture is a CMake C++ library whose `CMakeLists.txt` carries
//! `-fmodules-ts` exactly as fmt's does. With the flag filtered the harness builds
//! and fuzzes; without it the build fails on the unknown argument.
//!
//! Shells the built `govfuzz` binary; gated on clang++ so a toolchain-less lane
//! skips cleanly.

use std::path::Path;
use std::process::Command;

fn clangxx_available() -> bool {
    if which::which("clang++").is_err() {
        eprintln!("skipping auto_modules_ts_flag: clang++ not on PATH");
        return false;
    }
    true
}

fn write_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("include")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    // A self-contained, fuzzable free function: buffer + length.
    std::fs::write(
        root.join("include/numparse.h"),
        "#pragma once\nint parse_checksum(const unsigned char *data, unsigned len);\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/numparse.cpp"),
        "#include \"numparse.h\"\n\
         int parse_checksum(const unsigned char *data, unsigned len)\n\
         {\n\
         \x20   unsigned acc = 0;\n\
         \x20   for (unsigned i = 0; i < len; i++) acc = acc * 31u + data[i];\n\
         \x20   return (int)(acc & 0x7fffffff);\n\
         }\n",
    )
    .unwrap();
    // The fmt break, reproduced: a PUBLIC `-fmodules-ts` on the library target.
    // govfuzz's CMakeLists inference must drop it from the harness compile.
    std::fs::write(
        root.join("CMakeLists.txt"),
        "cmake_minimum_required(VERSION 3.10)\n\
         project(numparse CXX)\n\
         add_library(numparse STATIC src/numparse.cpp)\n\
         target_include_directories(numparse PUBLIC include)\n\
         target_compile_options(numparse PUBLIC -fmodules-ts)\n",
    )
    .unwrap();
}

#[test]
fn modules_ts_flag_is_filtered_so_the_harness_builds() {
    if !clangxx_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-modules-ts-")
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
        .arg("--max-targets")
        .arg("3")
        .output()
        .expect("spawn govfuzz auto");

    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
            panic!(
                "read run.json: {e}; govfuzz auto exit={:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        }),
    )
    .expect("parse run.json");
    let built_and_fuzzed = run["summary"]["built_and_fuzzed"].as_u64().unwrap_or(0);
    assert!(
        built_and_fuzzed >= 1,
        "harness must build+fuzz with -fmodules-ts filtered out; summary={}\nstderr:\n{}",
        run["summary"],
        String::from_utf8_lossy(&output.stderr)
    );

    // The generated harness Makefile must NOT carry the modules flag.
    let mut saw_makefile = false;
    if let Ok(entries) = std::fs::read_dir(work.join("harnesses")) {
        for entry in entries.flatten() {
            let mk = entry.path().join("Makefile");
            if let Ok(text) = std::fs::read_to_string(&mk) {
                saw_makefile = true;
                assert!(
                    !text.contains("-fmodules-ts"),
                    "harness Makefile must not forward -fmodules-ts:\n{text}"
                );
            }
        }
    }
    assert!(
        saw_makefile,
        "expected at least one generated harness Makefile"
    );
}
