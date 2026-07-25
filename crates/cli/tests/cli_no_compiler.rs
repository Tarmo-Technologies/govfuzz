// SPDX-License-Identifier: Apache-2.0
//! Subcommands must exit 2 when no Ada compiler can be found.
//!
//! These live here, as integration tests driving the real binary, rather than as
//! unit tests calling `run_from` directly: proving "no compiler is present" means
//! handing the process a `PATH` that contains none, and `PATH` is process-global
//! while cargo runs unit tests on many threads. Emptying it in-process hid the real
//! toolchain from every test running concurrently — a C++ header preflight spawning
//! `clang++` by name got `NotFound`, silently degraded to "preflight unavailable",
//! and generated a harness it should have blocked. A child process has its own
//! environment, so the hostile `PATH` cannot leak.

use std::path::Path;

fn run_with_empty_path(dir: &Path, args: &[&str]) -> i32 {
    let empty_path = dir.join("empty-path");
    std::fs::create_dir_all(&empty_path).expect("empty PATH directory is created");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .args(args)
        .env("PATH", &empty_path)
        .status()
        .expect("spawn govfuzz binary");
    status.code().unwrap_or(-1)
}

/// The Ada build inputs `build` expects to find, so the run reaches compiler
/// discovery instead of failing earlier on a malformed work dir.
fn create_minimal_work_dir(parent: &Path) -> std::path::PathBuf {
    let work_dir = parent.join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let harness_dir = work_dir.join("generated_harnesses/H-TEST");
    std::fs::create_dir_all(&source_dir).expect("instrumented source directory is created");
    std::fs::create_dir_all(&harness_dir).expect("harness directory is created");
    std::fs::write(
        source_dir.join("pkg.adb"),
        "procedure Pkg is begin null; end Pkg;\n",
    )
    .expect("instrumented source is written");
    std::fs::write(
        harness_dir.join("main.adb"),
        "procedure Main is begin null; end Main;\n",
    )
    .expect("harness main is written");
    work_dir
}

#[test]
fn build_subcommand_returns_two_when_no_compiler_present() {
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-build-no-compiler-")
        .tempdir()
        .expect("tempdir");
    let work_dir = create_minimal_work_dir(temp.path());
    let exit = run_with_empty_path(
        temp.path(),
        &["build", work_dir.to_str().expect("utf-8 work dir")],
    );
    assert_eq!(exit, 2, "no compiler on PATH must exit 2");
}

#[test]
fn stub_subcommand_returns_two_when_no_compiler() {
    let temp = tempfile::Builder::new()
        .prefix("govfuzz-stub-no-compiler-")
        .tempdir()
        .expect("tempdir");
    let exit = run_with_empty_path(temp.path(), &["stub", "/tmp/govfuzz-missing-work"]);
    assert_eq!(exit, 2, "no compiler on PATH must exit 2");
}
