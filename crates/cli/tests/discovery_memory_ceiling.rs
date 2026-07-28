// SPDX-License-Identifier: Apache-2.0
//
// Discovery degrades under memory pressure instead of being OOM-killed.
//
// Target discovery parses every source file in the tree and holds every
// candidate in memory. On a large C++ estate that exhausts RAM: in the
// 500-project sweep, carbon-language/carbon-lang was SIGKILLed (exit -9)
// during discovery in BOTH `list targets` and `auto`, so govfuzz produced no
// target list at all — the worst possible outcome, because a hard kill is
// indistinguishable from a hang and leaves nothing to act on.
//
// The static scan already survives those trees by degrading under an RSS
// ceiling. Discovery now shares that guard: past the ceiling it stops parsing
// new files, says so, and returns what it has.
//
// `GOVFUZZ_MAX_MEMORY_KB=1` forces pressure on the first sample (any live
// process is over 1 kB of RSS), which makes the degradation path deterministic
// without needing a multi-gigabyte repository.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/discovery_memory")
        .canonicalize()
        .expect("canonicalize discovery_memory fixture")
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
fn discovery_degrades_under_memory_pressure_instead_of_being_killed() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }

    let out = Command::new(&bin)
        .args(["list", "targets", fixture().to_str().unwrap()])
        .env("GOVFUZZ_MAX_MEMORY_KB", "1")
        .output()
        .expect("run govfuzz list targets under a 1 kB ceiling");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    // The whole point: a normal exit, not a signal. `code()` is None when the
    // process died on a signal, which is exactly the carbon-lang failure.
    assert!(
        out.status.code().is_some(),
        "discovery must not die on a signal under memory pressure; status={:?}\n{stderr}",
        out.status
    );
    assert!(
        stderr.contains("memory ceiling") && stderr.contains("PARTIAL"),
        "a truncated target list must say so, or it reads as 'this project has \
         nothing to fuzz':\n{stderr}"
    );
}

#[test]
fn discovery_is_unaffected_without_pressure() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }

    // The guard must be inert at a normal ceiling — the same fixture discovers
    // its targets and says nothing about memory.
    let out = Command::new(&bin)
        .args(["list", "targets", fixture().to_str().unwrap()])
        .env("GOVFUZZ_MAX_MEMORY_KB", "8000000")
        .output()
        .expect("run govfuzz list targets at a normal ceiling");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert!(
        !stderr.contains("memory ceiling"),
        "the guard must not fire with memory to spare:\n{stderr}"
    );
    assert!(
        stdout.contains("dm_parse") && stdout.contains("dm_scan"),
        "both targets must still be discovered:\n{stdout}\n{stderr}"
    );
}
