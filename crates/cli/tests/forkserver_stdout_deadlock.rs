// SPDX-License-Identifier: Apache-2.0

//! #427 regression: a target that writes to stdout must not deadlock the
//! persistent fork-server.
//!
//! The fork-server's sync channel is the harness's *original stdout* (the pipe
//! the engine reads one sync byte per input from). A target that also writes to
//! stdout shared that pipe: once its output passed the ~64 KB pipe buffer the
//! harness blocked in `write()`, stopped reading stdin, and the engine — feeding
//! the next frame lock-step — blocked in `write_input_frame`. A two-pipe
//! deadlock that hung `govfuzz auto` indefinitely (observed: an Ada harness stuck
//! on `pipe_write` for >60 min). The fix redirects the target's stdout to
//! `/dev/null` and writes sync bytes to a saved control fd, so neither pipe ever
//! fills.
//!
//! This builds a passthrough libFuzzer C target that writes >256 KB to stdout on
//! every input (so it goes through the driver/fork-server path) and asserts
//! `auto` runs it to completion under a wall-clock deadline. Pre-fix this hangs
//! and trips the deadline (test failure); post-fix it finishes and fuzzes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod support;

/// The driver build needs clang (the SanitizerCoverage runtime) + make. Skip
/// cleanly when absent — a missing toolchain is not a regression.
fn c_driver_toolchain() -> bool {
    let clang = Command::new("clang")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let make = Command::new("make")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    clang && make
}

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-fs-stdout-{prefix}-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A passthrough libFuzzer target that writes >256 KB to stdout per input.
const STDOUT_SPAMMER: &str = r#"// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char chunk[4096];
    for (unsigned i = 0; i < sizeof(chunk); i++) chunk[i] = 'x';
    /* 80 * 4096 = 320 KB, far past the ~64 KB pipe buffer the fork-server sync
       channel used to share with the target's stdout (#427). */
    for (int n = 0; n < 80; n++) {
        (void)!write(1, chunk, sizeof(chunk));
        printf("iteration n=%d size=%zu\n", n, size);
    }
    fflush(stdout);
    return (size >= 2 && data[0] == 'O' && data[1] == 'K') ? 1 : 0;
}
"#;

/// Run `govfuzz auto src` in `root`, killing it after `deadline`. Returns
/// `Some(exit_code)` if it finished on its own, `None` if it had to be killed
/// (i.e. it hung — the deadlock regression).
fn run_auto_bounded(root: &Path, per_target_time: &str, deadline: Duration) -> Option<i32> {
    let mut child = support::govfuzz_cargo_command()
        .current_dir(root)
        .args(["auto", "src", "--per-target-time", per_target_time])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn govfuzz auto");
    let until = Instant::now() + deadline;
    loop {
        match child.try_wait().expect("wait govfuzz auto") {
            Some(status) => return Some(status.code().unwrap_or(-1)),
            None => {
                if Instant::now() >= until {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

#[test]
fn stdout_spamming_target_does_not_deadlock_fork_server() {
    if !c_driver_toolchain() {
        eprintln!("skipping: clang/make toolchain unavailable");
        return;
    }
    let root = tmpdir("spam");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("spam.c"), STDOUT_SPAMMER).unwrap();

    // Generous deadline: post-fix the run finishes in well under this (the
    // spam goes to /dev/null); pre-fix it hangs forever and trips it.
    let outcome = run_auto_bounded(&root, "4", Duration::from_secs(120));
    assert!(
        outcome.is_some(),
        "govfuzz auto HUNG on a stdout-writing target — the fork-server stdout/sync \
         pipe deadlock has regressed (#427)"
    );

    // It must also have actually built+fuzzed the target through the driver
    // (the fork-server path), proving the no-deadlock result is real and not a
    // build skip.
    let run_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("govfuzz_work/auto/run.json")).unwrap())
            .unwrap();
    let built: Vec<_> = run_json["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed"))
        .collect();
    assert_eq!(
        built.len(),
        1,
        "the stdout-spamming C target must build+fuzz: {run_json}"
    );
    let execs: u64 = built[0]["outcome"]["passes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["executions"].as_u64())
        .sum();
    assert!(
        execs > 0,
        "the fork-server must execute the stdout-spamming target (no hang): {run_json}"
    );
}
