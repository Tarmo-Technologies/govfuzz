// SPDX-License-Identifier: Apache-2.0
//! Randomness determinism.
//!
//! Determinism is the premise of the whole replay and env-capsule story: a
//! saved input is a reproducer only if the second run makes the same decisions
//! as the first. Nothing in the shim used to intercept randomness, so a target
//! seeding a hash or minting an id from `rand`/`getrandom` could take a
//! different path on replay and a crash found once might never reproduce.
//!
//! The probe prints the values it observes. Two runs WITH the gate must agree
//! byte for byte; a run WITHOUT it must still see real entropy, so the plugin
//! cannot silently distort an ordinary run.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/govfuzz_runtrace_shim")
        .join("target")
}

fn shim_so() -> Option<PathBuf> {
    let base = target_dir();
    for profile in ["debug", "release"] {
        let p = base.join(profile).join("libgovfuzz_runtrace_shim.so");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

const PROBE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
int main(void) {
    unsigned char buf[4];
    printf("%d,%d|", rand(), rand());
    if (getrandom(buf, sizeof buf, 0) != (long)sizeof buf) return 2;
    printf("%02x%02x%02x%02x\n", buf[0], buf[1], buf[2], buf[3]);
    return 0;
}
"#;

fn run(probe: &PathBuf, shim: &PathBuf, deterministic: bool) -> String {
    let mut cmd = Command::new(probe);
    cmd.env("LD_PRELOAD", shim);
    if deterministic {
        cmd.env("GOVFUZZ_FAKE_DETERMINISM", "1");
    }
    let out = cmd.output().expect("run probe");
    assert!(out.status.success(), "probe failed: {:?}", out.status);
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn randomness_replays_identically_under_the_gate() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-det-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("det.c");
    let bin = dir.join("det");
    std::fs::write(&src, PROBE).unwrap();
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(built, "probe must compile");

    // Gated: two runs must agree byte for byte, or a saved crash input is not a
    // reproducer.
    let first = run(&bin, &shim, true);
    let second = run(&bin, &shim, true);
    assert_eq!(
        first, second,
        "two gated runs must observe identical randomness"
    );

    // ...and the plugin must not distort an ordinary run: without the gate the
    // real entropy source still shows through.
    let ungated = run(&bin, &shim, false);
    assert_ne!(
        ungated, first,
        "without the gate real entropy must show through"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
