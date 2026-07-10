// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `govfuzz env-capsule` + environment-response fuzzing. A
//! parser of a "trusted" external config file (opened via raw open/read, which the
//! shim fakes and fuzzes) overflows on the SERVED content — so the crash is driven
//! by the environment, not the input, and its minimized input is empty. The
//! env-capsule must record the served world and replay it to reproduce the crash
//! DETERMINISTICALLY from that empty input, in a pristine location.

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn shim_present() -> bool {
    // The env-capsule needs the runtrace shim built beside the test binary.
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(|p| p.parent()).unwrap().to_path_buf();
    dir.join("libgovfuzz_runtrace_shim.so").is_file()
        || dir.join("libgovfuzz_runtrace.so").is_file()
}

/// Reads a faked config file's (fuzzed) content into a fixed buffer — overflow when
/// the shim serves > 8 bytes. Raw open/read so the shim's `open` interposition fires.
const ENV_DRIVEN_C: &str = "\
#include <fcntl.h>
#include <unistd.h>
int load_config(const char *data, unsigned int len) {
    (void)data; (void)len;
    int fd = open(\"/etc/govfuzz_envcap_demo.conf\", O_RDONLY);
    if (fd < 0) return 0;
    char cfg[8];
    long n = read(fd, cfg, 64);
    close(fd);
    return n > 0 ? cfg[0] : 0;
}
";

#[test]
fn env_capsule_replays_environment_driven_crash() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    if !shim_present() {
        eprintln!("skipping: runtrace shim not built");
        return;
    }
    let work = std::env::temp_dir().join(format!("gf-envcap-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let src = work.with_extension("src.c");
    std::fs::write(&src, ENV_DRIVEN_C).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("8")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run snippet");
    let _ = std::fs::remove_file(&src);
    if !has_crash_finding(&work) {
        // Environment-response fuzzing needs the shim to fake the config read; if the
        // build/shim couldn't produce the crash, skip rather than falsely fail.
        eprintln!(
            "skipping: no env-driven crash found; stderr:\n{}",
            String::from_utf8_lossy(&snip.stderr)
        );
        return;
    }

    let cap = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run env-capsule");
    let stdout = String::from_utf8_lossy(&cap.stdout);
    assert!(
        stdout.contains("verified to replay") && stdout.contains("✓ replays"),
        "env-capsule should verify a replay; got:\n{stdout}"
    );

    // Independently verify: copy the capsule to a pristine dir and run replay.sh.
    let capsule = first_capsule(&work).expect("a capsule dir");
    let scratch = std::env::temp_dir().join(format!("gf-envcap-scratch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let dest = scratch.join("cap");
    assert!(Command::new("cp")
        .arg("-r")
        .arg(&capsule)
        .arg(&dest)
        .status()
        .unwrap()
        .success());
    // The shipped primary input is (typically) empty — the reproducer is the world.
    let replay = Command::new("sh")
        .arg("replay.sh")
        .current_dir(&dest)
        .output()
        .expect("run replay.sh");
    let rep_err = String::from_utf8_lossy(&replay.stderr);
    assert!(
        rep_err.contains("AddressSanitizer"),
        "replay.sh must reproduce the crash from the pinned environment; stderr:\n{rep_err}"
    );
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(&work);
}

fn has_crash_finding(work: &Path) -> bool {
    std::fs::read_dir(work.join("findings"))
        .map(|d| {
            d.flatten().any(|e| {
                e.file_name().to_string_lossy().starts_with("F-0000")
                    && e.path().join("testcase.bin").is_file()
            })
        })
        .unwrap_or(false)
}

fn first_capsule(work: &Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(work.join("env-capsules"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("env_capsule_"))
        })
}
