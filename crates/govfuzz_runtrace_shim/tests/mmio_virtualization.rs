// SPDX-License-Identifier: Apache-2.0
//! #441: MMIO / device-register virtualization via open-interception.
//!
//! A Linux MMIO driver does `open("/dev/mem")` + `mmap(fd)` to reach device
//! registers. Unprivileged that open fails (EACCES), so the driver path can't be
//! fuzzed; and as root, mapping real `/dev/mem` would touch real hardware. During
//! a fuzz pass the shim redirects the open to a private, mode-filled memfd, so the
//! open succeeds unprivileged, the mmap maps fuzz-controlled memory, and no real
//! device memory is touched.
//!
//! The probe opens `/dev/mem`, mmaps a page, and reads a register. WITHOUT the
//! shim it fails to open (unprivileged) and returns 2. WITH the shim it opens the
//! private fd, maps it, reads a byte, and returns 0 — a real behavioral change.

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
#define _GNU_SOURCE
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    int fd = open("/dev/mem", O_RDWR);
    if (fd < 0) return 2;                 /* unprivileged: EACCES without the shim */
    volatile unsigned char *regs =
        mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (regs == MAP_FAILED) return 3;
    unsigned char r = regs[0];            /* read a "device register" */
    (void)r;
    munmap((void *)regs, 4096);
    close(fd);
    return 0;
}
"#;

#[test]
fn dev_mem_open_is_redirected_to_private_mmap_under_a_fuzz_pass() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-mmio-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("mmio.c");
    std::fs::write(&src, PROBE).unwrap();
    let bin = dir.join("mmio");
    assert!(
        Command::new(cc)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap()
            .success(),
        "mmio probe failed to compile"
    );

    // Baseline (no shim): unprivileged open of /dev/mem fails. If we happen to be
    // root (open succeeds), skip — the contrast only holds unprivileged.
    let baseline = Command::new(&bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run baseline")
        .code();
    if baseline == Some(0) {
        eprintln!("skipping: running as root, /dev/mem opens for real");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // Under the shim: the open is redirected to a private mode-filled memfd, so it
    // opens, maps, and reads successfully without touching real device memory.
    let log = dir.join("rt.jsonl");
    let virtualized = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "rng")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run under shim")
        .code();
    assert_eq!(
        virtualized,
        Some(0),
        "/dev/mem open+mmap+read must succeed under the shim (MMIO virtualization)"
    );

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|l| l.contains("\"e\":\"mmio\"") && l.contains("/dev/mem")),
        "mmio substitution event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
