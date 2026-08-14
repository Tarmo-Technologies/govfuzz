// SPDX-License-Identifier: Apache-2.0
//! Device control plane.
//!
//! The MMIO fake (#441) redirects a device open to a private memfd so register
//! reads hit fuzz-controlled memory — but a memfd answers every `ioctl` with
//! `ENOTTY`, and real drivers and userspace HALs (V4L2, UIO, i2c, SPI, hidraw,
//! CAN) negotiate capabilities by ioctl BEFORE touching a register. Without an
//! answer the driver bails out and the prepared register window is never read.
//!
//! The probe has a driver's shape: open the device, negotiate, then report
//! whether the negotiated buffer came back populated. Without the shim it
//! cannot even open; under a faking pass it must get all the way through.

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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
/* _IOR encodes direction and payload size in the request, which is what lets
   the shim fill exactly 16 bytes and no more. */
#define GF_CAPS _IOR('g', 1, unsigned char[16])
int main(void) {
    unsigned char caps[16];
    int pipefd[2];
    if (pipe(pipefd) != 0) return 5;
    memset(caps, 0, sizeof caps);
    /* ENOTTY alone is not permission to fake: an ordinary pipe must retain its
       real failure and must not have its caller buffer populated. */
    if (ioctl(pipefd[0], GF_CAPS, caps) == 0) return 6;
    for (unsigned i = 0; i < sizeof caps; i++) if (caps[i] != 0) return 7;
    close(pipefd[0]);
    close(pipefd[1]);
    int fd = open("/dev/uio0", O_RDWR);
    if (fd < 0) return 2;                       /* no shim: device absent */
    memset(caps, 0, sizeof caps);
    if (ioctl(fd, GF_CAPS, caps) != 0) return 3; /* memfd alone: ENOTTY */
    int nonzero = 0;
    for (unsigned i = 0; i < sizeof caps; i++) nonzero |= caps[i];
    return nonzero ? 0 : 4;                     /* negotiated AND populated */
}
"#;

#[test]
fn a_capability_ioctl_is_answered_so_the_driver_reaches_the_register_window() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-ioctl-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("ioctl.c");
    let bin = dir.join("ioctl_probe");
    std::fs::write(&src, PROBE).unwrap();
    assert!(
        Command::new(cc)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "probe must compile"
    );

    // Without the shim the device does not exist, so the driver never starts —
    // which is the situation the MMIO fake exists to fix.
    let bare = Command::new(&bin).output().expect("run probe");
    assert_eq!(
        bare.status.code(),
        Some(2),
        "expected the open to fail without the shim"
    );

    // Under a faking pass the open is redirected AND the negotiation answered,
    // with the payload sized by the request's own _IOC_SIZE.
    let faked = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_MODE", "rng")
        .output()
        .expect("run probe under the shim");
    assert_eq!(
        faked.status.code(),
        Some(0),
        "driver must negotiate and receive a populated buffer (3 = ENOTTY, 4 = zeroed)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
