// SPDX-License-Identifier: Apache-2.0
//! #440: POSIX message-queue virtualization.
//!
//! A partition's message loop blocks in `mq_receive` waiting for another
//! partition; under fuzzing there is none, so the handler never runs. The shim
//! delivers the fuzz input as messages: `mq_open` succeeds with a fake
//! descriptor and `mq_receive` returns mode-driven bytes — bounded, so a
//! `while (1) mq_receive(...)` loop terminates instead of spinning.
//!
//! The probe opens a queue that does not exist (so WITHOUT the shim it can't even
//! open), receives a first message (must have content under rng mode), then
//! drains until EAGAIN. It returns 0 only if it got content AND the receive loop
//! terminated within a sane bound — proving both delivery and the anti-hang cap.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
#include <mqueue.h>
#include <fcntl.h>
int main(void) {
    mqd_t q = mq_open("/govfuzz_mq_vtest", O_RDONLY);
    if (q == (mqd_t)-1) return 2;          /* without the shim: no such queue */
    char buf[8192];
    int first = mq_receive(q, buf, sizeof buf, 0);
    if (first <= 0) return 3;              /* expected a message with content */
    int count = 1, guard = 0;
    while (guard++ < 100000) {
        int n = mq_receive(q, buf, sizeof buf, 0);
        if (n < 0) break;                  /* EAGAIN: delivery bounded -> loop ends */
        count++;
    }
    mq_close(q);
    /* content delivered AND the loop terminated within the delivery cap */
    return (count >= 1 && count <= 1000) ? 0 : 4;
}
"#;

#[test]
fn mq_receive_delivers_bounded_fuzz_messages_under_a_fuzz_pass() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-mq-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("mq.c");
    std::fs::write(&src, PROBE).unwrap();
    let bin = dir.join("mq");
    assert!(
        Command::new(cc)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .arg("-lrt") // mq_* live in librt
            .status()
            .unwrap()
            .success(),
        "mq probe failed to compile"
    );

    let log = dir.join("rt.jsonl");
    let mut child = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "rng") // deterministic non-empty messages
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mq probe");

    // A broken (unbounded) delivery would hang; bound the wait so that fails the
    // test loudly instead of hanging.
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = std::fs::remove_dir_all(&dir);
            panic!("mq_receive virtualization HUNG (delivery not bounded)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    assert_eq!(
        status.code(),
        Some(0),
        "mq probe must open a fake queue, receive content, and terminate (code {:?})",
        status.code()
    );

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|l| l.contains("\"e\":\"mq_receive\"") && l.contains("\"v\":1")),
        "virtualized mq_receive event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
