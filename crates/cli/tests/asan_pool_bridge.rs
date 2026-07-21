// SPDX-License-Identifier: Apache-2.0

//! #436: the custom-allocator ASan poison bridge (`c_runtime/govfuzz_asan.h`).
//!
//! Legacy / RTOS C hands out sub-regions of a static pool from a custom
//! allocator. ASan only knows about its own malloc redzones, so an overflow that
//! stays WITHIN the static pool array (past the logical allocation, but inside
//! the backing global) is a silent false negative.
//!
//! This test compiles the SAME overflow two ways under `-fsanitize=address`:
//!   * WITH the bridge (pool poisoned at init, allocation unpoisoned) -> ASan
//!     reports the one-past-allocation write.
//!   * WITHOUT the bridge -> the write into the still-addressable pool global is
//!     NOT caught (clean exit), which is exactly the false negative the bridge
//!     fixes.
//!
//! A non-rubber-stamp test: identical program, the bridge is the only difference,
//! and it flips a missed bug into a finding.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// clang (with the ASan runtime) is required. A missing toolchain is a skip, not
/// a failure.
fn have_clang_asan() -> bool {
    Command::new("clang")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn c_runtime_dir() -> PathBuf {
    // crates/cli -> repo root -> c_runtime
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("c_runtime")
}

fn tmpdir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-asan-pool-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A static-pool bump allocator. The one-past-allocation write at `a[8]` lands on
/// the next (unallocated) pool slot — inside the `pool` global, so plain ASan
/// misses it; poisoned by the bridge, so the bridge catches it.
const PROGRAM: &str = r#"
#include "govfuzz_asan.h"
#include <stddef.h>

static unsigned char pool[1024];
static size_t off = 0;

static void *bump(size_t n) {
    n = (n + 7u) & ~(size_t)7u; /* 8-byte align: exact ASan shadow granularity */
    if (off + n > sizeof pool) return 0;
    {
        void *p = &pool[off];
        off += n;
#ifdef USE_BRIDGE
        govfuzz_asan_on_alloc(p, n);
#endif
        return p;
    }
}

int main(void) {
#ifdef USE_BRIDGE
    govfuzz_asan_pool_init(pool, sizeof pool);
#endif
    {
        unsigned char *a = (unsigned char *)bump(8);
        if (!a) return 2;
        a[8] = 0x41; /* one past the 8-byte allocation, still inside `pool` */
        return (int)a[8];
    }
}
"#;

fn compile(dir: &std::path::Path, bin: &str, with_bridge: bool) -> bool {
    let src = dir.join("prog.c");
    std::fs::write(&src, PROGRAM).unwrap();
    let mut cmd = Command::new("clang");
    cmd.arg("-O1")
        .arg("-g")
        .arg("-fsanitize=address")
        .arg(format!("-I{}", c_runtime_dir().display()));
    if with_bridge {
        cmd.arg("-DUSE_BRIDGE");
    }
    cmd.arg("-o")
        .arg(dir.join(bin))
        .arg(&src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("spawn clang");
    if !out.status.success() {
        eprintln!("clang failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    out.status.success()
}

fn run(dir: &std::path::Path, bin: &str) -> (Option<i32>, String) {
    // Do not let llvm-symbolizer consult a distro-configured remote debuginfod
    // server. A network outage must not turn this local test into an unbounded
    // CI hang. Capture stderr in a file so the child cannot fill a pipe while
    // the timeout loop waits for it.
    let stderr_path = dir.join(format!("{bin}.stderr"));
    let stderr_file = std::fs::File::create(&stderr_path).expect("create stderr capture");
    let mut child = Command::new(dir.join(bin))
        .env("ASAN_OPTIONS", "abort_on_error=0:detect_leaks=0")
        .env("DEBUGINFOD_URLS", "")
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("run program");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll program") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("{bin} did not exit within 15 seconds; stderr:\n{stderr}");
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stderr = std::fs::read_to_string(stderr_path).expect("read stderr capture");
    (status.code(), stderr)
}

#[test]
fn bridge_makes_asan_catch_intra_pool_overflow() {
    if !have_clang_asan() {
        eprintln!("skipping: clang not available");
        return;
    }
    let dir = tmpdir();

    // With the bridge: the pool is poisoned and the allocation unpoisoned, so the
    // one-past write hits poisoned shadow -> ASan reports it.
    assert!(
        compile(&dir, "with_bridge", true),
        "bridge build must compile"
    );
    let (code, stderr) = run(&dir, "with_bridge");
    assert!(
        stderr.contains("AddressSanitizer"),
        "bridge build must report an ASan error; stderr was:\n{stderr}"
    );
    assert_ne!(
        code,
        Some(0),
        "bridge build must NOT exit cleanly (the overflow is a finding)"
    );

    // Without the bridge: the same write into the static pool global is not caught
    // — the false negative the bridge exists to fix.
    assert!(
        compile(&dir, "no_bridge", false),
        "control build must compile"
    );
    let (code, stderr) = run(&dir, "no_bridge");
    assert!(
        !stderr.contains("AddressSanitizer"),
        "control build must NOT report an ASan error (plain ASan misses intra-pool overflow); stderr:\n{stderr}"
    );
    assert_eq!(code, Some(0x41), "control build runs to completion");
}
