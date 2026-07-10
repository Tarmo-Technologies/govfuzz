// SPDX-License-Identifier: Apache-2.0
//! #438: POSIX shared-memory virtualization.
//!
//! The shim turns `shm_open` into a harness-private memfd during a fuzz pass, so
//! a second opener of the same name does NOT see the first's writes — there is no
//! foreign writer, which is what makes a partitioned target deterministic and
//! kills the cross-partition MSan/TSan false-positive classes.
//!
//! The probe shm_opens one name twice, writes 0x42 through the first mapping, and
//! reads back through the second. WITHOUT the shim the two map the same real
//! object, so it reads 0x42 (proving the probe genuinely exercises shared
//! memory). WITH the shim (a faking pass) the two get distinct private memfds, so
//! it reads 0. A real contrast — the shim flips shared into private.

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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    const char *name = "/govfuzz_shm_vtest";
    shm_unlink(name);
    int fd1 = shm_open(name, O_CREAT | O_RDWR, 0600);
    if (fd1 < 0) return 10;
    if (ftruncate(fd1, 4096) != 0) return 11;
    unsigned char *a = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
    if (a == MAP_FAILED) return 12;
    a[0] = 0x42;
    int fd2 = shm_open(name, O_RDWR, 0600);
    if (fd2 < 0) return 13;
    unsigned char *b = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    if (b == MAP_FAILED) return 14;
    int v = b[0];
    shm_unlink(name);
    return v; /* real shm: 0x42 (66); virtualized: 0 */
}
"#;

#[test]
fn shm_open_is_virtualized_to_private_memory_under_a_fuzz_pass() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shm-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(&src, PROBE).unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .arg("-lrt") // shm_open lives in librt on older glibc; harmless otherwise
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    // Baseline (no shim): the two openers share the real object -> reads 0x42.
    // If the host has no working POSIX shm, skip rather than fail.
    let baseline = Command::new(&bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run baseline");
    match baseline.code() {
        Some(0x42) => {} // real shared memory works here
        other => {
            eprintln!("skipping: host POSIX shm baseline returned {other:?}, not 0x42");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    }

    // Under the shim during a faking pass: distinct private memfds -> reads 0.
    let log = dir.join("rt.jsonl");
    let virtualized = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "empty") // any faking mode
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run under shim");
    assert_eq!(
        virtualized.code(),
        Some(0),
        "shm_open must be virtualized to private memory (reader saw the writer's byte — still shared)"
    );

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|l| l.contains("\"e\":\"shm_open\"") && l.contains("\"v\":1")),
        "virtualized shm_open event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// System V probe: `argv[1]` is `w` (create + write 0x42 + detach) or `r`
/// (attach + read + `IPC_RMID`), `argv[2]` is the key. Across two SEPARATE
/// process runs a real kernel segment persists after the writer exits, so the
/// reader sees 0x42; under the shim each process gets its OWN private segment,
/// so the reader sees 0.
const SYSV_PROBE: &str = r#"
#define _GNU_SOURCE
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 3) return 100;
    key_t key = (key_t)strtol(argv[2], 0, 10);
    if (argv[1][0] == 'w') {
        int id = shmget(key, 4096, IPC_CREAT | 0600);
        if (id < 0) return 10;
        unsigned char *a = shmat(id, 0, 0);
        if (a == (void *)-1) return 11;
        a[0] = 0x42;
        shmdt(a);
        return 0;
    } else {
        int id = shmget(key, 4096, 0600);
        if (id < 0) return 0; /* no real segment to read */
        unsigned char *b = shmat(id, 0, 0);
        if (b == (void *)-1) return 0;
        int v = b[0];
        shmctl(id, IPC_RMID, 0);
        return v; /* real shm: 0x42 (66); virtualized: 0 */
    }
}
"#;

#[test]
fn sysv_shmget_is_virtualized_to_private_memory_under_a_fuzz_pass() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-sysv-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("sysv.c");
    std::fs::write(&src, SYSV_PROBE).unwrap();
    let bin = dir.join("sysv");
    assert!(
        Command::new(cc)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap()
            .success(),
        "sysv probe failed to compile"
    );

    // Per-test key so concurrent / repeated runs don't collide on a stale segment.
    let key = format!("{}", 0x4747_0000u32 + (std::process::id() & 0xffff));
    let run = |with_shim: bool, role: &str, log: Option<&std::path::Path>| -> Option<i32> {
        let mut c = Command::new(&bin);
        c.arg(role)
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if with_shim {
            c.env("LD_PRELOAD", &shim)
                .env("GOVFUZZ_RUNTRACE_MODE", "empty");
            if let Some(l) = log {
                c.env("GOVFUZZ_RUNTRACE_LOG", l);
            }
        }
        c.status().expect("run sysv probe").code()
    };

    // Baseline (no shim): writer creates a kernel segment that persists; the
    // reader sees 0x42. Skip if the host has no working System V shm.
    assert_eq!(run(false, "w", None), Some(0), "sysv writer failed");
    match run(false, "r", None) {
        Some(0x42) => {}
        other => {
            eprintln!("skipping: host System V shm baseline returned {other:?}, not 0x42");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    }

    // Under the shim: each process gets its own private segment -> reader sees 0.
    let log = dir.join("rt.jsonl");
    assert_eq!(
        run(true, "w", Some(&log)),
        Some(0),
        "shim sysv writer failed"
    );
    assert_eq!(
        run(true, "r", Some(&log)),
        Some(0),
        "System V shmget must be virtualized to private memory (reader saw the writer's byte across processes — still shared)"
    );
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|l| l.contains("\"e\":\"shmget\"") && l.contains("\"v\":1")),
        "virtualized shmget event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// #443: anonymous `mmap(MAP_SHARED)` virtualization. The probe maps an anonymous
/// shared region, forks, the child writes 0x42, and the parent reads after the
/// child exits. WITHOUT the shim the pages are genuinely shared, so the parent
/// reads 0x42; under a fuzz pass the shim rewrites MAP_SHARED → MAP_PRIVATE, so
/// the child's write is copy-on-write-private and the parent reads 0.
const ANON_MMAP_PROBE: &str = r#"
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    unsigned char *p =
        mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 2;
    p[0] = 0;
    pid_t pid = fork();
    if (pid < 0) return 3;
    if (pid == 0) {
        p[0] = 0x42;
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    int v = p[0];
    munmap(p, 4096);
    return v; /* shared: 0x42 (66); converted to private: 0 */
}
"#;

#[test]
fn anonymous_map_shared_is_privatized_under_a_fuzz_pass() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-anonmmap-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("anon.c");
    std::fs::write(&src, ANON_MMAP_PROBE).unwrap();
    let bin = dir.join("anon");
    assert!(
        Command::new(cc)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap()
            .success(),
        "anon mmap probe failed to compile"
    );

    // Baseline (no shim): anonymous MAP_SHARED is shared across fork -> 0x42.
    let baseline = Command::new(&bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run baseline")
        .code();
    assert_eq!(
        baseline,
        Some(0x42),
        "baseline anonymous MAP_SHARED must be shared across fork (got {baseline:?})"
    );

    // Under the shim: MAP_SHARED -> MAP_PRIVATE, so the child's write is private
    // and the parent reads 0.
    let log = dir.join("rt.jsonl");
    let virtualized = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "empty")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run under shim")
        .code();
    assert_eq!(
        virtualized,
        Some(0),
        "anonymous MAP_SHARED must be privatized under a fuzz pass (parent saw the child's write — still shared)"
    );

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|l| l.contains("\"e\":\"mmap_private\"") && l.contains("\"v\":1")),
        "mmap_private event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression for the dogfood finding: a virtualized shm region must be DRIVEN by
/// the fuzz input, not left zero — otherwise a target that reads shared memory
/// (expecting a peer to have written it) takes the same path every input and the
/// fuzzer can't reach content-dependent handlers. The probe shm_opens, mmaps, and
/// reports whether the region has any non-zero byte. Under a content-bearing pass
/// (rng) it must be non-zero; a freshly created real shm object (no shim) is zero.
const SHM_CONTENT_PROBE: &str = r#"
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    int fd = shm_open("/govfuzz_shm_content", O_CREAT | O_RDWR, 0600);
    if (fd < 0) return 2;
    if (ftruncate(fd, 4096) != 0) return 3;
    unsigned char *p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) return 4;
    int nonzero = 0;
    for (int i = 0; i < 256; i++) {
        if (p[i]) { nonzero = 1; break; }
    }
    shm_unlink("/govfuzz_shm_content");
    return nonzero; /* 1 = fuzz-driven content present */
}
"#;

#[test]
fn shm_content_is_fuzz_driven_under_a_content_bearing_pass() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shm-content-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("content.c");
    std::fs::write(&src, SHM_CONTENT_PROBE).unwrap();
    let bin = dir.join("content");
    assert!(
        Command::new(cc)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .arg("-lrt")
            .status()
            .unwrap()
            .success(),
        "shm content probe failed to compile"
    );

    // Under the shim in rng mode the region is filled with mode-driven bytes, so a
    // reader sees content -> exit 1. (Without this, a fresh real shm reads zero.)
    let virt = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_MODE", "rng")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run under shim")
        .code();
    assert_eq!(
        virt,
        Some(1),
        "virtualized shm region must be fuzz-driven (non-zero) so the fuzzer reaches content-dependent code; got {virt:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
