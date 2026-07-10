// SPDX-License-Identifier: Apache-2.0
//! Regression guard for the dlvsym version bug: the shim resolved
//! every libc symbol at a hardcoded GLIBC_2.2.5, which returns NULL
//! for the GLIBC_2.4-versioned openat/faccessat/readlinkat. The
//! null-fallback then called the exported hook again and span
//! forever. A target's first openat() must complete, not hang.

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

/// Locate the preload cdylib without triggering a nested build. A
/// plain integration-test invocation may compile only this test
/// binary, so skip rather than load a stale .so from a previous build.
fn shim_so() -> Option<PathBuf> {
    let base = target_dir();
    for profile in ["debug", "release"] {
        let p = base.join(profile).join("libgovfuzz_runtrace_shim.so");
        if p.is_file() {
            let shim_mtime = p.metadata().and_then(|m| m.modified()).ok();
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let newest_hook_mtime = [
                "src/hooks/assertion.rs",
                "src/hooks/env.rs",
                "src/hooks/fs.rs",
                "src/hooks/proc.rs",
                "src/hooks/format.rs",
                "src/hooks/format_hooks.c",
            ]
            .iter()
            .filter_map(|relative| {
                manifest_dir
                    .join(relative)
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
            })
            .max();
            if let (Some(shim_mtime), Some(newest_hook_mtime)) = (shim_mtime, newest_hook_mtime) {
                if shim_mtime < newest_hook_mtime {
                    eprintln!(
                        "skipping: {p:?} is older than hook sources; run cargo build -p govfuzz_runtrace_shim first"
                    );
                    continue;
                }
            }
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

#[test]
fn at_syscall_hooks_do_not_hang_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-norec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            int fd = openat(AT_FDCWD, "/govfuzz/missing", O_RDONLY);
            if (fd >= 0) close(fd);
            faccessat(AT_FDCWD, "/govfuzz/missing", R_OK, 0);
            char buf[64];
            (void)readlinkat(AT_FDCWD, "/govfuzz/missing", buf, sizeof buf);
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let mut child = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn probe");

    // The old recursive hook span at 100% CPU forever; bound it.
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = std::fs::remove_dir_all(&dir);
            panic!("openat/faccessat/readlinkat under the shim HUNG (recursion regression)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(status.success(), "probe exited abnormally: {status:?}");
}

#[test]
fn env_hooks_log_secure_getenv_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-env-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #define _GNU_SOURCE
        #include <stdlib.h>
        int main(void) {
            unsetenv("DB_PASSWORD");
            return secure_getenv("DB_PASSWORD") != 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env_remove("DB_PASSWORD")
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"secure_getenv\"") && line.contains("\"n\":\"DB_PASSWORD\"")
        }),
        "secure_getenv event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn env_hooks_log_present_getenv_without_value_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-env-present-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdlib.h>
        int main(void) {
            const char *value = getenv("DB_PASSWORD");
            return value == 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("DB_PASSWORD", "super-secret-value")
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"getenv\"")
                && line.contains("\"n\":\"DB_PASSWORD\"")
                && line.contains("\"r\":1")
        }),
        "present getenv event missing from runtrace log:\n{text}"
    );
    assert!(
        !text.contains("super-secret-value"),
        "runtrace log leaked env value:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fs_hooks_log_open_close_lifecycle_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-lifecycle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The target file must live OUTSIDE the runtrace-log dir: that dir is the
    // engine-owned harness dir, and #403's self-exclusion (see policy.rs) keeps
    // the shim from auditing anything inside it. A real external open is what
    // this test exercises, so place it next to the dir, not within it.
    let target = std::env::temp_dir().join(format!(
        "govfuzz-shim-lifecycle-target-{}.txt",
        std::process::id()
    ));
    std::fs::write(&target, "fixture").unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <fcntl.h>
        #include <unistd.h>
        int main(int argc, char **argv) {
            if (argc < 2) return 1;
            int fd = open(argv[1], O_RDONLY);
            if (fd < 0) return 2;
            if (close(fd) != 0) return 3;
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .arg(&target)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let expected_path = format!("\"p\":\"{}\"", target.display());
    assert!(
        text.lines()
            .any(|line| line.contains("\"e\":\"open\"") && line.contains(&expected_path)),
        "successful open event missing from runtrace log:\n{text}"
    );
    assert!(
        text.lines()
            .any(|line| line.contains("\"e\":\"close\"") && line.contains("\"r\":0")),
        "successful close event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&target);
}

#[test]
fn process_hooks_log_system_commands_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-process-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdlib.h>
        int main(void) {
            return system(":; :");
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|line| { line.contains("\"e\":\"system\"") && line.contains("\"c\":\":; :\"") }),
        "system command event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn format_hooks_log_printf_formats_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-format-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdio.h>
        int main(void) {
            return printf("static %d\n", 7) < 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"format\"")
                && line.contains("\"a\":\"printf\"")
                && line.contains("\"f\":\"static %d\\n\"")
        }),
        "printf format event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// #403: the insecure-temp-file oracle (GF-417 / CWE-377) must not flag
/// govfuzz's OWN per-harness instrumentation files. `govfuzz auto` writes
/// `coverage.shm` (and vp.shm / cmp.shm / runtrace.jsonl) into the harness
/// dir with O_CREAT-without-O_EXCL; when `--work-dir` is under /tmp those
/// SHM bitmaps otherwise self-trip the oracle, flooding every target with
/// phantom findings. A genuine target temp file OUTSIDE the engine dir must
/// still be flagged (the oracle is self-excluded, not disabled).
#[test]
fn insecure_tempfile_oracle_excludes_engine_owned_shm_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    // Mirror `govfuzz auto`: a per-harness dir UNDER /tmp (the #403 trigger),
    // holding the runtrace log + the coverage.shm bitmap the driver creates.
    let harness_dir =
        std::env::temp_dir().join(format!("govfuzz-shim-selfexcl-{}", std::process::id()));
    std::fs::create_dir_all(&harness_dir).unwrap();
    let owned_shm = harness_dir.join("coverage.shm");
    // A genuine attacker-racing temp file the target itself creates, OUTSIDE
    // the engine-owned dir: this one must STILL be flagged.
    let victim_name = format!("govfuzz-victim-{}.tmp", std::process::id());
    let target_tmp = std::env::temp_dir().join(&victim_name);

    let src = harness_dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <unistd.h>
        int main(int argc, char **argv) {
            // argv[1] = engine-owned coverage.shm (O_CREAT, no O_EXCL)
            // argv[2] = genuine insecure temp file the target creates
            int a = open(argv[1], O_CREAT | O_RDWR, 0600);
            if (a >= 0) close(a);
            int b = open(argv[2], O_CREAT | O_RDWR, 0600);
            if (b >= 0) close(b);
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = harness_dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = harness_dir.join("runtrace.jsonl");
    let status = Command::new(&bin)
        .arg(&owned_shm)
        .arg(&target_tmp)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let tempfile_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("\"e\":\"insecure_tempfile\""))
        .collect();

    let _ = std::fs::remove_dir_all(&harness_dir);
    let _ = std::fs::remove_file(&target_tmp);

    // The engine-owned coverage.shm must NOT be flagged (the #403 bug).
    assert!(
        !tempfile_lines
            .iter()
            .any(|line| line.contains("coverage.shm")),
        "engine-owned coverage.shm self-flagged as insecure temp file:\n{text}"
    );
    // ...but a genuine target temp file in /tmp still must be (oracle alive).
    assert!(
        tempfile_lines
            .iter()
            .any(|line| line.contains(&victim_name)),
        "genuine insecure temp file no longer flagged (oracle over-suppressed):\n{text}"
    );
}

#[test]
fn assertion_hooks_log_assert_failures_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-assert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <assert.h>
        int main(void) {
            assert(0 && "boom");
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(!status.success(), "assertion probe unexpectedly succeeded");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"assertion_failed\"")
                && line.contains("\"a\":\"__assert_fail\"")
                && line.contains("\\\"boom\\\"")
        }),
        "assertion failure event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// #422: the open/openat hooks must tag a path event with byte-origin
/// taint (`u`=1, `o`=offset) when the path was derived from the current
/// fuzz input, and must NOT tag an unrelated path. This is the runtime
/// substrate the `path-controlled-open-runtime` oracle (GF-405) confirms,
/// and the same publish→sink flow a generated harness uses
/// (`govfuzz_shim_set_fuzz_input` before driving the target).
#[test]
fn fs_hooks_record_path_taint_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("govfuzz-shim-taint-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    // The "input" embeds a tainted path; the program publishes it to the
    // shim, then opens (a) that exact path (controlled) and (b) an
    // unrelated path (not controlled). Both miss (ENOENT), so both take
    // the log_path_miss branch. The weak extern mirrors the harness
    // template: NULL when not preloaded, bound to the shim when preloaded.
    std::fs::write(
        &src,
        r#"
        #include <fcntl.h>
        #include <unistd.h>
        #include <string.h>
        #include <stddef.h>
        extern void govfuzz_shim_set_fuzz_input(const unsigned char *data, size_t size)
            __attribute__((weak));
        int main(void) {
            const char *input = "open:/var/lib/govfuzz-taint-probe.dat;mode=r";
            if (govfuzz_shim_set_fuzz_input)
                govfuzz_shim_set_fuzz_input((const unsigned char *)input, strlen(input));
            /* tainted: a >=4-byte substring of the published input */
            int a = open("/var/lib/govfuzz-taint-probe.dat", O_RDONLY);
            if (a >= 0) close(a);
            /* untainted: not derived from the input */
            int b = open("/var/lib/govfuzz-unrelated-file.dat", O_RDONLY);
            if (b >= 0) close(b);
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("GOVFUZZ_RUNTRACE_LOG", &log)
        .env("GOVFUZZ_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();

    let tainted_line = text
        .lines()
        .find(|line| line.contains("govfuzz-taint-probe.dat"))
        .unwrap_or_default();
    let untainted_line = text
        .lines()
        .find(|line| line.contains("govfuzz-unrelated-file.dat"))
        .unwrap_or_default();

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !tainted_line.is_empty(),
        "tainted open event missing from runtrace log:\n{text}"
    );
    assert!(
        tainted_line.contains("\"u\":1") && tainted_line.contains("\"o\":"),
        "tainted open event missing byte-origin taint fields: {tainted_line}"
    );
    assert!(
        !untainted_line.is_empty(),
        "untainted open event missing from runtrace log:\n{text}"
    );
    assert!(
        !untainted_line.contains("\"u\":1"),
        "untainted open event must not carry taint: {untainted_line}"
    );
}
