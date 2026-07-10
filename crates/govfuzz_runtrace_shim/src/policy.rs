// SPDX-License-Identifier: Apache-2.0

//! "Should this path be audited?" policy. Real-system paths
//! (/proc/self/...,  /sys/devices, /dev/urandom, the host's own
//! work dir) are normal target behaviour and should NOT appear in
//! the audit log — only paths that look like genuinely-missing
//! external resources matter.

use std::sync::OnceLock;

/// The directory portion of `path`, INCLUDING the trailing '/'. `None`
/// when `path` has no '/' (a bare relative filename has no usable dir).
fn dir_with_trailing_slash(path: &[u8]) -> Option<&[u8]> {
    let slash = path.iter().rposition(|&b| b == b'/')?;
    Some(&path[..=slash])
}

/// GovFuzz's own per-harness instrumentation directory, derived ONCE from
/// the `GOVFUZZ_RUNTRACE_LOG` path. `govfuzz auto` writes the runtrace log,
/// the coverage/value-profile/cmplog SHM bitmaps, and every other
/// instrumentation artefact directly into this directory, so anything under
/// it is engine infrastructure, never target behaviour. Returned WITH the
/// trailing '/' so the prefix test in [`should_audit_path`] matches only
/// paths *inside* the dir, never a sibling such as `<dir>-evil/...`. `None`
/// when the var is unset (host is not running under `govfuzz auto`) or has
/// no directory component.
///
/// Caching is load-bearing for correctness, not just speed: `env::var_os`
/// routes through the hooked `getenv`, so resolving this on every audited
/// path would re-enter the shim repeatedly. The `OnceLock` bounds that to
/// the first audited path per process.
fn owned_dir_prefix() -> Option<&'static [u8]> {
    static PREFIX: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    PREFIX
        .get_or_init(|| {
            let log = std::env::var_os("GOVFUZZ_RUNTRACE_LOG")?;
            dir_with_trailing_slash(log.as_encoded_bytes()).map(<[u8]>::to_vec)
        })
        .as_deref()
}

/// Returns true when a failed open(path)/stat(path)/readlink(path)
/// should be recorded. Pure function over raw C string bytes; safe
/// to call from any hook.
pub fn should_audit_path(path: &[u8]) -> bool {
    should_audit_path_inner(path, owned_dir_prefix())
}

/// Core policy, factored to take the engine-owned dir explicitly so it is a
/// pure function the tests can drive without touching the process env.
fn should_audit_path_inner(path: &[u8], owned_dir: Option<&[u8]>) -> bool {
    if path.is_empty() {
        return false;
    }
    // GovFuzz's own per-harness instrumentation files (coverage.shm, vp.shm,
    // cmp.shm, runtrace.jsonl). These are created by the harness driver, not
    // the target, with O_CREAT-without-O_EXCL in whatever `--work-dir` the
    // user picked. When that work-dir is under /tmp the SHM bitmaps otherwise
    // self-trip the insecure-temp-file oracle (GF-417 / CWE-377, #403) on
    // 100% of targets; excluding the engine-owned dir keeps the work-dir
    // location from manufacturing phantom findings. The hardcoded segment
    // checks below only catch the default `./govfuzz_work` name, not an
    // arbitrary `--work-dir`, so this prefix is the general fix.
    if let Some(dir) = owned_dir {
        if path.starts_with(dir) {
            return false;
        }
    }
    // Belt-and-braces for the same #403 self-FP: GovFuzz's own per-harness
    // instrumentation files have fixed basenames the target never creates
    // (the driver writes the coverage / hit-count / value-profile / cmplog SHM
    // bitmaps and the runtrace log into the work-dir with O_CREAT-without-O_EXCL).
    // The owned-dir prefix above is the general fix, but it depends on
    // GOVFUZZ_RUNTRACE_LOG being resolvable from *this* hooked process — which
    // fails for the driver child that opens coverage.shm (the lookup routes
    // through the hooked getenv and can resolve to None before the var is
    // observable), so a /tmp work-dir self-trips GF-417 on every target. Match
    // the engine's instrumentation basenames directly so the SHM bitmaps are
    // never audited regardless of how the owned-dir prefix resolves.
    if let Some(name) = path.rsplit(|&b| b == b'/').next() {
        if name == b"coverage.shm"
            || name == b"coverage_cnt.shm"
            || name == b"vp.shm"
            || name == b"cmp.shm"
            || name == b"cmp_progress.shm"
            || name == b"runtrace.jsonl"
        {
            return false;
        }
    }
    // Real-system filesystems — let the target read /proc/self/maps,
    // /sys/fs/cgroup/*, /dev/urandom, etc. without spamming the log.
    if path.starts_with(b"/proc/")
        || path == b"/proc"
        || path.starts_with(b"/sys/")
        || path == b"/sys"
        || path.starts_with(b"/dev/")
        || path == b"/dev"
    {
        return false;
    }
    // Sanitizer/symbolizer infrastructure, not target behavior: when ASan prints
    // a crash report it `access()`es then `open()`s the separate debuginfo under
    // /usr/lib/debug/.build-id/..., which otherwise surfaces as a spurious TOCTOU
    // (GF-418) on every sanitizer crash.
    if path.starts_with(b"/usr/lib/debug/") || path_contains_segment(path, b".build-id") {
        return false;
    }
    // GovFuzz's own synthetic fixtures. setenv injection points env
    // vars at /tmp/govfuzz/fake_env/<NAME>, and Slice C's fake_fs
    // lives at /tmp/govfuzz/fake_fs/...; both are GovFuzz-owned and
    // their ENOENTs are noise, not real "missing config" misses. The
    // local ./govfuzz_work/ dir is the same story for relative-path
    // invocations.
    if path.starts_with(b"/tmp/govfuzz/") || path.starts_with(b"./govfuzz_work/") {
        return false;
    }
    // GovFuzz's own work artefacts — the shim must not log its own
    // log file open, the fuzz harness's runtime dir, etc.
    if path_contains_segment(path, b"govfuzz_work")
        || path_contains_segment(path, b"generated_harnesses")
    {
        return false;
    }
    true
}

/// Returns true when a failed connect()/gethostbyname() should be
/// recorded. AF_UNIX paths inside /tmp or the work dir are
/// audit-worthy; loopback (127.0.0.1 / ::1) is too noisy. Caller
/// passes the sa_family + a printable address.
pub fn should_audit_endpoint(family: i32, address: &[u8]) -> bool {
    // AF_UNIX = 1, AF_INET = 2, AF_INET6 = 10 on Linux.
    if family == libc::AF_UNIX {
        return !address.is_empty();
    }
    // Loopback often just means "we tried our own gRPC server but
    // it's not up yet" — boring. Real misses go to non-loopback.
    if address.starts_with(b"127.") || address == b"::1" || address.starts_with(b"localhost") {
        return false;
    }
    true
}

fn path_contains_segment(path: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut start = 0usize;
    while start + needle.len() <= path.len() {
        if &path[start..start + needle.len()] == needle {
            let prev_ok = start == 0 || path[start - 1] == b'/';
            let next = start + needle.len();
            let next_ok = next == path.len() || path[next] == b'/';
            if prev_ok && next_ok {
                return true;
            }
        }
        start += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_self_maps_not_audited() {
        assert!(!should_audit_path(b"/proc/self/maps"));
    }

    #[test]
    fn real_missing_path_audited() {
        assert!(should_audit_path(b"/etc/myconfig.conf"));
    }

    #[test]
    fn govfuzz_work_path_not_audited() {
        assert!(!should_audit_path(
            b"/home/u/proj/govfuzz_work/auto/H-X/runtrace.jsonl"
        ));
    }

    #[test]
    fn generated_harness_main_not_audited() {
        assert!(!should_audit_path(
            b"/work/generated_harnesses/H-C0001/main.c"
        ));
    }

    #[test]
    fn segment_match_requires_slash_boundary() {
        // "govfuzz_workshop" should NOT match govfuzz_work.
        assert!(should_audit_path(b"/work/govfuzz_workshop/foo"));
    }

    #[test]
    fn loopback_endpoints_not_audited() {
        assert!(!should_audit_endpoint(libc::AF_INET, b"127.0.0.1:8080"));
        assert!(!should_audit_endpoint(libc::AF_INET6, b"::1"));
    }

    #[test]
    fn unix_sockets_audited() {
        assert!(should_audit_endpoint(libc::AF_UNIX, b"/var/run/acme.sock"));
    }

    #[test]
    fn real_tcp_endpoint_audited() {
        assert!(should_audit_endpoint(libc::AF_INET, b"10.0.0.1:5432"));
    }

    #[test]
    fn fake_env_path_not_audited() {
        assert!(!should_audit_path(b"/tmp/govfuzz/fake_env/ACME_CONFIG"));
    }

    #[test]
    fn fake_fs_path_not_audited() {
        assert!(!should_audit_path(b"/tmp/govfuzz/fake_fs/foo/bar"));
    }

    #[test]
    fn dir_with_trailing_slash_extracts_directory() {
        assert_eq!(dir_with_trailing_slash(b"/a/b/c.txt"), Some(&b"/a/b/"[..]));
        assert_eq!(dir_with_trailing_slash(b"/a"), Some(&b"/"[..]));
        // A bare relative filename has no directory component.
        assert_eq!(dir_with_trailing_slash(b"bare.txt"), None);
    }

    #[test]
    fn engine_owned_dir_paths_not_audited() {
        // #403: the per-harness instrumentation files live in the engine-owned
        // dir regardless of where --work-dir points (here, under /tmp). None of
        // them must be audited, or the insecure-temp-file oracle self-fires.
        let owned = &b"/tmp/wd/auto/H-C0007-x/"[..];
        assert!(!should_audit_path_inner(
            b"/tmp/wd/auto/H-C0007-x/coverage.shm",
            Some(owned)
        ));
        assert!(!should_audit_path_inner(
            b"/tmp/wd/auto/H-C0007-x/cmp.shm",
            Some(owned)
        ));
        assert!(!should_audit_path_inner(
            b"/tmp/wd/auto/H-C0007-x/runtrace.jsonl",
            Some(owned)
        ));
    }

    #[test]
    fn engine_shm_basenames_not_audited_even_without_owned_dir() {
        // #403 belt-and-braces: when the owned-dir prefix can't be resolved in
        // the hooked driver child (owned_dir == None), the engine's own SHM /
        // log files under a /tmp work-dir must STILL be suppressed by basename —
        // otherwise GF-417 self-fires on coverage.shm for 100% of targets.
        for f in [
            b"/tmp/fix_cjson/wd/auto/H-C0007/coverage.shm".as_slice(),
            b"/tmp/wd/auto/H-1/coverage_cnt.shm".as_slice(),
            b"/var/tmp/run/vp.shm".as_slice(),
            b"/dev/shm/job/cmp.shm".as_slice(),
            b"/tmp/wd/auto/H-1/runtrace.jsonl".as_slice(),
        ] {
            assert!(
                !should_audit_path_inner(f, None),
                "engine instrumentation file must not be audited: {}",
                String::from_utf8_lossy(f)
            );
        }
        // A real target temp file that merely shares the directory is still
        // audited — the guard keys on the engine basenames, not the location.
        assert!(should_audit_path_inner(
            b"/tmp/fix_cjson/wd/auto/H-C0007/victim.scratch",
            None
        ));
    }

    #[test]
    fn genuine_temp_file_still_audited_with_owned_dir_set() {
        // The oracle is self-excluded, not disabled: a real target temp file
        // OUTSIDE the engine dir is still audit-worthy.
        let owned = &b"/tmp/wd/auto/H-C0007-x/"[..];
        assert!(should_audit_path_inner(b"/tmp/victim.scratch", Some(owned)));
        assert!(should_audit_path_inner(b"/etc/passwd", Some(owned)));
    }

    #[test]
    fn owned_dir_prefix_requires_slash_boundary() {
        // A sibling dir sharing a name prefix must NOT be swallowed by the
        // trailing-slash-anchored prefix.
        let owned = &b"/tmp/wd/auto/H-1/"[..];
        assert!(should_audit_path_inner(
            b"/tmp/wd/auto/H-1-evil/scratch",
            Some(owned)
        ));
    }

    #[test]
    fn no_owned_dir_falls_through_to_default_policy() {
        // When GOVFUZZ_RUNTRACE_LOG is unset there is no engine dir; behaviour
        // matches the pre-#403 policy exactly.
        assert!(should_audit_path_inner(b"/etc/myconfig.conf", None));
        assert!(!should_audit_path_inner(b"/proc/self/maps", None));
    }
}
