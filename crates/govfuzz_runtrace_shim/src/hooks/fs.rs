// SPDX-License-Identifier: Apache-2.0

//! open / openat / close / stat / access / readlink interceptors.
//! Each calls the real libc function via dlsym(RTLD_NEXT), records
//! JSONL events for audited missing paths and fd lifecycle edges, and
//! returns the original result + errno to the caller unchanged.
//!
//! Safety: every #[no_mangle] extern "C" fn here is invoked by the
//! dynamic linker as a libc symbol. The caller-supplied pointers
//! must satisfy the matching libc function's contract — we forward
//! them unchanged to the real implementation.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::policy::should_audit_path;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_OPEN: ResolvedFn = ResolvedFn::new(b"open\0");
static REAL_OPENAT: ResolvedFn = ResolvedFn::new(b"openat\0");
static REAL_STAT: ResolvedFn = ResolvedFn::new(b"__xstat\0");
static REAL_ACCESS: ResolvedFn = ResolvedFn::new(b"access\0");
static REAL_FACCESSAT: ResolvedFn = ResolvedFn::new(b"faccessat\0");
static REAL_READLINK: ResolvedFn = ResolvedFn::new(b"readlink\0");
static REAL_READLINKAT: ResolvedFn = ResolvedFn::new(b"readlinkat\0");
static REAL_CLOSE: ResolvedFn = ResolvedFn::new(b"close\0");
static REAL_UNLINK: ResolvedFn = ResolvedFn::new(b"unlink\0");
static REAL_UNLINKAT: ResolvedFn = ResolvedFn::new(b"unlinkat\0");
static REAL_REMOVE: ResolvedFn = ResolvedFn::new(b"remove\0");
static REAL_CHMOD: ResolvedFn = ResolvedFn::new(b"chmod\0");
static REAL_FCHMOD: ResolvedFn = ResolvedFn::new(b"fchmod\0");
static REAL_MKDIR: ResolvedFn = ResolvedFn::new(b"mkdir\0");
static REAL_MKDIRAT: ResolvedFn = ResolvedFn::new(b"mkdirat\0");
static REAL_RMDIR: ResolvedFn = ResolvedFn::new(b"rmdir\0");
static REAL_RENAME: ResolvedFn = ResolvedFn::new(b"rename\0");
static REAL_RENAMEAT: ResolvedFn = ResolvedFn::new(b"renameat\0");
static REAL_SYMLINK: ResolvedFn = ResolvedFn::new(b"symlink\0");
static REAL_SYMLINKAT: ResolvedFn = ResolvedFn::new(b"symlinkat\0");
static REAL_LINK: ResolvedFn = ResolvedFn::new(b"link\0");
static REAL_LINKAT: ResolvedFn = ResolvedFn::new(b"linkat\0");
static REAL_TRUNCATE: ResolvedFn = ResolvedFn::new(b"truncate\0");

/// Permission bits that make a `chmod` dangerous: setuid, setgid, or
/// world-writable. Assigning any of these from data derived from untrusted
/// input (e.g. an archive extractor honouring an attacker-controlled entry
/// mode) is a CWE-732 incorrect-permission-assignment vulnerability.
fn mode_is_insecure(mode: libc::mode_t) -> bool {
    mode & (libc::S_ISUID | libc::S_ISGID | libc::S_IWOTH) != 0
}

/// A directory mode is insecure if it is world-writable WITHOUT the sticky bit
/// (any local user can then rename/delete entries), or setuid/setgid. A
/// world-writable *sticky* directory (mode `01777`, the `/tmp` pattern) is the
/// safe idiom and is not flagged.
fn dir_mode_is_insecure(mode: libc::mode_t) -> bool {
    (mode & libc::S_IWOTH != 0 && mode & libc::S_ISVTX == 0)
        || mode & (libc::S_ISUID | libc::S_ISGID) != 0
}

/// World-writable directories where a predictably-named file is exposed to a
/// symlink / temp-file race by any other local user.
fn in_world_writable_tmp(path: &[u8]) -> bool {
    const DIRS: &[&[u8]] = &[b"/tmp/", b"/var/tmp/", b"/dev/shm/"];
    DIRS.iter().any(|dir| path.starts_with(dir))
}

/// A file *created* in a world-writable temp directory with O_CREAT but
/// without O_EXCL: the classic insecure-temporary-file pattern (CWE-377). The
/// missing O_EXCL means an attacker who pre-creates a symlink at the
/// predictable path can redirect the write. O_TMPFILE creations are anonymous
/// (no name) and never set O_CREAT, so they are excluded automatically.
fn tempfile_is_insecure(path: &[u8], flags: libc::c_int) -> bool {
    flags & libc::O_CREAT != 0 && flags & libc::O_EXCL == 0 && in_world_writable_tmp(path)
}

/// Record an attempt to create an insecure temporary file. The attempt itself
/// is the signal (the race exists whether or not this particular open won),
/// so this logs on the requested flags regardless of the call's result.
fn log_insecure_tempfile(api: &[u8], path: &[u8], flags: libc::c_int) {
    // GovFuzz's own infrastructure files (the coverage/value-profile/cmplog
    // SHM, event logs, runtrace log) are created by the harness driver itself,
    // not the target, and legitimately use O_CREAT-without-O_EXCL in the work
    // dir. Flagging them is a false positive (#403), so apply the same
    // audit-path filter the other fs loggers use — it excludes the engine-owned
    // harness dir wherever `--work-dir` points, not just the default name.
    if !should_audit_path(path) {
        return;
    }
    let mut b = Builder::new(b"insecure_tempfile");
    b.field_str(b"a", api);
    b.field_str(b"p", path);
    b.field_i64(b"f", flags as i64);
    b.emit();
}

/// Record a successful path existence/permission check (the "time of check"
/// half of a TOCTOU pair, CWE-367). The cli correlates this with a later open
/// of the same path; keeping the correlation in the cli rather than the shim
/// avoids any signal-unsafe cross-call state here.
fn log_path_check(api: &[u8], path: &[u8]) {
    if !should_audit_path(path) {
        return;
    }
    let mut b = Builder::new(b"path_check");
    b.field_str(b"a", api);
    b.field_str(b"p", path);
    b.emit();
}

/// Preserve errno across our logging path. We may call write(2) in
/// emit() which can clobber errno.
fn save_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn restore_errno(saved: i32) {
    unsafe { *libc::__errno_location() = saved };
}

unsafe fn path_bytes_from_ptr(p: *const libc::c_char) -> &'static [u8] {
    if p.is_null() {
        return &[];
    }
    let cstr = CStr::from_ptr(p);
    // Cast to 'static — we're only ever using the bytes inside the
    // current call and never escape them past the hook return.
    let slice: &[u8] = cstr.to_bytes();
    std::mem::transmute::<&[u8], &'static [u8]>(slice)
}

/// Minimum run of fuzz-input-derived bytes a path must contain before it
/// is treated as taint (#422). Short runs match almost any input by
/// chance; 4 bytes is the floor the shim uses for byte-origin taint.
const TAINT_MIN_LEN: usize = 4;

/// Append byte-origin taint fields to a path event when the path was
/// derived from the current fuzz input: `u`=1 (controlled) and `o`=the
/// input offset where the path bytes originate. Mirrors the printf
/// format-string hook's `u` flag so the CLI can confirm a
/// path-controlled-open candidate (GF-405) with a source→sink path.
fn append_path_taint(b: &mut Builder, path: &[u8]) {
    if let Some((offset, _len)) = crate::fakes::fuzz_input::taint_span(path, TAINT_MIN_LEN) {
        b.field_i64(b"u", 1);
        b.field_i64(b"o", offset as i64);
    }
}

fn log_path_miss(event: &[u8], path: &[u8], result: i64, errno: i32) {
    if !should_audit_path(path) {
        return;
    }
    let mut b = Builder::new(event);
    b.field_str(b"p", path);
    b.field_i64(b"r", result);
    b.field_i64(b"n", errno as i64);
    append_path_taint(&mut b, path);
    b.emit();
}

fn log_path_open(event: &[u8], path: &[u8], fd: libc::c_int) {
    if fd < 0 || !should_audit_path(path) {
        return;
    }
    let mut b = Builder::new(event);
    b.field_str(b"p", path);
    b.field_i64(b"d", fd as i64);
    b.field_i64(b"r", fd as i64);
    append_path_taint(&mut b, path);
    b.emit();
}

fn log_fd_close(fd: libc::c_int, result: libc::c_int) {
    if fd < 0 || result != 0 {
        return;
    }
    let mut b = Builder::new(b"close");
    b.field_i64(b"d", fd as i64);
    b.field_i64(b"r", result as i64);
    b.emit();
}

fn log_path_delete(event: &[u8], path: &[u8], result: libc::c_int) {
    if result != 0 || !should_audit_path(path) {
        return;
    }
    let mut b = Builder::new(event);
    b.field_str(b"p", path);
    b.field_i64(b"r", result as i64);
    b.emit();
}

/// Emit a `fs_destroy` sink event for a path reaching a destructive filesystem
/// API during a fuzz execution, tagged with byte-origin taint (#422) when a
/// contiguous run of the path came from the current fuzz input. Emitted on every
/// call (regardless of result, so an ENOENT attempt on a controlled path still
/// registers) so the CLI's destructive-path sink oracle (GF-440) can confirm a
/// fuzz-controlled path and suppress a constant one. Caller holds a HookGuard.
fn emit_fs_destroy(api: &[u8], path: &[u8]) {
    if path.is_empty() || !should_audit_path(path) {
        return;
    }
    let mut b = Builder::new(b"fs_destroy");
    b.field_str(b"a", api);
    b.field_str(b"p", path);
    if let Some((offset, _len)) = crate::fakes::fuzz_input::input_derived_run(path, TAINT_MIN_LEN) {
        b.field_i64(b"u", 1);
        b.field_i64(b"o", offset as i64);
    }
    b.emit();
}

/// Record an attempt to set dangerous (setuid/setgid/world-writable) permissions.
/// The attempt itself is the security signal, so this logs on the requested mode
/// regardless of the call's result.
fn log_insecure_chmod(path: &[u8], mode: libc::mode_t) {
    let mut b = Builder::new(b"insecure_chmod");
    b.field_str(b"p", path);
    b.field_i64(b"m", mode as i64);
    b.emit();
}

/// Memory-mapped device files a driver `open`s and then `mmap`s to reach device
/// registers (#441). Matched by exact name or `/dev/` family prefix.
fn is_mmio_device_path(path: &[u8]) -> bool {
    const EXACT: &[&[u8]] = &[b"/dev/mem", b"/dev/kmem", b"/dev/gpiomem", b"/dev/watchdog"];
    if EXACT.contains(&path) {
        return true;
    }
    const PREFIX: &[&[u8]] = &[
        b"/dev/uio",      // userspace I/O (uio0, uio1, ...)
        b"/dev/mtd",      // raw flash (mtd0, mtd0ro, ...)
        b"/dev/i2c-",     // I2C buses
        b"/dev/spidev",   // SPI devices
        b"/dev/watchdog", // watchdog0, ...
    ];
    PREFIX.iter().any(|p| path.starts_with(p))
}

fn log_mmio(path: &[u8], fd: libc::c_int) {
    // Unlike log_path_open, this is NOT gated on should_audit_path (which excludes
    // /dev/): MMIO devices live under /dev/ and are exactly what we substitute.
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(b"mmio");
        b.field_str(b"p", path);
        b.field_i64(b"d", fd as i64);
        b.field_i64(b"v", 1);
        b.emit();
    }
}

/// #441: during a fuzz pass, an `open` of a memory-mapped device is redirected to
/// a private, mode-filled memfd so the driver's subsequent `mmap` + register
/// reads hit fuzz-controlled memory instead of real hardware (and the
/// unprivileged open that would fail with EACCES now succeeds). Returns the fake
/// fd to hand back, or `None` to keep the real result. Any real fd that opened is
/// closed so the fuzzer never maps real device memory.
unsafe fn maybe_substitute_mmio(path: &[u8], real_result: libc::c_int) -> Option<libc::c_int> {
    if !crate::fakes::mode::current().is_faking() || !is_mmio_device_path(path) {
        return None;
    }
    if real_result >= 0 {
        libc::close(real_result);
    }
    let fake = crate::fakes::memfd::create_fake_mmio_fd(path);
    if fake < 0 {
        return None;
    }
    log_mmio(path, fake);
    Some(fake)
}

#[no_mangle]
pub unsafe extern "C" fn open(
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    let real = REAL_OPEN.ptr() as *const ();
    if real.is_null() {
        // dlsym failed; fall back to libc directly (which is the
        // same call but routed via libc's own indirect ptr).
        return libc::open(path, flags, mode);
    }
    let real: unsafe extern "C" fn(*const libc::c_char, libc::c_int, libc::mode_t) -> libc::c_int =
        std::mem::transmute(real);
    let result = real(path, flags, mode);
    let saved_errno = save_errno();
    let path_bytes = path_bytes_from_ptr(path);
    if let Some(fake) = maybe_substitute_mmio(path_bytes, result) {
        restore_errno(saved_errno);
        return fake;
    }
    if tempfile_is_insecure(path_bytes, flags) {
        if let Some(_g) = HookGuard::acquire() {
            log_insecure_tempfile(b"open", path_bytes, flags);
        }
    }
    if result >= 0 {
        if let Some(_g) = HookGuard::acquire() {
            log_path_open(b"open", path_bytes, result);
        }
    } else if saved_errno == libc::ENOENT {
        if let Some(_g) = HookGuard::acquire() {
            log_path_miss(b"open", path_bytes, result as i64, saved_errno);
        }
        if crate::fakes::mode::current().is_faking() && should_audit_path(path_bytes) {
            let fake_fd = crate::fakes::memfd::create_fake_file_fd(path_bytes);
            if fake_fd >= 0 {
                if let Some(_g) = HookGuard::acquire() {
                    log_path_open(b"open", path_bytes, fake_fd);
                }
                restore_errno(saved_errno);
                return fake_fd;
            }
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn openat(
    dirfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    let real = REAL_OPENAT.ptr() as *const ();
    if real.is_null() {
        // Defense in depth: never call the exported `openat` symbol
        // here — it would re-enter this hook and recurse forever. Go
        // straight to the kernel.
        return libc::syscall(libc::SYS_openat, dirfd, path, flags, mode) as libc::c_int;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::mode_t,
    ) -> libc::c_int = std::mem::transmute(real);
    let result = real(dirfd, path, flags, mode);
    let saved_errno = save_errno();
    let path_bytes = path_bytes_from_ptr(path);
    if let Some(fake) = maybe_substitute_mmio(path_bytes, result) {
        restore_errno(saved_errno);
        return fake;
    }
    if tempfile_is_insecure(path_bytes, flags) {
        if let Some(_g) = HookGuard::acquire() {
            log_insecure_tempfile(b"openat", path_bytes, flags);
        }
    }
    if result >= 0 {
        if let Some(_g) = HookGuard::acquire() {
            log_path_open(b"openat", path_bytes, result);
        }
    } else if saved_errno == libc::ENOENT {
        if let Some(_g) = HookGuard::acquire() {
            log_path_miss(b"openat", path_bytes, result as i64, saved_errno);
        }
        if crate::fakes::mode::current().is_faking() && should_audit_path(path_bytes) {
            let fake_fd = crate::fakes::memfd::create_fake_file_fd(path_bytes);
            if fake_fd >= 0 {
                if let Some(_g) = HookGuard::acquire() {
                    log_path_open(b"openat", path_bytes, fake_fd);
                }
                restore_errno(saved_errno);
                return fake_fd;
            }
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn access(path: *const libc::c_char, mode: libc::c_int) -> libc::c_int {
    let real = REAL_ACCESS.ptr() as *const ();
    if real.is_null() {
        return libc::access(path, mode);
    }
    let real: unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int =
        std::mem::transmute(real);
    let result = real(path, mode);
    let saved_errno = save_errno();
    if result == 0 {
        if let Some(_g) = HookGuard::acquire() {
            log_path_check(b"access", path_bytes_from_ptr(path));
        }
    } else if saved_errno == libc::ENOENT {
        if let Some(_g) = HookGuard::acquire() {
            let path_bytes = path_bytes_from_ptr(path);
            log_path_miss(b"access", path_bytes, result as i64, saved_errno);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn faccessat(
    dirfd: libc::c_int,
    path: *const libc::c_char,
    mode: libc::c_int,
    flags: libc::c_int,
) -> libc::c_int {
    let real = REAL_FACCESSAT.ptr() as *const ();
    if real.is_null() {
        // Raw-syscall fallback (never re-enter the exported hook). The
        // bare faccessat syscall takes no flags; flags need faccessat2.
        return if flags == 0 {
            libc::syscall(libc::SYS_faccessat, dirfd, path, mode) as libc::c_int
        } else {
            libc::syscall(libc::SYS_faccessat2, dirfd, path, mode, flags) as libc::c_int
        };
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(real);
    let result = real(dirfd, path, mode, flags);
    let saved_errno = save_errno();
    if result == 0 {
        if let Some(_g) = HookGuard::acquire() {
            log_path_check(b"faccessat", path_bytes_from_ptr(path));
        }
    } else if saved_errno == libc::ENOENT {
        if let Some(_g) = HookGuard::acquire() {
            let path_bytes = path_bytes_from_ptr(path);
            log_path_miss(b"faccessat", path_bytes, result as i64, saved_errno);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn readlink(
    path: *const libc::c_char,
    buf: *mut libc::c_char,
    bufsiz: libc::size_t,
) -> libc::ssize_t {
    let real = REAL_READLINK.ptr() as *const ();
    if real.is_null() {
        return libc::readlink(path, buf, bufsiz);
    }
    let real: unsafe extern "C" fn(
        *const libc::c_char,
        *mut libc::c_char,
        libc::size_t,
    ) -> libc::ssize_t = std::mem::transmute(real);
    let result = real(path, buf, bufsiz);
    let saved_errno = save_errno();
    if result < 0 && saved_errno == libc::ENOENT {
        if let Some(_g) = HookGuard::acquire() {
            let path_bytes = path_bytes_from_ptr(path);
            log_path_miss(b"readlink", path_bytes, result as i64, saved_errno);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn readlinkat(
    dirfd: libc::c_int,
    path: *const libc::c_char,
    buf: *mut libc::c_char,
    bufsiz: libc::size_t,
) -> libc::ssize_t {
    let real = REAL_READLINKAT.ptr() as *const ();
    if real.is_null() {
        // Raw-syscall fallback (never re-enter the exported hook).
        return libc::syscall(libc::SYS_readlinkat, dirfd, path, buf, bufsiz) as libc::ssize_t;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        *mut libc::c_char,
        libc::size_t,
    ) -> libc::ssize_t = std::mem::transmute(real);
    let result = real(dirfd, path, buf, bufsiz);
    let saved_errno = save_errno();
    if result < 0 && saved_errno == libc::ENOENT {
        if let Some(_g) = HookGuard::acquire() {
            let path_bytes = path_bytes_from_ptr(path);
            log_path_miss(b"readlinkat", path_bytes, result as i64, saved_errno);
        }
    }
    restore_errno(saved_errno);
    result
}

/// LEGACY: glibc <2.33 routed stat()/lstat() through __xstat;
/// glibc 2.33+ compiles them to direct fstatat(AT_FDCWD, ...) syscalls,
/// bypassing this hook entirely. The hook is preserved for compatibility
/// with older glibc but on most modern hosts it never fires. Slice C
/// adds a fstatat hook to close the gap; for Slice B, openat() and
/// access() catch the common "open a config file" case which is what
/// the audit was primarily after.
#[no_mangle]
pub unsafe extern "C" fn __xstat(
    ver: libc::c_int,
    path: *const libc::c_char,
    buf: *mut libc::stat,
) -> libc::c_int {
    let real = REAL_STAT.ptr() as *const ();
    if real.is_null() {
        // Fall back: glibc only exposes __xstat as an extern, not
        // libc::stat directly. If dlsym failed there's nothing we
        // can do; return -1/ENOENT to keep the contract.
        unsafe { *libc::__errno_location() = libc::ENOENT };
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        *mut libc::stat,
    ) -> libc::c_int = std::mem::transmute(real);
    let result = real(ver, path, buf);
    let saved_errno = save_errno();
    if result < 0 && saved_errno == libc::ENOENT {
        if let Some(_g) = HookGuard::acquire() {
            let path_bytes = path_bytes_from_ptr(path);
            log_path_miss(b"stat", path_bytes, result as i64, saved_errno);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn close(fd: libc::c_int) -> libc::c_int {
    let real = REAL_CLOSE.ptr() as *const ();
    let result = if real.is_null() {
        libc::syscall(libc::SYS_close, fd) as libc::c_int
    } else {
        let real: unsafe extern "C" fn(libc::c_int) -> libc::c_int = std::mem::transmute(real);
        real(fd)
    };
    let saved_errno = save_errno();
    if result == 0 {
        // Clear virtual-device provenance before this numeric descriptor can be
        // reused for an unrelated file or pipe.
        crate::fakes::memfd::clear_fake_fd(fd);
        if let Some(_g) = HookGuard::acquire() {
            log_fd_close(fd, result);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn unlink(path: *const libc::c_char) -> libc::c_int {
    let real = REAL_UNLINK.ptr() as *const ();
    let result = if real.is_null() {
        // aarch64-linux has no legacy unlink syscall number; the unlinkat
        // form is defined on every dist architecture.
        libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path, 0) as libc::c_int
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char) -> libc::c_int =
            std::mem::transmute(real);
        real(path)
    };
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        let path_bytes = path_bytes_from_ptr(path);
        emit_fs_destroy(b"unlink", path_bytes);
        if result == 0 {
            log_path_delete(b"unlink", path_bytes, result);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn unlinkat(
    dirfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    let real = REAL_UNLINKAT.ptr() as *const ();
    let result = if real.is_null() {
        libc::syscall(libc::SYS_unlinkat, dirfd, path, flags) as libc::c_int
    } else {
        let real: unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_char,
            libc::c_int,
        ) -> libc::c_int = std::mem::transmute(real);
        real(dirfd, path, flags)
    };
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        let path_bytes = path_bytes_from_ptr(path);
        emit_fs_destroy(b"unlinkat", path_bytes);
        if result == 0 {
            log_path_delete(b"unlinkat", path_bytes, result);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn remove(path: *const libc::c_char) -> libc::c_int {
    let real = REAL_REMOVE.ptr() as *const ();
    let result = if real.is_null() {
        libc::remove(path)
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char) -> libc::c_int =
            std::mem::transmute(real);
        real(path)
    };
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        let path_bytes = path_bytes_from_ptr(path);
        emit_fs_destroy(b"remove", path_bytes);
        if result == 0 {
            log_path_delete(b"remove", path_bytes, result);
        }
    }
    restore_errno(saved_errno);
    result
}

/// Forward a single-path destructive op (`rmdir`/`truncate`) to the real libc
/// function, auditing the controlled path (GF-440) before returning. If the real
/// symbol can't be resolved (essentially never for a standard libc function) the
/// call fails with ENOSYS — there is deliberately NO legacy raw-syscall fallback,
/// because the legacy non-`*at` syscall numbers do not exist on every dist
/// architecture (aarch64 dropped them in favour of the `*at` forms).
unsafe fn destructive_one(
    real_fn: &ResolvedFn,
    api: &[u8],
    path: *const libc::c_char,
    call: impl FnOnce(*const ()) -> libc::c_int,
) -> libc::c_int {
    let real = real_fn.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        call(real)
    };
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        emit_fs_destroy(api, path_bytes_from_ptr(path));
    }
    restore_errno(saved_errno);
    result
}

/// Audit BOTH controlled paths of a two-path destructive op
/// (`rename`/`link`/`symlink`): a controlled source picks what to move/link, a
/// controlled destination picks what to clobber (GF-440). The caller has already
/// forwarded to the real function.
unsafe fn audit_destructive_two(
    api: &[u8],
    p1: *const libc::c_char,
    p2: *const libc::c_char,
    result: libc::c_int,
) -> libc::c_int {
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        emit_fs_destroy(api, path_bytes_from_ptr(p1));
        emit_fs_destroy(api, path_bytes_from_ptr(p2));
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn rmdir(path: *const libc::c_char) -> libc::c_int {
    destructive_one(&REAL_RMDIR, b"rmdir", path, |real| {
        let real: unsafe extern "C" fn(*const libc::c_char) -> libc::c_int =
            std::mem::transmute(real);
        real(path)
    })
}

#[no_mangle]
pub unsafe extern "C" fn truncate(path: *const libc::c_char, length: libc::off_t) -> libc::c_int {
    destructive_one(&REAL_TRUNCATE, b"truncate", path, |real| {
        let real: unsafe extern "C" fn(*const libc::c_char, libc::off_t) -> libc::c_int =
            std::mem::transmute(real);
        real(path, length)
    })
}

#[no_mangle]
pub unsafe extern "C" fn rename(
    oldpath: *const libc::c_char,
    newpath: *const libc::c_char,
) -> libc::c_int {
    let real = REAL_RENAME.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int =
            std::mem::transmute(real);
        real(oldpath, newpath)
    };
    audit_destructive_two(b"rename", oldpath, newpath, result)
}

#[no_mangle]
pub unsafe extern "C" fn renameat(
    oldfd: libc::c_int,
    oldpath: *const libc::c_char,
    newfd: libc::c_int,
    newpath: *const libc::c_char,
) -> libc::c_int {
    let real = REAL_RENAMEAT.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        let real: unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_char,
            libc::c_int,
            *const libc::c_char,
        ) -> libc::c_int = std::mem::transmute(real);
        real(oldfd, oldpath, newfd, newpath)
    };
    audit_destructive_two(b"renameat", oldpath, newpath, result)
}

#[no_mangle]
pub unsafe extern "C" fn symlink(
    target: *const libc::c_char,
    linkpath: *const libc::c_char,
) -> libc::c_int {
    let real = REAL_SYMLINK.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int =
            std::mem::transmute(real);
        real(target, linkpath)
    };
    audit_destructive_two(b"symlink", target, linkpath, result)
}

#[no_mangle]
pub unsafe extern "C" fn symlinkat(
    target: *const libc::c_char,
    newdirfd: libc::c_int,
    linkpath: *const libc::c_char,
) -> libc::c_int {
    let real = REAL_SYMLINKAT.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        let real: unsafe extern "C" fn(
            *const libc::c_char,
            libc::c_int,
            *const libc::c_char,
        ) -> libc::c_int = std::mem::transmute(real);
        real(target, newdirfd, linkpath)
    };
    audit_destructive_two(b"symlinkat", target, linkpath, result)
}

#[no_mangle]
pub unsafe extern "C" fn link(
    oldpath: *const libc::c_char,
    newpath: *const libc::c_char,
) -> libc::c_int {
    let real = REAL_LINK.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int =
            std::mem::transmute(real);
        real(oldpath, newpath)
    };
    audit_destructive_two(b"link", oldpath, newpath, result)
}

#[no_mangle]
pub unsafe extern "C" fn linkat(
    oldfd: libc::c_int,
    oldpath: *const libc::c_char,
    newfd: libc::c_int,
    newpath: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    let real = REAL_LINKAT.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        let real: unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_char,
            libc::c_int,
            *const libc::c_char,
            libc::c_int,
        ) -> libc::c_int = std::mem::transmute(real);
        real(oldfd, oldpath, newfd, newpath, flags)
    };
    audit_destructive_two(b"linkat", oldpath, newpath, result)
}

pub struct Fs;

impl crate::sdk::FakeResource for Fs {
    fn name(&self) -> &'static str {
        "fs"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"open\0",
            b"openat\0",
            b"close\0",
            // `__xstat` is the only stat-family symbol this module defines, and
            // it is legacy: glibc 2.33+ compiles stat()/lstat() to direct
            // fstatat syscalls that bypass it (see the note above the hook).
            // There is no `fopen` interposer at all. Both were advertised by
            // `--list-fakes`, overstating what the shim actually sees.
            b"__xstat\0",
            b"unlink\0",
            b"unlinkat\0",
            b"remove\0",
            b"mkdir\0",
            b"mkdirat\0",
            b"rmdir\0",
            b"rename\0",
            b"renameat\0",
            b"symlink\0",
            b"symlinkat\0",
            b"link\0",
            b"linkat\0",
            b"truncate\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log missing-file ENOENT, fd lifecycle, controlled destructive path ops, and substitute fake file fds"
    }
}

#[no_mangle]
pub unsafe extern "C" fn chmod(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int {
    let real = REAL_CHMOD.ptr() as *const ();
    let result = if real.is_null() {
        libc::syscall(
            libc::SYS_fchmodat,
            libc::AT_FDCWD,
            path,
            mode as libc::c_uint,
            0,
        ) as libc::c_int
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> libc::c_int =
            std::mem::transmute(real);
        real(path, mode)
    };
    let saved_errno = save_errno();
    if mode_is_insecure(mode) {
        if let Some(_g) = HookGuard::acquire() {
            log_insecure_chmod(path_bytes_from_ptr(path), mode);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn fchmod(fd: libc::c_int, mode: libc::mode_t) -> libc::c_int {
    let real = REAL_FCHMOD.ptr() as *const ();
    let result = if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        -1
    } else {
        let real: unsafe extern "C" fn(libc::c_int, libc::mode_t) -> libc::c_int =
            std::mem::transmute(real);
        real(fd, mode)
    };
    let saved_errno = save_errno();
    if mode_is_insecure(mode) {
        if let Some(_g) = HookGuard::acquire() {
            // No path for an fd-based chmod; record the fd as the subject.
            let mut b = Builder::new(b"insecure_chmod");
            b.field_i64(b"d", fd as i64);
            b.field_i64(b"m", mode as i64);
            b.emit();
        }
    }
    restore_errno(saved_errno);
    result
}

/// Record an attempt to create a world-writable (non-sticky) or setuid/setgid
/// directory. Like chmod, the requested mode is the security signal, so this
/// logs regardless of the call's result.
fn log_insecure_mkdir(api: &[u8], path: &[u8], mode: libc::mode_t) {
    let mut b = Builder::new(b"insecure_mkdir");
    b.field_str(b"a", api);
    b.field_str(b"p", path);
    b.field_i64(b"m", mode as i64);
    b.emit();
}

#[no_mangle]
pub unsafe extern "C" fn mkdir(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int {
    let real = REAL_MKDIR.ptr() as *const ();
    let result = if real.is_null() {
        libc::syscall(
            libc::SYS_mkdirat,
            libc::AT_FDCWD,
            path,
            mode as libc::c_uint,
        ) as libc::c_int
    } else {
        let real: unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> libc::c_int =
            std::mem::transmute(real);
        real(path, mode)
    };
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        emit_fs_destroy(b"mkdir", path_bytes_from_ptr(path));
        if dir_mode_is_insecure(mode) {
            log_insecure_mkdir(b"mkdir", path_bytes_from_ptr(path), mode);
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn mkdirat(
    dirfd: libc::c_int,
    path: *const libc::c_char,
    mode: libc::mode_t,
) -> libc::c_int {
    let real = REAL_MKDIRAT.ptr() as *const ();
    let result = if real.is_null() {
        libc::syscall(libc::SYS_mkdirat, dirfd, path, mode as libc::c_uint) as libc::c_int
    } else {
        let real: unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_char,
            libc::mode_t,
        ) -> libc::c_int = std::mem::transmute(real);
        real(dirfd, path, mode)
    };
    let saved_errno = save_errno();
    if let Some(_g) = HookGuard::acquire() {
        emit_fs_destroy(b"mkdirat", path_bytes_from_ptr(path));
        if dir_mode_is_insecure(mode) {
            log_insecure_mkdir(b"mkdirat", path_bytes_from_ptr(path), mode);
        }
    }
    restore_errno(saved_errno);
    result
}

#[cfg(test)]
mod tests {
    use super::{dir_mode_is_insecure, tempfile_is_insecure};

    #[test]
    fn dir_mode_flags_world_writable_without_sticky() {
        // World-writable without the sticky bit is unsafe...
        assert!(dir_mode_is_insecure(0o777));
        assert!(dir_mode_is_insecure(0o0002));
        // ...setuid/setgid dirs are flagged...
        assert!(dir_mode_is_insecure(0o2755));
        // ...but the sticky /tmp idiom and private modes are fine.
        assert!(!dir_mode_is_insecure(0o1777));
        assert!(!dir_mode_is_insecure(0o0755));
    }

    #[test]
    fn flags_world_writable_create_without_o_excl() {
        let create = libc::O_WRONLY | libc::O_CREAT;
        assert!(tempfile_is_insecure(b"/tmp/scratch.123", create));
        assert!(tempfile_is_insecure(
            b"/var/tmp/x",
            libc::O_RDWR | libc::O_CREAT
        ));
        assert!(tempfile_is_insecure(b"/dev/shm/y", create));
    }

    #[test]
    fn ignores_o_excl_non_create_and_private_dirs() {
        let create = libc::O_WRONLY | libc::O_CREAT;
        // O_EXCL makes the create safe (no symlink race).
        assert!(!tempfile_is_insecure(b"/tmp/x", create | libc::O_EXCL));
        // Opening an existing temp file for read is not a create.
        assert!(!tempfile_is_insecure(b"/tmp/x", libc::O_RDONLY));
        // A private directory is not world-writable.
        assert!(!tempfile_is_insecure(b"/home/user/.cache/x", create));
        assert!(!tempfile_is_insecure(b"/tmpfoo/x", create)); // not under /tmp/
    }
}
