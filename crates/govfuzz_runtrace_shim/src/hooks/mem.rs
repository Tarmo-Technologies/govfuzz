// SPDX-License-Identifier: Apache-2.0

//! Shared-memory virtualization interceptors (#438).
//!
//! POSIX shared memory (`shm_open`/`shm_unlink`) is the modern cross-process /
//! cross-partition shared-memory path (DDS shm transport, RTOS-on-Linux IPC,
//! cFS). Under fuzzing it is a liability: a second process / partition writes the
//! region, so from a single-process harness's view those bytes are an
//! uncontrolled foreign writer — non-deterministic, and the root of the MSan
//! "use of uninitialized value" and TSan data-race false-positive storms on
//! partitioned code.
//!
//! When a fuzz pass is active (`is_faking()`), the shim VIRTUALIZES the POSIX shm
//! surface: `shm_open` returns a harness-private, anonymous memfd instead of a
//! real named object. Two `shm_open`s of the same name get DISTINCT memfds, so
//! nothing is actually shared between processes — the region is the harness's
//! alone, deterministic, with no foreign writer. `shm_unlink` becomes a no-op
//! success (there is no real named object to remove). In audit mode the calls
//! pass through to the real implementation unchanged.
//!
//! This module also virtualizes System V shared memory (shmget/shmat/...) and the
//! anonymous `mmap(MAP_SHARED)` path (#443) — see those sections below. shm_open-
//! and shmget-backed mappings are already private regardless of the MAP_SHARED
//! flag (no other process holds the fd / segment); the mmap interposer handles
//! the remaining case of memory shared directly via `mmap(MAP_SHARED|MAP_ANONYMOUS)`.
//!
//! Safety: each #[no_mangle] extern "C" fn is invoked by the dynamic linker as a
//! libc symbol; pointers are forwarded unchanged to the real implementation.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;
use std::sync::Mutex;

static REAL_SHM_OPEN: ResolvedFn = ResolvedFn::new(b"shm_open\0");
static REAL_SHM_UNLINK: ResolvedFn = ResolvedFn::new(b"shm_unlink\0");
static REAL_SHMGET: ResolvedFn = ResolvedFn::new(b"shmget\0");
static REAL_SHMAT: ResolvedFn = ResolvedFn::new(b"shmat\0");
static REAL_SHMDT: ResolvedFn = ResolvedFn::new(b"shmdt\0");
static REAL_SHMCTL: ResolvedFn = ResolvedFn::new(b"shmctl\0");

fn save_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn restore_errno(saved: i32) {
    unsafe {
        *libc::__errno_location() = saved;
    }
}

/// NUL-terminated C string -> byte slice (without the terminator). Empty slice
/// for NULL.
unsafe fn cstr_bytes<'a>(ptr: *const libc::c_char) -> &'a [u8] {
    if ptr.is_null() {
        return b"";
    }
    CStr::from_ptr(ptr).to_bytes()
}

fn log_shm(event: &[u8], name: &[u8], fd: i64, virtualized: bool) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(event);
        b.field_str(b"n", name);
        b.field_i64(b"fd", fd);
        b.field_i64(b"v", virtualized as i64);
        b.emit();
    }
}

#[no_mangle]
pub unsafe extern "C" fn shm_open(
    name: *const libc::c_char,
    oflag: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    let name_bytes = cstr_bytes(name);
    // Virtualize during a fuzz pass: hand back a private memfd so this process's
    // "shared" memory has no foreign writer (deterministic; kills cross-partition
    // MSan-uninitialized / TSan-race false positives).
    if crate::fakes::mode::current().is_faking() {
        let fake = crate::fakes::memfd::create_fake_shm_fd(name_bytes);
        if fake >= 0 {
            log_shm(b"shm_open", name_bytes, fake as i64, true);
            return fake;
        }
        // creation failed — fall through to the real call below.
    }

    let real = REAL_SHM_OPEN.ptr() as *const ();
    if real.is_null() {
        // No real shm_open resolvable (e.g. no librt) and not faking: report
        // unsupported rather than recursing into this exported symbol.
        restore_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(*const libc::c_char, libc::c_int, libc::mode_t) -> libc::c_int =
        std::mem::transmute(real);
    let result = real(name, oflag, mode);
    let saved = save_errno();
    log_shm(b"shm_open", name_bytes, result as i64, false);
    restore_errno(saved);
    result
}

#[no_mangle]
pub unsafe extern "C" fn shm_unlink(name: *const libc::c_char) -> libc::c_int {
    let name_bytes = cstr_bytes(name);
    if crate::fakes::mode::current().is_faking() {
        // The virtualized object has no real backing name; unlink is a no-op
        // success so the target's cleanup path proceeds normally.
        log_shm(b"shm_unlink", name_bytes, 0, true);
        return 0;
    }
    let real = REAL_SHM_UNLINK.ptr() as *const ();
    if real.is_null() {
        restore_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(*const libc::c_char) -> libc::c_int = std::mem::transmute(real);
    let result = real(name);
    let saved = save_errno();
    log_shm(b"shm_unlink", name_bytes, result as i64, false);
    restore_errno(saved);
    result
}

// ---------------------------------------------------------------------------
// System V shared memory (shmget / shmat / shmdt / shmctl) virtualization (#438)
// ---------------------------------------------------------------------------
//
// Same goal as the POSIX path: during a fuzz pass, back each segment with
// harness-PRIVATE anonymous memory so there is no foreign writer. shmget hands
// out a synthetic id mapped to a private `mmap`; shmat returns that private
// pointer; shmdt is a no-op; shmctl(IPC_RMID) frees it. A bounded table keyed by
// the System V key reuses the segment across persistent-mode iterations so a
// harness that re-`shmget`s the same key each input does not leak.

struct SysvSeg {
    key: libc::key_t,
    id: libc::c_int,
    ptr: usize,
    size: usize,
}

/// Synthetic shmid base — high enough not to collide with real kernel ids (which
/// are small), and `shmat`/`shmdt`/`shmctl` use it to route our ids vs real ones.
const SYSV_SYNTH_BASE: libc::c_int = 0x4756_0000;
/// Cap the table so a pathological harness can't exhaust memory; once full,
/// further shmget calls fall through to the real implementation.
const SYSV_CAP: usize = 256;

/// Table of synthesized SysV shared-memory segments. Every access uses
/// `try_lock`, never `lock`: the `shm*` hooks can be reentered from a signal
/// handler that interrupted another `shm*` hook mid-critical-section, and a
/// blocking lock would self-deadlock the target. On contention each hook falls
/// through to the real implementation (the same path taken when the table is
/// full or the lock is poisoned).
static SYSV: Mutex<Vec<SysvSeg>> = Mutex::new(Vec::new());

fn is_synth_shmid(id: libc::c_int) -> bool {
    id >= SYSV_SYNTH_BASE
}

#[no_mangle]
pub unsafe extern "C" fn shmget(
    key: libc::key_t,
    size: libc::size_t,
    shmflg: libc::c_int,
) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        if let Ok(mut table) = SYSV.try_lock() {
            // Reuse an existing keyed segment (bounds persistent-mode growth).
            if key != libc::IPC_PRIVATE {
                if let Some(seg) = table.iter().find(|s| s.key == key) {
                    let id = seg.id;
                    drop(table);
                    log_shm(b"shmget", b"sysv", id as i64, true);
                    return id;
                }
            }
            if table.len() < SYSV_CAP {
                let len = size.max(1);
                let ptr = libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if ptr != libc::MAP_FAILED {
                    // Drive the segment's content from the fuzz input (mode-driven)
                    // so a reader of the virtualized segment explores
                    // content-dependent paths — like the POSIX shm / file / MMIO
                    // fakes. Still private (no foreign writer) and, written by us,
                    // "initialized" to MSan.
                    crate::fakes::memfd::fill_region(b"sysv", ptr as *mut u8, len);
                    let id = SYSV_SYNTH_BASE + table.len() as libc::c_int;
                    table.push(SysvSeg {
                        key,
                        id,
                        ptr: ptr as usize,
                        size: len,
                    });
                    drop(table);
                    log_shm(b"shmget", b"sysv", id as i64, true);
                    return id;
                }
            }
        }
        // lock poisoned / table full / mmap failed -> fall through to real.
    }
    let real = REAL_SHMGET.ptr() as *const ();
    if real.is_null() {
        restore_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(libc::key_t, libc::size_t, libc::c_int) -> libc::c_int =
        std::mem::transmute(real);
    let result = real(key, size, shmflg);
    let saved = save_errno();
    log_shm(b"shmget", b"sysv", result as i64, false);
    restore_errno(saved);
    result
}

#[no_mangle]
pub unsafe extern "C" fn shmat(
    shmid: libc::c_int,
    shmaddr: *const libc::c_void,
    shmflg: libc::c_int,
) -> *mut libc::c_void {
    if is_synth_shmid(shmid) {
        if let Ok(table) = SYSV.try_lock() {
            if let Some(seg) = table.iter().find(|s| s.id == shmid) {
                let ptr = seg.ptr as *mut libc::c_void;
                drop(table);
                log_shm(b"shmat", b"sysv", shmid as i64, true);
                return ptr;
            }
        }
        // Unknown synthetic id: report an invalid attach rather than passing a
        // fabricated id to the real shmat.
        restore_errno(libc::EINVAL);
        return usize::MAX as *mut libc::c_void; // (void*)-1
    }
    let real = REAL_SHMAT.ptr() as *const ();
    if real.is_null() {
        restore_errno(libc::ENOSYS);
        return usize::MAX as *mut libc::c_void;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_void,
        libc::c_int,
    ) -> *mut libc::c_void = std::mem::transmute(real);
    real(shmid, shmaddr, shmflg)
}

#[no_mangle]
pub unsafe extern "C" fn shmdt(shmaddr: *const libc::c_void) -> libc::c_int {
    let addr = shmaddr as usize;
    if let Ok(table) = SYSV.try_lock() {
        if table.iter().any(|s| s.ptr == addr) {
            drop(table);
            // Keep the private mapping for the process lifetime (freed on
            // IPC_RMID); detach is a no-op success.
            log_shm(b"shmdt", b"sysv", 0, true);
            return 0;
        }
    }
    let real = REAL_SHMDT.ptr() as *const ();
    if real.is_null() {
        restore_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(*const libc::c_void) -> libc::c_int = std::mem::transmute(real);
    real(shmaddr)
}

#[no_mangle]
pub unsafe extern "C" fn shmctl(
    shmid: libc::c_int,
    cmd: libc::c_int,
    buf: *mut libc::shmid_ds,
) -> libc::c_int {
    if is_synth_shmid(shmid) {
        if let Ok(mut table) = SYSV.try_lock() {
            if let Some(pos) = table.iter().position(|s| s.id == shmid) {
                if cmd == libc::IPC_RMID {
                    let seg = table.remove(pos);
                    libc::munmap(seg.ptr as *mut libc::c_void, seg.size);
                    drop(table);
                    log_shm(b"shmctl", b"sysv", shmid as i64, true);
                    return 0;
                }
                if cmd == libc::IPC_STAT && !buf.is_null() {
                    let size = table[pos].size;
                    drop(table);
                    std::ptr::write_bytes(buf, 0, 1);
                    (*buf).shm_segsz = size as _;
                    log_shm(b"shmctl", b"sysv", shmid as i64, true);
                    return 0;
                }
                drop(table);
                log_shm(b"shmctl", b"sysv", shmid as i64, true);
                return 0;
            }
        }
        restore_errno(libc::EINVAL);
        return -1;
    }
    let real = REAL_SHMCTL.ptr() as *const ();
    if real.is_null() {
        restore_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::shmid_ds) -> libc::c_int =
        std::mem::transmute(real);
    real(shmid, cmd, buf)
}

// ---------------------------------------------------------------------------
// Anonymous mmap(MAP_SHARED) virtualization (#443)
// ---------------------------------------------------------------------------
//
// A target can create inter-process shared memory directly with
// `mmap(NULL, len, prot, MAP_SHARED | MAP_ANONYMOUS, -1, 0)` — no shm_open /
// shmget. That region stays truly shared, so the foreign-writer / MSan-uninit /
// TSan-race problem persists for this path (shm_open- and shmget-backed maps are
// already private, #438). During a faking pass we convert it to MAP_PRIVATE so it
// is harness-private.
//
// SAFETY — `mmap` is in the allocator / loader hot path: malloc, thread-stack
// setup, dlsym, and even this module's own logging can call it. Two rules keep
// the interposer from recursing or deadlocking:
//   1. The FAST PATH (everything that is not an anonymous MAP_SHARED) touches
//      nothing — no reentrancy guard, no thread-local, no mode lookup, no
//      allocation — it just issues the raw `mmap` syscall and returns. Every
//      bootstrap / allocator mapping is MAP_PRIVATE, so it takes this path and
//      can never recurse through us.
//   2. The conversion path runs only for an explicit anonymous MAP_SHARED (a
//      deliberate, post-bootstrap target action) and is gated by `HookGuard`: if
//      we are already inside a hook (e.g. the mode lookup's first-use env read
//      allocated and re-entered mmap), we skip conversion and pass through.
// The real mapping is always issued via the raw `SYS_mmap` syscall, never via the
// `mmap` libc symbol (which is THIS function) — so there is no self-recursion and
// no dependence on dlsym resolving a `REAL_MMAP`.

unsafe fn raw_mmap(
    addr: *mut libc::c_void,
    len: libc::size_t,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off_t,
) -> *mut libc::c_void {
    libc::syscall(libc::SYS_mmap, addr, len, prot, flags, fd, offset) as *mut libc::c_void
}

#[inline]
unsafe fn mmap_impl(
    addr: *mut libc::c_void,
    len: libc::size_t,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off_t,
) -> *mut libc::c_void {
    // Candidate = anonymous shared mapping. File-backed MAP_SHARED is left alone
    // (shm_open/shmget fds are already private via #438, and converting a real
    // file map would change write-back semantics).
    let is_anon_shared = flags & libc::MAP_SHARED != 0 && flags & libc::MAP_ANONYMOUS != 0;
    if is_anon_shared {
        if let Some(_g) = HookGuard::acquire() {
            if crate::fakes::mode::current().is_faking() {
                let private_flags = (flags & !libc::MAP_SHARED) | libc::MAP_PRIVATE;
                let ret = raw_mmap(addr, len, prot, private_flags, fd, offset);
                if ret != libc::MAP_FAILED {
                    // Logged within the held guard (do not re-acquire).
                    let mut b = Builder::new(b"mmap_private");
                    b.field_i64(b"len", len as i64);
                    b.field_i64(b"v", 1);
                    b.emit();
                }
                return ret;
            }
        }
    }
    raw_mmap(addr, len, prot, flags, fd, offset)
}

#[no_mangle]
pub unsafe extern "C" fn mmap(
    addr: *mut libc::c_void,
    len: libc::size_t,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off_t,
) -> *mut libc::c_void {
    mmap_impl(addr, len, prot, flags, fd, offset)
}

// glibc exposes a separate `mmap64` symbol (large-file API); on 64-bit it is the
// same call. Programs built with _FILE_OFFSET_BITS=64 bind to it directly.
#[no_mangle]
pub unsafe extern "C" fn mmap64(
    addr: *mut libc::c_void,
    len: libc::size_t,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off_t,
) -> *mut libc::c_void {
    mmap_impl(addr, len, prot, flags, fd, offset)
}

/// `--list-fakes` plugin entry for the shared-memory virtualization hooks.
pub struct Mem;

impl crate::sdk::FakeResource for Mem {
    fn name(&self) -> &'static str {
        "mem"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"shm_open\0",
            b"shm_unlink\0",
            b"shmget\0",
            b"shmat\0",
            b"shmdt\0",
            b"shmctl\0",
            b"mmap\0",
            b"mmap64\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "virtualize POSIX (shm_open), System V (shmget/shmat), and anonymous mmap(MAP_SHARED) shared memory as private memory so there is no foreign writer"
    }
}
