// SPDX-License-Identifier: Apache-2.0

//! `libgovfuzz_cc_intercept.so` — a build-time LD_PRELOAD shim that catches
//! compiler invocations the front-of-`PATH` wrapper cannot: compilers invoked by
//! ABSOLUTE path (vendor RTOS toolchains like `/opt/ghs/.../ccarm`, a Bazel
//! toolchain, anything a build hardcodes) and via `posix_spawn` (ninja/cmake).
//!
//! It interposes the `exec*` / `posix_spawn*` family, and when the program being
//! launched is a compiler (by basename), appends one record to the file named by
//! `$GF_CC_LOG` — the SAME `DIR`/`CC`/`ARG`/`ENDREC` format the Make-tier and
//! `--build-command` PATH shims emit, so `build_probe::parse_intercept_log`
//! consumes it unchanged. `build_probe` deduplicates by source file, so running
//! this alongside the PATH shim never double-counts a translation unit.
//!
//! Safety discipline (mirrors the runtrace shim): a hook may run between `fork()`
//! and `exec()` in a multithreaded build tool, i.e. in async-signal context. So
//! it must call ONLY async-signal-safe primitives — no malloc, no `String`/`Vec`,
//! no stdio. Each record is built in a fixed stack buffer and emitted with ONE
//! `write(2)` to an `O_APPEND` fd (atomic w.r.t. concurrent `-j` compilers). Real
//! symbols are resolved once at load (`.init_array`, normal context) so the hooks
//! never call the non-async-signal-safe `dlsym`.

#![cfg(target_os = "linux")]

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use libc::{c_char, c_int};

// ---- cached real symbols + log path, set once at load -------------------------

static REAL_EXECVE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_EXECV: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_EXECVP: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_EXECVPE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_POSIX_SPAWN: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_POSIX_SPAWNP: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

const LOG_PATH_CAP: usize = 4096;
/// `$GF_CC_LOG`, copied NUL-terminated at load. Written once before any hook can
/// fire (`.init_array` precedes the program's own code), read-only thereafter.
static mut LOG_PATH: [u8; LOG_PATH_CAP] = [0; LOG_PATH_CAP];
static HAVE_LOG: AtomicBool = AtomicBool::new(false);

unsafe fn resolve(name: &[u8]) -> *mut c_void {
    libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast())
}

/// Loaded via `.init_array` at `.so` load (normal context: `dlsym`/`getenv` are
/// safe here). Caches the real exec symbols and the log path so the hooks are
/// pure async-signal-safe writes.
extern "C" fn init() {
    unsafe {
        REAL_EXECVE.store(resolve(b"execve\0"), Ordering::Relaxed);
        REAL_EXECV.store(resolve(b"execv\0"), Ordering::Relaxed);
        REAL_EXECVP.store(resolve(b"execvp\0"), Ordering::Relaxed);
        REAL_EXECVPE.store(resolve(b"execvpe\0"), Ordering::Relaxed);
        REAL_POSIX_SPAWN.store(resolve(b"posix_spawn\0"), Ordering::Relaxed);
        REAL_POSIX_SPAWNP.store(resolve(b"posix_spawnp\0"), Ordering::Relaxed);

        let key = b"GF_CC_LOG\0";
        let val = libc::getenv(key.as_ptr().cast());
        if !val.is_null() {
            let mut i = 0usize;
            // Bounded copy, leaving room for the NUL.
            while i < LOG_PATH_CAP - 1 {
                let b = *val.add(i);
                if b == 0 {
                    break;
                }
                LOG_PATH[i] = b as u8;
                i += 1;
            }
            LOG_PATH[i] = 0;
            if i > 0 {
                HAVE_LOG.store(true, Ordering::Relaxed);
            }
        }
    }
}

#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = init;

// ---- compiler recognition (no alloc) ------------------------------------------

/// Basename of a NUL-terminated path: the slice after the last `/`, bounded.
unsafe fn basename(path: *const c_char) -> (*const u8, usize) {
    if path.is_null() {
        return (core::ptr::null(), 0);
    }
    let p = path.cast::<u8>();
    let mut len = 0usize;
    while len < 1024 && *p.add(len) != 0 {
        len += 1;
    }
    let mut start = 0usize;
    let mut i = 0usize;
    while i < len {
        if *p.add(i) == b'/' {
            start = i + 1;
        }
        i += 1;
    }
    (p.add(start), len - start)
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// Curated compiler basenames — host frontends + the named vendor compilers
/// (Diab, Green Hills per-arch, QNX, Keil/IAR, TI). Mirrors
/// `build_probe::INTERCEPT_COMPILER_NAMES`.
const COMPILER_NAMES: &[&[u8]] = &[
    b"cc",
    b"c++",
    b"gcc",
    b"g++",
    b"clang",
    b"clang++",
    b"cpp",
    b"clang-cpp",
    b"dcc",
    b"dplus",
    b"ccarm",
    b"cxarm",
    b"ccppc",
    b"cxppc",
    b"ccintarm64",
    b"ccx86",
    b"cxx86",
    b"qcc",
    b"q++",
    b"armcc",
    b"armclang",
    b"iccarm",
    b"cl2000",
    b"cl6x",
    b"cl430",
];

/// Whether `name` ends with a cross-compiler suffix (`aarch64-linux-gnu-gcc`,
/// `ntoaarch64-gcc`, …) preceded by a real prefix.
fn is_cross_name(name: &[u8]) -> bool {
    const SUF: &[&[u8]] = &[b"-gcc", b"-g++", b"-cc", b"-c++", b"-clang", b"-clang++"];
    SUF.iter()
        .any(|s| name.len() > s.len() && &name[name.len() - s.len()..] == *s)
}

unsafe fn is_compiler(path: *const c_char) -> bool {
    let (ptr, len) = basename(path);
    if ptr.is_null() || len == 0 {
        return false;
    }
    let name = core::slice::from_raw_parts(ptr, len);
    COMPILER_NAMES.iter().any(|n| eq(name, n)) || is_cross_name(name)
}

// ---- record buffer (fixed, no alloc) ------------------------------------------

const REC_CAP: usize = 64 * 1024;

struct Rec {
    buf: [u8; REC_CAP],
    len: usize,
    ok: bool,
}

impl Rec {
    fn new() -> Self {
        Rec {
            buf: [0; REC_CAP],
            len: 0,
            ok: true,
        }
    }
    fn put(&mut self, bytes: &[u8]) {
        if !self.ok {
            return;
        }
        if self.len + bytes.len() > REC_CAP {
            self.ok = false; // overflow: drop the record rather than truncate
            return;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }
    /// Append a NUL-terminated C string's bytes (bounded), without the NUL.
    unsafe fn put_cstr(&mut self, s: *const c_char) {
        if s.is_null() {
            return;
        }
        let p = s.cast::<u8>();
        let mut i = 0usize;
        while i < REC_CAP {
            let b = *p.add(i);
            if b == 0 {
                break;
            }
            i += 1;
        }
        self.put(core::slice::from_raw_parts(p, i));
    }
}

/// Append one `DIR/CC/ARG.../ENDREC` record for `path` + `argv` to `$GF_CC_LOG`
/// in a single atomic write. No-op when there is no log or the program is not a
/// compiler. Pure async-signal-safe primitives only.
unsafe fn maybe_log(path: *const c_char, argv: *const *const c_char) {
    if !HAVE_LOG.load(Ordering::Relaxed) || !is_compiler(path) {
        return;
    }
    let mut rec = Rec::new();

    // DIR <cwd>
    let mut cwd = [0u8; 4096];
    let got = libc::getcwd(cwd.as_mut_ptr().cast(), cwd.len());
    rec.put(b"DIR ");
    if !got.is_null() {
        let mut n = 0usize;
        while n < cwd.len() && cwd[n] != 0 {
            n += 1;
        }
        rec.put(&cwd[..n]);
    }
    rec.put(b"\n");

    // CC <path>
    rec.put(b"CC ");
    rec.put_cstr(path);
    rec.put(b"\n");

    // ARG <argv[i]> for i >= 1 (argv[0] is the program name)
    if !argv.is_null() {
        let mut i = 1usize;
        loop {
            let a = *argv.add(i);
            if a.is_null() {
                break;
            }
            rec.put(b"ARG ");
            rec.put_cstr(a);
            rec.put(b"\n");
            i += 1;
            if i > 4096 {
                break; // pathological argv guard
            }
        }
    }
    rec.put(b"ENDREC\n");

    if !rec.ok || rec.len == 0 {
        return;
    }

    let path_ptr = (&raw const LOG_PATH).cast::<c_char>();
    let fd = libc::open(
        path_ptr,
        libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT,
        0o644,
    );
    if fd < 0 {
        return;
    }
    let _ = libc::write(fd, rec.buf.as_ptr().cast(), rec.len);
    libc::close(fd);
}

// ---- interposed entry points --------------------------------------------------

type ExecveFn =
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int;
type ExecvFn = unsafe extern "C" fn(*const c_char, *const *const c_char) -> c_int;
type SpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const c_char,
    *const c_void,
    *const c_void,
    *const *const c_char,
    *const *const c_char,
) -> c_int;

/// # Safety
/// LD_PRELOAD entry point; raw C ABI. Arguments come from the C caller.
#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    maybe_log(path, argv);
    let real = REAL_EXECVE.load(Ordering::Relaxed);
    if real.is_null() {
        libc::syscall(libc::SYS_execve, path, argv, envp) as c_int
    } else {
        core::mem::transmute::<*mut c_void, ExecveFn>(real)(path, argv, envp)
    }
}

/// # Safety
/// LD_PRELOAD entry point; raw C ABI.
#[no_mangle]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    maybe_log(path, argv);
    let real = REAL_EXECV.load(Ordering::Relaxed);
    debug_assert!(!real.is_null());
    core::mem::transmute::<*mut c_void, ExecvFn>(real)(path, argv)
}

/// # Safety
/// LD_PRELOAD entry point; raw C ABI.
#[no_mangle]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    maybe_log(file, argv);
    let real = REAL_EXECVP.load(Ordering::Relaxed);
    debug_assert!(!real.is_null());
    core::mem::transmute::<*mut c_void, ExecvFn>(real)(file, argv)
}

/// # Safety
/// LD_PRELOAD entry point; raw C ABI.
#[no_mangle]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    maybe_log(file, argv);
    let real = REAL_EXECVPE.load(Ordering::Relaxed);
    if real.is_null() {
        // Fallback: PATH search isn't reproducible here, so chain to execvp which
        // we also interpose (it will not re-log because of source-dedup).
        return execvp(file, argv);
    }
    core::mem::transmute::<*mut c_void, ExecveFn>(real)(file, argv, envp)
}

/// # Safety
/// LD_PRELOAD entry point; raw C ABI.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    maybe_log(path, argv);
    let real = REAL_POSIX_SPAWN.load(Ordering::Relaxed);
    debug_assert!(!real.is_null());
    core::mem::transmute::<*mut c_void, SpawnFn>(real)(pid, path, file_actions, attrp, argv, envp)
}

/// # Safety
/// LD_PRELOAD entry point; raw C ABI.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    maybe_log(file, argv);
    let real = REAL_POSIX_SPAWNP.load(Ordering::Relaxed);
    debug_assert!(!real.is_null());
    core::mem::transmute::<*mut c_void, SpawnFn>(real)(pid, file, file_actions, attrp, argv, envp)
}
