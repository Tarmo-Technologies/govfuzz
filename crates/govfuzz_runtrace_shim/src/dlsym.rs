// SPDX-License-Identifier: Apache-2.0

//! Resolve the "real" implementations of intercepted syscalls in the
//! next link-map entry after ours (the host libc).
//!
//! We must not call the plain `dlsym` symbol from inside the shim:
//! this cdylib overrides `dlsym` (see `hooks/dlsym.rs`), so the
//! `dlsym` name would bind back to our own hook and recurse. So we
//! resolve in two steps:
//!
//! 1. `dlvsym(RTLD_NEXT, name, "GLIBC_2.2.5")` — the un-hooked
//!    versioned lookup, which catches every symbol present in the
//!    base glibc x86_64 version.
//! 2. If that fails, the symbol is versioned later than the base
//!    (e.g. `openat`/`faccessat`/`readlinkat` are `GLIBC_2.4`). Fall
//!    back to an *unversioned* lookup through the real libc `dlsym`,
//!    whose address we obtain once via `dlvsym` (so we still never
//!    re-enter our own hook). `dlsym(RTLD_NEXT, name)` resolves a
//!    symbol regardless of its version tag.
//!
//! The previous single hardcoded `GLIBC_2.2.5` lookup returned NULL
//! for the `*at` family, and the hooks' null-fallback then called
//! `libc::openat` — which, because this shim exports `openat`, bound
//! straight back to the hook and span forever. Step 2 makes the
//! happy path resolve, so that fallback is no longer reached.
//!
//! We cache each resolution in a static AtomicPtr so subsequent
//! calls are a single relaxed-atomic load.

use std::ffi::CStr;
use std::sync::atomic::{AtomicPtr, Ordering};

const GLIBC_BASE_VERSION: &[u8] = b"GLIBC_2.2.5\0";

/// The real libc `dlsym`, resolved once via the un-hooked `dlvsym`.
/// Used only for the unversioned fallback in `resolve`.
static REAL_DLSYM_PTR: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());

type DlsymFn = unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void;

unsafe fn real_dlsym() -> Option<DlsymFn> {
    let cached = REAL_DLSYM_PTR.load(Ordering::Relaxed);
    let raw = if cached.is_null() {
        // `dlsym` itself is present at the base version, so the
        // versioned lookup resolves it without touching our hook.
        let p = libc::dlvsym(
            libc::RTLD_NEXT,
            c"dlsym".as_ptr(),
            GLIBC_BASE_VERSION.as_ptr() as *const libc::c_char,
        );
        REAL_DLSYM_PTR.store(p, Ordering::Relaxed);
        p
    } else {
        cached
    };
    if raw.is_null() {
        None
    } else {
        Some(std::mem::transmute::<*mut libc::c_void, DlsymFn>(raw))
    }
}

/// Look up `symbol` in the next link-map entry after ours (the host
/// libc). Returns null on failure — caller should short-circuit
/// (not call anything, just return a sensible default to the
/// original caller).
unsafe fn resolve(symbol: &CStr) -> *mut libc::c_void {
    let versioned = libc::dlvsym(
        libc::RTLD_NEXT,
        symbol.as_ptr(),
        GLIBC_BASE_VERSION.as_ptr() as *const libc::c_char,
    );
    if !versioned.is_null() {
        return versioned;
    }
    // Symbol versioned later than the base — unversioned fallback via
    // the real dlsym. RTLD_NEXT is evaluated against this shim's call
    // frame, so it still resolves to libc, not back to our hook.
    match real_dlsym() {
        Some(dlsym) => dlsym(libc::RTLD_NEXT, symbol.as_ptr()),
        None => std::ptr::null_mut(),
    }
}

/// Cache the resolution of a single named symbol. Use one
/// `ResolvedFn` per intercepted function:
///
/// ```ignore
/// static REAL_OPEN: ResolvedFn = ResolvedFn::new(b"open\0");
/// ```
pub struct ResolvedFn {
    name: &'static [u8],
    cache: AtomicPtr<libc::c_void>,
}

impl ResolvedFn {
    pub const fn new(name: &'static [u8]) -> Self {
        Self {
            name,
            cache: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    /// Returns the resolved fn pointer or null if dlsym failed. Use
    /// `is_null()` on the result before casting + calling.
    pub fn ptr(&self) -> *mut libc::c_void {
        let cached = self.cache.load(Ordering::Relaxed);
        if !cached.is_null() {
            return cached;
        }
        // Safety: `name` is a static nul-terminated byte slice.
        let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(self.name) };
        let p = unsafe { resolve(cstr) };
        self.cache.store(p, Ordering::Relaxed);
        p
    }
}
