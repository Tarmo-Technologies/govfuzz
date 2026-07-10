// SPDX-License-Identifier: Apache-2.0

//! Synthetic dlopen handle table. dlopen() failures in faking mode
//! get a non-NULL handle from here; subsequent dlsym(handle, name)
//! returns the address of `govfuzz_fake_dlsym_stub` — a stub that
//! returns NULL/0 in rax. This is safe-by-default for the vast
//! majority of dlsym caller patterns (pointer return, scalar return,
//! function pointer return). Callers expecting struct return-by-value
//! still hit undefined behaviour; those targets must opt out via
//! `GOVFUZZ_DISABLE_DLOPEN_FAKE=1`.
//!
//! The handle range (0x8000…0x0000 to 0xC000…0x0000) deliberately
//! excludes RTLD_NEXT (`(void*)-1`) and RTLD_DEFAULT (`(void*)0`)
//! so dlsym(RTLD_NEXT, ...) inside our own ResolvedFn resolver
//! doesn't get redirected to the fake stub.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::doc_lazy_continuation)]

use std::sync::atomic::{AtomicUsize, Ordering};

/// Sentinel handle. We hand out small distinct values so dlclose()
/// + multiple dlopen()s see different handles. Real dlopen returns
/// pointers into the host's link-map; ours are deliberately
/// recognisable: high bits set so they can't collide with valid
/// pointers. We cap the synthetic range below RTLD_NEXT
/// (`(void*)-1`) and RTLD_DEFAULT (`(void*)0`) so dlsym(RTLD_NEXT,
/// ...) inside our own ResolvedFn resolver doesn't get redirected
/// to the fake stub.
const SYNTHETIC_HANDLE_BASE: usize = 0x8000_0000_0000_0000;
const SYNTHETIC_HANDLE_END: usize = 0xC000_0000_0000_0000;

static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(SYNTHETIC_HANDLE_BASE);

pub fn alloc_handle() -> *mut libc::c_void {
    let h = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    h as *mut libc::c_void
}

pub fn is_synthetic(handle: *mut libc::c_void) -> bool {
    let v = handle as usize;
    (SYNTHETIC_HANDLE_BASE..SYNTHETIC_HANDLE_END).contains(&v)
}

/// Per-name stub returned by dlsym() against a synthetic handle.
/// Returns `NULL` (rax = 0 on x86_64 SysV). This single stub safely
/// handles the three common dlsym caller patterns:
///
///   - Caller expects `void *`: gets a NULL sentinel, the canonical
///     "lookup failed" value. Subsequent `if (result == NULL)` checks
///     branch correctly to the fallback path.
///   - Caller expects `int` / `long` / any 64-bit-or-smaller scalar:
///     gets 0, indistinguishable from a "no value" result.
///   - Caller expects `void (*)(args)`: gets a NULL function pointer.
///     `if (!sym)` checks succeed; indirect calls through NULL
///     segfault at a known address (0x0) instead of jumping to
///     garbage in our shim's address range.
///
/// Callers that expect a small-struct return-by-value (rare for
/// dlsym'd APIs) still get undefined behaviour because SysV uses
/// `rdx` + hidden first arg conventions for those. Such callers
/// must explicitly opt out via `GOVFUZZ_DISABLE_DLOPEN_FAKE=1`.
#[no_mangle]
pub unsafe extern "C" fn govfuzz_fake_dlsym_stub() -> *mut libc::c_void {
    std::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_handles_are_distinct() {
        let h1 = alloc_handle();
        let h2 = alloc_handle();
        assert_ne!(h1, h2);
        assert!(is_synthetic(h1));
        assert!(is_synthetic(h2));
    }

    #[test]
    fn null_is_not_synthetic() {
        assert!(!is_synthetic(std::ptr::null_mut()));
    }

    #[test]
    fn rtld_next_is_not_synthetic() {
        // RTLD_NEXT is (void*)-1 — must not match the synthetic
        // range or dlsym(RTLD_NEXT, ...) inside ResolvedFn would
        // wrongly redirect to govfuzz_fake_dlsym_stub.
        assert!(!is_synthetic(libc::RTLD_NEXT));
        assert!(!is_synthetic(libc::RTLD_DEFAULT));
    }
}
