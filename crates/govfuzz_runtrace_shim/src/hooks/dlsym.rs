// SPDX-License-Identifier: Apache-2.0

//! Intercept dlsym(handle, name). When the handle is one of ours
//! (synthetic dlopen handle from Task 5), return a pointer to the
//! per-name stub. Otherwise pass through to the real dlsym.
//!
//! Safety: the #[no_mangle] extern "C" fn here overrides libdl's
//! dlsym. Caller-supplied pointers must satisfy libdl's dlsym()
//! contract — we forward unchanged or substitute a stub address.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::fakes::dl_handle::{govfuzz_fake_dlsym_stub, is_synthetic};
use crate::fakes::mode::current;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_DLSYM: ResolvedFn = ResolvedFn::new(b"dlsym\0");

#[no_mangle]
pub unsafe extern "C" fn dlsym(
    handle: *mut libc::c_void,
    symbol: *const libc::c_char,
) -> *mut libc::c_void {
    if is_synthetic(handle) {
        if !symbol.is_null() {
            if let Some(_g) = HookGuard::acquire() {
                let name = CStr::from_ptr(symbol).to_bytes();
                let mut b = Builder::new(b"dlsym");
                b.field_str(b"s", name);
                b.field_str(b"r", b"stub");
                b.field_str(b"m", current().as_str().as_bytes());
                b.emit();
            }
        }
        return govfuzz_fake_dlsym_stub as *mut libc::c_void;
    }
    let real = REAL_DLSYM.ptr() as *const ();
    if real.is_null() {
        // Can't call libc::dlsym here — that would re-dispatch
        // back into this hook and recurse. Return null and let
        // the caller treat the symbol as unresolved.
        return std::ptr::null_mut();
    }
    let real: unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void =
        std::mem::transmute(real);
    real(handle, symbol)
}

pub struct Dlsym;

impl crate::sdk::FakeResource for Dlsym {
    fn name(&self) -> &'static str {
        "dlsym"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"dlsym\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "resolve dlsym lookups against fake dlopen handles"
    }
}
