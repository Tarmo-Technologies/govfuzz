// SPDX-License-Identifier: Apache-2.0

//! dlopen audit hook. NULL return means the requested library
//! isn't on the search path or doesn't satisfy the requested
//! symbol version. Slice C will return a synthetic handle and
//! redirect dlsym; for now we just observe.
//!
//! Safety: the #[no_mangle] extern "C" fn here is invoked by the
//! dynamic linker as a libdl symbol. Caller-supplied pointers
//! must satisfy libdl's dlopen() contract — we forward unchanged.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_DLOPEN: ResolvedFn = ResolvedFn::new(b"dlopen\0");
static REAL_DLMOPEN: ResolvedFn = ResolvedFn::new(b"dlmopen\0");
static REAL_DLCLOSE: ResolvedFn = ResolvedFn::new(b"dlclose\0");

/// Minimum run of fuzz-input-derived bytes a library path must contain before it
/// is treated as taint (#422). Matches the floor the other sink hooks use.
const TAINT_MIN_LEN: usize = 4;

/// Emit a `lib_load` sink event for a dynamic-library path reached during a fuzz
/// execution, tagged with byte-origin taint when a contiguous run of the path
/// came from the current fuzz input. Emitted on every load (tainted or not, and
/// regardless of success) so the CLI's controlled-library-load sink oracle
/// (GF-435) can confirm a fuzz-controlled path and suppress a constant plugin
/// path. Loading an attacker-chosen shared object is arbitrary code execution.
unsafe fn emit_lib_load(api: &[u8], filename: *const libc::c_char) {
    if filename.is_null() {
        return;
    }
    let name = CStr::from_ptr(filename).to_bytes();
    if name.is_empty() {
        return;
    }
    let mut b = Builder::new(b"lib_load");
    b.field_str(b"a", api);
    b.field_str(b"l", name);
    if let Some((offset, _len)) = crate::fakes::fuzz_input::input_derived_run(name, TAINT_MIN_LEN) {
        b.field_i64(b"u", 1);
        b.field_i64(b"o", offset as i64);
    }
    b.emit();
}

#[no_mangle]
pub unsafe extern "C" fn dlopen(
    filename: *const libc::c_char,
    flags: libc::c_int,
) -> *mut libc::c_void {
    let real = REAL_DLOPEN.ptr() as *const ();
    if real.is_null() {
        return libc::dlopen(filename, flags);
    }
    let real: unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> *mut libc::c_void =
        std::mem::transmute(real);
    let result = real(filename, flags);
    // #422: emit the controlled-library-load sink event on every load (GF-435).
    if let Some(_g) = HookGuard::acquire() {
        emit_lib_load(b"dlopen", filename);
    }
    if result.is_null() && !filename.is_null() {
        if let Some(_g) = HookGuard::acquire() {
            let name: &'static [u8] = std::mem::transmute(CStr::from_ptr(filename).to_bytes());
            let mut b = Builder::new(b"dlopen");
            b.field_str(b"l", name);
            b.field_null(b"r");
            b.emit();
        }
        if crate::fakes::mode::current().is_faking()
            && std::env::var_os("GOVFUZZ_DISABLE_DLOPEN_FAKE").is_none()
        {
            return crate::fakes::dl_handle::alloc_handle();
        }
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn dlmopen(
    lmid: libc::c_long,
    filename: *const libc::c_char,
    flags: libc::c_int,
) -> *mut libc::c_void {
    let real = REAL_DLMOPEN.ptr() as *const ();
    if real.is_null() {
        *libc::__errno_location() = libc::ENOSYS;
        return std::ptr::null_mut();
    }
    let real: unsafe extern "C" fn(
        libc::c_long,
        *const libc::c_char,
        libc::c_int,
    ) -> *mut libc::c_void = std::mem::transmute(real);
    let result = real(lmid, filename, flags);
    if let Some(_g) = HookGuard::acquire() {
        emit_lib_load(b"dlmopen", filename);
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn dlclose(handle: *mut libc::c_void) -> libc::c_int {
    if crate::fakes::dl_handle::is_synthetic(handle) {
        return 0;
    }
    let real = REAL_DLCLOSE.ptr() as *const ();
    if real.is_null() {
        return 0;
    }
    let real: unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int = std::mem::transmute(real);
    real(handle)
}

pub struct Dl;

impl crate::sdk::FakeResource for Dl {
    fn name(&self) -> &'static str {
        "dl"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"dlopen\0", b"dlmopen\0", b"dlclose\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "fake dlopen handles for missing .so files and audit controlled library loads"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlclose_synthetic_handle_returns_success() {
        let handle = crate::fakes::dl_handle::alloc_handle();

        let result = unsafe { dlclose(handle) };

        assert_eq!(result, 0);
    }
}
