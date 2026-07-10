// SPDX-License-Identifier: Apache-2.0

//! C/C++ assertion audit hooks. These record native contract
//! failures before forwarding to glibc's terminating implementation.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

static REAL_ASSERT_FAIL: ResolvedFn = ResolvedFn::new(b"__assert_fail\0");
static REAL_ASSERT_PERROR_FAIL: ResolvedFn = ResolvedFn::new(b"__assert_perror_fail\0");

unsafe fn bytes_from_ptr(p: *const libc::c_char) -> &'static [u8] {
    if p.is_null() {
        return &[];
    }
    let cstr = CStr::from_ptr(p);
    let slice: &[u8] = cstr.to_bytes();
    std::mem::transmute::<&[u8], &'static [u8]>(slice)
}

fn field_str_if_present(builder: &mut Builder, key: &[u8], value: &[u8]) {
    if !value.is_empty() {
        builder.field_str(key, value);
    }
}

fn log_assertion(api: &[u8], expression: &[u8], file: &[u8], line: libc::c_uint, function: &[u8]) {
    let Some(_guard) = HookGuard::acquire() else {
        return;
    };
    let mut builder = Builder::new(b"assertion_failed");
    builder.field_str(b"a", api);
    field_str_if_present(&mut builder, b"x", expression);
    field_str_if_present(&mut builder, b"f", file);
    builder.field_i64(b"n", line as i64);
    field_str_if_present(&mut builder, b"g", function);
    builder.emit();
}

#[no_mangle]
pub unsafe extern "C" fn __assert_fail(
    assertion: *const libc::c_char,
    file: *const libc::c_char,
    line: libc::c_uint,
    function: *const libc::c_char,
) -> ! {
    log_assertion(
        b"__assert_fail",
        bytes_from_ptr(assertion),
        bytes_from_ptr(file),
        line,
        bytes_from_ptr(function),
    );

    let real = REAL_ASSERT_FAIL.ptr() as *const ();
    if real.is_null() {
        libc::abort();
    }
    let real: unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        libc::c_uint,
        *const libc::c_char,
    ) -> ! = std::mem::transmute(real);
    real(assertion, file, line, function)
}

#[no_mangle]
pub unsafe extern "C" fn __assert_perror_fail(
    errnum: libc::c_int,
    file: *const libc::c_char,
    line: libc::c_uint,
    function: *const libc::c_char,
) -> ! {
    let Some(_guard) = HookGuard::acquire() else {
        let real = REAL_ASSERT_PERROR_FAIL.ptr() as *const ();
        if real.is_null() {
            libc::abort();
        }
        let real: unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_char,
            libc::c_uint,
            *const libc::c_char,
        ) -> ! = std::mem::transmute(real);
        real(errnum, file, line, function)
    };

    let mut builder = Builder::new(b"assertion_failed");
    builder.field_str(b"a", b"__assert_perror_fail");
    builder.field_str(b"x", b"perror");
    builder.field_i64(b"r", errnum as i64);
    field_str_if_present(&mut builder, b"f", bytes_from_ptr(file));
    builder.field_i64(b"n", line as i64);
    field_str_if_present(&mut builder, b"g", bytes_from_ptr(function));
    builder.emit();
    drop(_guard);

    let real = REAL_ASSERT_PERROR_FAIL.ptr() as *const ();
    if real.is_null() {
        libc::abort();
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_uint,
        *const libc::c_char,
    ) -> ! = std::mem::transmute(real);
    real(errnum, file, line, function)
}

pub struct Assertion;

impl crate::sdk::FakeResource for Assertion {
    fn name(&self) -> &'static str {
        "assertion"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"__assert_fail\0", b"__assert_perror_fail\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log native C/C++ assertion failures before forwarding to libc"
    }
}
