// SPDX-License-Identifier: Apache-2.0

//! Printf-style format-string audit hooks. The variadic entrypoints
//! live in `format_hooks.c`; this Rust module provides the log helper
//! and plugin metadata.

#![allow(clippy::missing_safety_doc)]

use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

unsafe extern "C" {
    fn dprintf();
    fn fprintf();
    fn govfuzz_format_hook_anchor();
    fn printf();
    fn snprintf();
    fn sprintf();
}

#[used]
static KEEP_FORMAT_HOOKS: [unsafe extern "C" fn(); 6] = [
    govfuzz_format_hook_anchor,
    printf,
    fprintf,
    dprintf,
    sprintf,
    snprintf,
];

#[no_mangle]
pub unsafe extern "C" fn govfuzz_runtrace_log_format(
    api: *const libc::c_char,
    format: *const libc::c_char,
) {
    if api.is_null() || format.is_null() {
        return;
    }
    let api = CStr::from_ptr(api).to_bytes();
    let format = CStr::from_ptr(format).to_bytes();
    if api.is_empty() || format.is_empty() {
        return;
    }
    let Some(_guard) = HookGuard::acquire() else {
        return;
    };
    let controlled = crate::fakes::fuzz_input::contains_bytes(format);
    let mut builder = Builder::new(b"format");
    builder.field_str(b"a", api);
    builder.field_str(b"f", format);
    builder.field_i64(b"u", i64::from(controlled));
    builder.emit();
}

pub struct Format;

impl crate::sdk::FakeResource for Format {
    fn name(&self) -> &'static str {
        "format"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"printf\0",
            b"fprintf\0",
            b"sprintf\0",
            b"snprintf\0",
            b"dprintf\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log printf-style format strings and whether they match current fuzz input"
    }
}
