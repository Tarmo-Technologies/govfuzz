// SPDX-License-Identifier: Apache-2.0

//! CmpLog intercepts. When `GOVFUZZ_CMPLOG=1` is set, `strcmp`,
//! `strncmp`, and `memcmp` calls record both operand byte ranges
//! (capped at 64 bytes per side) to the audit log as `c:"cmplog"`
//! events. The builtin engine's mutator consumes the log via
//! `cmplog::ingest_from_jsonl_log` to splice operand values back
//! into inputs at matching offsets — the RedQueen-style
//! magic-byte trick that turns equality guards from a brute-force
//! search into a one-shot transformation.
//!
//! Allocation discipline: same as the other hook modules — no
//! malloc / Box / Vec / String from inside the hooks. Operands
//! are emitted as base64-of-hex pairs via the existing
//! jsonl::Builder fixed-buffer path.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use crate::sdk::FakeResource;

const ENV_VAR: &[u8] = b"GOVFUZZ_CMPLOG\0";
const MAX_OPERAND_BYTES: usize = 64;

static REAL_STRCMP: ResolvedFn = ResolvedFn::new(b"strcmp\0");
static REAL_STRNCMP: ResolvedFn = ResolvedFn::new(b"strncmp\0");
static REAL_MEMCMP: ResolvedFn = ResolvedFn::new(b"memcmp\0");

pub fn env_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static CACHED: AtomicU8 = AtomicU8::new(2);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let value = unsafe { libc::getenv(ENV_VAR.as_ptr() as *const libc::c_char) };
    let enabled = if value.is_null() {
        false
    } else {
        let s = unsafe { std::ffi::CStr::from_ptr(value) };
        s.to_bytes() == b"1"
    };
    CACHED.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    enabled
}

pub struct CmpLog;

impl FakeResource for CmpLog {
    fn name(&self) -> &'static str {
        "cmplog"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"strcmp\0", b"strncmp\0", b"memcmp\0"]
    }
    fn is_enabled(&self) -> bool {
        env_enabled()
    }
    fn describe(&self) -> &'static str {
        "record strcmp/strncmp/memcmp operands so the engine can splice them into inputs"
    }
}

/// Hex-encode up to `MAX_OPERAND_BYTES` bytes into a stack buffer.
/// Returns a slice into the supplied output buffer.
fn hex_into<'a>(input: &[u8], out: &'a mut [u8; MAX_OPERAND_BYTES * 2]) -> &'a [u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = input.len().min(MAX_OPERAND_BYTES);
    for (i, byte) in input.iter().take(n).enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0F) as usize];
    }
    &out[..n * 2]
}

fn emit_cmp(kind: &[u8], a: &[u8], b_bytes: &[u8]) {
    if let Some(_g) = HookGuard::acquire() {
        let mut buf_a = [0u8; MAX_OPERAND_BYTES * 2];
        let mut buf_b = [0u8; MAX_OPERAND_BYTES * 2];
        let hex_a = hex_into(a, &mut buf_a);
        let hex_b = hex_into(b_bytes, &mut buf_b);
        let mut b = Builder::new(b"cmplog");
        b.field_str(b"k", kind);
        b.field_str(b"a", hex_a);
        b.field_str(b"b", hex_b);
        b.emit();
    }
}

#[no_mangle]
pub unsafe extern "C" fn strcmp(a: *const libc::c_char, b: *const libc::c_char) -> i32 {
    let real = REAL_STRCMP.ptr() as *const ();
    if real.is_null() {
        // Last-resort: call libc directly; we lose the cmplog
        // event but stay correct.
        return libc::strcmp(a, b);
    }
    let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> i32 =
        std::mem::transmute(real);
    if env_enabled() && !a.is_null() && !b.is_null() {
        let len_a = libc::strlen(a).min(MAX_OPERAND_BYTES);
        let len_b = libc::strlen(b).min(MAX_OPERAND_BYTES);
        let slice_a = std::slice::from_raw_parts(a as *const u8, len_a);
        let slice_b = std::slice::from_raw_parts(b as *const u8, len_b);
        emit_cmp(b"strcmp", slice_a, slice_b);
    }
    real(a, b)
}

#[no_mangle]
pub unsafe extern "C" fn strncmp(
    a: *const libc::c_char,
    b: *const libc::c_char,
    n: libc::size_t,
) -> i32 {
    let real = REAL_STRNCMP.ptr() as *const ();
    if real.is_null() {
        return libc::strncmp(a, b, n);
    }
    let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, libc::size_t) -> i32 =
        std::mem::transmute(real);
    if env_enabled() && !a.is_null() && !b.is_null() {
        let (slice_a, slice_b) = strncmp_safe_slices(a, b, n);
        emit_cmp(b"strncmp", slice_a, slice_b);
    }
    real(a, b, n)
}

/// Build read-safe byte slices over the strncmp operands.
///
/// strncmp stops at the first null byte in either operand, so a
/// caller that passes a huge `n` against a short string is perfectly
/// legal. The hook must respect that bound or `from_raw_parts` reads
/// past the buffer (heap OOB / SEGV in the harness). We cap with
/// strnlen on each side, then with `MAX_OPERAND_BYTES`, before handing
/// the slice to the JSON emitter.
///
/// # Safety
///
/// Caller must guarantee `a` and `b` are valid for reads up to
/// `min(n, MAX_OPERAND_BYTES)` bytes or terminate with a null within
/// that range. These are exactly the preconditions a well-formed
/// strncmp caller already supplies.
unsafe fn strncmp_safe_slices<'a>(
    a: *const libc::c_char,
    b: *const libc::c_char,
    n: libc::size_t,
) -> (&'a [u8], &'a [u8]) {
    let cap = n.min(MAX_OPERAND_BYTES);
    let len_a = libc::strnlen(a, cap);
    let len_b = libc::strnlen(b, cap);
    (
        std::slice::from_raw_parts(a as *const u8, len_a),
        std::slice::from_raw_parts(b as *const u8, len_b),
    )
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(
    a: *const libc::c_void,
    b: *const libc::c_void,
    n: libc::size_t,
) -> i32 {
    let real = REAL_MEMCMP.ptr() as *const ();
    if real.is_null() {
        return libc::memcmp(a, b, n);
    }
    let real: unsafe extern "C" fn(*const libc::c_void, *const libc::c_void, libc::size_t) -> i32 =
        std::mem::transmute(real);
    if env_enabled() && !a.is_null() && !b.is_null() {
        let len = n.min(MAX_OPERAND_BYTES);
        let slice_a = std::slice::from_raw_parts(a as *const u8, len);
        let slice_b = std::slice::from_raw_parts(b as *const u8, len);
        emit_cmp(b"memcmp", slice_a, slice_b);
    }
    real(a, b, n)
}

#[cfg(test)]
mod tests {
    use super::CmpLog;
    use crate::sdk::FakeResource;

    #[test]
    fn cmplog_plugin_metadata_matches_manifest() {
        let plugin = CmpLog;
        assert_eq!(plugin.name(), "cmplog");
        assert_eq!(
            plugin.intercepts(),
            &[b"strcmp\0" as &[u8], b"strncmp\0", b"memcmp\0"]
        );
        assert!(plugin.describe().contains("strcmp/strncmp/memcmp"));
    }

    #[test]
    fn hex_into_encodes_bytes_lowercase() {
        let mut buf = [0u8; super::MAX_OPERAND_BYTES * 2];
        let out = super::hex_into(&[0xab, 0x01, 0xff], &mut buf);
        assert_eq!(out, b"ab01ff");
    }

    #[test]
    fn hex_into_caps_at_max_operand_bytes() {
        let input = [0xCDu8; super::MAX_OPERAND_BYTES + 10];
        let mut buf = [0u8; super::MAX_OPERAND_BYTES * 2];
        let out = super::hex_into(&input, &mut buf);
        assert_eq!(out.len(), super::MAX_OPERAND_BYTES * 2);
    }

    #[test]
    fn strncmp_safe_slices_caps_at_null_terminator_when_n_is_huge() {
        use std::ffi::CString;
        let a = CString::new("ab").unwrap();
        let b = CString::new("cd").unwrap();
        // n=1000 but strings are only 2 bytes — must NOT read past null.
        let (sa, sb) = unsafe { super::strncmp_safe_slices(a.as_ptr(), b.as_ptr(), 1000) };
        assert_eq!(sa, b"ab");
        assert_eq!(sb, b"cd");
    }

    #[test]
    fn strncmp_safe_slices_respects_explicit_n_when_smaller_than_string() {
        use std::ffi::CString;
        let a = CString::new("abcdef").unwrap();
        let b = CString::new("ghijkl").unwrap();
        let (sa, sb) = unsafe { super::strncmp_safe_slices(a.as_ptr(), b.as_ptr(), 3) };
        assert_eq!(sa, b"abc");
        assert_eq!(sb, b"ghi");
    }

    #[test]
    fn strncmp_safe_slices_caps_at_max_operand_bytes() {
        use std::ffi::CString;
        let long = "x".repeat(super::MAX_OPERAND_BYTES + 50);
        let a = CString::new(long.clone()).unwrap();
        let b = CString::new(long).unwrap();
        let (sa, sb) = unsafe { super::strncmp_safe_slices(a.as_ptr(), b.as_ptr(), 10_000) };
        assert_eq!(sa.len(), super::MAX_OPERAND_BYTES);
        assert_eq!(sb.len(), super::MAX_OPERAND_BYTES);
    }
}
