// SPDX-License-Identifier: Apache-2.0

//! Determinism plugin: when `GOVFUZZ_FAKE_DETERMINISM=1` is set, the clock and
//! the randomness sources return fixed, reproducible values.
//!
//! Determinism is the premise of the whole replay and env-capsule story — a
//! saved input is only a reproducer if the second run makes the same decisions
//! as the first. That premise did not hold: nothing in the shim intercepted
//! time or randomness, so any target that branches on `clock_gettime`, `time`,
//! `rand` or `getrandom` could take a different path on replay, and a crash
//! found once might never reproduce.
//!
//! The clock is MONOTONIC but synthetic: each observation advances a counter by
//! a fixed tick rather than returning a constant. A frozen clock deadlocks any
//! target that polls "has the timeout elapsed yet?", while a counter both
//! reproduces exactly and always eventually satisfies a deadline.
//!
//! Randomness is a deterministic xorshift64* stream, seeded from
//! `GOVFUZZ_RUNTRACE_SEED` when present so a campaign can vary the stream
//! across runs while any single run stays replayable.
//!
//! Allocation discipline matches the other hook modules: no malloc / Box / Vec
//! / String inside the hooks, and the env gate is read once.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use crate::sdk::FakeResource;

const ENV_VAR: &[u8] = b"GOVFUZZ_FAKE_DETERMINISM\0";
const SEED_VAR: &[u8] = b"GOVFUZZ_RUNTRACE_SEED\0";

/// Wall-clock origin for the synthetic clock: 2020-01-01T00:00:00Z. A fixed,
/// plausible date rather than 0, so a target that formats or subtracts dates
/// sees something sane.
const EPOCH_SECONDS: i64 = 1_577_836_800;
/// Advance per observation. One millisecond is small enough that a target
/// measuring a short operation sees a believable duration, and large enough
/// that a polling loop reaches its deadline in a bounded number of calls.
const TICK_NANOS: u64 = 1_000_000;

static ELAPSED_NANOS: AtomicU64 = AtomicU64::new(0);
static RNG_STATE: AtomicU64 = AtomicU64::new(0);

/// Reads `GOVFUZZ_FAKE_DETERMINISM` once via libc::getenv. True iff exactly "1".
pub fn env_enabled() -> bool {
    static CACHED: AtomicU8 = AtomicU8::new(2); // 0=false, 1=true, 2=uninit
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let value = unsafe { libc::getenv(ENV_VAR.as_ptr() as *const libc::c_char) };
    let enabled = if value.is_null() {
        false
    } else {
        unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes() == b"1"
    };
    CACHED.store(u8::from(enabled), Ordering::Relaxed);
    enabled
}

/// Nanoseconds since the synthetic epoch, advanced one tick per observation.
fn next_nanos() -> u64 {
    ELAPSED_NANOS.fetch_add(TICK_NANOS, Ordering::Relaxed) + TICK_NANOS
}

/// xorshift64*, seeded from `GOVFUZZ_RUNTRACE_SEED` when set. Never returns a
/// zero state, which would make the stream degenerate to all zeroes.
fn next_random() -> u64 {
    let mut state = RNG_STATE.load(Ordering::Relaxed);
    if state == 0 {
        state = seed_from_env();
        if state == 0 {
            state = 0x9E37_79B9_7F4A_7C15;
        }
    }
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    RNG_STATE.store(state, Ordering::Relaxed);
    state.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn seed_from_env() -> u64 {
    let value = unsafe { libc::getenv(SEED_VAR.as_ptr() as *const libc::c_char) };
    if value.is_null() {
        return 0;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes();
    // Hand-rolled parse: `str::parse` would allocate on error paths in some
    // std configurations, and this runs inside an interposer.
    let mut acc: u64 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return 0;
        }
        acc = acc.wrapping_mul(10).wrapping_add(u64::from(byte - b'0'));
    }
    acc
}

fn emit_audit(symbol: &[u8], value: i64) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(b"determinism");
        b.field_str(b"f", symbol);
        b.field_i64(b"v", value);
        b.emit();
    }
}

pub struct Determinism;

impl FakeResource for Determinism {
    fn name(&self) -> &'static str {
        "determinism"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"time\0",
            b"clock_gettime\0",
            b"gettimeofday\0",
            b"rand\0",
            b"srand\0",
            b"random\0",
            b"getrandom\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        env_enabled()
    }
    fn describe(&self) -> &'static str {
        "fixed clock and deterministic randomness so a saved input replays identically"
    }
}

#[no_mangle]
pub unsafe extern "C" fn time(out: *mut libc::time_t) -> libc::time_t {
    if !env_enabled() {
        return real_time(out);
    }
    let seconds = EPOCH_SECONDS + (next_nanos() / 1_000_000_000) as i64;
    if !out.is_null() {
        *out = seconds as libc::time_t;
    }
    emit_audit(b"time", seconds);
    seconds as libc::time_t
}

unsafe fn real_time(out: *mut libc::time_t) -> libc::time_t {
    let real = crate::dlsym::ResolvedFn::new(b"time\0").ptr() as *const ();
    if real.is_null() {
        return 0;
    }
    let real: unsafe extern "C" fn(*mut libc::time_t) -> libc::time_t = std::mem::transmute(real);
    real(out)
}

#[no_mangle]
pub unsafe extern "C" fn clock_gettime(
    clock_id: libc::clockid_t,
    tp: *mut libc::timespec,
) -> libc::c_int {
    if !env_enabled() {
        let real = crate::dlsym::ResolvedFn::new(b"clock_gettime\0").ptr() as *const ();
        if real.is_null() {
            return -1;
        }
        let real: unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int =
            std::mem::transmute(real);
        return real(clock_id, tp);
    }
    if tp.is_null() {
        return -1;
    }
    let nanos = next_nanos();
    (*tp).tv_sec = (EPOCH_SECONDS + (nanos / 1_000_000_000) as i64) as libc::time_t;
    (*tp).tv_nsec = (nanos % 1_000_000_000) as _;
    emit_audit(b"clock_gettime", (*tp).tv_sec);
    0
}

#[no_mangle]
pub unsafe extern "C" fn gettimeofday(
    tv: *mut libc::timeval,
    _tz: *mut libc::c_void,
) -> libc::c_int {
    if !env_enabled() {
        let real = crate::dlsym::ResolvedFn::new(b"gettimeofday\0").ptr() as *const ();
        if real.is_null() {
            return -1;
        }
        let real: unsafe extern "C" fn(*mut libc::timeval, *mut libc::c_void) -> libc::c_int =
            std::mem::transmute(real);
        return real(tv, _tz);
    }
    if tv.is_null() {
        return -1;
    }
    let nanos = next_nanos();
    (*tv).tv_sec = (EPOCH_SECONDS + (nanos / 1_000_000_000) as i64) as libc::time_t;
    (*tv).tv_usec = ((nanos % 1_000_000_000) / 1_000) as _;
    emit_audit(b"gettimeofday", (*tv).tv_sec);
    0
}

#[no_mangle]
pub unsafe extern "C" fn rand() -> libc::c_int {
    if !env_enabled() {
        let real = crate::dlsym::ResolvedFn::new(b"rand\0").ptr() as *const ();
        if real.is_null() {
            return 0;
        }
        let real: unsafe extern "C" fn() -> libc::c_int = std::mem::transmute(real);
        return real();
    }
    // RAND_MAX is 2^31-1 on glibc; keep the result in that range.
    (next_random() >> 33) as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn random() -> libc::c_long {
    if !env_enabled() {
        let real = crate::dlsym::ResolvedFn::new(b"random\0").ptr() as *const ();
        if real.is_null() {
            return 0;
        }
        let real: unsafe extern "C" fn() -> libc::c_long = std::mem::transmute(real);
        return real();
    }
    (next_random() >> 33) as libc::c_long
}

#[no_mangle]
pub unsafe extern "C" fn srand(seed: libc::c_uint) {
    if !env_enabled() {
        let real = crate::dlsym::ResolvedFn::new(b"srand\0").ptr() as *const ();
        if !real.is_null() {
            let real: unsafe extern "C" fn(libc::c_uint) = std::mem::transmute(real);
            real(seed);
        }
        return;
    }
    // Honour the target's own seeding so a program that seeds deterministically
    // keeps its intended stream; a zero seed would stall xorshift.
    RNG_STATE.store(
        if seed == 0 { 1 } else { u64::from(seed) },
        Ordering::Relaxed,
    );
}

#[no_mangle]
pub unsafe extern "C" fn getrandom(
    buf: *mut libc::c_void,
    buflen: libc::size_t,
    flags: libc::c_uint,
) -> libc::ssize_t {
    if !env_enabled() {
        let real = crate::dlsym::ResolvedFn::new(b"getrandom\0").ptr() as *const ();
        if real.is_null() {
            return -1;
        }
        let real: unsafe extern "C" fn(
            *mut libc::c_void,
            libc::size_t,
            libc::c_uint,
        ) -> libc::ssize_t = std::mem::transmute(real);
        return real(buf, buflen, flags);
    }
    if buf.is_null() {
        return -1;
    }
    let out = buf as *mut u8;
    let mut written = 0usize;
    while written < buflen {
        let chunk = next_random().to_le_bytes();
        let take = core::cmp::min(chunk.len(), buflen - written);
        core::ptr::copy_nonoverlapping(chunk.as_ptr(), out.add(written), take);
        written += take;
    }
    emit_audit(b"getrandom", written as i64);
    written as libc::ssize_t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_synthetic_clock_advances_monotonically() {
        // A frozen clock deadlocks any target that polls "has the timeout
        // elapsed?", so the clock must move — while still being reproducible.
        ELAPSED_NANOS.store(0, Ordering::Relaxed);
        let first = next_nanos();
        let second = next_nanos();
        assert!(
            second > first,
            "the clock must advance: {first} -> {second}"
        );
        assert_eq!(second - first, TICK_NANOS);
    }

    #[test]
    fn the_random_stream_is_reproducible_from_a_seed() {
        // Determinism is the point: the same seed must give the same bytes, or
        // a saved crash input is not a reproducer.
        RNG_STATE.store(12345, Ordering::Relaxed);
        let first: Vec<u64> = (0..8).map(|_| next_random()).collect();
        RNG_STATE.store(12345, Ordering::Relaxed);
        let second: Vec<u64> = (0..8).map(|_| next_random()).collect();
        assert_eq!(first, second);
        // ...and not a degenerate constant stream.
        assert!(
            first.windows(2).any(|w| w[0] != w[1]),
            "stream must vary: {first:?}"
        );
    }

    #[test]
    fn a_zero_state_never_stalls_the_stream() {
        // xorshift is absorbing at zero; a zero seed must be replaced.
        RNG_STATE.store(0, Ordering::Relaxed);
        assert_ne!(next_random(), 0);
    }
}
