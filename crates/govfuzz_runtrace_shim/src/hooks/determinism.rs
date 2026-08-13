// SPDX-License-Identifier: Apache-2.0

//! Determinism plugin: when `GOVFUZZ_FAKE_DETERMINISM=1` is set, the randomness
//! sources return a fixed, reproducible stream.
//!
//! Determinism is the premise of the whole replay and env-capsule story — a
//! saved input is a reproducer only if the second run makes the same decisions
//! as the first. Nothing in the shim intercepted randomness, so any target that
//! seeds a hash, salts a table or mints an id from `rand`/`getrandom` could take
//! a different path on replay, and a crash found once might never reproduce.
//!
//! The stream is xorshift64*, seeded from `GOVFUZZ_RUNTRACE_SEED` when present
//! so a campaign can vary it across runs while any single run stays replayable.
//! `srand` still honours the target's own seed.
//!
//! The CLOCK is deliberately not interposed. It was, and it broke targets:
//! `clock_gettime`/`gettimeofday` are resolved through the vDSO and versioned
//! symbols, and the lazy `dlsym` a pass-through needs can run under the loader
//! lock. Measured effect was targets that built and were then NEVER ENTERED —
//! a silent loss far worse than a non-reproducible timestamp. A clock fake needs
//! eager resolution at load time (or a `LD_PRELOAD`-free mechanism) before it
//! can be reintroduced.
//!
//! Allocation discipline matches the other hook modules: no malloc / Box / Vec
//! / String inside the hooks, and the env gate is read once.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use crate::sdk::FakeResource;

use crate::dlsym::ResolvedFn;

// Resolved ONCE into statics, like every other hook module. Building a
// `ResolvedFn` as a temporary per call re-resolves on every invocation, and
// nothing then guards against the lookup returning THIS symbol — which is an
// unbounded recursion that kills the harness before it reaches the target.
static REAL_RAND: ResolvedFn = ResolvedFn::new(b"rand\0");
static REAL_RANDOM: ResolvedFn = ResolvedFn::new(b"random\0");
static REAL_SRAND: ResolvedFn = ResolvedFn::new(b"srand\0");
static REAL_GETRANDOM: ResolvedFn = ResolvedFn::new(b"getrandom\0");

/// The real implementation, or null when the lookup found only OURSELVES —
/// calling that would recurse forever.
fn real_of(resolved: &ResolvedFn, hook: *const ()) -> *const () {
    let real = resolved.ptr() as *const ();
    if real.is_null() || real == hook {
        return core::ptr::null();
    }
    real
}

const ENV_VAR: &[u8] = b"GOVFUZZ_FAKE_DETERMINISM\0";
const SEED_VAR: &[u8] = b"GOVFUZZ_RUNTRACE_SEED\0";

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
        &[b"rand\0", b"srand\0", b"random\0", b"getrandom\0"]
    }
    fn is_enabled(&self) -> bool {
        env_enabled()
    }
    fn describe(&self) -> &'static str {
        "deterministic randomness so a saved input replays identically"
    }
}

#[no_mangle]
pub unsafe extern "C" fn rand() -> libc::c_int {
    if !env_enabled() {
        let real = real_of(&REAL_RAND, rand as *const ());
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
        let real = real_of(&REAL_RANDOM, random as *const ());
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
        let real = real_of(&REAL_SRAND, srand as *const ());
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
        let real = real_of(&REAL_GETRANDOM, getrandom as *const ());
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
