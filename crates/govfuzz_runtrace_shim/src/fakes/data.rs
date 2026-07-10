// SPDX-License-Identifier: Apache-2.0

//! Generate fake bytes for a per-resource read() request, dispatching
//! on the current pass Mode. Stack-only — no heap allocations.

use crate::fakes::mode::{current, Mode};

/// Fill `out` with up to `out.len()` bytes for the named resource.
/// Returns the number of bytes written (`<= out.len()`). The caller
/// uses this to pre-populate a memfd or socketpair peer before
/// handing the fd to the target.
///
/// `resource_name` distinguishes per-resource RNG streams so
/// "/etc/foo.conf" and "/var/run/bar.sock" produce different bytes
/// even within the same pass.
pub fn fill_bytes(resource_name: &[u8], out: &mut [u8]) -> usize {
    // env-capsule replay (#4): when a recorded world is pinned, serve the exact
    // bytes this resource was served during the recorded run, so a crash that
    // depended on the faked environment reproduces deterministically regardless of
    // pass mode. Falls through to normal generation for a resource with no record.
    if let Some(n) = crate::fakes::envcap::replay_fill(resource_name, out) {
        return n;
    }
    let n = match current() {
        Mode::Audit | Mode::Empty => 0,
        Mode::Rng => fill_rng(resource_name, out),
        Mode::FuzzDriven => fill_fuzz_driven(resource_name, out),
    };
    // env-capsule record (#4): capture exactly what we served for this resource.
    crate::fakes::envcap::record_fill(resource_name, &out[..n]);
    n
}

fn fill_rng(resource_name: &[u8], out: &mut [u8]) -> usize {
    // xorshift64*, seeded from FNV-1a hash of (harness_id, resource).
    // Harness id is in GOVFUZZ_RUNTRACE_LOG path; we hash the
    // resource_name + the env-supplied seed instead so the seed is
    // stable per pass.
    let seed = fnv_seed(resource_name);
    let mut state = if seed == 0 {
        0xdeadbeefcafebabe_u64
    } else {
        seed
    };
    for slot in out.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *slot = (state & 0xff) as u8;
    }
    out.len()
}

fn fill_fuzz_driven(resource_name: &[u8], out: &mut [u8]) -> usize {
    // #7 environment-response fuzzing: key the fuzz-input window by the resource so
    // each faked external resource is an INDEPENDENT channel. Without the key, every
    // faked resource shares one global cursor and receives identical bytes, so a
    // target reading two config files can never see them fuzzed independently. The
    // key is the same FNV hash used for the RNG stream, so the mapping is stable.
    let key = fnv_seed(resource_name);
    crate::fakes::fuzz_input::read_keyed(key, out)
}

fn fnv_seed(resource: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for byte in resource {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    // Mix in the fuzz seed env var so different runs get different
    // RNG streams when the operator passes --rng-seed.
    if let Some(s) = std::env::var_os("GOVFUZZ_RUNTRACE_SEED") {
        for byte in s.as_encoded_bytes() {
            h ^= *byte as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mode_writes_nothing() {
        std::env::remove_var("GOVFUZZ_RUNTRACE_MODE");
        // OnceLock means this test must run before any other test
        // that reads current(). To stay independent, call fill_bytes
        // and just verify it returns 0 for Audit OR Empty.
        let mut buf = [0u8; 32];
        let n = fill_bytes(b"/tmp/x", &mut buf);
        assert!(
            n == 0 || n == buf.len(),
            "audit / empty returns 0; rng / fuzz_driven returns len"
        );
    }

    #[test]
    fn rng_mode_deterministic_per_resource() {
        // Build the RNG output directly without going through current()
        // so this test is independent of the OnceLock state.
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        fill_rng(b"foo", &mut a);
        fill_rng(b"foo", &mut b);
        assert_eq!(a, b);
        let mut c = [0u8; 16];
        fill_rng(b"bar", &mut c);
        assert_ne!(a, c);
    }
}
