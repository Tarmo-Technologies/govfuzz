// SPDX-License-Identifier: Apache-2.0
//
// Campaign fixture (byteorder `ByteOrder::write_*` shape). The public API is a
// `pub trait` with STATIC methods that take an OUTPUT buffer `buf: &mut [u8]` plus
// a value and write a FIXED-width prefix (`buf[..N].copy_from_slice(..)`). The
// real byteorder campaign generated harnesses for these and the Rust lane backed
// the `&mut [u8]` with an EMPTY slice, so every input panicked
// ("range end index 8 out of range for slice of length 0") — 72 noise findings.
// With an adequately-sized backing buffer the write path runs cleanly, so these
// harnesses build+fuzz WITHOUT the panic storm. No bug is planted: the correct
// outcome is zero findings.

/// A byte-packing trait: write a value's big-endian bytes into the caller's
/// output buffer. STATIC methods (no `self`) — the Rust lane reaches them by UFCS
/// `<Big as Pack>::write_u64(&mut buf, n)`, exactly like byteorder's `ByteOrder`.
pub trait Pack {
    /// Write `n` as 8 big-endian bytes into the first 8 bytes of `buf`.
    /// Panics if `buf.len() < 8` (byteorder's documented precondition).
    fn write_u64(buf: &mut [u8], n: u64);

    /// Write `n` as 16 big-endian bytes into the first 16 bytes of `buf` — the
    /// widest fixed-width primitive write, so the synthesized output buffer must
    /// be at least 16 bytes. Panics if `buf.len() < 16`.
    fn write_u128(buf: &mut [u8], n: u128);
}

/// Big-endian packer marker (the `BigEndian` shape).
pub enum Big {}

impl Pack for Big {
    fn write_u64(buf: &mut [u8], n: u64) {
        buf[..8].copy_from_slice(&n.to_be_bytes());
    }

    fn write_u128(buf: &mut [u8], n: u128) {
        buf[..16].copy_from_slice(&n.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_u64_packs_big_endian() {
        let mut buf = [0u8; 8];
        Big::write_u64(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn write_u128_needs_sixteen_bytes() {
        let mut buf = [0u8; 16];
        Big::write_u128(&mut buf, 1);
        assert_eq!(buf[15], 1);
    }
}
