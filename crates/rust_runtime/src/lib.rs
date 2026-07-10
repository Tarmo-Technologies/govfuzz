// SPDX-License-Identifier: Apache-2.0

//! govfuzz-native byte→typed decode runtime for generated Rust harnesses.
//!
//! This is the Rust analog of `c_runtime/govfuzz_decode.h`: a [`Cursor`] over a
//! `&[u8]` fuzz input that yields the typed argument values a generated
//! `govfuzz_run_one` feeds to the target function. It deliberately has **no**
//! `arbitrary` / `libfuzzer-sys` dependency — it is first-party, dependency-free
//! govfuzz code so the generated harness staticlib stays clean of any
//! third-party fuzzer in the licensable artifact (the same posture as the C
//! decoder header).
//!
//! ## Decode model (matches `govfuzz_decode.h`)
//!
//! - A scalar reads its little-endian bytes from the cursor, **zero-filling**
//!   when the input is short rather than failing — every call always yields a
//!   value, so a tiny/empty input still drives the target (with zeros). This is
//!   exactly `gf_u8`/`gf_i32`/`gf_i64`'s behavior and is what lets the engine
//!   start fuzzing from the empty seed.
//! - A length-bounded field (`bytes`/`str`/`String`) reads a 16-bit LE length
//!   prefix (clamped to `[0, max]` and to the bytes remaining) then the bytes,
//!   so later parameters still see fresh input. Mirrors `gf_c_string`.
//! - The single largest variable-length field a harness emits is the **rest of
//!   the input** (`rest_bytes`/`rest_str`), placed LAST by the generator, so the
//!   bulk of the fuzz input feeds the primary byte channel (mirrors
//!   `gf_data_slice`). This is the high-value path: a `parse(&[u8])` target gets
//!   the whole input, not a length-prefixed slice of it.

/// A forward-only cursor over a fuzz input. Cheap to construct; borrows the
/// input for its lifetime. Every read advances `pos` and zero-fills past the
/// end, so reads never panic and always produce a value.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Open a cursor over the whole fuzz input.
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Read `N` bytes little-endian into a fixed buffer, zero-filling when the
    /// input is exhausted. The primitive every fixed-width scalar reader builds
    /// on; matches the C decoder's "fill what's available, leave the rest zero".
    #[inline]
    fn take_le<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for slot in out.iter_mut() {
            if self.pos < self.data.len() {
                *slot = self.data[self.pos];
                self.pos += 1;
            } else {
                break;
            }
        }
        out
    }

    /// One byte (`u8`), `0` when exhausted. Mirrors `gf_u8`.
    #[inline]
    pub fn u8(&mut self) -> u8 {
        self.take_le::<1>()[0]
    }

    /// Signed byte.
    #[inline]
    pub fn i8(&mut self) -> i8 {
        self.u8() as i8
    }

    #[inline]
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take_le::<2>())
    }

    #[inline]
    pub fn i16(&mut self) -> i16 {
        i16::from_le_bytes(self.take_le::<2>())
    }

    #[inline]
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take_le::<4>())
    }

    #[inline]
    pub fn i32(&mut self) -> i32 {
        i32::from_le_bytes(self.take_le::<4>())
    }

    #[inline]
    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take_le::<8>())
    }

    #[inline]
    pub fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.take_le::<8>())
    }

    /// `usize`/`isize` decode as their 64-bit cousins (govfuzz targets 64-bit
    /// hosts); a target that uses the value as a length sees a wide range.
    #[inline]
    pub fn usize(&mut self) -> usize {
        self.u64() as usize
    }

    #[inline]
    pub fn isize(&mut self) -> isize {
        self.i64() as isize
    }

    /// `bool` from one byte's low bit (mirrors how the C decoder would treat a
    /// `bool`/`int` flag: any odd byte is `true`).
    #[inline]
    pub fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    /// `f32`/`f64` from raw little-endian bits. A NaN/inf is a perfectly valid
    /// fuzz value — we do NOT canonicalize, so the target sees every bit
    /// pattern (some parsers branch on NaN).
    #[inline]
    pub fn f32(&mut self) -> f32 {
        f32::from_le_bytes(self.take_le::<4>())
    }

    #[inline]
    pub fn f64(&mut self) -> f64 {
        f64::from_le_bytes(self.take_le::<8>())
    }

    /// `char` bounded to a valid scalar value. Reads a `u32` and reduces it into
    /// the Unicode scalar range, skipping surrogates — always yields a `char`.
    #[inline]
    pub fn char(&mut self) -> char {
        let raw = self.u32();
        // 0x110000 scalar values minus the 0x800 surrogate gap = 0x10F800.
        let idx = raw % 0x10_F800;
        let scalar = if idx < 0xD800 { idx } else { idx + 0x800 };
        char::from_u32(scalar).unwrap_or('\u{FFFD}')
    }

    /// Read a length-bounded owned `Vec<u8>`. A 16-bit LE length prefix is read
    /// first (clamped to `max` and to the remaining bytes) so subsequent reads
    /// still see fresh input. Mirrors `gf_c_string` (sans the NUL terminator).
    #[inline]
    pub fn bytes(&mut self, max: usize) -> Vec<u8> {
        let want = self.bounded_len(max);
        let start = self.pos;
        let end = start + want;
        self.pos = end;
        self.data[start..end].to_vec()
    }

    /// Read a length-bounded `String`. The bytes are taken like [`Cursor::bytes`]
    /// then decoded as UTF-8 lossily — a generated harness must always be able to
    /// hand the target a real `String`, and invalid UTF-8 in the fuzz bytes is
    /// the norm, so replacement is the only total option.
    #[inline]
    pub fn string(&mut self, max: usize) -> String {
        let raw = self.bytes(max);
        String::from_utf8_lossy(&raw).into_owned()
    }

    /// The rest of the input as an owned `Vec<u8>`. The generator places the
    /// single largest variable-length parameter last and backs it with this, so
    /// the bulk of the fuzz input feeds the primary byte channel. Mirrors
    /// `gf_data_slice` (but owned, so the harness can pass `&v` or `v`).
    #[inline]
    pub fn rest_bytes(&mut self) -> Vec<u8> {
        let start = self.pos;
        self.pos = self.data.len();
        self.data[start..].to_vec()
    }

    /// The rest of the input as a borrowed `&[u8]` (no allocation). Lifetime
    /// matches the backing fuzz buffer, so the harness can pass it directly to a
    /// `&[u8]` parameter.
    #[inline]
    pub fn rest_slice(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.pos = self.data.len();
        &self.data[start..]
    }

    /// The rest of the input as an owned `String` (UTF-8 lossy). For a trailing
    /// `&str` / `String` parameter that should consume the whole tail.
    #[inline]
    pub fn rest_string(&mut self) -> String {
        let rest = self.rest_slice();
        String::from_utf8_lossy(rest).into_owned()
    }

    /// A length value bounded to `[0, max]` AND to the bytes remaining, read
    /// from a 16-bit LE prefix. Public so a generated harness can size an
    /// element array (`Vec<T>`) consistently with the count it passes.
    #[inline]
    pub fn bounded_len(&mut self, max: usize) -> usize {
        let prefix = self.u16() as usize;
        prefix.min(max).min(self.remaining())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_read_little_endian() {
        let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(c.u8(), 0x01);
        // Next two bytes LE -> 0x0302.
        assert_eq!(c.u16(), 0x0302);
        // u32 from remaining four read bytes? cursor at pos 3 now: 04 05 06 07.
        assert_eq!(c.u32(), 0x0706_0504);
        assert_eq!(c.remaining(), 1);
    }

    #[test]
    fn exhausted_reads_zero_fill_and_never_panic() {
        let mut c = Cursor::new(&[0xAB]);
        assert_eq!(c.u8(), 0xAB);
        // Past the end: every scalar yields zero, no panic.
        assert_eq!(c.u8(), 0);
        assert_eq!(c.u32(), 0);
        assert_eq!(c.u64(), 0);
        assert_eq!(c.i64(), 0);
        assert!(c.bytes(16).is_empty());
        assert!(c.string(16).is_empty());
        assert!(c.rest_bytes().is_empty());
    }

    #[test]
    fn empty_input_is_total() {
        let mut c = Cursor::new(&[]);
        assert_eq!(c.remaining(), 0);
        assert_eq!(c.u8(), 0);
        assert_eq!(c.f64(), 0.0);
        assert!(!c.bool());
        assert_eq!(c.string(8), "");
        assert_eq!(c.rest_string(), "");
    }

    #[test]
    fn bytes_reads_length_prefixed_and_leaves_rest() {
        // prefix = 3 (LE 0x0003), then 3 payload bytes, then a trailing tail.
        let mut c = Cursor::new(&[0x03, 0x00, b'a', b'b', b'c', 0xFF, 0xEE]);
        assert_eq!(c.bytes(16), b"abc".to_vec());
        // The trailing bytes are still available to later reads.
        assert_eq!(c.u8(), 0xFF);
        assert_eq!(c.u8(), 0xEE);
    }

    #[test]
    fn bytes_clamps_to_max_and_remaining() {
        // prefix says 100, max says 2 -> 2 bytes consumed.
        let mut c = Cursor::new(&[0x64, 0x00, b'x', b'y', b'z']);
        assert_eq!(c.bytes(2), b"xy".to_vec());
        // prefix says 100, max big, but only 1 byte remains -> 1 byte.
        let mut c2 = Cursor::new(&[0x64, 0x00, b'q']);
        assert_eq!(c2.bytes(1024), b"q".to_vec());
    }

    #[test]
    fn string_is_lossy_utf8() {
        // prefix=2, then an invalid UTF-8 pair -> replacement chars, no panic.
        let mut c = Cursor::new(&[0x02, 0x00, 0xFF, 0xFE]);
        let s = c.string(16);
        assert!(s.chars().all(|ch| ch == '\u{FFFD}'), "{s:?}");
    }

    #[test]
    fn rest_slice_consumes_remaining_without_alloc() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        assert_eq!(c.u8(), 1);
        assert_eq!(c.rest_slice(), &[2, 3, 4]);
        assert_eq!(c.remaining(), 0);
        // A second rest read is empty.
        assert_eq!(c.rest_slice(), &[] as &[u8]);
    }

    #[test]
    fn rest_bytes_and_rest_string_match_slice() {
        let mut a = Cursor::new(b"hello");
        let _ = a.u8();
        assert_eq!(a.rest_bytes(), b"ello".to_vec());

        let mut b = Cursor::new(b"hi\xFF");
        assert_eq!(b.rest_string(), "hi\u{FFFD}");
    }

    #[test]
    fn bool_uses_low_bit() {
        let mut c = Cursor::new(&[0x00, 0x01, 0x02, 0x03]);
        assert!(!c.bool());
        assert!(c.bool());
        assert!(!c.bool());
        assert!(c.bool());
    }

    #[test]
    fn char_is_always_valid_scalar() {
        // Sweep a range of raw u32s; every produced char must be valid.
        for raw in (0u32..0x20_0000).step_by(97) {
            let bytes = raw.to_le_bytes();
            let mut c = Cursor::new(&bytes);
            let ch = c.char();
            // char is valid by construction (no surrogate, in range); just
            // assert it round-trips through u32.
            assert!(char::from_u32(ch as u32).is_some());
        }
    }

    #[test]
    fn floats_preserve_bit_patterns() {
        let nan_bits = f64::NAN.to_le_bytes();
        let mut c = Cursor::new(&nan_bits);
        assert!(c.f64().is_nan());
    }
}
