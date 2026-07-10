// SPDX-License-Identifier: Apache-2.0
//
// End-to-end fixture for the M1.2 native Rust fuzzing lane. `parse_packet` is a
// real `&[u8]` parser the generator backs with the whole fuzz input; it hides a
// planted bug behind a two-byte magic gate so the engine demonstrably FINDS a
// crash quickly (proving native fork-server fuzzing with coverage), while the
// surrounding branches give the coverage map real edges to grow.

/// Parse a "packet": a couple of magic bytes, then a length-prefixed body. The
/// branches before the bug exist so the coverage map records >0 edges on inputs
/// that do not crash, demonstrating coverage-guided progress; the planted bug is
/// an out-of-bounds slice index reachable only after the `b"AB"` magic gate, so
/// the engine's value-profile/cmplog gets past the magic and triggers an ASan
/// abort (a Rust panic in the `extern "C"` harness aborts and surfaces as a
/// crash exactly like a C sanitizer abort).
pub fn parse_packet(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    // Magic gate: only inputs starting with "AB" reach the deeper logic. A
    // non-matching input still exercises this branch (coverage), so the map
    // grows even before the crash is found.
    if data[0] != b'A' || data[1] != b'B' {
        return 1;
    }
    // A version byte selects a code path — more edges for the map.
    let version = data[2];
    let body_len = data[3] as usize;
    let mut checksum: u32 = 0;
    match version {
        1 => {
            // PLANTED BUG: trusts the attacker-supplied `body_len` and indexes
            // past the slice end. ASan/bounds-check aborts -> the engine reports
            // a crash. Reachable only after the magic + version gate, so finding
            // it proves the engine got PAST a multi-byte gate.
            for i in 0..body_len {
                checksum = checksum.wrapping_add(data[4 + i] as u32);
            }
        }
        2 => {
            // A safe path for a different version: bounded, no bug. Gives the
            // fuzzer a second deep branch to cover.
            let end = (4 + body_len).min(data.len());
            for &b in &data[4..end] {
                checksum = checksum.wrapping_mul(31).wrapping_add(b as u32);
            }
        }
        _ => {
            checksum = version as u32;
        }
    }
    checksum
}

/// A second entry point with a different signature, so discovery has more than
/// one Rust candidate to rank and harness (a scalar + str surface).
pub fn decode_tag(tag: &str, repeat: u8) -> usize {
    tag.len().wrapping_mul(repeat as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_magic_input_is_safe() {
        assert_eq!(parse_packet(b"\x00\x00\x00\x00"), 1);
        assert_eq!(parse_packet(b""), 0);
    }

    #[test]
    fn version_two_is_bounded() {
        // version=2, body_len huge, but the v2 path clamps to the slice.
        let input = b"AB\x02\xff\x01\x02\x03";
        let _ = parse_packet(input);
    }

    #[test]
    fn decode_tag_multiplies() {
        assert_eq!(decode_tag("abc", 4), 12);
    }
}
