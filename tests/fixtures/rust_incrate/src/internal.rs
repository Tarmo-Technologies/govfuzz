// SPDX-License-Identifier: Apache-2.0
//
// A byte parser in a PRIVATE module. `Parser` is `pub`, but because `mod internal`
// is private and not re-exported, it is unreachable from an external dependent
// crate (E0603) — reachable only from inside the crate as `crate::internal::Parser`,
// which is exactly what the in-crate build mode emits.

/// A stateful byte-record parser.
pub struct Parser {
    seen: usize,
}

impl Parser {
    /// Construct an empty parser (the receiver constructor the harness uses).
    pub fn new() -> Self {
        Parser { seen: 0 }
    }

    /// Parse a record fed the whole fuzz input. A two-byte magic gate (`b"GF"`)
    /// guards a planted out-of-bounds index bug (GF-201): the attacker-supplied
    /// `body_len` is trusted and indexes past the slice end. The magic + version
    /// branches give the coverage map real edges to grow before the crash is found.
    pub fn parse(&mut self, data: &[u8]) -> u32 {
        self.seen = self.seen.wrapping_add(data.len());
        if data.len() < 4 {
            return 0;
        }
        // Magic gate: only inputs starting with "GF" reach the deeper logic.
        if data[0] != b'G' || data[1] != b'F' {
            return 1;
        }
        let version = data[2];
        let body_len = data[3] as usize;
        let mut checksum: u32 = 0;
        if version == 1 {
            // PLANTED BUG: trusts the attacker-supplied `body_len` and indexes past
            // the slice end -> a bounds-check panic the native engine surfaces as a
            // crash. Reachable only after the magic + version gate, proving the
            // in-crate harness drove a private-module method past a multi-byte gate.
            for i in 0..body_len {
                checksum = checksum.wrapping_add(data[4 + i] as u32);
            }
        } else {
            let end = (4 + body_len).min(data.len());
            for &b in &data[4..end] {
                checksum = checksum.wrapping_mul(31).wrapping_add(b as u32);
            }
        }
        checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_magic_is_safe() {
        let mut p = Parser::new();
        assert_eq!(p.parse(b"\x00\x00\x00\x00"), 1);
        assert_eq!(p.parse(b""), 0);
    }
}
