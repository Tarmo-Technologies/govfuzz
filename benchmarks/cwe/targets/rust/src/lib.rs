// SPDX-License-Identifier: Apache-2.0
//! Three parser functions, each with a different panic-class bug. cargo-fuzz's
//! single fuzz_target! harness reaches ONE of them; govfuzz auto-harnesses all.

/// CWE-125-class: out-of-bounds slice index panic, past a 'P' gate.
pub fn parse_packet(data: &[u8]) {
    if data.len() < 2 || data[0] != b'P' { return; }
    let table = [0u8; 4];
    let _ = std::hint::black_box(table[(data.len() & 0x3f) + 4]); // index OOB panic
}

/// CWE-190-class: arithmetic overflow panic (overflow-checks on), past a 'V' gate.
pub fn decode_varint(data: &[u8]) {
    if data.len() < 2 || data[0] != b'V' { return; }
    let mut acc: u8 = 250;
    for &b in &data[1..] { acc += b; } // overflow panic once the sum wraps
    std::hint::black_box(acc);
}

/// CWE-476-class: unwrap on None, past a 'U' gate.
pub fn unwrap_field(data: &[u8]) {
    if data.len() < 2 || data[0] != b'U' { return; }
    let v: Option<u8> = if data[1] == 0xAA { None } else { Some(data[1]) };
    std::hint::black_box(v.unwrap()); // panics when data[1]==0xAA
}
