// SPDX-License-Identifier: Apache-2.0
//! Benchmark target: a magic-gated out-of-bounds index panic. Reachable only
//! past a 4-byte magic, so the fuzzer must crack the gate.
pub fn target_one_input(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    if data[0] == 0x11 && data[1] == 0xee && data[2] == 0xff && data[3] == 0xc0 {
        let table = [0u8; 4];
        let idx = (data.len() & 0x3f) + 4; // always >= 4 -> OOB on a 4-elem array
        std::hint::black_box(table[idx]); // index-out-of-bounds panic past the gate
    }
}
