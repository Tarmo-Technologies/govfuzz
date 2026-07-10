// SPDX-License-Identifier: Apache-2.0
// Uncontrolled allocation size (GF-436, CWE-789) in Rust. An AMPLIFIED capacity
// (multiply/shift of a tainted value → integer overflow → undersized buffer) is a
// finding; an allocate-to-fit `with_capacity(x.len())` is the safe idiom and must
// NOT fire.

fn grow(user_input: &str) -> Vec<u8> {
    let n = user_input.len();
    Vec::with_capacity(n * 8) // EXPECT GF-436
}

fn fit(user_input: &str) -> Vec<u8> {
    // Sized exactly to existing data — safe, not uncontrolled: no finding.
    Vec::with_capacity(user_input.len())
}
