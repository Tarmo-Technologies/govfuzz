// SPDX-License-Identifier: Apache-2.0
package com.acme;

/**
 * A String-magic-gated planted crash for the JVM cmplog/RedQueen test. The gate is
 * a multi-byte String comparison — the dominant real Java magic mechanism — which
 * pure coverage-guided byte-flipping cannot solve in reasonable time, but cmplog
 * solves in a few execs by splicing the captured operand. Mirrors the C/Rust
 * cmplog story (AB+version magic), bringing Java to parity.
 */
public class StringMagic {
    public static void check(String s) {
        if (s.startsWith("GOVFUZZ_MAGIC")) {
            int[] tiny = new int[1];
            int value = tiny[s.length()];   // out-of-bounds read past the gate
            if (value == 0) {
                return;
            }
        }
    }
}
