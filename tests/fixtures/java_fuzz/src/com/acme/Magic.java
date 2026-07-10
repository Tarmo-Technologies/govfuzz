// SPDX-License-Identifier: Apache-2.0
package com.acme;

/**
 * A planted-crash parser for the end-to-end native Java fuzzing test. A byte
 * channel (byte[]) reaches an ArrayIndexOutOfBoundsException behind a single-byte
 * gate: the matching input opens a NEW basic block (govfuzz's own JVM coverage
 * records it) AND immediately trips the out-of-bounds read, so the engine finds it
 * from coverage/random exploration without a seed. (Multi-byte magic gates are the
 * job of JVM cmplog/RedQueen — a future lever; pure coverage-guided byte-flipping
 * struggles with them, exactly as in AFL-without-cmplog.)
 */
public class Magic {
    public static void parse(byte[] data) {
        if (data.length < 2) {
            return;
        }
        if (data[0] == 'G') {
            // Reached only when the first byte is 'G': an out-of-bounds read.
            int[] tiny = new int[1];
            int value = tiny[data.length];
            if (value == 0) {
                return;
            }
        }
    }
}
