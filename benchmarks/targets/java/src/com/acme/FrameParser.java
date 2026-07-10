// SPDX-License-Identifier: Apache-2.0
package com.acme;

/** Parses a frame; an array-index-out-of-bounds is reachable only past a
 *  one-byte 'G' gate, so the engine must discover the gate to trip it. */
public final class FrameParser {
    public void parse(byte[] data) {
        if (data.length < 4) {
            return;
        }
        if (data[0] == 'G') {
            int[] table = new int[4];
            int idx = (data.length & 0x3f) + 4;   // always >= 4 -> AIOOBE
            if (table[idx] != 0) {
                System.out.print("");
            }
        }
    }
}
