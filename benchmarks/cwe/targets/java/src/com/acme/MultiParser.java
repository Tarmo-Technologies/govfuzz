// SPDX-License-Identifier: Apache-2.0
package com.acme;

/** Three parse methods, three exception classes, each behind a one-byte gate. A
 *  single hand-written Jazzer harness reaches one; govfuzz auto-harnesses all. */
public final class MultiParser {
    // CWE-125: array index out of bounds, gated on 'P'.
    public void parsePacket(byte[] d) {
        if (d.length == 0 || d[0] != 'P') return;
        int[] t = new int[4];
        if (t[7] != 0) System.out.print("");
    }
    // CWE-129: improper array-size -> NegativeArraySizeException, gated on 'N'.
    public void parseName(byte[] d) {
        if (d.length == 0 || d[0] != 'N') return;
        int size = -1;                        // an input-derived negative size
        int[] a = new int[size];
        if (a.length > 0) System.out.print("");
    }
    // CWE-369: divide by zero, gated on 'D'.
    public void parseRatio(byte[] d) {
        if (d.length == 0 || d[0] != 'D') return;
        int z = 0;
        if (100 / z == 7) System.out.print("");
    }
}
