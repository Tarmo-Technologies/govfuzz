// SPDX-License-Identifier: Apache-2.0
package com.govfuzz;

import java.nio.charset.StandardCharsets;

/**
 * A dependency-free byte→typed-value cursor for govfuzz-generated Java harnesses —
 * the JVM analog of {@code rust_runtime::Cursor} / {@code c_runtime/govfuzz_decode.h}
 * (and a small, ours, equivalent of Jazzer's {@code FuzzedDataProvider}). The
 * generated harness consumes typed arguments from the fuzz input through this so a
 * mutation of the raw bytes maps to a structured change in the call.
 *
 * <p>Reads are little-endian and saturating: consuming past the end yields zeros /
 * empty rather than throwing, so a short input never crashes the decoder (only the
 * target under test should ever produce a finding).
 */
public final class GovfuzzData {
    private final byte[] data;
    private int pos;

    public GovfuzzData(byte[] data) {
        this.data = data != null ? data : new byte[0];
    }

    public int remaining() {
        return data.length - pos;
    }

    public byte consumeByte() {
        return pos < data.length ? data[pos++] : 0;
    }

    public boolean consumeBoolean() {
        return (consumeByte() & 1) != 0;
    }

    public char consumeChar() {
        return (char) (consumeShort() & 0xffff);
    }

    public short consumeShort() {
        int b0 = consumeByte() & 0xff;
        int b1 = consumeByte() & 0xff;
        return (short) (b0 | (b1 << 8));
    }

    public int consumeInt() {
        int v = 0;
        for (int i = 0; i < 4; i++) {
            v |= (consumeByte() & 0xff) << (8 * i);
        }
        return v;
    }

    public long consumeLong() {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= (long) (consumeByte() & 0xff) << (8 * i);
        }
        return v;
    }

    public float consumeFloat() {
        return Float.intBitsToFloat(consumeInt());
    }

    public double consumeDouble() {
        return Double.longBitsToDouble(consumeLong());
    }

    /** Consume up to {@code max} bytes (fewer if the input runs out). */
    public byte[] consumeBytes(int max) {
        int n = Math.max(0, Math.min(max, remaining()));
        byte[] out = new byte[n];
        System.arraycopy(data, pos, out, 0, n);
        pos += n;
        return out;
    }

    /** Consume all remaining bytes — the bulk channel for the last byte parameter. */
    public byte[] consumeRemainingAsBytes() {
        return consumeBytes(remaining());
    }

    public String consumeString(int maxBytes) {
        return new String(consumeBytes(maxBytes), StandardCharsets.UTF_8);
    }

    public String consumeRemainingAsString() {
        return new String(consumeRemainingAsBytes(), StandardCharsets.UTF_8);
    }
}
