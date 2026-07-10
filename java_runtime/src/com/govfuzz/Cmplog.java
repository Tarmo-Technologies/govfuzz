// SPDX-License-Identifier: Apache-2.0
package com.govfuzz;

import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * govfuzz's JVM RedQueen/cmplog operand capture — the Java side of the engine's
 * comparison-solving mutator. When the engine is about to mutate a corpus entry it
 * ARMS the {@code GOVFUZZ_CMP_SHM} ring; the instrumented JVM pushes the operands
 * of string/byte comparisons it executes; the engine then splices those operands
 * into the input at the offset they were compared — solving a multi-byte magic
 * gate (e.g. {@code header.equals("PK\003\004")}) in a handful of execs instead of
 * the 256^N a coverage-only fuzzer needs. This is exactly the cmplog the C/Rust
 * lanes get from SanitizerCoverage trace-compares; this brings Java to parity.
 *
 * <p>The ring layout MUST match {@code c_runtime/govfuzz_driver.c} /
 * {@code CmpShmReader}: {@code [u32 armed][u32 count]} then {@code GOVFUZZ_CMP_CAP}
 * records of {@code [u8 len_a][u8 len_b][u8 a[OPMAX]][u8 b[OPMAX]]}. The map is a
 * file the engine mmaps {@code MAP_SHARED}, so — like {@link Coverage} — Java joins
 * it with pure {@link FileChannel#map}, no JNI.
 */
public final class Cmplog {
    private static final int CAP = 2048;
    private static final int OPMAX = 32;
    private static final int REC = 2 + 2 * OPMAX;
    private static final int BYTES = 8 + CAP * REC;

    private static final MappedByteBuffer MAP = open();

    private Cmplog() {}

    private static MappedByteBuffer open() {
        try {
            String path = System.getenv("GOVFUZZ_CMP_SHM");
            if (path == null || path.isEmpty()) {
                return null;
            }
            RandomAccessFile raf = new RandomAccessFile(path, "rw");
            if (raf.length() < BYTES) {
                raf.setLength(BYTES);
            }
            MappedByteBuffer m = raf.getChannel().map(FileChannel.MapMode.READ_WRITE, 0, BYTES);
            raf.close();
            return m;
        } catch (Throwable t) {
            return null;
        }
    }

    private static boolean armed(MappedByteBuffer m) {
        return (m.get(0) | m.get(1) | m.get(2) | m.get(3)) != 0;
    }

    /** Push one comparison's operand pair into the ring (clamped to OPMAX). */
    private static void push(byte[] a, byte[] b) {
        MappedByteBuffer m = MAP;
        if (m == null || !armed(m)) {
            return;
        }
        int la = Math.min(a.length, OPMAX);
        int lb = Math.min(b.length, OPMAX);
        int count = (m.get(4) & 0xff)
                | ((m.get(5) & 0xff) << 8)
                | ((m.get(6) & 0xff) << 16)
                | ((m.get(7) & 0xff) << 24);
        if (count >= CAP) {
            return;
        }
        int off = 8 + count * REC;
        m.put(off, (byte) la);
        m.put(off + 1, (byte) lb);
        for (int i = 0; i < la; i++) {
            m.put(off + 2 + i, a[i]);
        }
        for (int i = 0; i < lb; i++) {
            m.put(off + 2 + OPMAX + i, b[i]);
        }
        count++;
        m.put(4, (byte) count);
        m.put(5, (byte) (count >> 8));
        m.put(6, (byte) (count >> 16));
        m.put(7, (byte) (count >> 24));
    }

    /**
     * Hook for {@code String}/{@code CharSequence} comparison calls (equals,
     * equalsIgnoreCase, startsWith, endsWith, contains, contentEquals, compareTo).
     * Pushes the two operands' UTF-8 bytes when they differ (equal/empty operands
     * carry no gradient).
     */
    public static void hookStringCompare(Object a, Object b) {
        if (MAP == null || !(a instanceof CharSequence) || !(b instanceof CharSequence)) {
            return;
        }
        byte[] ab = a.toString().getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.toString().getBytes(StandardCharsets.UTF_8);
        if (ab.length == 0 || bb.length == 0 || Arrays.equals(ab, bb)) {
            return;
        }
        push(ab, bb);
    }

    /** Hook for {@code Arrays.equals(byte[], byte[])} / {@code MessageDigest.isEqual}. */
    public static void hookBytesEquals(byte[] a, byte[] b) {
        if (MAP == null || a == null || b == null || a.length == 0 || b.length == 0) {
            return;
        }
        if (!Arrays.equals(a, b)) {
            push(a, b);
        }
    }
}
