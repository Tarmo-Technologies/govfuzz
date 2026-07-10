// SPDX-License-Identifier: Apache-2.0
package com.govfuzz;

import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

/**
 * Joins govfuzz's file-backed edge-coverage map and records AFL-style edge hits
 * into it. The govfuzz engine names the map via the {@code GOVFUZZ_COV_SHM}
 * environment variable, which is a plain FILE PATH the engine/driver mmap with
 * {@code MAP_SHARED} (see {@code c_runtime/govfuzz_driver.c}). Because it is a
 * file, this agent joins the EXACT same pages with {@link FileChannel#map} — pure
 * Java, no JNI, no native helper. Writes from the instrumented JVM and reads from
 * the Rust engine see the same bytes.
 *
 * <p>Layout MUST match {@code GOVFUZZ_COV_BITS} (1 &lt;&lt; 16) in the C driver.
 */
public final class Coverage {
    /** Must equal GOVFUZZ_COV_BITS in c_runtime/govfuzz_driver.c. */
    private static final int COV_BITS = 1 << 16;
    private static final int COV_MASK = COV_BITS - 1;

    /** The shared edge map, or null when GOVFUZZ_COV_SHM is unset (coverage off). */
    private static final MappedByteBuffer MAP = open();

    /**
     * AFL "previous location" for edge hashing. The harness runs one input at a
     * time on a single thread, but keep it thread-local so background threads in
     * the target can record coverage without racing the index.
     */
    private static final ThreadLocal<int[]> PREV = ThreadLocal.withInitial(() -> new int[1]);

    private Coverage() {}

    private static MappedByteBuffer open() {
        try {
            String path = System.getenv("GOVFUZZ_COV_SHM");
            if (path == null || path.isEmpty()) {
                return null;
            }
            RandomAccessFile raf = new RandomAccessFile(path, "rw");
            if (raf.length() < COV_BITS) {
                raf.setLength(COV_BITS);
            }
            MappedByteBuffer m = raf.getChannel().map(FileChannel.MapMode.READ_WRITE, 0, COV_BITS);
            // The channel/file can be closed; the mapping stays valid until GC.
            raf.close();
            return m;
        } catch (Throwable t) {
            // Coverage is best-effort — never let a mapping failure break fuzzing.
            return null;
        }
    }

    /** True when a coverage map is attached (GOVFUZZ_COV_SHM was set + mappable). */
    public static boolean enabled() {
        return MAP != null;
    }

    /**
     * Reset the AFL "previous location" to 0. The driver calls this at the START of
     * each fuzz input so an input's recorded edges are DETERMINISTIC (independent of
     * whatever block the previous input ended on). Without it, `prev` carries across
     * the persistent loop and the same input hashes to different edge indices each
     * run — non-deterministic coverage that drowns the real novelty gradient and
     * pollutes the corpus, so coverage-guided fuzzing can't climb a magic gate.
     */
    public static void resetPrev() {
        PREV.get()[0] = 0;
    }

    /**
     * Record entry into the basic block identified by {@code blockId}. Uses the
     * classic AFL edge hash so the map captures EDGES (block transitions), richer
     * than block presence: {@code idx = prev ^ block; map[idx]++; prev = block>>1}.
     * The byte counter saturates at 255 (degrades to a presence bitmap), which the
     * engine reads as a covered feature. Called from instrumented bytecode.
     */
    public static void recordEdge(int blockId) {
        MappedByteBuffer m = MAP;
        if (m == null) {
            return;
        }
        int[] prev = PREV.get();
        int idx = (prev[0] ^ blockId) & COV_MASK;
        byte v = m.get(idx);
        if (v != (byte) 0xff) {
            m.put(idx, (byte) (v + 1));
        }
        prev[0] = blockId >> 1;
    }
}
