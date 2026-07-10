// SPDX-License-Identifier: Apache-2.0
package com.govfuzz;

import java.io.FileWriter;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * govfuzz's JVM sink-reachability recorder — the native, Jazzer-free equivalent of a
 * sink oracle for the JVM. The coverage agent ({@link CoverageAgent}) instruments the
 * target's bytecode so that every call site of a dangerous sink (untrusted
 * deserialization, process execution, dynamic code evaluation, dynamic SQL, an LDAP
 * search) invokes {@link #record(int)} before the sink runs. A sink reached while the
 * fuzzer drives the input is input-reachable attack surface — the behavioral finding
 * class a crash-only JVM fuzzer never reports.
 *
 * <p>Reached sink KINDS are deduped in-process; the driver writes them to the file
 * named by {@code GOVFUZZ_SINK_OUT} at exit, and govfuzz turns each into a finding
 * (mapping the kind to its CWE/rule). The probe is stack-neutral ({@code LDC kind;
 * INVOKESTATIC Sink.record(I)V}), so instrumentation never breaks the verifier.
 */
public final class Sink {
    /** Untrusted deserialization (CWE-502). */
    public static final int DESERIALIZATION = 1;
    /** OS command / process execution (CWE-78). */
    public static final int PROCESS_EXEC = 2;
    /** Dynamic code evaluation (CWE-94). */
    public static final int CODE_EVAL = 3;
    /** Dynamic SQL execution (CWE-89). */
    public static final int SQL = 4;
    /** LDAP / directory search (CWE-90). */
    public static final int LDAP = 5;

    private static final Set<Integer> REACHED = ConcurrentHashMap.newKeySet();

    private Sink() {}

    /** Probe entry the agent inserts before each sink call site. Stack-neutral. */
    public static void record(int kind) {
        REACHED.add(kind);
    }

    /** Reached sink kinds so far (test/inspection hook). */
    static Set<Integer> reached() {
        return REACHED;
    }

    /**
     * Write the reached sink kinds (one integer per line) to {@code GOVFUZZ_SINK_OUT},
     * if that env var is set and any sink was reached. Called by the driver at exit;
     * best-effort — a report failure must never perturb fuzzing.
     */
    public static void report() {
        String path = System.getenv("GOVFUZZ_SINK_OUT");
        if (path == null || path.isEmpty() || REACHED.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (Integer kind : REACHED) {
            sb.append(kind).append('\n');
        }
        // Append (not truncate) so a per-spawn isolation JVM can't overwrite the
        // fuller campaign report; govfuzz dedupes kinds on read.
        try (FileWriter writer = new FileWriter(path, true)) {
            writer.write(sb.toString());
        } catch (Exception ignored) {
            // best-effort
        }
    }
}
