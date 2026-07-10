// SPDX-License-Identifier: Apache-2.0
package com.govfuzz;

import java.io.DataInputStream;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Native govfuzz JVM fork-server driver — the Java analog of the persistent
 * {@code main} in {@code c_runtime/govfuzz_driver.c}. It speaks the SAME
 * {@code GOVFUZZ_FRAMED} protocol so the govfuzz builtin engine drives a warm,
 * long-lived JVM one input at a time (amortizing JVM startup), exactly like it
 * drives a C/Rust fork-server binary — no Jazzer, no libFuzzer.
 *
 * <p>Protocol (must match the C driver):
 * <ol>
 *   <li>Duplicate the engine's control pipe (fd 1) and redirect Java stdout to a
 *       sink so target {@code System.out} prints can't corrupt the sync stream.</li>
 *   <li>Write one ready byte to the control fd.</li>
 *   <li>Loop: read {@code {u32 little-endian length, bytes}} from fd 0, run the
 *       harness on it, write one sync byte to the control fd.</li>
 * </ol>
 * An uncaught {@link Throwable} from the harness is a finding: print it to stderr
 * (the engine captures it for the report) and HARD-halt without the sync byte, so
 * the engine sees the process die and re-isolates the input — the same crash
 * surface as an ASan abort in the C lane.
 *
 * <p>Without {@code GOVFUZZ_FRAMED}, {@code args[1]} is a single input file to
 * replay once (the per-spawn isolation path the engine uses to capture a crash).
 */
public final class Driver {
    /** Exit code used for a hard halt on a finding (distinct, non-zero). */
    private static final int FINDING_HALT_CODE = 86;

    /**
     * Simple names of the target's DECLARED exceptions (its `throws` contract),
     * from GOVFUZZ_EXPECTED_EXCEPTIONS. These are expected rejections of bad input
     * — NOT findings — even when unchecked (e.g. org.json's
     * {@code JSONException extends RuntimeException}, declared on
     * {@code JSONObject(String) throws JSONException}). Set by the launcher from
     * the discovered target's signature.
     */
    private static final java.util.Set<String> EXPECTED_EXCEPTIONS = loadExpectedExceptions();

    /**
     * Minimum number of target (non-infrastructure) stack frames a
     * {@link NullPointerException} must traverse before it is treated as a genuine
     * null-dereference defect (CWE-476) rather than a shallow input-validation gap.
     * Tunable via {@code GOVFUZZ_NPE_MIN_DEPTH} (default 3).
     */
    private static final int NPE_MIN_DEPTH = loadNpeMinDepth();

    private Driver() {}

    private static java.util.Set<String> loadExpectedExceptions() {
        java.util.Set<String> set = new java.util.HashSet<>();
        String raw = System.getenv("GOVFUZZ_EXPECTED_EXCEPTIONS");
        if (raw != null) {
            for (String part : raw.split(",")) {
                String name = part.trim();
                if (name.isEmpty()) {
                    continue;
                }
                set.add(name);
                // isFinding compares against getSimpleName(), but a declared `throws`
                // may be fully qualified (`java.io.IOException`); add the simple name
                // too so suppression matches either form. (RC review fix.)
                int dot = name.lastIndexOf('.');
                if (dot >= 0 && dot + 1 < name.length()) {
                    set.add(name.substring(dot + 1));
                }
            }
        }
        return set;
    }

    private static int loadNpeMinDepth() {
        String raw = System.getenv("GOVFUZZ_NPE_MIN_DEPTH");
        if (raw != null) {
            try {
                int v = Integer.parseInt(raw.trim());
                if (v >= 0) {
                    return v;
                }
            } catch (NumberFormatException ignored) {
                // fall through to the default
            }
        }
        return 3;
    }

    public static void main(String[] args) throws Exception {
        String harnessClass = args.length > 0 ? args[0] : System.getenv("GOVFUZZ_HARNESS_CLASS");
        if (harnessClass == null || harnessClass.isEmpty()) {
            System.err.println("govfuzz Driver: no harness class (argv[0] / GOVFUZZ_HARNESS_CLASS)");
            System.exit(2);
        }
        Method runOne = Class.forName(harnessClass).getMethod("govfuzzRunOne", byte[].class);

        if (System.getenv("GOVFUZZ_FRAMED") != null) {
            runFramedLoop(runOne);
            return;
        }
        // Per-spawn single-input replay (the engine isolates a crashing input
        // here). The input arrives EITHER as a file in argv[1] (replay tooling) OR
        // on stdin (the engine's `run_harness` per-spawn path writes stdin, no
        // argv) — support both: prefer a readable argv[1] file, else read stdin.
        byte[] data;
        if (args.length > 1 && Files.isReadable(Path.of(args[1]))) {
            data = Files.readAllBytes(Path.of(args[1]));
        } else {
            data = System.in.readAllBytes();
        }
        runInput(runOne, data);
    }

    private static void runFramedLoop(Method runOne) throws IOException {
        // fd 1 is the engine's control pipe. Write sync bytes here directly; redirect
        // Java-level System.out to a sink so library prints don't reach the pipe.
        FileOutputStream control = new FileOutputStream(FileDescriptor.out);
        PrintStream sink = new PrintStream(OutputStream.nullOutputStream());
        System.setOut(sink);
        DataInputStream in = new DataInputStream(new FileInputStream(FileDescriptor.in));

        control.write(1); // ready byte
        control.flush();

        while (true) {
            int len = readU32Le(in);
            if (len < 0) {
                break; // EOF — engine closed the input pipe
            }
            byte[] buf = new byte[len];
            in.readFully(buf);
            runInput(runOne, buf);
            control.write(1); // sync byte
            control.flush();
        }
    }

    /** Invoke the harness on one input; an uncaught Throwable that is a finding
     *  halts the JVM, an expected one is swallowed (the input is just rejected). */
    private static void runInput(Method runOne, byte[] data) {
        // Deterministic per-input coverage: start every input from a fixed AFL
        // "previous location" so identical inputs hash to identical edges.
        Coverage.resetPrev();
        Throwable thrown = null;
        try {
            runOne.invoke(null, (Object) data);
        } catch (InvocationTargetException ite) {
            thrown = ite.getCause() != null ? ite.getCause() : ite;
        } catch (Throwable t) {
            thrown = t;
        }
        if (thrown != null && isFinding(thrown)) {
            reportFinding(thrown);
        }
    }

    /**
     * The noise policy, applied at runtime by class so the generated harness needs
     * no exception imports. A finding is a genuine bug:
     * <ul>
     *   <li>any {@link Error} — OOM, StackOverflow, AssertionError, …;</li>
     *   <li>a "real bug" {@link RuntimeException} — NPE, array/index OOB, class
     *       cast, arithmetic, negative array size, …;</li>
     * </ul>
     * NOT a finding (the target merely rejected the input):
     * <ul>
     *   <li>{@link IllegalArgumentException} (incl. {@code NumberFormatException}) —
     *       input validation;</li>
     *   <li>any checked exception (extends {@code Exception} but not
     *       {@code RuntimeException}) — a declared, normal failure mode such as a
     *       parser's {@code ParseException}/{@code IOException}.</li>
     * </ul>
     * <p>A {@link NullPointerException} is promoted to a finding only when it
     * surfaces after the input has flowed through at least {@link #NPE_MIN_DEPTH}
     * of the target's own frames — a deep null-dereference defect (CWE-476) — while
     * a NPE at the immediate API surface stays noise (an input-validation gap).
     */
    static boolean isFinding(Throwable t) {
        // The target's DECLARED exceptions (its `throws` contract) are expected
        // rejections of bad input — not findings — even when unchecked. Walk the
        // throwable's class hierarchy so a subclass of a declared type also counts.
        if (!EXPECTED_EXCEPTIONS.isEmpty()) {
            for (Class<?> c = t.getClass(); c != null && c != Object.class; c = c.getSuperclass()) {
                if (EXPECTED_EXCEPTIONS.contains(c.getSimpleName())) {
                    return false;
                }
            }
        }
        // Any Error is a genuine bug: OutOfMemoryError / StackOverflowError (DoS),
        // AssertionError (invariant violation), NoClassDefFoundError, …
        if (t instanceof Error) {
            return true;
        }
        // A NullPointerException is the dominant JVM auto-harness noise when the
        // target dereferences the raw input without a guard (a validation gap at the
        // surface). But a NPE that surfaces only after the input has travelled
        // through several of the target's OWN frames is a genuine null-dereference
        // defect (CWE-476), not an entry check — promote by processing depth.
        if (t instanceof NullPointerException) {
            return targetFrameDepth(t) >= NPE_MIN_DEPTH;
        }
        // Findings are the UNAMBIGUOUS memory/logic-safety runtime exceptions. A
        // library throwing its OWN exception (JSONException, SerializationException)
        // or IllegalArgument/NumberFormat on malformed input is expected input
        // rejection — NOISE, not a finding. This keeps the signal on real defects.
        return t instanceof IndexOutOfBoundsException        // array/string OOB read
                || t instanceof NegativeArraySizeException   // CWE-129-ish
                || t instanceof ArithmeticException          // div-by-zero
                || t instanceof ClassCastException;          // type-confusion
    }

    /**
     * Count of stack frames in target/library code — excluding the JVM runtime, the
     * JDK, reflection glue, and the govfuzz driver/harness/agent — a proxy for how
     * deep the input travelled before the throw.
     */
    private static int targetFrameDepth(Throwable t) {
        int depth = 0;
        for (StackTraceElement frame : t.getStackTrace()) {
            String cls = frame.getClassName();
            if (cls.startsWith("java.")
                    || cls.startsWith("javax.")
                    || cls.startsWith("jdk.")
                    || cls.startsWith("sun.")
                    || cls.startsWith("com.sun.")
                    || cls.startsWith("com.govfuzz.")
                    || cls.startsWith("govfuzzgen.")) {
                continue;
            }
            depth++;
        }
        return depth;
    }

    /** Report a finding and hard-halt without the sync byte so the engine sees the
     *  process die and re-isolates the input. */
    private static void reportFinding(Throwable t) {
        System.err.println("== govfuzz JVM finding: " + t.getClass().getName()
                + (t.getMessage() != null ? ": " + t.getMessage() : ""));
        t.printStackTrace(System.err);
        System.err.flush();
        // Hard halt: no shutdown hooks, no sync byte -> the engine sees a crash.
        Runtime.getRuntime().halt(FINDING_HALT_CODE);
    }

    /** Read a little-endian u32 length; returns -1 on EOF. */
    private static int readU32Le(DataInputStream in) throws IOException {
        int b0 = in.read();
        if (b0 < 0) {
            return -1;
        }
        int b1 = in.read();
        int b2 = in.read();
        int b3 = in.read();
        if ((b1 | b2 | b3) < 0) {
            return -1;
        }
        return (b0 & 0xff) | ((b1 & 0xff) << 8) | ((b2 & 0xff) << 16) | ((b3 & 0xff) << 24);
    }
}
