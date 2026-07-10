// SPDX-License-Identifier: Apache-2.0
package com.govfuzz;

import static org.objectweb.asm.Opcodes.ACC_ABSTRACT;
import static org.objectweb.asm.Opcodes.ACC_NATIVE;
import static org.objectweb.asm.Opcodes.ATHROW;
import static org.objectweb.asm.Opcodes.DUP2;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;
import static org.objectweb.asm.Opcodes.IRETURN;
import static org.objectweb.asm.Opcodes.RETURN;

import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;

/**
 * govfuzz's OWN JVM bytecode coverage agent — the native, Jazzer-free equivalent
 * of SanitizerCoverage for the JVM. Loaded via {@code -javaagent}, it instruments
 * the target's classes at load time so each basic block records an edge into the
 * shared coverage map (see {@link Coverage}). The govfuzz builtin engine reads
 * that map exactly as it reads a C/Rust sancov binary's map — same feedback loop,
 * no third-party fuzzer.
 *
 * <p>Instrumentation is a stack-neutral probe — {@code LDC <blockId>;
 * INVOKESTATIC Coverage.recordEdge(I)V} — inserted at method entry and at the
 * start of each basic block (after each label). Even though the probe is
 * stack-neutral, inserting it shifts bytecode offsets, which invalidates any
 * preserved {@code StackMapTable} entry that references an instruction offset (an
 * {@code Uninitialized} type points at a {@code NEW}) — so {@code COMPUTE_MAXS},
 * which keeps the original frames, makes the verifier throw {@code ClassFormatError}
 * (e.g. {@code CSVParser.createHeaders()}). The writer therefore uses
 * {@code COMPUTE_FRAMES} to recompute frames from scratch, and overrides
 * {@link FrameClassWriter#getCommonSuperClass} to resolve the type hierarchy by
 * reading {@code .class} resources rather than loading classes — preserving the
 * no-{@code Class.forName}, no-deadlock property that motivated the original
 * {@code COMPUTE_MAXS} choice.
 *
 * <p>Which classes get instrumented is controlled by {@code GOVFUZZ_COV_INCLUDE}
 * (comma-separated internal-name prefixes, e.g. {@code com/acme/}) or the agent
 * argument; with neither, all non-JDK application classes are instrumented.
 */
public final class CoverageAgent {
    private static final AtomicInteger NEXT_BLOCK_ID = new AtomicInteger(1);
    private static volatile String[] includePrefixes = new String[0];

    private CoverageAgent() {}

    public static void premain(String agentArgs, Instrumentation inst) {
        includePrefixes = parsePrefixes(agentArgs);
        inst.addTransformer(new Transformer());
        // Flush the sink-reachability report on normal JVM exit, independent of the
        // driver, so any agent-instrumented run records the dangerous sinks it reached.
        Runtime.getRuntime().addShutdownHook(new Thread(Sink::report));
    }

    private static String[] parsePrefixes(String agentArgs) {
        String raw = (agentArgs != null && !agentArgs.isEmpty())
                ? agentArgs
                : System.getenv("GOVFUZZ_COV_INCLUDE");
        if (raw == null || raw.isBlank()) {
            return new String[0];
        }
        String[] parts = raw.split(",");
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String p : parts) {
            String t = p.trim().replace('.', '/');
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out.toArray(new String[0]);
    }

    private static boolean shouldInstrument(String internalName) {
        if (internalName == null) {
            return false;
        }
        // Never instrument the agent/runtime, the JDK, or ASM itself.
        if (internalName.startsWith("com/govfuzz/")
                || internalName.startsWith("java/")
                || internalName.startsWith("jdk/")
                || internalName.startsWith("sun/")
                || internalName.startsWith("javax/")
                || internalName.startsWith("org/objectweb/asm/")) {
            return false;
        }
        if (includePrefixes.length == 0) {
            return true; // default: all application classes
        }
        for (String p : includePrefixes) {
            if (internalName.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    private static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            if (!shouldInstrument(className)) {
                return null; // null => leave the class unchanged
            }
            try {
                return instrument(classfileBuffer, loader);
            } catch (Throwable t) {
                // Never let an instrumentation failure break class loading.
                return null;
            }
        }
    }

    static byte[] instrument(byte[] classfileBuffer, ClassLoader loader) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassNode cn = new ClassNode();
        cr.accept(cn, ClassReader.EXPAND_FRAMES);

        for (MethodNode mn : cn.methods) {
            if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) {
                continue;
            }
            InsnList insns = mn.instructions;
            if (insns.size() == 0) {
                continue;
            }
            // Find the first real instruction of every basic block. A block begins
            // at: method entry, any jump TARGET (a label), and the FALL-THROUGH
            // after any branch/switch/return/throw. Probing only labels (jump
            // targets) misses fall-through blocks — e.g. the taken side of an `if`
            // chain — so distinct paths would record identical coverage.
            List<AbstractInsnNode> blockStarts = new ArrayList<>();
            boolean atBlockStart = true;
            for (AbstractInsnNode node = insns.getFirst(); node != null; node = node.getNext()) {
                if (node instanceof LabelNode) {
                    atBlockStart = true; // a jump target starts a block
                    continue;
                }
                if (node instanceof FrameNode || node instanceof LineNumberNode) {
                    continue;
                }
                int op = node.getOpcode();
                if (op < 0) {
                    continue;
                }
                if (atBlockStart) {
                    blockStarts.add(node);
                    atBlockStart = false;
                }
                boolean terminatesBlock = node instanceof JumpInsnNode
                        || node instanceof TableSwitchInsnNode
                        || node instanceof LookupSwitchInsnNode
                        || (op >= IRETURN && op <= RETURN)
                        || op == ATHROW;
                if (terminatesBlock) {
                    atBlockStart = true; // the next real instruction starts a block
                }
            }
            for (AbstractInsnNode start : blockStarts) {
                insns.insertBefore(start, probe(NEXT_BLOCK_ID.getAndIncrement()));
            }
            instrumentComparisons(insns);
            instrumentSinks(insns);
        }

        // COMPUTE_FRAMES recomputes the stack-map frames from scratch, so the
        // offset-shifting caused by inserting probes can't leave a stale frame (the
        // `Uninitialized` / `bad offset` ClassFormatError). The writer is seeded with
        // the ClassReader to reuse its constant pool, and its getCommonSuperClass is
        // overridden to walk the hierarchy via .class resources on `loader` — no
        // Class.forName, so no class-loading deadlock inside the transformer.
        ClassWriter cw = new FrameClassWriter(cr, ClassWriter.COMPUTE_FRAMES, loader);
        cn.accept(cw);
        return cw.toByteArray();
    }

    /**
     * A {@link ClassWriter} that uses {@code COMPUTE_FRAMES} but resolves the common
     * superclass needed for frame merging WITHOUT loading classes into the JVM. The
     * default ASM implementation calls {@code Class.forName} +
     * {@code Class.isAssignableFrom}, which can deadlock when invoked from inside a
     * {@link ClassFileTransformer} (the class being instrumented is mid-load on the
     * same loader). Instead it reads each class's super-name from its {@code .class}
     * resource and walks the superclass chains, returning {@code java/lang/Object}
     * as a safe (always-valid) fallback whenever a class can't be resolved.
     */
    private static final class FrameClassWriter extends ClassWriter {
        private static final String OBJECT = "java/lang/Object";
        private final ClassLoader loader;

        FrameClassWriter(ClassReader classReader, int flags, ClassLoader loader) {
            super(classReader, flags);
            // Fall back to the system loader when the transformer was handed null
            // (bootstrap / platform classes), so resources are still resolvable.
            this.loader = (loader != null) ? loader : ClassLoader.getSystemClassLoader();
        }

        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            if (type1.equals(type2)) {
                return type1;
            }
            if (OBJECT.equals(type1) || OBJECT.equals(type2)) {
                return OBJECT;
            }
            // Collect type1's superclass chain (itself + ancestors up to Object).
            Set<String> chain1 = new LinkedHashSet<>();
            for (String c = type1; c != null; c = superNameOf(c)) {
                chain1.add(c);
                if (OBJECT.equals(c)) {
                    break;
                }
            }
            if (!chain1.contains(OBJECT)) {
                return OBJECT; // type1 couldn't be fully resolved — safe fallback
            }
            // Walk type2's chain; the first class also in type1's chain is the lowest
            // common ancestor. (Interfaces are ignored: Object is always a valid,
            // if imprecise, answer the verifier accepts.)
            for (String d = type2; d != null; d = superNameOf(d)) {
                if (chain1.contains(d)) {
                    return d;
                }
                if (OBJECT.equals(d)) {
                    break;
                }
            }
            return OBJECT;
        }

        /** The internal super-name of an internal class name, read from its
         *  {@code .class} resource, or null if unresolved (or for Object). */
        private String superNameOf(String internalName) {
            try (InputStream is = openClassResource(internalName)) {
                if (is == null) {
                    return null;
                }
                return new ClassReader(is).getSuperName();
            } catch (Exception e) {
                return null;
            }
        }

        /** Open a class file as a resource without loading the class: the
         *  transformer's loader first, then the system loader, then the agent's own
         *  loader (for ASM/agent classes). */
        private InputStream openClassResource(String internalName) {
            String resource = internalName + ".class";
            InputStream is = loader.getResourceAsStream(resource);
            if (is == null) {
                ClassLoader sys = ClassLoader.getSystemClassLoader();
                if (sys != null) {
                    is = sys.getResourceAsStream(resource);
                }
            }
            if (is == null) {
                is = CoverageAgent.class.getResourceAsStream("/" + resource);
            }
            return is;
        }
    }

    private static InsnList probe(int blockId) {
        InsnList l = new InsnList();
        l.add(new LdcInsnNode(blockId));
        l.add(new MethodInsnNode(INVOKESTATIC, "com/govfuzz/Coverage", "recordEdge", "(I)V", false));
        return l;
    }

    /**
     * RedQueen/cmplog capture: before each String/byte comparison CALL, duplicate
     * its two operands ({@code DUP2}) and pass them to a {@link Cmplog} hook, which
     * records the pair into the operand ring for the engine to splice. The probe is
     * stack-neutral ({@code DUP2} pushes 2, the hook pops 2), so frames stay valid.
     * Only fires for two-ref-operand comparisons (both category-1), which is every
     * targeted call below.
     */
    private static void instrumentComparisons(InsnList insns) {
        // Collect first (mutating the list while iterating is unsafe).
        java.util.List<MethodInsnNode> calls = new ArrayList<>();
        for (AbstractInsnNode n = insns.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof MethodInsnNode && cmplogHookFor((MethodInsnNode) n) != null) {
                calls.add((MethodInsnNode) n);
            }
        }
        for (MethodInsnNode call : calls) {
            String hook = cmplogHookFor(call);
            String desc = "hookStringCompare".equals(hook)
                    ? "(Ljava/lang/Object;Ljava/lang/Object;)V"
                    : "([B[B)V";
            InsnList probe = new InsnList();
            probe.add(new InsnNode(DUP2));
            probe.add(new MethodInsnNode(INVOKESTATIC, "com/govfuzz/Cmplog", hook, desc, false));
            insns.insertBefore(call, probe);
        }
    }

    /**
     * The {@link Cmplog} hook method for a comparison call site, or null if the call
     * is not a tracked comparison. Targets the dominant Java magic-gate mechanisms:
     * {@code String}/{@code CharSequence} comparisons and {@code byte[]} equality —
     * each leaves exactly its two operands (both single-slot refs) on the stack.
     */
    private static String cmplogHookFor(MethodInsnNode m) {
        if ("java/lang/String".equals(m.owner)) {
            switch (m.name) {
                case "equals":
                case "equalsIgnoreCase":
                case "contentEquals":
                case "compareTo":
                case "compareToIgnoreCase":
                case "startsWith":
                case "endsWith":
                case "contains":
                    // Require EXACTLY one object parameter so the stack is
                    // [receiver:String, arg:ref] — two category-1 refs that DUP2 +
                    // (Object,Object) hook handle. This excludes the 2-arg overload
                    // `startsWith(String, int)` whose `int` operand would break the
                    // hook (and the verifier).
                    if (isSingleObjectParam(m.desc)) {
                        return "hookStringCompare";
                    }
                    return null;
                default:
                    return null;
            }
        }
        if ("java/util/Arrays".equals(m.owner)
                && "equals".equals(m.name)
                && "([B[B)Z".equals(m.desc)) {
            return "hookBytesEquals";
        }
        if ("java/security/MessageDigest".equals(m.owner)
                && "isEqual".equals(m.name)
                && "([B[B)Z".equals(m.desc)) {
            return "hookBytesEquals";
        }
        return null;
    }

    /**
     * Sink-reachability probe: before each call site of a dangerous sink, insert a
     * stack-neutral {@code LDC <kind>; INVOKESTATIC Sink.record(I)V} so that reaching
     * the sink under fuzzing is recorded as input-reachable attack surface. Mirrors
     * {@link #instrumentComparisons(InsnList)}: collect the matching calls first
     * (mutating while iterating is unsafe), then insert before each.
     */
    private static void instrumentSinks(InsnList insns) {
        List<MethodInsnNode> calls = new ArrayList<>();
        for (AbstractInsnNode n = insns.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof MethodInsnNode && sinkKindFor((MethodInsnNode) n) != 0) {
                calls.add((MethodInsnNode) n);
            }
        }
        for (MethodInsnNode call : calls) {
            int kind = sinkKindFor(call);
            InsnList probe = new InsnList();
            probe.add(new LdcInsnNode(kind));
            probe.add(new MethodInsnNode(INVOKESTATIC, "com/govfuzz/Sink", "record", "(I)V", false));
            insns.insertBefore(call, probe);
        }
    }

    /**
     * The {@link Sink} kind for a call site, or {@code 0} if it is not a tracked sink.
     * Matches the declaring type of the invoked method — for the interface-typed sinks
     * ({@code ScriptEngine}, {@code Statement}, {@code DirContext}) the INVOKEINTERFACE
     * owner IS the interface, so {@code engine.eval(...)} etc. are caught. Reflection
     * ({@code Class.forName}/{@code Method.invoke}) is intentionally NOT tracked: its
     * reachability alone is too common to be a signal without argument taint.
     */
    private static int sinkKindFor(MethodInsnNode m) {
        switch (m.owner) {
            case "java/io/ObjectInputStream":
                if ("readObject".equals(m.name) || "readUnshared".equals(m.name)) {
                    return Sink.DESERIALIZATION;
                }
                return 0;
            case "java/lang/ProcessBuilder":
                return "start".equals(m.name) ? Sink.PROCESS_EXEC : 0;
            case "java/lang/Runtime":
                return "exec".equals(m.name) ? Sink.PROCESS_EXEC : 0;
            case "javax/script/ScriptEngine":
                return "eval".equals(m.name) ? Sink.CODE_EVAL : 0;
            case "java/sql/Statement":
            case "java/sql/PreparedStatement":
                return m.name.startsWith("execute") ? Sink.SQL : 0;
            case "javax/naming/directory/DirContext":
            case "javax/naming/directory/InitialDirContext":
                return "search".equals(m.name) ? Sink.LDAP : 0;
            default:
                return 0;
        }
    }

    /** True when a method descriptor has EXACTLY one parameter and it is an object
     *  reference type (`(Lsomething;)X`), so the receiver+arg are two ref slots. */
    private static boolean isSingleObjectParam(String desc) {
        int close = desc.indexOf(')');
        if (close < 0) {
            return false;
        }
        String params = desc.substring(1, close);
        return params.startsWith("L")
                && params.endsWith(";")
                && params.indexOf(';') == params.length() - 1;
    }
}
