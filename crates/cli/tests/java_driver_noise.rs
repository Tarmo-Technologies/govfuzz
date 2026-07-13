// SPDX-License-Identifier: Apache-2.0
//
// Unit-level regression for the JVM Driver's finding/noise policy
// (`com.govfuzz.Driver.isFinding`), in particular the M2.2 NullPointerException
// depth promotion: a deep null-dereference (CWE-476) — the input reached several of
// the target's own frames before the throw — is a finding, while a shallow surface
// NPE and ordinary input-validation exceptions stay noise. Compiles the REAL
// java_runtime Driver + Coverage together with a same-package probe and runs it, so
// the policy is exercised as shipped. Skips cleanly without a JDK (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

fn java_runtime_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../java_runtime/src/com/govfuzz")
        .canonicalize()
        .expect("canonicalize java_runtime dir")
}

fn has_jdk() -> bool {
    Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok()
}

/// A same-package probe that drives `Driver.isFinding` (package-private) across the
/// noise policy's decision points and exits non-zero on any mismatch.
const PROBE: &str = r#"
package com.govfuzz;

public final class NpeNoiseProbe {
    private static int failures = 0;

    private static StackTraceElement f(String cls) {
        return new StackTraceElement(cls, "m", cls + ".java", 10);
    }

    private static Throwable withStack(Throwable t, StackTraceElement[] st) {
        t.setStackTrace(st);
        return t;
    }

    private static void check(String name, boolean got, boolean want) {
        if (got != want) {
            System.err.println("FAIL " + name + ": got " + got + " want " + want);
            failures++;
        } else {
            System.out.println("ok " + name);
        }
    }

    public static void main(String[] args) {
        // Deep NPE: 3 target frames before the harness/driver boundary -> CWE-476 finding.
        StackTraceElement[] deep = {
            f("com.acme.Inner"),
            f("com.acme.Middle"),
            f("com.acme.Outer"),
            new StackTraceElement("govfuzzgen.Harness", "govfuzzRunOne", "Harness.java", 1),
            new StackTraceElement("jdk.internal.reflect.DirectMethodHandleAccessor", "invoke", null, 1),
            new StackTraceElement("com.govfuzz.Driver", "runInput", "Driver.java", 1),
        };
        check("deep-npe", Driver.isFinding(withStack(new NullPointerException(), deep)), true);

        // Shallow NPE: only 2 target frames (< default depth 3) -> validation-gap noise.
        StackTraceElement[] shallow = {
            f("com.acme.Api"),
            f("com.acme.Outer"),
            new StackTraceElement("govfuzzgen.Harness", "govfuzzRunOne", "Harness.java", 1),
            new StackTraceElement("com.govfuzz.Driver", "runInput", "Driver.java", 1),
        };
        check("shallow-npe", Driver.isFinding(withStack(new NullPointerException(), shallow)), false);

        // NPE entirely inside the JDK (no target frames) -> noise.
        StackTraceElement[] jdkOnly = {
            new StackTraceElement("java.util.HashMap", "get", "HashMap.java", 1),
            new StackTraceElement("govfuzzgen.Harness", "govfuzzRunOne", "Harness.java", 1),
        };
        check("jdk-only-npe", Driver.isFinding(withStack(new NullPointerException(), jdkOnly)), false);

        // Unambiguous memory/logic-safety exceptions stay findings.
        check("aioobe", Driver.isFinding(new ArrayIndexOutOfBoundsException("x")), true);
        check("arith", Driver.isFinding(new ArithmeticException("/ by zero")), true);
        check("oom", Driver.isFinding(new OutOfMemoryError("heap")), true);

        // Input-validation exceptions stay noise.
        check("iae", Driver.isFinding(new IllegalArgumentException("bad")), false);
        check("nfe", Driver.isFinding(new NumberFormatException("nan")), false);

        if (failures > 0) {
            System.err.println(failures + " failure(s)");
            System.exit(1);
        }
        System.out.println("all ok");
    }
}
"#;

/// A probe for the scalar-only-target suppression (GOVFUZZ_SCALAR_ONLY_TARGET=1): a
/// synthesized out-of-range `int` hitting a JDK container's documented range
/// contract is expected noise, while a genuine logic defect still halts.
const SCALAR_PROBE: &str = r#"
package com.govfuzz;

public final class ScalarOnlyProbe {
    public static void main(String[] args) {
        int failures = 0;
        // Documented range/size preconditions on a scalar-only target -> noise.
        if (Driver.isFinding(new IndexOutOfBoundsException("idx"))) {
            System.err.println("FAIL ioobe"); failures++;
        }
        if (Driver.isFinding(new ArrayIndexOutOfBoundsException("idx"))) {
            System.err.println("FAIL aioobe"); failures++;
        }
        if (Driver.isFinding(new NegativeArraySizeException("-1"))) {
            System.err.println("FAIL nase"); failures++;
        }
        if (Driver.isFinding(new OutOfMemoryError("capacity"))) {
            System.err.println("FAIL oom"); failures++;
        }
        // A genuine logic defect still halts even for a scalar-only target.
        if (!Driver.isFinding(new ArithmeticException("/ by zero"))) {
            System.err.println("FAIL arith"); failures++;
        }
        if (!Driver.isFinding(new ClassCastException("cce"))) {
            System.err.println("FAIL cce"); failures++;
        }
        if (failures > 0) {
            System.exit(1);
        }
        System.out.println("scalar-only ok");
    }
}
"#;

#[test]
fn driver_noise_policy_promotes_deep_npe_and_suppresses_shallow() {
    if !has_jdk() {
        eprintln!("skip: no JDK (JVM Driver noise policy needs javac/java)");
        return;
    }
    let rt = java_runtime_dir();
    let tmp = std::env::temp_dir().join(format!("govfuzz-jvm-noise-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("com/govfuzz");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(rt.join("Driver.java"), src.join("Driver.java")).unwrap();
    std::fs::copy(rt.join("Coverage.java"), src.join("Coverage.java")).unwrap();
    std::fs::write(src.join("NpeNoiseProbe.java"), PROBE).unwrap();
    std::fs::write(src.join("ScalarOnlyProbe.java"), SCALAR_PROBE).unwrap();

    let classes = tmp.join("classes");
    std::fs::create_dir_all(&classes).unwrap();
    let compile = Command::new("javac")
        .args(["-d", classes.to_str().unwrap()])
        .arg(src.join("Driver.java"))
        .arg(src.join("Coverage.java"))
        .arg(src.join("NpeNoiseProbe.java"))
        .arg(src.join("ScalarOnlyProbe.java"))
        .output()
        .expect("javac");
    assert!(
        compile.status.success(),
        "javac failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run = Command::new("java")
        .args([
            "-cp",
            classes.to_str().unwrap(),
            "com.govfuzz.NpeNoiseProbe",
        ])
        .output()
        .expect("java");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        run.status.success(),
        "JVM Driver noise policy mismatch:\n{combined}"
    );

    // Second run with GOVFUZZ_SCALAR_ONLY_TARGET=1: the container range/size
    // preconditions become noise (the static is read once per JVM, so this needs a
    // separate process from the default-policy run above).
    let scalar_run = Command::new("java")
        .env("GOVFUZZ_SCALAR_ONLY_TARGET", "1")
        .args([
            "-cp",
            classes.to_str().unwrap(),
            "com.govfuzz.ScalarOnlyProbe",
        ])
        .output()
        .expect("java");
    let scalar_combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&scalar_run.stdout),
        String::from_utf8_lossy(&scalar_run.stderr)
    );
    assert!(
        scalar_run.status.success(),
        "JVM Driver scalar-only noise policy mismatch:\n{scalar_combined}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
