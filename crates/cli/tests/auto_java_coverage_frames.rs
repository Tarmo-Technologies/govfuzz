// SPDX-License-Identifier: Apache-2.0
//
// Regression test for the JVM coverage agent's stack-map handling (F10). The agent
// (`java_runtime/.../CoverageAgent.java`) instruments classes for coverage; it used
// to write with `COMPUTE_MAXS`, which KEEPS the original `StackMapTable` frames.
// Inserting coverage probes shifts bytecode offsets, so a frame holding an
// `Uninitialized(offset)` verification type (a `new` whose offset is referenced by a
// later frame — e.g. `new Foo(branchyArg())`) becomes stale and the JVM verifier
// throws `java.lang.ClassFormatError: StackMapTable format error: bad offset for
// Uninitialized` (the canonical `CSVParser.createHeaders()` failure), aborting the
// fuzz loop. The fix switches the writer to `COMPUTE_FRAMES` with a
// resource-reading `getCommonSuperClass` (no `Class.forName`, no class-load
// deadlock). This test instruments a class with that exact uninitialized-frame
// shape under the real agent and asserts it loads + verifies with NO ClassFormatError.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A usable JDK (`javac` + `java`) — the native Java lane needs it; with none the
/// agent never runs, so this test self-skips (the GNAT-less rule).
fn has_jdk() -> bool {
    Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok()
}

fn build_agent_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../java_runtime/build-agent.sh")
}

/// The class with the uninitialized-frame shape that reproduces the bug: a `new
/// Box(...)` whose constructor arguments are computed through branches, so javac
/// emits a stack-map frame while the *uninitialized* `Box` reference is on the
/// operand stack (`uninitialized <offset>`). Probe insertion shifts that offset.
const FRAME_PROBE_JAVA: &str = r#"package gffix;
import java.util.HashSet;
import java.util.Set;
public class FrameProbe {
    public static final class Box {
        final String s; final int n;
        Box(String s, int n) { this.s = s; this.n = n; }
    }
    public Box build(String[] items, boolean flag) {
        Set<String> seen = new HashSet<>();
        int count = 0;
        String first = null;
        for (String it : items) {
            if (it == null) continue;
            if (seen.add(it)) {
                count++;
                if (first == null) first = it;
            } else if (flag) {
                count += it.length();
            }
        }
        return new Box(first != null ? first : "none", flag ? count : -count);
    }
}
"#;

/// Forces a class to be linked + verified (loading alone is lazy): `Class.forName`
/// with initialization, then touch its declared methods.
const FORCE_LOAD_JAVA: &str = r#"public class ForceLoad {
    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName(a[0], true, ForceLoad.class.getClassLoader());
        c.getDeclaredMethods();
        System.out.println("OK loaded+verified: " + c.getName());
    }
}
"#;

#[test]
fn coverage_agent_emits_valid_frames_for_uninitialized_stackmap() {
    if !has_jdk() {
        eprintln!("skip: no JDK (the JVM coverage agent needs javac/java)");
        return;
    }
    let script = build_agent_script();
    if !script.is_file() {
        eprintln!("skip: build-agent.sh not found at {}", script.display());
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-java-frames-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src/gffix");
    let out = tmp.join("out");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(src.join("FrameProbe.java"), FRAME_PROBE_JAVA).unwrap();
    std::fs::write(tmp.join("src/ForceLoad.java"), FORCE_LOAD_JAVA).unwrap();

    // Build the agent jar from the CURRENT runtime sources (so the test exercises
    // the fix, not a stale cached jar). `build-agent.sh` may need ASM jars it can't
    // fetch offline — skip cleanly if the build can't be produced.
    let agent_jar = tmp.join("govfuzz-jvm-agent.jar");
    let build = Command::new("sh")
        .arg(&script)
        .arg(&agent_jar)
        .output()
        .expect("spawn build-agent.sh");
    if !build.status.success() || !agent_jar.is_file() {
        eprintln!(
            "skip: could not build the JVM agent jar (offline ASM?): {}",
            String::from_utf8_lossy(&build.stderr)
        );
        return;
    }

    let javac_ok = Command::new("javac")
        .arg("-d")
        .arg(&out)
        .arg(src.join("FrameProbe.java"))
        .arg(tmp.join("src/ForceLoad.java"))
        .status()
        .expect("spawn javac")
        .success();
    assert!(javac_ok, "fixture javac should succeed");

    let cp = format!("{}:{}", out.display(), agent_jar.display());
    let run = Command::new("java")
        .arg(format!("-javaagent:{}", agent_jar.display()))
        .arg("-cp")
        .arg(&cp)
        .arg("ForceLoad")
        .arg("gffix.FrameProbe")
        // Restrict instrumentation to the fixture package (and force a value so the
        // agent doesn't read the ambient env).
        .env("GOVFUZZ_COV_INCLUDE", "gffix/")
        .output()
        .expect("run ForceLoad under the agent");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    assert!(
        !combined.contains("ClassFormatError") && !combined.contains("StackMapTable"),
        "instrumented class must verify (no StackMapTable ClassFormatError), got:\n{combined}"
    );
    assert!(
        combined.contains("OK loaded+verified: gffix.FrameProbe"),
        "instrumented class should load + verify under the agent, got:\n{combined}"
    );
}
