// SPDX-License-Identifier: Apache-2.0
//
// End-to-end JVM sink-reachability oracle: build the real govfuzz agent jar (coverage
// agent + Sink recorder, shaded with ASM), instrument a target that deserializes
// untrusted bytes, run it under `-javaagent`, and confirm the agent recorded the
// deserialization sink into GOVFUZZ_SINK_OUT — the input-reachable attack surface the
// crash-only JVM lane never reports. Then confirm the Rust oracle turns that report
// into a GF-421 finding, and that a sink-free target records nothing (no FP).
// Skips cleanly without a JDK, or if the agent jar can't be built (no cached ASM).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::sink_oracle::run_sink_oracle;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn has_jdk() -> bool {
    Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok()
        && Command::new("jar").arg("--version").output().is_ok()
}

fn build_agent_jar(out: &Path) -> bool {
    Command::new("bash")
        .arg(repo_root().join("java_runtime/build-agent.sh"))
        .arg(out)
        .output()
        .map(|o| o.status.success() && out.is_file())
        .unwrap_or(false)
}

/// Compile `src` (a single .java file) into `classes_dir`.
fn javac(src: &Path, classes_dir: &Path) {
    let out = Command::new("javac")
        .arg("-d")
        .arg(classes_dir)
        .arg(src)
        .output()
        .expect("javac");
    assert!(
        out.status.success(),
        "javac failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run `class_name` under the agent with GOVFUZZ_SINK_OUT set, returning the report
/// text (empty string if no report was written).
fn run_under_agent(agent: &Path, classes: &Path, class_name: &str, report: &Path) -> String {
    let _ = std::fs::remove_file(report);
    let status = Command::new("java")
        .arg(format!("-javaagent:{}", agent.display()))
        .arg("-cp")
        .arg(classes)
        .arg(class_name)
        .env("GOVFUZZ_SINK_OUT", report)
        .status()
        .expect("java");
    assert!(status.success(), "{class_name} exited non-zero");
    std::fs::read_to_string(report).unwrap_or_default()
}

#[test]
fn agent_records_deserialization_sink_and_oracle_emits_finding() {
    if !has_jdk() {
        eprintln!("skip: no JDK");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("govfuzz-jsink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let classes = tmp.join("classes");
    let src = tmp.join("src").join("t");
    std::fs::create_dir_all(&classes).unwrap();
    std::fs::create_dir_all(&src).unwrap();

    let agent = tmp.join("govfuzz-jvm-agent.jar");
    if !build_agent_jar(&agent) {
        eprintln!("skip: could not build agent jar (no cached ASM / no network)");
        return;
    }

    // A target that deserializes untrusted bytes — the classic Java RCE sink.
    std::fs::write(
        src.join("Target.java"),
        "package t;\n\
         import java.io.*;\n\
         public class Target {\n\
             public static void run(byte[] data) {\n\
                 try {\n\
                     ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));\n\
                     ois.readObject();\n\
                 } catch (Throwable ignored) {}\n\
             }\n\
             public static void main(String[] a) { run(new byte[]{(byte)0xac,(byte)0xed,0,5}); }\n\
         }\n",
    )
    .unwrap();
    javac(&src.join("Target.java"), &classes);

    // A sink-free target (control): must record nothing.
    std::fs::write(
        src.join("Clean.java"),
        "package t;\n\
         public class Clean {\n\
             public static void main(String[] a) {\n\
                 int x = 0; for (int i = 0; i < 10; i++) x += i;\n\
                 if (x < 0) System.out.println(x);\n\
             }\n\
         }\n",
    )
    .unwrap();
    javac(&src.join("Clean.java"), &classes);

    // The deserializing target records sink kind 1 (DESERIALIZATION).
    let report = tmp.join("sink_report.txt");
    let text = run_under_agent(&agent, &classes, "t.Target", &report);
    assert!(
        text.lines().any(|l| l.trim() == "1"),
        "agent should record the deserialization sink (kind 1), got: {text:?}"
    );

    // The sink-free target records nothing (no report file / empty).
    let clean_report = tmp.join("clean_report.txt");
    let clean = run_under_agent(&agent, &classes, "t.Clean", &clean_report);
    assert!(
        clean.trim().is_empty(),
        "a sink-free target must not record any sink, got: {clean:?}"
    );

    // The Rust oracle turns the recorded sink into a GF-421 finding.
    let work = tmp.join("work");
    let hdir = work.join("harnesses").join("H-J0001");
    std::fs::create_dir_all(&hdir).unwrap();
    std::fs::copy(&report, hdir.join("sink_report.txt")).unwrap();
    let written = run_sink_oracle(&work);
    assert_eq!(written, 1, "one GF-421 deserialization finding expected");
    let finding = std::fs::read_dir(work.join("findings"))
        .unwrap()
        .flatten()
        .find_map(|e| std::fs::read_to_string(e.path().join("finding.json")).ok())
        .expect("a finding.json");
    assert!(finding.contains("GF-421"), "finding:\n{finding}");
    assert!(finding.contains("CWE-502"), "finding:\n{finding}");

    let _ = std::fs::remove_dir_all(&tmp);
}
