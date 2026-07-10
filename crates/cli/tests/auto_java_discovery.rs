// SPDX-License-Identifier: Apache-2.0
//
// M2.1a Java discovery lane: the `java_discovery` fixture is parsed, ranked, and
// listed by `govfuzz auto`, then pre-skipped cleanly at attempt time (the build +
// JVM coverage-agent + engine lane lands in M2.1b-d).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_discovery")
        .canonicalize()
        .expect("canonicalize java_discovery fixture")
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

#[test]
fn discovers_and_ranks_java_targets() {
    let candidates = discover(&fixture()).expect("discover java fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();

    assert!(
        candidates.iter().all(|c| c.lang == Lang::Java),
        "every candidate from the Java fixture is tagged Lang::Java: {names:?}"
    );

    // Public byte-channel / sink entries are discovered.
    for expected in ["parse", "readValue", "parseString", "decodeOrNull"] {
        assert!(
            names.contains(&expected),
            "expected public entry `{expected}` in {names:?}"
        );
    }

    // Package-private, private, and abstract (no-body interface) methods are not
    // externally callable -> dropped by the ranker.
    for dropped in ["decodeInternal", "reset", "decode"] {
        assert!(
            !names.contains(&dropped),
            "non-public/abstract method `{dropped}` must be skipped: {names:?}"
        );
    }

    // The harness id prefix marks the Java engine lane.
    let parse = candidates
        .iter()
        .find(|c| c.name == "parse")
        .expect("parse discovered");
    assert!(
        parse.harness_id.starts_with("H-J"),
        "Java harness id prefix is H-J: {}",
        parse.harness_id
    );
    assert_eq!(
        parse.input_reachability,
        Some(target_rank::InputReachability::AttackerReachable),
        "a `byte[]` parser is attacker-reachable"
    );
    assert!(parse.is_static, "`parse` is a static method");

    // The security sink (`readValue`) out-ranks the plain String parser.
    let read_value = candidates.iter().find(|c| c.name == "readValue").unwrap();
    let parse_string = candidates.iter().find(|c| c.name == "parseString").unwrap();
    assert!(
        read_value.score > parse_string.score,
        "deserialization sink `readValue` ({}) should out-rank `parseString` ({})",
        read_value.score,
        parse_string.score
    );
}

/// Whether a usable JDK is installed (the native Java lane needs javac/java);
/// without one the lane skips cleanly, so this test self-skips too.
fn has_jdk() -> bool {
    Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok()
}

#[test]
fn java_static_target_builds_and_fuzzes_natively() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built at {}", bin.display());
        return;
    }
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("govfuzz-java-disc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let output = Command::new(&bin)
        .args([
            "auto",
            fixture().to_str().unwrap(),
            "--per-target-time",
            "2",
            "--max-targets",
            "2",
            "--work-dir",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto on java fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The fixture's top static byte-channel targets (readValue / parse) now build
    // and fuzz natively through the JVM lane — no planted crash, so 0 findings, but
    // the lane reaches "built+fuzzed" rather than the old M2.1a pre-skip.
    assert!(
        combined.contains("built+fuzzed"),
        "a static Java byte-channel target should build + fuzz natively, got:\n{combined}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
