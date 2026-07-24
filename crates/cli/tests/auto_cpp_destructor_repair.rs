// SPDX-License-Identifier: Apache-2.0

//! #97: a C++ target whose class has a DECLARED but UNDEFINED destructor (no
//! in-tree definition) no longer leaves an otherwise viable harness in
//! FailedBuild — govfuzz emits one source-level destructor definition so the link
//! closes. `--no-stubs` preserves the original failure.

use std::path::Path;
use std::process::Command;

fn run_auto_outcome(root: &Path, work: &Path, extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("2")
        .arg("--single-pass")
        .args(extra)
        .output()
        .expect("spawn govfuzz auto");
    let run: serde_json::Value = std::fs::read(work.join("auto/run.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| {
            panic!(
                "no run.json\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    run["targets"]
        .as_array()
        .and_then(|t| t.first())
        .map(|t| t["outcome"]["outcome"].as_str().unwrap_or("?").to_owned())
        .unwrap_or_default()
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-dtor-{tag}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_fixture(root: &Path) {
    // A StrPair-style class: default-constructible, a fuzzable Set(const char*),
    // and a destructor DECLARED here but DEFINED nowhere in the tree.
    std::fs::write(
        root.join("strpair.hpp"),
        "#include <cstddef>\nstruct StrPair {\n  StrPair() : n(0) {}\n  ~StrPair();\n  int Set(const char* s);\n  int n;\n};\n",
    )
    .unwrap();
    std::fs::write(
        root.join("strpair.cpp"),
        "#include \"strpair.hpp\"\nint StrPair::Set(const char* s){ return s ? (int)s[0] + n : 0; }\n",
    )
    .unwrap();
}

#[test]
fn declared_but_undefined_destructor_no_longer_fails_the_build() {
    if which::which("clang++").is_err() {
        eprintln!("SKIP: clang++ not on PATH");
        return;
    }
    let root = tmpdir("ok");
    write_fixture(&root);
    let work = tmpdir("ok-work");
    let outcome = run_auto_outcome(&root, &work, &[]);
    assert_eq!(
        outcome, "built_and_fuzzed",
        "the destructor stub must let the harness build and fuzz (got {outcome})"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn no_stubs_preserves_the_destructor_link_failure() {
    if which::which("clang++").is_err() {
        eprintln!("SKIP: clang++ not on PATH");
        return;
    }
    let root = tmpdir("nostub");
    write_fixture(&root);
    let work = tmpdir("nostub-work");
    let outcome = run_auto_outcome(&root, &work, &["--no-stubs"]);
    assert_ne!(
        outcome, "built_and_fuzzed",
        "--no-stubs must not synthesize the destructor; the build stays failed"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}
