// SPDX-License-Identifier: Apache-2.0

//! #98: C++ access is keyed by exact signature. When a method name has a public
//! overload and a private overload, only the public one is targeted — the private
//! overload is never discovered (targeting it is a guaranteed "is a private
//! member" build failure).

use std::path::Path;
use std::process::Command;

fn run_auto(root: &Path, work: &Path) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass")
        .output()
        .expect("spawn govfuzz auto");
    let bytes = std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
        panic!(
            "read run.json: {e}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    serde_json::from_slice(&bytes).expect("parse run.json")
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-overload-{tag}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn private_overload_is_not_targeted_when_a_public_overload_exists() {
    if which::which("clang++").is_err() {
        eprintln!("SKIP: clang++ not on PATH");
        return;
    }
    let root = tmpdir("src");
    std::fs::write(
        root.join("doc.hpp"),
        "#include <cstddef>\nclass XmlDoc {\npublic:\n  XmlDoc() {}\n  int Parse(const char* data, size_t len);\nprivate:\n  int Parse();\n  int n = 0;\n};\n",
    )
    .unwrap();
    std::fs::write(
        root.join("doc.cpp"),
        "#include \"doc.hpp\"\nint XmlDoc::Parse(const char* data, size_t len){ return len && data[0]=='<'; }\nint XmlDoc::Parse(){ return n; }\n",
    )
    .unwrap();
    let work = tmpdir("work");
    let run = run_auto(&root, &work);

    let names: Vec<String> = run["targets"]
        .as_array()
        .map(|targets| {
            targets
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    // The public buffer overload is targeted (and fuzzes); the private zero-arg
    // overload is never discovered.
    assert!(
        names.iter().any(|n| n.contains("Parse(const char")),
        "the public overload must be targeted: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "XmlDoc::Parse()"),
        "the private zero-arg overload must NOT be targeted: {names:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}
