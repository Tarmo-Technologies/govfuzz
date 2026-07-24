// SPDX-License-Identifier: Apache-2.0

//! #93: a recovered compile database carries the project's warning policy
//! (`-Werror -Wmissing-prototypes`). govfuzz applies it to the generated harness
//! translation unit too, so the generated `govfuzz_run_one` /
//! `LLVMFuzzerTestOneInput` must not trip `-Wmissing-prototypes` — govfuzz
//! forward-declares them. The project's own sources still receive the full policy.

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
        .arg("--max-targets")
        .arg("1")
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
    let dir = std::env::temp_dir().join(format!("govfuzz-werror-{tag}-{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fuzzed(run: &serde_json::Value) -> bool {
    run["targets"]
        .as_array()
        .map(|targets| {
            targets
                .iter()
                .any(|t| t["outcome"]["outcome"] == "built_and_fuzzed")
        })
        .unwrap_or(false)
}

#[test]
fn c_project_with_werror_missing_prototypes_builds_the_generated_harness() {
    if which::which("clang").is_err() {
        eprintln!("SKIP: clang not on PATH");
        return;
    }
    let root = tmpdir("c");
    std::fs::write(
        root.join("lib.h"),
        "#include <stddef.h>\n#include <stdint.h>\nint lib_parse(const unsigned char *d, unsigned long n);\n",
    )
    .unwrap();
    std::fs::write(
        root.join("lib.c"),
        "#include \"lib.h\"\nint lib_parse(const unsigned char *d, unsigned long n){ return n>=2 && d[0]=='O' && d[1]=='K'; }\n",
    )
    .unwrap();
    let cdb = format!(
        "[{{\"directory\":\"{d}\",\"file\":\"{d}/lib.c\",\"command\":\"clang -Werror -Wmissing-prototypes -c lib.c -o lib.o\"}}]",
        d = root.display()
    );
    std::fs::write(root.join("compile_commands.json"), cdb).unwrap();
    let work = tmpdir("c-work");
    let run = run_auto(&root, &work);
    assert!(
        fuzzed(&run),
        "the generated harness must build+fuzz under -Werror -Wmissing-prototypes: {}",
        run["targets"]
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn cpp_project_with_werror_missing_declarations_builds_the_generated_harness() {
    if which::which("clang++").is_err() {
        eprintln!("SKIP: clang++ not on PATH");
        return;
    }
    let root = tmpdir("cpp");
    std::fs::write(
        root.join("lib.hpp"),
        "#include <cstddef>\n#include <cstdint>\nint lib_parse(const uint8_t *d, size_t n);\n",
    )
    .unwrap();
    std::fs::write(
        root.join("lib.cpp"),
        "#include \"lib.hpp\"\nint lib_parse(const uint8_t *d, size_t n){ return n>=2 && d[0]=='O' && d[1]=='K'; }\n",
    )
    .unwrap();
    let cdb = format!(
        "[{{\"directory\":\"{d}\",\"file\":\"{d}/lib.cpp\",\"command\":\"clang++ -Werror -Wmissing-declarations -c lib.cpp -o lib.o\"}}]",
        d = root.display()
    );
    std::fs::write(root.join("compile_commands.json"), cdb).unwrap();
    let work = tmpdir("cpp-work");
    let run = run_auto(&root, &work);
    assert!(
        fuzzed(&run),
        "the generated C++ harness must build+fuzz under -Werror -Wmissing-declarations: {}",
        run["targets"]
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}
