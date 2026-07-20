// SPDX-License-Identifier: Apache-2.0

//! End-to-end regression for legacy C projects that rely on tentative globals
//! from headers being merged with `-fcommon`, the compiler default before GCC 10
//! and Clang 11.

use std::path::{Path, PathBuf};
use std::process::Command;

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

fn has_built_target(work: &Path) -> bool {
    let Ok(bytes) = std::fs::read(work.join("auto/run.json")) else {
        return false;
    };
    let Ok(run): Result<serde_json::Value, _> = serde_json::from_slice(&bytes) else {
        return false;
    };
    run["targets"].as_array().is_some_and(|targets| {
        targets.iter().any(|target| {
            matches!(
                target["outcome"]["outcome"].as_str(),
                Some("built" | "built_and_fuzzed")
            )
        })
    })
}

#[test]
fn auto_retries_legacy_tentative_definitions_with_fcommon() {
    if Command::new("clang").arg("--version").output().is_err()
        || Command::new("make").arg("--version").output().is_err()
    {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let bin = govfuzz_bin();
    if !bin.is_file() {
        eprintln!("skip: govfuzz binary not built");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-c-common-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    let work = tmp.join("work");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("legacy.h"),
        "#ifndef LEGACY_H\n#define LEGACY_H\n\
         #include <stddef.h>\n\
         int legacy_counter;\n\
         int legacy_helper(int value);\n\
         int legacy_parse(const unsigned char *data, size_t size);\n\
         #endif\n",
    )
    .unwrap();
    std::fs::write(
        src.join("parse.c"),
        "#include \"legacy.h\"\n\
         int legacy_parse(const unsigned char *data, size_t size) {\n\
             return legacy_helper(size ? data[0] : 0);\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("helper.c"),
        "#include \"legacy.h\"\n\
         int legacy_helper(int value) {\n\
             legacy_counter += value;\n\
             return legacy_counter;\n\
         }\n",
    )
    .unwrap();

    let output = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--deps-only",
            "--max-targets",
            "1",
            "--max-repair-rounds",
            "6",
            "--languages",
            "c",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run govfuzz auto");

    assert!(
        has_built_target(&work),
        "legacy common-symbol target must build; stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        std::fs::read_to_string(work.join("c_compat.mk")).unwrap_or_default(),
        "C_COMPAT_FLAGS := -fcommon\n"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
