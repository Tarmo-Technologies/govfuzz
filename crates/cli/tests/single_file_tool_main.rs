// SPDX-License-Identifier: Apache-2.0

//! A non-static target whose defining `.c` ALSO contains `int main` (a
//! single-file legacy tool or benchmark, like http-parser's bench.c) must not be
//! LINKED beside the harness driver — two `main` symbols collide at link time.
//! `generate-harness` must route it through the whole-TU `#include` path, which
//! renames the source's `main`, so the harness builds. This is a codegen
//! assertion (no toolchain needed): we inspect the emitted `main.c`/`Makefile`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn tmpdir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-singlefile-{tag}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn non_static_target_in_main_defining_tu_is_included_not_linked() {
    let dir = tmpdir("maincollide");
    let src = dir.join("tool.c");
    // A non-static, fuzzable helper sharing a TU with `int main`.
    fs::write(
        &src,
        "#include <stddef.h>\n\
         int score(const char *p, size_t n) {\n\
         \tint s = 0;\n\
         \tfor (size_t i = 0; i < n; i++) s += p[i];\n\
         \treturn s;\n\
         }\n\
         int main(int argc, char **argv) {\n\
         \t(void)argc; (void)argv;\n\
         \treturn score(\"x\", 1);\n\
         }\n",
    )
    .unwrap();

    let out = dir.join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .args([
            "generate-harness",
            "--target",
            "score",
            "--output",
            out.to_str().unwrap(),
            "--id",
            "H-SINGLE",
            src.to_str().unwrap(),
        ])
        .status()
        .expect("run generate-harness");
    assert!(status.success(), "generate-harness should succeed");

    let hdir = out.join("H-SINGLE");
    let main_c = fs::read_to_string(hdir.join("main.c")).expect("main.c emitted");
    let makefile = fs::read_to_string(hdir.join("Makefile")).expect("Makefile emitted");

    // The TU is #included with its `main` renamed (reuses the whole-TU wrapper).
    assert!(
        main_c.contains("#define main govfuzz_included_main_")
            && main_c.contains("#include \"tool.c\"")
            && main_c.contains("#undef main"),
        "main-defining TU must be included with its main renamed:\n{main_c}"
    );
    // It must NOT also be passed to the linker as a raw source — that is the
    // collision we are avoiding.
    let recipe_links_tool = makefile
        .lines()
        .any(|l| l.contains("$(CC)") && l.contains("tool.c"));
    assert!(
        !recipe_links_tool,
        "main-defining TU must not be linked raw in the recipe:\n{makefile}"
    );
}

#[test]
fn library_tu_without_main_is_linked_normally() {
    // Control: a TU with NO `main` is linked as before (regression guard so the
    // new routing only triggers on a real `main` collision).
    let dir = tmpdir("nomain");
    let src = dir.join("lib.c");
    fs::write(
        &src,
        "#include <stddef.h>\n\
         int score(const char *p, size_t n) {\n\
         \tint s = 0;\n\
         \tfor (size_t i = 0; i < n; i++) s += p[i];\n\
         \treturn s;\n\
         }\n",
    )
    .unwrap();

    let out = dir.join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .args([
            "generate-harness",
            "--target",
            "score",
            "--output",
            out.to_str().unwrap(),
            "--id",
            "H-LIB",
            src.to_str().unwrap(),
        ])
        .status()
        .expect("run generate-harness");
    assert!(status.success());

    let hdir = out.join("H-LIB");
    let main_c = fs::read_to_string(hdir.join("main.c")).unwrap();
    let makefile = fs::read_to_string(hdir.join("Makefile")).unwrap();
    assert!(
        !main_c.contains("#include \"lib.c\""),
        "a library TU should be linked, not #included:\n{main_c}"
    );
    assert!(
        makefile
            .lines()
            .any(|l| l.contains("$(CC)") && l.contains("lib.c")),
        "a library TU must be linked in the recipe:\n{makefile}"
    );
}
