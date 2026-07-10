// SPDX-License-Identifier: Apache-2.0

//! Campaign gap (bson_t / libdeflate_decompressor / friends): a C target whose
//! first parameter is a pointer to an INCOMPLETE opaque handle — forward-declared
//! in the public header, its full struct body living only in a `.c` the harness
//! does NOT `#include` — was skipped with "no returning-constructor lifecycle;
//! cannot stack-allocate it — skipping", EVEN when the tree ships a
//! returning-constructor / destructor pair (`widget *widget_new(void)` /
//! `void widget_destroy(widget *)`).
//!
//! Root cause: the prototype-return-type normalizer drops the `struct` keyword
//! from `struct widget *widget_new(void)` (yielding `widget *`), while the
//! destructor parameter and the target parameter keep it (`struct widget *`), so
//! the tree-wide lifecycle pairing keyed the constructor and destructor under two
//! distinct table entries and never paired a returning constructor for the
//! handle. The fix canonicalizes the elaborated-tag spelling
//! (`struct X` / `union X` / `enum X` <-> `X`) on both the lifecycle-table key and
//! the decoder lookup, so the pair merges and the harness builds the handle via
//! `H = widget_new(); target(H, ..); widget_destroy(H);`.
//!
//! This fixture is the minimal reproduction: a public header that only
//! FORWARD-declares the handle (`typedef struct widget widget;`) plus the API, and
//! a separate `src/widget.c` (NOT included by the header) with the full struct body
//! and the `widget_new` / `widget_destroy` / `widget_process` definitions. The
//! target `int widget_process(widget *, const uint8_t *, size_t)` must now
//! build+fuzz through the returning constructor instead of being skipped.
//!
//! Shells the built `govfuzz` binary; gated on clang so a toolchain-less lane
//! skips cleanly.

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    if which::which("clang").is_err() {
        eprintln!("skipping auto_c_opaque_returning_ctor: clang not on PATH");
        return false;
    }
    true
}

fn write_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("include")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();

    // Public header: the handle is OPAQUE here — only forward-declared. The full
    // `struct widget` body is NOT visible to anyone who includes only this header
    // (so the handle can never be stack-allocated / zero-constructed). The API is
    // a returning constructor + destructor + a fuzzable processor.
    std::fs::write(
        root.join("include/widget.h"),
        "#ifndef WIDGET_H\n\
         #define WIDGET_H\n\
         #include <stdint.h>\n\
         #include <stddef.h>\n\
         typedef struct widget widget;\n\
         widget *widget_new(void);\n\
         void widget_destroy(widget *w);\n\
         int widget_process(widget *w, const uint8_t *data, size_t n);\n\
         #endif\n",
    )
    .unwrap();

    // Implementation TU: holds the full struct body AND the lifecycle pair. The
    // public header does NOT include this file, so a harness that includes only
    // widget.h sees `struct widget` as incomplete and must build it via the
    // returning constructor. `widget_process` does real, fuzz-driven work on the
    // bytes so the fuzzer has something to explore (no UB — the test asserts a
    // clean build+fuzz, not a crash).
    std::fs::write(
        root.join("src/widget.c"),
        "#include \"widget.h\"\n\
         #include <stdlib.h>\n\
         struct widget {\n\
         \x20   uint32_t state;\n\
         \x20   uint32_t count;\n\
         };\n\
         widget *widget_new(void) {\n\
         \x20   widget *w = (widget *)calloc(1, sizeof(*w));\n\
         \x20   if (w) w->state = 0x9e3779b9u;\n\
         \x20   return w;\n\
         }\n\
         void widget_destroy(widget *w) {\n\
         \x20   free(w);\n\
         }\n\
         int widget_process(widget *w, const uint8_t *data, size_t n) {\n\
         \x20   if (!w || !data) return -1;\n\
         \x20   for (size_t i = 0; i < n; i++) {\n\
         \x20       w->state = (w->state ^ data[i]) * 16777619u;\n\
         \x20       if ((w->state & 0xffu) == data[i]) w->count++;\n\
         \x20   }\n\
         \x20   return (int)(w->state ^ w->count);\n\
         }\n",
    )
    .unwrap();

    // A compile database so the build picks up the exact include path and links
    // the implementation TU deterministically.
    let db = format!(
        r#"[
  {{"directory":"{root}","file":"src/widget.c","arguments":["clang","-Iinclude","-c","src/widget.c"]}}
]"#,
        root = root.display()
    );
    std::fs::write(root.join("compile_commands.json"), db).unwrap();
}

#[test]
fn incomplete_opaque_handle_builds_via_returning_constructor() {
    if !clang_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("govfuzz-opaque-ctor-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_fixture(root);
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_govfuzz"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--no-discovery-cache")
        .output()
        .expect("spawn govfuzz auto");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
            panic!(
                "read run.json: {e}; govfuzz auto exit={:?}\nstderr:\n{stderr}",
                output.status.code(),
            )
        }),
    )
    .expect("parse run.json");

    // The opaque-handle target must build+fuzz via the discovered returning
    // constructor instead of being skipped for lacking a lifecycle.
    let built_and_fuzzed = run["summary"]["built_and_fuzzed"].as_u64().unwrap_or(0);
    assert!(
        built_and_fuzzed >= 1,
        "widget_process (incomplete opaque handle) must build+fuzz via the \
         returning constructor widget_new/widget_destroy; summary={}\nstderr:\n{stderr}",
        run["summary"],
    );

    // And the generated harness must construct the handle through the returning
    // constructor and free it through the destructor — not stack-allocate the
    // incomplete struct.
    let main_c = find_harness_main(&work.join("harnesses"), "widget_process")
        .expect("a generated harness main.c for widget_process");
    let src = std::fs::read_to_string(&main_c).unwrap();
    assert!(
        src.contains("widget_new()"),
        "harness must build the handle via the returning constructor;\n{src}"
    );
    assert!(
        src.contains("widget_destroy("),
        "harness must release the handle via the destructor;\n{src}"
    );
    assert!(
        !src.contains("struct widget _gf_lc"),
        "harness must NOT stack-allocate the incomplete struct;\n{src}"
    );
}

/// Locate the generated `main.c` whose target was `needle` by scanning the auto
/// output tree for a harness that calls the target.
fn find_harness_main(auto_dir: &Path, needle: &str) -> Option<std::path::PathBuf> {
    for entry in std::fs::read_dir(auto_dir).ok()? {
        let dir = entry.ok()?.path();
        let main_c = dir.join("main.c");
        if main_c.is_file() {
            if let Ok(src) = std::fs::read_to_string(&main_c) {
                if src.contains(&format!("{needle}(")) {
                    return Some(main_c);
                }
            }
        }
    }
    None
}
