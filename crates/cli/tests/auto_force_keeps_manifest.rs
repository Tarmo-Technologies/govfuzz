// SPDX-License-Identifier: Apache-2.0
//
// `--force` must not empty the missing-dependency manifest.
//
// Forcing degrades a residual `failed_build` to a report-only static scan, which
// is the right floor — but a report-only outcome carries no `last_errors` for the
// manifest to mine, and the degradation used to replace the diagnostic with a bare
// COUNT of residual errors. The dependency evidence vanished with it, so the run
// that most needs the manifest produced none:
//
//   unforced:  "4 external dependencies needed: 4 still blocking"  (naming `event`)
//   forced:    "No external dependencies were missing — the tree built against
//               its own sources."
//
// Measured on tmux, whose every target embeds libevent's `struct event` by value.
// The fixture reproduces that shape: a public header declaring a struct that
// embeds an undefined external type, so no placeholder can complete it.

use std::path::Path;
use std::process::Command;

fn toolchain_available() -> bool {
    which::which("clang").is_ok() && which::which("make").is_ok()
}

fn write_fixture(root: &Path) {
    // `struct ext_handle` is never defined here — it belongs to an external
    // library that is not installed. Embedding it BY VALUE means an opaque
    // `void *` placeholder cannot satisfy it, so the build fails however hard
    // GovFuzz forces, and the honest answer is "you need that library".
    std::fs::write(
        root.join("session.h"),
        "#ifndef SESSION_H\n#define SESSION_H\n\
         #include <stddef.h>\n\
         struct ext_handle;\n\
         struct session {\n\
         \x20   struct ext_handle timer;\n\
         \x20   int id;\n\
         };\n\
         int session_parse(const unsigned char *data, size_t len);\n\
         #endif\n",
    )
    .unwrap();
    std::fs::write(
        root.join("session.c"),
        "#include \"session.h\"\n\
         int session_parse(const unsigned char *data, size_t len)\n\
         {\n\
         \x20   struct session s;\n\
         \x20   s.id = 0;\n\
         \x20   if (len > 0 && data[0] == 'S')\n\
         \x20       return (int)len;\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
}

fn manifest_for(args: &[&str], tag: &str) -> (usize, String) {
    let tmp = std::env::temp_dir().join(format!("gf-force-manifest-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    write_fixture(&tmp);
    let work = tmp.join("gw");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_govfuzz"));
    cmd.arg("auto")
        .arg(&tmp)
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "1", "--jobs", "1"])
        .args(args);
    let _ = cmd.output().expect("run govfuzz auto");

    let json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/missing-deps.json")).expect("missing-deps.json"),
    )
    .expect("parse missing-deps.json");
    let entries = json["entries"].as_array().cloned().unwrap_or_default();
    let text = std::fs::read_to_string(work.join("auto/missing-deps.txt")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&tmp);
    (entries.len(), text)
}

#[test]
fn forcing_does_not_empty_the_missing_dependency_manifest() {
    if !toolchain_available() {
        eprintln!("skipping: clang/make not on PATH");
        return;
    }

    let (unforced_entries, unforced_text) = manifest_for(&[], "plain");
    assert!(
        unforced_entries > 0,
        "the fixture must report a missing dependency unforced:\n{unforced_text}"
    );

    let (forced_entries, forced_text) = manifest_for(&["--force"], "forced");
    assert!(
        forced_entries > 0,
        "--force must not empty the manifest (was {unforced_entries} unforced):\n{forced_text}"
    );
    assert!(
        !forced_text.contains("No external dependencies were missing"),
        "a forced run that could not build must never claim nothing was missing:\n{forced_text}"
    );
    // The evidence has to name what is unresolved, not just count errors — that
    // name is the only actionable thing in the entry.
    assert!(
        forced_text.contains("ext_handle"),
        "the forced manifest must still name the unresolved type:\n{forced_text}"
    );
}
