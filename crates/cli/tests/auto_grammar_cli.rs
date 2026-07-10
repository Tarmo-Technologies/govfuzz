// SPDX-License-Identifier: Apache-2.0
//
// `govfuzz auto --grammar` end-to-end. The grammar's every derivation starts with a
// distinctive 11-byte token that random/RNG mutation is astronomically unlikely to
// produce; the fixture crashes ONLY on that token. So a crash whose input carries the
// token proves the grammar reached the fuzz loop (published via GOVFUZZ_GRAMMAR and
// read back on the auto path) and drove generation. A second case asserts a malformed
// grammar fails the run fast, not per-target. Skips cleanly without clang.

use std::path::{Path, PathBuf};
use std::process::Command;

fn have_clang() -> bool {
    Command::new("clang").arg("--version").output().is_ok()
        && Command::new("make").arg("--version").output().is_ok()
}

fn govfuzz_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("govfuzz")
}

const TOKEN: &str = "ZZGRAMMARZZ";

#[test]
fn auto_grammar_drives_generation_and_rejects_bad_grammar() {
    let bin = govfuzz_bin();
    if !bin.exists() {
        eprintln!("skip: govfuzz binary not built");
        return;
    }
    if !have_clang() {
        eprintln!("skip: clang/make unavailable");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("govfuzz-auto-grammar-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).unwrap();

    // The fixture crashes (null write) only when its input begins with TOKEN.
    std::fs::write(
        src.join("gt.c"),
        format!(
            "#include <stddef.h>\n\
             #include <string.h>\n\
             void process(const char *data, size_t len) {{\n\
                 if (len >= {n} && memcmp(data, \"{tok}\", {n}) == 0) {{\n\
                     *(volatile int *)0 = 1;\n\
                 }}\n\
             }}\n",
            n = TOKEN.len(),
            tok = TOKEN,
        ),
    )
    .unwrap();

    // Every derivation is TOKEN followed by an optional tail, so the grammar mutator
    // produces a crashing input essentially every time it is selected.
    let grammar = tmp.join("grammar.json");
    std::fs::write(
        &grammar,
        format!("{{\"START\": [\"{TOKEN}{{TAIL}}\"], \"TAIL\": [\"A\", \"B\", \"\"]}}"),
    )
    .unwrap();

    let work = tmp.join("work");
    let output = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--grammar",
            grammar.to_str().unwrap(),
            "--per-target-time",
            "8",
            "--max-targets",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto --grammar");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // A finding whose reproducer starts with TOKEN proves the grammar drove it.
    let mut grammar_drove_a_crash = false;
    if let Ok(entries) = std::fs::read_dir(work.join("findings")) {
        for entry in entries.flatten() {
            if let Ok(tc) = std::fs::read(entry.path().join("testcase.bin")) {
                if tc.starts_with(TOKEN.as_bytes()) {
                    grammar_drove_a_crash = true;
                }
            }
        }
    }
    assert!(
        grammar_drove_a_crash,
        "expected a crash whose input starts with the grammar-only token {TOKEN:?}; \
         grammar did not drive generation on the auto path.\n{combined}"
    );

    // A malformed grammar must fail the run fast (before per-target work), not silently.
    let bad = tmp.join("bad.json");
    std::fs::write(&bad, br#"{"START": ["{UNDEFINED}"]}"#).unwrap();
    let bad_out = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--grammar",
            bad.to_str().unwrap(),
            "--per-target-time",
            "2",
            "--work-dir",
            tmp.join("work_bad").to_str().unwrap(),
        ])
        .output()
        .expect("run govfuzz auto with bad grammar");
    assert!(
        !bad_out.status.success(),
        "a malformed grammar should fail the run"
    );
    assert!(
        String::from_utf8_lossy(&bad_out.stderr)
            .to_lowercase()
            .contains("grammar"),
        "the error should name the grammar problem:\n{}",
        String::from_utf8_lossy(&bad_out.stderr)
    );

    let _ = std::fs::remove_dir_all(Path::new(&tmp));
}
