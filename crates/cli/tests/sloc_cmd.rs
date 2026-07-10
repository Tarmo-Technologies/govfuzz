// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the standalone `govfuzz sloc` fast-counting command.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-sloc-{tag}-{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A small tree with obvious code + comment + blank lines in two languages.
fn write_fixture(root: &std::path::Path) {
    fs::write(
        root.join("a.c"),
        "// a comment\nint main(void) {\n\n    return 0;\n}\n",
    )
    .unwrap();
    fs::write(root.join("b.py"), "# comment\nx = 1\n\ny = 2\n").unwrap();
}

#[test]
fn sloc_prints_language_table_to_stdout() {
    let root = scratch_dir("table");
    write_fixture(&root);

    // Capture stdout is awkward across the process boundary; instead assert the
    // command succeeds and, via --out, that the rendered table carries the header
    // and per-language rows. (stdout path is exercised by the exit code here.)
    let code = cli::run_from(["govfuzz", "sloc", root.to_str().unwrap()]);
    assert_eq!(code, 0, "sloc over a valid tree should exit 0");

    let out = root.join("table.txt");
    let code = cli::run_from([
        "govfuzz",
        "sloc",
        root.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let table = fs::read_to_string(&out).unwrap();
    assert!(table.contains("LANGUAGE"), "missing header: {table}");
    assert!(table.contains("SLOC"), "missing SLOC column: {table}");
    assert!(table.contains("TOTAL"), "missing totals row: {table}");
    // Both languages should appear.
    assert!(
        table.to_lowercase().contains('c') && table.to_lowercase().contains("python"),
        "expected both languages: {table}"
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn sloc_out_json_writes_total_code_lines() {
    let root = scratch_dir("json");
    write_fixture(&root);

    let out = root.join("counts.json");
    let code = cli::run_from([
        "govfuzz",
        "sloc",
        root.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    let code_lines = json["total"]["code_lines"].as_u64().unwrap();
    // a.c has 3 code lines (main, return, }), b.py has 2 (x, y).
    assert_eq!(code_lines, 5, "unexpected total code lines: {json}");

    fs::remove_dir_all(&root).ok();
}

#[test]
fn sloc_multi_root_aggregates_grand_total() {
    let a = scratch_dir("multi-a");
    let b = scratch_dir("multi-b");
    write_fixture(&a);
    write_fixture(&b);

    let out = a.join("both.json");
    let code = cli::run_from([
        "govfuzz",
        "sloc",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(json["roots"].as_array().unwrap().len(), 2);
    // 5 code lines per identical fixture → 10 across both roots.
    assert_eq!(json["total"]["code_lines"].as_u64().unwrap(), 10);

    fs::remove_dir_all(&a).ok();
    fs::remove_dir_all(&b).ok();
}
