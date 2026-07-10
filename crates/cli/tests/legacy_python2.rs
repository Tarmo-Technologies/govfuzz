// SPDX-License-Identifier: Apache-2.0
//! M22 Phase 2: Python 2 source is discovered via the tolerant line-based
//! extractor (the bundled tree-sitter-python grammar is Python 3 only and fails
//! on `print` statements / `except E, e:`), tagged with the Python 2 dialect, so
//! legacy Python 2 targets are ranked and reported on instead of silently
//! dropped. With no `python2` interpreter present they take the report-only path
//! (discover + statically analyze, not fuzzed); where `python2` exists a later
//! increment fuzzes them.

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;
use std::fs;
use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("govfuzz-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn python2_file_is_discovered_with_python2_dialect() {
    let dir = tmp("py2-disc");
    // A genuine Python 2 module: `print` statement + `except E, e:` comma bind.
    fs::write(
        dir.join("legacy.py"),
        "def parse_record(data):\n\
         \x20   print 'parsing', data\n\
         \x20   try:\n\
         \x20       return int(data)\n\
         \x20   except ValueError, e:\n\
         \x20       return None\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover py2 tree");
    let py = candidates
        .iter()
        .find(|c| c.lang == Lang::Python && c.name == "parse_record")
        .expect("the Python 2 function must be discovered by the tolerant extractor");
    assert_eq!(
        py.dialect.map(|d| d.as_str()),
        Some("python2"),
        "discovered Python 2 target must carry the Python 2 dialect"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn modern_python3_file_keeps_python3_dialect_and_tree_sitter_path() {
    let dir = tmp("py3-disc");
    fs::write(
        dir.join("modern.py"),
        "def decode(data: bytes) -> dict:\n\
         \x20   print(data)\n\
         \x20   return {}\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover py3 tree");
    let py = candidates
        .iter()
        .find(|c| c.lang == Lang::Python && c.name == "decode")
        .expect("the Python 3 function must be discovered");
    assert_eq!(py.dialect.map(|d| d.as_str()), Some("python3"));

    let _ = fs::remove_dir_all(&dir);
}
