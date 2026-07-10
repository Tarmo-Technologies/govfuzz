// SPDX-License-Identifier: Apache-2.0
//! Regression guard: real-world macro-heavy C (the bundled miniz
//! amalgamation) parses with dozens of scattered tree-sitter ERROR
//! nodes, and recovery often wraps large *valid* regions inside an
//! ERROR subtree. Discovery must keep indexing functions inside those
//! regions — an over-eager "reject anything under an ERROR node"
//! filter once zeroed out the whole file (191 → 0 targets).

use std::path::PathBuf;

fn miniz_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build_recovery/fixtures/miniz/miniz.c")
}

#[test]
fn macro_heavy_real_world_c_keeps_its_functions() {
    let src = std::fs::read_to_string(miniz_path()).expect("bundled miniz fixture");
    let errors = c_parser::count_parse_errors(&src);
    assert!(
        errors > 0,
        "fixture is supposed to confuse tree-sitter; if this is now 0 the guard is stale"
    );
    let fns = c_parser::parse_c_functions(&src).expect("parses");
    assert!(
        fns.len() > 150,
        "expected the full miniz API surface despite {errors} parse errors, got {}",
        fns.len()
    );
    assert!(
        fns.iter().all(|f| f.name != "if" && f.name != "else"),
        "keyword candidates must stay rejected"
    );
    assert!(
        fns.iter().any(|f| f.name == "mz_adler32"),
        "known-good public function missing"
    );
}

#[test]
fn macro_heavy_real_world_c_extracts_type_definitions() {
    // The API typedefs/structs live in miniz.h (the .c includes it);
    // header indexing in the auto lane stitches the two together, so
    // the parser-level guard parses both and merges.
    let header = miniz_path().with_file_name("miniz.h");
    let mut src = std::fs::read_to_string(header).expect("bundled miniz header");
    src.push_str(&std::fs::read_to_string(miniz_path()).expect("bundled miniz fixture"));
    let defs = c_parser::parse_c_type_defs(&src).expect("parses");
    assert!(
        defs.typedefs.len() > 20,
        "miniz is typedef-heavy, got {}",
        defs.typedefs.len()
    );
    let zip = defs
        .structs
        .iter()
        .find(|s| s.name == "mz_zip_archive_tag" || s.name == "mz_zip_archive")
        .expect("mz_zip_archive struct definition");
    assert!(
        zip.complete && zip.fields.len() >= 10,
        "mz_zip_archive has a rich field list, got {} fields",
        zip.fields.len()
    );
    assert!(
        defs.typedefs.iter().any(|t| t.name == "mz_ulong"),
        "scalar typedef mz_ulong recorded"
    );
    assert!(
        defs.structs
            .iter()
            .any(|s| s.name.contains("tinfl_decompressor") && s.complete),
        "tinfl decompressor struct definition found"
    );
}
