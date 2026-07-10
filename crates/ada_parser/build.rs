// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

fn main() {
    let vendor_dir = Path::new("../../vendor/tree-sitter-ada");
    let source_dir = vendor_dir.join("src");
    let parser = source_dir.join("parser.c");
    let scanner = source_dir.join("scanner.c");
    let parser_header = source_dir.join("tree_sitter").join("parser.h");

    println!("cargo:rerun-if-changed={}", parser.display());
    println!("cargo:rerun-if-changed={}", parser_header.display());
    if scanner.exists() {
        println!("cargo:rerun-if-changed={}", scanner.display());
    }

    let mut build = cc::Build::new();
    build.std("c11").include(&source_dir).file(&parser);

    if scanner.exists() {
        build.file(&scanner);
    }

    build.compile("tree_sitter_ada");
}
