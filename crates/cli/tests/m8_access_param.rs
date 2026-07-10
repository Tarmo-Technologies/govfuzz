// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::TypeKind;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn access_param_fixture_is_present_and_parses() {
    let spec_path = fixture_root().join("access_param.ads");
    let body_path = fixture_root().join("access_param.adb");
    let spec = fs::read_to_string(&spec_path).expect("fixture spec is readable");
    let body = fs::read_to_string(&body_path).expect("fixture body is readable");
    let spec_ast = ada_parser::reconcile::build_structural_ast(&spec, None, &spec_path)
        .expect("fixture spec parses");
    let body_ast = ada_parser::reconcile::build_structural_ast(&body, None, &body_path)
        .expect("fixture body parses");

    assert!(fixture_root().join("manifest.toml").is_file());
    assert!(fixture_root().join("README.md").is_file());
    assert!(!fixture_root().join("src.adb").exists());
    assert!(body_ast
        .subprograms
        .iter()
        .any(|subprogram| subprogram.name.eq_ignore_ascii_case("Process")));
    assert!(spec_ast.types.iter().any(|ty| {
        ty.name_path
            .last()
            .is_some_and(|name| name.eq_ignore_ascii_case("Node_Ptr"))
            && matches!(&ty.kind, TypeKind::Access { .. })
    }));
}

#[test]
fn access_param_harness_generates_without_gnat() {
    let temp = temp_dir("m8-access-param-generate");
    let (work_dir, main_adb) = generate_access_param_harness(&temp);
    let main_text = fs::read_to_string(&main_adb).expect("generated main is readable");

    assert!(work_dir.join("src_instrumented/access_param.ads").is_file());
    assert!(work_dir.join("src_instrumented/access_param.adb").is_file());
    assert!(!work_dir.join("src_instrumented/src.adb").exists());
    assert!(main_text.contains("function Decode_N return Access_Param.Node_Ptr is"));
    assert!(main_text.contains("AdaFuzz.Decode.Slot_Index (Cur, 4)"));
    ada_parser::reconcile::build_structural_ast(&main_text, None, &main_adb)
        .expect("generated access harness parses");
}

#[test]
fn access_param_harness_generates_and_compiles_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m8-access-param-build");
    let (work_dir, _main_adb) = generate_access_param_harness(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-M8",
        ]),
        0
    );
}

fn generate_access_param_harness(temp: &Path) -> (PathBuf, PathBuf) {
    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    let source = fixture_root().join("access_param.adb");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "instrument",
            source.to_str().expect("fixture source path is utf-8"),
            "--output",
            instrumented_dir
                .to_str()
                .expect("instrumented path is utf-8"),
        ]),
        0
    );
    fs::copy(
        fixture_root().join("access_param.ads"),
        instrumented_dir.join("access_param.ads"),
    )
    .expect("fixture spec is copied");

    let instrumented_source = instrumented_dir.join("access_param.adb");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "generate-harness",
            instrumented_source
                .to_str()
                .expect("instrumented source path is utf-8"),
            "--target",
            "Process",
            "--output",
            harness_root.to_str().expect("harness root path is utf-8"),
            "--id",
            "H-M8",
        ]),
        0
    );

    (work_dir, harness_root.join("H-M8/main.adb"))
}

fn fixture_root() -> PathBuf {
    repo_root().join("examples/access_param")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("cli crate is under crates/cli")
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}
