// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use ada_parser::ast::AdaStandard;
use compiler_adapter::CompilerAdapter;
use project_synth::{ProjectSpec, SourceRoot, Switches};
use stub_gen::{run_build_loop, BuildLoopOutcome};

#[test]
fn missing_dependency_fixture_is_present() {
    let root = fixture_root();

    assert!(root.join("src.adb").is_file());
    assert!(root.join("manifest.toml").is_file());
    assert!(root.join("README.md").is_file());
}

#[test]
fn missing_dependency_fixture_passes_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = tempfile::TempDir::new().expect("temp dir is created");
    let work_dir = temp.path().join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let stubs_dir = work_dir.join("generated_stubs");
    fs::create_dir_all(&source_dir).expect("source dir is created");
    fs::create_dir_all(&stubs_dir).expect("stubs dir is created");
    fs::copy(fixture_root().join("src.adb"), source_dir.join("src.adb"))
        .expect("fixture source is copied");

    let spec = ProjectSpec {
        project_name: "Govfuzz_Build".to_owned(),
        extends_project: None,
        source_roots: vec![
            SourceRoot {
                path: source_dir,
                language: "Ada".to_owned(),
            },
            SourceRoot {
                path: stubs_dir.clone(),
                language: "Ada".to_owned(),
            },
        ],
        object_dir: work_dir.join("build/obj"),
        exec_dir: None,
        main_adb: Some("src.adb".to_owned()),
        ada_standard: AdaStandard::Ada95,
        target: None,
        runtime: None,
        toolchain: None,
        switches: Switches::default(),
        with_clauses: Vec::new(),
        executable_name: None,
        compile_c: false,
        excluded_source_files: Vec::new(),
    };
    let adapter = CompilerAdapter::discover().expect("compiler is discoverable");

    let result = run_build_loop(&work_dir, &spec, &adapter).expect("build loop runs");

    assert_eq!(result.outcome, BuildLoopOutcome::CleanBuild);
    assert!(stubs_dir.join("external_lib.ads").is_file());
}

fn fixture_root() -> PathBuf {
    repo_root().join("examples/missing_dependency")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("stub_gen crate is under crates/stub_gen")
        .to_path_buf()
}
