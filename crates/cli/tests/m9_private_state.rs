// SPDX-License-Identifier: Apache-2.0

use event_log::{group_into_testcases, EventReader};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn private_state_fixture_is_present_and_parses() {
    let spec_path = fixture_root().join("state.ads");
    let body_path = fixture_root().join("state.adb");
    let spec = fs::read_to_string(&spec_path).expect("fixture spec is readable");
    let body = fs::read_to_string(&body_path).expect("fixture body is readable");
    let spec_ast = ada_parser::reconcile::build_structural_ast(&spec, None, &spec_path)
        .expect("fixture spec parses");
    let body_ast = ada_parser::reconcile::build_structural_ast(&body, None, &body_path)
        .expect("fixture body parses");

    assert!(fixture_root().join("manifest.toml").is_file());
    assert!(fixture_root().join("README.md").is_file());
    assert!(spec_ast
        .packages
        .iter()
        .any(|package| package.name.eq_ignore_ascii_case("State")));
    assert!(body_ast
        .subprograms
        .iter()
        .any(|subprogram| subprogram.name.eq_ignore_ascii_case("Push")));
    assert!(body_ast
        .subprograms
        .iter()
        .any(|subprogram| subprogram.name.eq_ignore_ascii_case("Pop")));
    assert!(body_ast
        .subprograms
        .iter()
        .any(|subprogram| subprogram.name.eq_ignore_ascii_case("Top")));
}

#[test]
fn private_state_sequence_harness_generates_without_gnat() {
    let temp = temp_dir("m9-private-state-generate");
    let (work_dir, main_adb) = generate_private_state_sequence_harness(&temp);
    let main_text = fs::read_to_string(&main_adb).expect("generated main is readable");

    assert!(work_dir.join("src_instrumented/state.ads").is_file());
    assert!(work_dir.join("src_instrumented/state.adb").is_file());
    assert!(main_text.contains("Max_Steps : constant Natural := 32;"));
    assert!(main_text.contains("State.Push"));
    assert!(main_text.contains("State.Pop"));
    assert!(main_text.contains("State.Top"));
    ada_parser::reconcile::build_structural_ast(&main_text, None, &main_adb)
        .expect("generated sequence harness parses");
}

#[test]
fn private_state_sequence_harness_builds_and_reaches_swallowed_handler_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m9-private-state-build-run");
    let (work_dir, _main_adb) = generate_private_state_sequence_harness(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-M9",
        ]),
        0
    );

    let events_path = temp.join("events.bin");
    let exe = find_built_executable(&work_dir, "H-M9");
    let input = private_state_push_pop_pop_input();
    let mut child = Command::new(exe)
        .env("GOVFUZZ_EVENTS_PATH", &events_path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("sequence harness starts");
    {
        let mut stdin = child.stdin.take().expect("harness stdin is piped");
        stdin.write_all(&input).expect("input is written");
    }
    let status = child.wait().expect("sequence harness exits");
    assert!(status.success());

    let events = fs::File::open(&events_path).expect("events file exists");
    let testcases = group_into_testcases(EventReader::new(events)).expect("events parse");
    assert_eq!(testcases.len(), 1);
    assert!(testcases[0].handlers.iter().any(|handler| {
        handler.exception_name.contains("CONSTRAINT_ERROR")
            && handler.handler_file.contains("state.adb")
    }));
}

fn generate_private_state_sequence_harness(temp: &Path) -> (PathBuf, PathBuf) {
    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    let source = fixture_root().join("state.adb");

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
        fixture_root().join("state.ads"),
        instrumented_dir.join("state.ads"),
    )
    .expect("fixture spec is copied");

    let instrumented_source = instrumented_dir.join("state.adb");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "generate-harness",
            instrumented_source
                .to_str()
                .expect("instrumented source path is utf-8"),
            "--target",
            "State",
            "--kind",
            "sequence",
            "--output",
            harness_root.to_str().expect("harness root path is utf-8"),
            "--id",
            "H-M9",
        ]),
        0
    );

    (work_dir, harness_root.join("H-M9/main.adb"))
}

fn find_built_executable(work_dir: &Path, harness_id: &str) -> PathBuf {
    let build_dir = work_dir.join("build").join(harness_id);
    let candidates = [
        build_dir.join("main"),
        build_dir.join("obj").join("main"),
        build_dir.join("obj").join("main.exe"),
    ];

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("built executable not found under {}", build_dir.display()))
}

fn private_state_push_pop_pop_input() -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bounded_range(&mut bytes, 2);
    push_bounded_range(&mut bytes, 0);
    bytes.extend_from_slice(&7_i32.to_le_bytes());
    push_bounded_range(&mut bytes, 1);
    push_bounded_range(&mut bytes, 1);
    bytes
}

fn push_bounded_range(bytes: &mut Vec<u8>, raw: u32) {
    bytes.push(1);
    bytes.extend_from_slice(&raw.to_le_bytes());
}

fn fixture_root() -> PathBuf {
    repo_root().join("examples/private_state")
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
