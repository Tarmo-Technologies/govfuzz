// SPDX-License-Identifier: Apache-2.0
//! End-to-end regression for a `restrict`-qualifier MACRO in a C parameter
//! signature (the xxHash `XXH_RESTRICT` pattern). The C parser cannot expand a
//! project macro, so a bare `MYLIB_RESTRICT` token lands in the parameter
//! qualifier position. Before the fix the parser took the macro as the parameter
//! NAME, so the harness emitted the macro name as the decode variable — three
//! same-named variables of differing types (`void *` vs `const void *`) collide
//! (`redefinition of 'MYLIB_RESTRICT'`), and once the macro expands to `restrict`
//! the declaration is `expected identifier`. Either way: `failed_build`.
//!
//! The fix strips the qualifier macro and recovers the real names, so the harness
//! must reach a BUILT/built+fuzzed outcome.

use std::path::PathBuf;
use std::time::Duration;

mod support;

use cli::auto::attempt::{attempt, AttemptOptions, FuzzEngine, Outcome};
use cli::auto::candidate::{Candidate, Lang};
use cli::auto::decl_index::DeclarationIndex;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/c_restrict_macro")
}

fn cpp_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cpp_restrict_macro")
}

fn options(src_root: &std::path::Path) -> AttemptOptions {
    AttemptOptions {
        project: None,
        decoder_limits: Default::default(),
        force: false,
        engines: vec![FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: Duration::from_secs(2),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src_root.to_path_buf()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    }
}

/// Line (1-based) of the `unsigned long mix_bytes(` definition.
fn target_line(source: &str, name: &str) -> u32 {
    source
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains(&format!("{name}(")) && l.contains("unsigned long"))
        .map(|(i, _)| i as u32 + 1)
        .unwrap_or_else(|| panic!("target {name} not found in fixture"))
}

#[test]
fn restrict_qualifier_macro_param_builds() {
    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("c-restrict-macro") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let dir = fixture_dir();
    let source_path = dir.join("restrict_macro.c");
    let source = std::fs::read_to_string(&source_path).unwrap();
    let line = target_line(&source, "mix_bytes");

    let work = std::env::temp_dir().join(format!(
        "govfuzz-c-restrict-macro-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();

    let candidate = Candidate {
        harness_id: "H-RESTRICT-mix_bytes".to_owned(),
        lang: Lang::C,
        source_path,
        line,
        name: "mix_bytes".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&dir).unwrap();
    let result = attempt(&candidate, &work, &idx, options(&dir)).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!(
            "a restrict-qualifier macro (MYLIB_RESTRICT) in the parameter list must \
             be stripped so the harness builds, got {other:?}"
        ),
    }
}

#[test]
fn restrict_qualifier_macro_param_builds_cpp() {
    // xxHash's `xxhash.h` is classified and compiled as C++ in real campaigns, so
    // the same qualifier-macro gap must be closed in the C++ parser/codegen — the
    // observed failure was `main.cpp: redefinition of 'XXH_RESTRICT'`.
    if which::which("clang++").is_err() && which::which("clang").is_err() {
        eprintln!("skipping: no clang on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available_with("clang++", "cpp-restrict-macro") {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let dir = cpp_fixture_dir();
    let source_path = dir.join("restrict_macro.cpp");
    let source = std::fs::read_to_string(&source_path).unwrap();
    let line = target_line(&source, "cpp_mix_bytes");

    let work = std::env::temp_dir().join(format!(
        "govfuzz-cpp-restrict-macro-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();

    let candidate = Candidate {
        harness_id: "H-RESTRICT-cpp_mix_bytes".to_owned(),
        lang: Lang::Cpp,
        source_path,
        line,
        name: "cpp_mix_bytes".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&dir).unwrap();
    let result = attempt(&candidate, &work, &idx, options(&dir)).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!(
            "a restrict-qualifier macro (MYLIB_RESTRICT) in a C++ parameter list must \
             be stripped so the harness builds, got {other:?}"
        ),
    }
}
