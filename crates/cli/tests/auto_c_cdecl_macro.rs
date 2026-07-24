// SPDX-License-Identifier: Apache-2.0
//! End-to-end regression for a CALLING-CONVENTION macro in a function-pointer
//! declarator (the cJSON `internal_hooks` pattern). A funcptr struct field
//! `void (CDECL_MACRO *deallocate)(void *)` carries a convention macro between the
//! `(` and the `*name`. Before the fix the parser took the macro as the field
//! NAME, so the harness emitted `.CDECL_MACRO = <trampoline>` — and because the
//! macro is empty on Linux, `. = <trampoline>` -> `expected identifier` ->
//! `failed_build`. The fix reads the name from the `*name` pointer declarator, so
//! the field resolves and the harness builds.

use std::path::PathBuf;
use std::time::Duration;

mod support;

use cli::auto::attempt::{attempt, AttemptOptions, FuzzEngine, Outcome};
use cli::auto::candidate::{Candidate, Lang};
use cli::auto::decl_index::DeclarationIndex;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/c_cdecl_macro")
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

fn target_line(source: &str, name: &str) -> u32 {
    source
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains(&format!("{name}(")) && l.contains("unsigned long"))
        .map(|(i, _)| i as u32 + 1)
        .unwrap_or_else(|| panic!("target {name} not found in fixture"))
}

#[test]
fn calling_convention_macro_funcptr_field_builds() {
    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("c-cdecl-macro") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let dir = fixture_dir();
    let source_path = dir.join("cdecl_macro.c");
    let source = std::fs::read_to_string(&source_path).unwrap();
    let line = target_line(&source, "use_hooks");

    let work = std::env::temp_dir().join(format!(
        "govfuzz-c-cdecl-macro-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();

    let candidate = Candidate {
        harness_id: "H-CDECL-use_hooks".to_owned(),
        lang: Lang::C,
        source_path,
        line,
        name: "use_hooks".to_owned(),
        score: 60,
        // `static` so the harness includes the defining source, making `my_hooks` a
        // complete type that is constructed field-by-field (the path the fix fixes).
        is_static: true,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&dir).unwrap();
    let result = attempt(&candidate, &work, &idx, options(&dir)).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!(
            "a calling-convention macro (CDECL_MACRO) in a function-pointer field \
             must be stripped so the field name resolves and the harness builds, \
             got {other:?}"
        ),
    }
}
