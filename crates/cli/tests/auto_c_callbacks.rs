// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for C function-pointer / callback harness generation:
//! every callback shape must drive `auto` all the way to a BUILT harness rather
//! than a placeholder/skip/failed-build. Each target in the
//! `tests/fixtures/c_callbacks/callbacks.c` fixture exercises one gap:
//!   - §26.5  a typedef'd function-pointer parameter            (run_visitor)
//!   - §27.3  a callback ARRAY struct field                     (run_dispatch)
//!   - §27.3  a VARIADIC function-pointer parameter             (run_logger)
//!   - §27.9  an inline (non-typedef) function-pointer parameter (run_inline)
//!   - §27.9  an inline function-pointer struct field           (run_ops)

use std::path::PathBuf;
use std::time::Duration;

mod support;

use cli::auto::attempt::{attempt, AttemptOptions, FuzzEngine, Outcome};
use cli::auto::candidate::{Candidate, Lang};
use cli::auto::decl_index::DeclarationIndex;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/c_callbacks")
}

/// Line (1-based) of the `int <name>(` definition in the fixture source.
fn target_line(source: &str, name: &str) -> u32 {
    let needle = format!("int {name}(");
    source
        .lines()
        .enumerate()
        .find(|(_, l)| l.trim_start().starts_with(&needle))
        .map(|(i, _)| i as u32 + 1)
        .unwrap_or_else(|| panic!("target {name} not found in fixture"))
}

fn options(src_root: &std::path::Path) -> AttemptOptions {
    AttemptOptions {
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

/// Drive one fixture target through `auto::attempt` and require a BUILT harness —
/// the proof that the emitted main.c compiled with the callback satisfied (a
/// trampoline / filled array), not skipped or failed.
fn assert_target_builds(name: &str) {
    if which::which("clang").is_err() {
        eprintln!("skipping {name}: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping {name}: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("c-callbacks") {
        eprintln!("skipping {name}: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let dir = fixture_dir();
    let source_path = dir.join("callbacks.c");
    let source = std::fs::read_to_string(&source_path).unwrap();
    let line = target_line(&source, name);

    let work = std::env::temp_dir().join(format!(
        "govfuzz-c-callbacks-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();

    let candidate = Candidate {
        harness_id: format!("H-CB-{name}"),
        lang: Lang::C,
        source_path,
        line,
        name: name.to_owned(),
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
            "callback target {name} must build a harness (callback satisfied with a \
             trampoline / filled array), got {other:?}"
        ),
    }
}

#[test]
fn typedef_function_pointer_param_builds() {
    // §26.5: `int run_visitor(visit_cb cb, ...)`.
    assert_target_builds("run_visitor");
}

#[test]
fn callback_array_struct_field_builds() {
    // §27.3: `struct dispatch { void (*handlers[4])(int); ... }`.
    assert_target_builds("run_dispatch");
}

#[test]
fn variadic_callback_param_builds() {
    // §27.3: `int run_logger(log_fn fn, ...)` where `log_fn` is `void (*)(int, ...)`.
    assert_target_builds("run_logger");
}

#[test]
fn inline_function_pointer_param_builds() {
    // §27.9: `int run_inline(int (*cb)(int, int), ...)`.
    assert_target_builds("run_inline");
}

#[test]
fn inline_function_pointer_struct_field_builds() {
    // §27.9: `struct ops { int (*cmp)(const void *, const void *); ... }`.
    assert_target_builds("run_ops");
}
