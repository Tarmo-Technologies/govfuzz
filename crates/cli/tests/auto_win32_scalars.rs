// SPDX-License-Identifier: Apache-2.0
//! End-to-end regression: a Win32/MFC C++ target whose parameters are the
//! Windows integer typedefs `BOOL`/`DWORD`/`WORD`. On an offline non-Windows
//! lab `<windows.h>` is absent, so these typedefs used to resolve opaque and the
//! whole target was skipped ("needs lifecycle support (Phase C)").
//!
//! Two fixes make it build+fuzz: (1) the Win32 integer spellings are recognized
//! as scalars (`type_model::SCALAR_SPELLINGS`); (2) the synthesized MSVC
//! CRT-compat stub advertises native wchar_t so the faux `_MSC_VER` no longer
//! makes clang re-typedef the builtin `wchar_t`, which otherwise broke every C++
//! translation unit that pulls `<cstddef>` ("cannot combine with previous
//! 'int'"). The `#include <afxwin.h>` routes govfuzz to its win32 platform stub,
//! which supplies BOOL/DWORD/WORD so the emitted decoder compiles.

use std::path::PathBuf;
use std::time::Duration;

mod support;

use cli::auto::attempt::{attempt, AttemptOptions, FuzzEngine, Outcome};
use cli::auto::candidate::{Candidate, Lang};
use cli::auto::decl_index::DeclarationIndex;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/win32_mfc")
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
        per_target_time: Duration::from_secs(3),
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
        .find(|(_, l)| l.contains(&format!("{name}(")) && l.contains("BOOL"))
        .map(|(i, _)| i as u32 + 1)
        .unwrap_or_else(|| panic!("target {name} not found in fixture"))
}

#[test]
fn win32_integer_typedef_params_build_and_fuzz() {
    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::cpp_stdlib_toolchain_available("clang++") {
        eprintln!("skipping: clang++ can't compile the C++ standard headers");
        return;
    }

    let dir = fixture_dir();
    let source_path = dir.join("win32_scalars.cpp");
    let source = std::fs::read_to_string(&source_path).unwrap();
    let line = target_line(&source, "process_flags");

    let work = std::env::temp_dir().join(format!(
        "govfuzz-win32-scalars-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();

    let candidate = Candidate {
        harness_id: "H-WIN32-process_flags".to_owned(),
        lang: Lang::Cpp,
        source_path,
        line,
        name: "process_flags".to_owned(),
        score: 60,
        is_static: false,
        // What discovery assigns to an `#include <afxwin.h>` source — routes the
        // attempt to the win32 (MFC/ATL) platform stub.
        foreign_guard: Some("win32 (MFC/ATL framework header)".to_owned()),
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&dir).unwrap();
    let result = attempt(&candidate, &work, &idx, options(&dir)).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!(
            "Win32 integer typedef params (const BOOL / DWORD / WORD) must decode \
             as scalars and the win32-stubbed harness must build, got {other:?}"
        ),
    }
}
