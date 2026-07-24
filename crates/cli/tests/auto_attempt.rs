// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-auto-it-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn clangxx_libfuzzer_flags(prefix: &str) -> Option<Vec<String>> {
    if clangxx_probe(prefix, &[]) {
        return Some(Vec::new());
    }
    for dir in [
        "/usr/lib/gcc/x86_64-linux-gnu/14",
        "/usr/lib/gcc/x86_64-linux-gnu/13",
        "/usr/lib/gcc/x86_64-linux-gnu/12",
        "/usr/lib/gcc/x86_64-linux-gnu/11",
    ] {
        let flag = format!("--gcc-install-dir={dir}");
        if clangxx_probe(prefix, std::slice::from_ref(&flag)) {
            return Some(vec![flag]);
        }
    }
    None
}

fn clangxx_probe(prefix: &str, extra_flags: &[String]) -> bool {
    let dir = std::env::temp_dir().join(format!(
        "govfuzz-{prefix}-clangxx-probe-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    if fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let src = dir.join("p.cpp");
    let bin = dir.join("p");
    let wrote = fs::write(
        &src,
        "#include <cstddef>\n\
         #include <cstdint>\n\
         #include <string>\n\
         extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { std::string s; return d && n ? d[0] : (int)s.size(); }\n",
    )
    .is_ok();
    let ok = wrote
        && Command::new("clang++")
            .args(extra_flags)
            .args(["-O1", "-g", "-fsanitize=fuzzer,address,undefined", "-o"])
            .arg(&bin)
            .arg(&src)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
    let _ = fs::remove_dir_all(&dir);
    ok
}

#[test]
fn attempt_repairs_missing_header_for_simple_c_target() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("good.c"),
        "#include \"missing.h\"\n\
         int parse_input(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0002".to_owned(),
        lang: Lang::C,
        source_path: src.join("good.c"),
        line: 2,
        name: "parse_input".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = cli::auto::attempt::AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(10),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    match &result.outcome {
        Outcome::Built { repairs, retries }
        | Outcome::BuiltAndFuzzed {
            repairs, retries, ..
        } => {
            assert!(*retries >= 1, "expected at least one retry");
            assert!(
                repairs.iter().any(|r| matches!(
                    r,
                    cli::auto::repair::Repair::HeaderPlaceholder { virtual_path }
                        if virtual_path == "missing.h"
                )),
                "expected HeaderPlaceholder for missing.h, got {repairs:?}"
            );
        }
        other => panic!("expected built, got {other:?}"),
    }
    if let Outcome::BuiltAndFuzzed { passes, .. } = &result.outcome {
        let total_executions: usize = passes.iter().map(|p| p.executions).sum();
        assert!(
            total_executions > 0,
            "fuzz should have run at least one iteration"
        );
    }
}

#[test]
fn attempt_skips_target_whose_definition_is_conditionally_compiled_out() {
    // GAP #9: the target's DEFINITION sits inside an inactive feature/platform
    // `#if` (here `#ifdef ENABLE_HIDDEN`; in the wild a CPU-feature guard like
    // `#if defined(HAVE_CRC32C)` over sc's `crc32_hw`). Its own source is already
    // compiled into the harness build, so the only repair the planner can offer is
    // re-adding that same source — a self-target repair that cannot resolve the
    // symbol. Rather than loop to an opaque `failed_build` with `undefined
    // reference`, the attempt must report an HONEST skip naming the unavailable
    // target. (The candidate target is also never replaced with a stub.)
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("conditional.c"),
        "#ifdef ENABLE_HIDDEN\n\
         void hidden_target(char *s) { (void)s; }\n\
         #endif\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0003".to_owned(),
        lang: Lang::C,
        source_path: src.join("conditional.c"),
        line: 2,
        name: "hidden_target".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::UnsupportedParams { reason } => {
            assert!(
                reason.contains("hidden_target"),
                "skip reason must name the unavailable target: {reason}"
            );
            assert!(
                reason.contains("conditionally compiled out")
                    || reason.contains("inactive")
                    || reason.contains("no definition in the active build"),
                "skip reason must explain the conditional-compilation cause: {reason}"
            );
        }
        other => panic!("expected an honest skip (UnsupportedParams), got {other:?}"),
    }
}

#[test]
fn attempt_pairs_tree_wide_c_lifecycle_from_unincluded_header() {
    // §27.2: the target `widget_decode(widget_t *, const char *, size_t)` takes an
    // opaque handle whose constructor/destructor are declared in `widget_internal.h`
    // — a header pulled in TRANSITIVELY by `widget.h` but never scanned by the
    // per-target declaration pass (which does not follow nested includes). Without
    // the tree-wide lifecycle index the handle has no constructor and the target is
    // skipped "needs lifecycle support"; with it (computed once in decl_index) the
    // handle pairs, the harness constructs it via `widget_create()`, and the build
    // links the real definition via AddSource.
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // An opaque `struct widget` handle + the decode prototype; the
    // constructor/destructor live in `widget_internal.h`, pulled in TRANSITIVELY by
    // `widget.h` but never scanned by the per-target declaration pass (which does
    // not follow nested includes).
    fs::write(
        src.join("widget.h"),
        "struct widget;\n\
         #include \"widget_internal.h\"\n\
         int widget_decode(struct widget *w, const char *p, unsigned long n);\n",
    )
    .unwrap();
    fs::write(
        src.join("widget_internal.h"),
        "struct widget *widget_create(void);\n\
         void widget_destroy(struct widget *w);\n",
    )
    .unwrap();
    fs::write(
        src.join("widget.c"),
        "#include \"widget.h\"\n\
         int widget_decode(struct widget *w, const char *p, unsigned long n) {\n\
         \x20  (void)w; return n > 0 ? p[0] : 0;\n\
         }\n",
    )
    .unwrap();
    fs::write(
        src.join("widget_impl.c"),
        "#include <stdlib.h>\n\
         #include \"widget.h\"\n\
         struct widget { int x; };\n\
         struct widget *widget_create(void) { struct widget *w = malloc(sizeof *w); if (w) w->x = 0; return w; }\n\
         void widget_destroy(struct widget *w) { free(w); }\n",
    )
    .unwrap();

    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C27LC".to_owned(),
        lang: Lang::C,
        source_path: src.join("widget.c"),
        line: 2,
        name: "widget_decode".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    // Precondition: the tree-wide lifecycle index paired the cross-header handle.
    assert!(
        idx.c_tree_lifecycle
            .iter()
            .any(|h| h.init.as_deref() == Some("widget_create")
                && h.delete.as_deref() == Some("widget_destroy")),
        "tree-wide lifecycle must pair widget_create/widget_destroy: {:?}",
        idx.c_tree_lifecycle
    );
    let options = cli::auto::attempt::AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!("tree-wide lifecycle should let widget_decode build, got {other:?}"),
    }
}

#[test]
fn attempt_adds_project_source_for_missing_c_symbol() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("api.c"),
        "extern int helper(const unsigned char *d, unsigned long n);\n\
         int parse_input(const unsigned char *d, unsigned long n) { return helper(d, n); }\n",
    )
    .unwrap();
    let helper = src.join("helper.c");
    fs::write(
        &helper,
        "int helper(const unsigned char *d, unsigned long n) { return d && n ? (int)d[0] : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0004".to_owned(),
        lang: Lang::C,
        source_path: src.join("api.c"),
        line: 2,
        name: "parse_input".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::Built { repairs, retries }
        | Outcome::BuiltAndFuzzed {
            repairs, retries, ..
        } => {
            assert!(*retries >= 1, "expected source repair retry");
            assert!(
                repairs.iter().any(|repair| matches!(
                    repair,
                    cli::auto::repair::Repair::AddSource {
                        symbol,
                        source_path,
                    } if symbol == "helper" && source_path == &helper
                )),
                "expected AddSource repair for helper.c, got {repairs:?}"
            );
            assert!(
                !repairs.iter().any(|repair| matches!(
                    repair,
                    cli::auto::repair::Repair::StubBlind { symbol }
                    | cli::auto::repair::Repair::StubDeclared { symbol, .. }
                        if symbol == "helper"
                )),
                "real helper source should be added instead of stubbing: {repairs:?}"
            );
        }
        other => panic!("expected built after adding helper.c, got {other:?}"),
    }
}

#[test]
fn attempt_builds_harness_for_unnamed_param_callback_typedef() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-unnamed-cb") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // qsort-style comparator typedef with unnamed parameters: the
    // generated trampoline must synthesize parameter names or the
    // harness does not compile.
    fs::write(
        src.join("sorter.c"),
        "typedef int (*compare_cb)(const void *, const void*);\n\
         int sort_records(const unsigned char *data, unsigned long len, compare_cb cmp) {\n\
             if (!data || !len) return -1;\n\
             if (cmp) return cmp(data, data + (len / 2));\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0007".to_owned(),
        lang: Lang::C,
        source_path: src.join("sorter.c"),
        line: 2,
        name: "sort_records".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    assert!(
        matches!(
            &result.outcome,
            Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. }
        ),
        "unnamed-param callback harness should build, got {:?}",
        result.outcome
    );
}

#[test]
fn attempt_adds_project_source_for_missing_cpp_symbol() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("api.cpp"),
        "#include <string>\n\
         #include <string_view>\n\
         namespace gov {\n\
         std::string normalize(const std::string &seed);\n\
         class Parser {\n\
         public:\n\
             Parser(const std::string &seed) : seed_(normalize(seed)) {}\n\
             int parse(std::string_view input) { return (int)(seed_.size() + input.size()); }\n\
         private:\n\
             std::string seed_;\n\
         };\n\
         }\n",
    )
    .unwrap();
    let helper = src.join("helper.cpp");
    fs::write(
        &helper,
        "#include <string>\n\
         namespace gov { std::string normalize(const std::string &seed) { return seed; } }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            src.join("api.cpp").display(),
            cxx_flags.join(" "),
            src.join("api.cpp").display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-X0006".to_owned(),
        lang: Lang::Cpp,
        source_path: src.join("api.cpp"),
        line: 7,
        name: "gov::Parser::parse".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::Built { repairs, retries }
        | Outcome::BuiltAndFuzzed {
            repairs, retries, ..
        } => {
            assert!(*retries >= 1, "expected source repair retry");
            assert!(
                repairs.iter().any(|repair| matches!(
                    repair,
                    cli::auto::repair::Repair::AddSource {
                        symbol,
                        source_path,
                    } if symbol.contains("normalize") && source_path == &helper
                )),
                "expected AddSource repair for helper.cpp, got {repairs:?}"
            );
            assert!(
                !repairs.iter().any(|repair| matches!(
                    repair,
                    cli::auto::repair::Repair::StubBlind { symbol }
                    | cli::auto::repair::Repair::StubDeclared { symbol, .. }
                        if symbol.contains("normalize")
                )),
                "real C++ helper source should be added instead of stubbing: {repairs:?}"
            );
        }
        other => panic!("expected built after adding helper.cpp, got {other:?}"),
    }
}

#[test]
fn attempt_prefers_sequence_for_cpp_class_method_with_lifecycle_steps() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-sequence") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include <string_view>\n\
         namespace gov {\n\
         class Parser {\n\
         public:\n\
             Parser() {}\n\
             void reset() {}\n\
             void feed(std::string_view chunk) { (void)chunk; }\n\
             int parse(std::string_view input) { return (int)input.size(); }\n\
         };\n\
         }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XSEQ-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api.clone(),
        line: 8,
        name: "gov::Parser::parse".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "C++ sequence target should run the empty pass"
            );
        }
        other => panic!("expected C++ sequence target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(
        main.contains("_gf_lifecycle_count"),
        "auto should generate a C++ sequence harness for class methods with visible lifecycle steps:\n{main}"
    );
    assert!(main.contains("_gf_receiver.reset();"));
    assert!(main.contains("_gf_receiver.feed("));
    assert!(main.contains("int R = _gf_receiver.parse(input);"));
}

#[test]
fn attempt_uses_direct_cpp_harness_when_lifecycle_helpers_are_private() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-private-lifecycle") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include <string_view>\n\
         namespace gov {\n\
         class Parser {\n\
         public:\n\
             Parser() {}\n\
             int parse(std::string_view input) { return (int)input.size(); }\n\
         private:\n\
             void reset() {}\n\
         };\n\
         }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XSEQ-PRIVATE-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api.clone(),
        line: 6,
        name: "gov::Parser::parse".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "C++ direct target should run the empty pass"
            );
        }
        other => panic!("expected C++ target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(
        !main.contains("_gf_lifecycle_count"),
        "auto must not select C++ sequence mode using private-only helpers:\n{main}"
    );
    assert!(
        !main.contains("_gf_receiver.reset("),
        "private lifecycle helper must not be emitted:\n{main}"
    );
    assert!(main.contains("int R = _gf_receiver.parse(input);"));
}

#[test]
fn attempt_runtime_cap_excludes_build_time() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("fast.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return d && n ? (int)d[0] : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0005".to_owned(),
        lang: Lang::C,
        source_path: src.join("fast.c"),
        line: 1,
        name: "parse_input".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        // A tight fuzz cap that is still well above the persistent fork-server's
        // spawn/handshake (a few ms, paid after the fuzz timer starts) yet far
        // below the ASan/UBSan/sancov build time (~1s+). If the cap wrongly
        // included build time it would be exhausted before any exec (0 execs);
        // excluding build, a quarter-second of fuzzing yields many. (1ms was
        // shorter than the fork-server spawn itself, so it flaked to 0 execs.)
        per_target_time: std::time::Duration::from_millis(250),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "runtime cap should still allow the first fuzz pass after build"
            );
        }
        other => panic!("expected built_and_fuzzed, got {other:?}"),
    }
}

#[test]
fn attempt_total_time_apportions_across_passes() {
    // #402: --total-time is a single per-target wall budget split across passes,
    // so the report records total/per-pass budgets that don't depend on the
    // caller hand-dividing by the pass count.
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("skipping: clang/make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-total") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("fast.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return d && n ? (int)d[0] : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-TOTAL".to_owned(),
        lang: Lang::C,
        source_path: src.join("fast.c"),
        line: 1,
        name: "parse_input".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        // per_target_time is the per-target total; the deprecated --total-time
        // alias overrides it when set (as here).
        per_target_time: std::time::Duration::from_secs(999),
        total_time: Some(std::time::Duration::from_secs(6)),
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty, Pass::Rng, Pass::FuzzDriven],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let started = std::time::Instant::now();
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    let fuzz_wall = started.elapsed();

    match &result.outcome {
        Outcome::BuiltAndFuzzed {
            per_pass_budget_secs,
            total_wall_budget_secs,
            passes,
            ..
        } => {
            assert_eq!(*total_wall_budget_secs, 6, "total budget recorded");
            assert_eq!(*per_pass_budget_secs, 2, "6s / 3 passes = 2s per pass");
            assert!(!passes.is_empty());
            // The campaign honors the shared deadline: wall is ~total, not
            // total*passes. Generous ceiling absorbs build + repair overhead.
            assert!(
                fuzz_wall < std::time::Duration::from_secs(60),
                "total-time campaign must not run ~per_target_time*passes; took {fuzz_wall:?}"
            );
        }
        other => panic!("expected built_and_fuzzed, got {other:?}"),
    }
}

#[test]
fn attempt_builds_and_fuzzes_struct_by_value_c_target() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-struct") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("struct_target.h"),
        "enum mode { MODE_A, MODE_B };\n\
         struct config { int count; enum mode mode; char tag[4]; };\n\
         int run_config(struct config a, struct config b);\n",
    )
    .unwrap();
    fs::write(
        src.join("struct_target.c"),
        "#include \"struct_target.h\"\n\
         int run_config(struct config a, struct config b) { return a.count + b.count + (int)a.mode + (int)b.mode + a.tag[0] + b.tag[0]; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CSTRUCT".to_owned(),
        lang: Lang::C,
        source_path: src.join("struct_target.c"),
        line: 2,
        name: "run_config".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "struct target should run the empty pass"
            );
        }
        other => panic!("expected struct target to build+fuzz, got {other:?}"),
    }
}

// #386: a per-harness RSS cap turns a fuzzer-controlled huge allocation into an
// OOM finding (GF-209) instead of OOM-killing the host. A target that grows the
// resident set past the cap on a marker input must be caught + classified.
#[test]
fn attempt_rss_limit_classifies_oom_as_gf209() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-oom") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("bomb.h"),
        "int eat_memory(const unsigned char *d, unsigned long n);\n",
    )
    .unwrap();
    // Grows the resident set in 16 MB steps on a "BOMB" input. The volatile sink
    // reads each chunk so -O1 cannot dead-code-eliminate the allocations.
    fs::write(
        src.join("bomb.c"),
        "#include \"bomb.h\"\n#include <stdlib.h>\n#include <string.h>\n\
         volatile unsigned char govfuzz_oom_sink;\n\
         int eat_memory(const unsigned char *d, unsigned long n){\n\
           if(n>=4 && d[0]=='B'&&d[1]=='O'&&d[2]=='M'&&d[3]=='B'){\n\
             unsigned long chunk=16ul*1024*1024;\n\
             for(int i=0;i<64;i++){ unsigned char*p=(unsigned char*)malloc(chunk); if(!p)break; memset(p,(unsigned char)(i+1),chunk); govfuzz_oom_sink+=p[(unsigned long)i*7919u%chunk]; }\n\
           }\n return 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-OOM".to_owned(),
        lang: Lang::C,
        source_path: src.join("bomb.c"),
        line: 5,
        name: "eat_memory".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(10),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        // The "BOMB" seed is executed on pass 1 and trips the cap.
        user_seeds: vec![b"BOMB".to_vec()],
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: Some(8),
        rss_limit_mb: 256,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    let Outcome::BuiltAndFuzzed { passes, .. } = &result.outcome else {
        panic!(
            "expected OOM target to build+fuzz, got {:?}",
            result.outcome
        );
    };
    let finding_ids: Vec<&String> = passes.iter().flat_map(|p| p.findings.iter()).collect();
    assert!(
        !finding_ids.is_empty(),
        "RSS cap should have produced an OOM finding"
    );
    // The synthesized OOM is classified GF-209.
    let mut saw_gf209 = false;
    for id in &finding_ids {
        let fj = work.join("findings").join(id).join("finding.json");
        let text = fs::read_to_string(&fj).unwrap_or_default();
        if text.contains("GF-209") {
            saw_gf209 = true;
        }
    }
    assert!(saw_gf209, "OOM finding must carry rule id GF-209");
}

#[test]
fn attempt_prefers_sequence_for_first_param_handle_c_target() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-sequence") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("session.h"),
        "struct session { int seed; int total; };\n\
         int session_init(struct session *s, int seed);\n\
         int session_step(struct session *s, int delta);\n\
         void session_end(struct session *s);\n",
    )
    .unwrap();
    fs::write(
        src.join("session.c"),
        "#include \"session.h\"\n\
         int session_init(struct session *s, int seed) { s->seed = seed; s->total = 0; return 0; }\n\
         int session_step(struct session *s, int delta) { s->total += delta; return s->total; }\n\
         void session_end(struct session *s) { s->seed = 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CSEQ-AUTO".to_owned(),
        lang: Lang::C,
        source_path: src.join("session.c"),
        line: 3,
        name: "session_step".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "sequence target should run the empty pass"
            );
        }
        other => panic!("expected sequence target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(
        main.contains("_gf_lifecycle_count"),
        "auto should generate a C sequence harness for first-param handle targets:\n{main}"
    );
    assert!(main.contains("session_init(&_gf_handle"));
    assert!(main.contains("session_step(&_gf_handle"));
    assert!(main.contains("session_end(&_gf_handle"));
}

#[test]
fn attempt_prefers_sequence_for_c_target_with_static_lifecycle_helpers() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-static-sequence") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("session.h"),
        "#pragma once\n\
         struct session { int seed; int total; };\n\
         int session_step(struct session *s, int delta);\n",
    )
    .unwrap();
    let source = src.join("session.c");
    fs::write(
        &source,
        "#include \"session.h\"\n\
         static int session_init(struct session *s, int seed) { s->seed = seed; s->total = 0; return 0; }\n\
         int session_step(struct session *s, int delta) { s->total += delta; return s->total; }\n\
         static void session_end(struct session *s) { s->seed = 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CSEQ-STATIC-AUTO".to_owned(),
        lang: Lang::C,
        source_path: source,
        line: 3,
        name: "session_step".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(1),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: Vec::new(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => {
            panic!("expected C static-lifecycle target to build through sequence harness, got {other:?}")
        }
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(
        main.contains("_gf_lifecycle_count"),
        "auto should generate a C sequence harness when static init/end helpers are usable:\n{main}"
    );
    assert!(main.contains("#include \"session.c\""));
    assert!(main.contains("session_init(&_gf_handle"));
    assert!(main.contains("session_step(&_gf_handle"));
    assert!(main.contains("session_end(&_gf_handle"));
}

#[test]
fn attempt_uses_direct_harness_for_generic_void_pointer_c_target() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-void-direct") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("buffers.c"),
        "#include <stddef.h>\n\
         #include <string.h>\n\
         void *scratch_alloc(void *opaque, size_t items, size_t size) { (void)items; (void)size; return opaque; }\n\
         void scratch_free(void *p) { (void)p; }\n\
         int buffer_copy(void *out, size_t out_len, const void *in, size_t in_len) { if (!out || !in) return 0; size_t n = out_len < in_len ? out_len : in_len; memcpy(out, in, n); return (int)n; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CVOID-DIRECT".to_owned(),
        lang: Lang::C,
        source_path: src.join("buffers.c"),
        line: 5,
        name: "buffer_copy".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "direct void-pointer target should run the empty pass"
            );
        }
        other => panic!("expected void-pointer target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(
        !main.contains("_gf_lifecycle_count"),
        "generic void* buffer APIs must not be classified as lifecycle handle sequences:\n{main}"
    );
    assert!(
        !main.contains("void _gf_handle"),
        "generic void* sequence classification generates invalid C:\n{main}"
    );
}

#[test]
fn attempt_builds_and_fuzzes_c_scalar_and_enum_output_pointers() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-output-pointers") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("outputs.h"),
        "typedef unsigned int mz_uint32;\n\
         typedef enum { MZ_ZIP_NO_ERROR, MZ_ZIP_INVALID_PARAMETER } mz_zip_error;\n\
         int fill_outputs(mz_uint32 *pIndex, mz_zip_error *pErr);\n",
    )
    .unwrap();
    fs::write(
        src.join("outputs.c"),
        "#include \"outputs.h\"\n\
         int fill_outputs(mz_uint32 *pIndex, mz_zip_error *pErr) { if (pIndex) *pIndex += 1; if (pErr) *pErr = MZ_ZIP_NO_ERROR; return pIndex && pErr ? 1 : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-COUTPUT-PTRS".to_owned(),
        lang: Lang::C,
        source_path: src.join("outputs.c"),
        line: 2,
        name: "fill_outputs".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "output-pointer target should run the empty pass"
            );
        }
        other => panic!("expected output-pointer target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(main.contains("mz_uint32 _gf_out_pIndex"));
    assert!(main.contains("mz_zip_error _gf_out_pErr"));
    assert!(main.contains("fill_outputs(pIndex, pErr)"));
}

#[test]
fn attempt_builds_and_fuzzes_c_const_byte_typedef_pair() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-byte-typedef") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("bytes.h"),
        "#include <stddef.h>\n\
         typedef unsigned char mz_uint8;\n\
         unsigned long checksum(unsigned long crc, const mz_uint8 *ptr, size_t buf_len);\n",
    )
    .unwrap();
    fs::write(
        src.join("bytes.c"),
        "#include \"bytes.h\"\n\
         unsigned long checksum(unsigned long crc, const mz_uint8 *ptr, size_t buf_len) { for (size_t i = 0; ptr && i < buf_len; ++i) crc += ptr[i]; return crc; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CBYTE-TYPEDEF-AUTO".to_owned(),
        lang: Lang::C,
        source_path: src.join("bytes.c"),
        line: 2,
        name: "checksum".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "const byte typedef target should run the empty pass"
            );
        }
        other => panic!("expected const byte typedef target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(main.contains("const mz_uint8 * ptr = (const mz_uint8 *)Data"));
    assert!(main.contains("size_t buf_len = (size_t)Size"));
    assert!(
        !main.contains("_gf_out_ptr"),
        "const byte input pointer should borrow Data, not use output storage:\n{main}"
    );
}

#[test]
fn attempt_builds_and_fuzzes_c_miniz_file_macro_pointer() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-mz-file") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("cfile.h"),
        "#include <stdio.h>\n\
         #define MZ_FILE FILE\n\
         int parse_cfile(MZ_FILE *pFile);\n",
    )
    .unwrap();
    fs::write(
        src.join("cfile.c"),
        "#include \"cfile.h\"\n\
         int parse_cfile(MZ_FILE *pFile) { return pFile ? fgetc(pFile) : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CMZFILE-AUTO".to_owned(),
        lang: Lang::C,
        source_path: src.join("cfile.c"),
        line: 2,
        name: "parse_cfile".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "MZ_FILE pointer target should run the empty pass"
            );
        }
        other => panic!("expected MZ_FILE pointer target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(main.contains("MZ_FILE * pFile = (MZ_FILE *)(_gf_file_buf_pFile ?"));
    assert!(main.contains("fmemopen(_gf_file_buf_pFile, Size, \"r+\")"));
    assert!(main.contains("parse_cfile(pFile)"));
    assert!(main.contains("if (pFile) fclose(pFile);"));
    assert!(main.contains("free(_gf_file_buf_pFile);"));
}

#[test]
fn attempt_builds_and_fuzzes_c_miniz_time_pointer_alias() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-mz-time") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("time_api.h"),
        "#include <time.h>\n\
         #define MZ_TIME_T time_t\n\
         int stamp_time(const MZ_TIME_T *pFile_time);\n",
    )
    .unwrap();
    fs::write(
        src.join("time_api.c"),
        "#include \"time_api.h\"\n\
         int stamp_time(const MZ_TIME_T *pFile_time) { return pFile_time ? (int)(*pFile_time & 1) : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CMZTIME-AUTO".to_owned(),
        lang: Lang::C,
        source_path: src.join("time_api.c"),
        line: 2,
        name: "stamp_time".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "MZ_TIME_T pointer target should run the empty pass"
            );
        }
        other => panic!("expected MZ_TIME_T pointer target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(main.contains("MZ_TIME_T _gf_out_pFile_time"));
    assert!(main.contains("const MZ_TIME_T * pFile_time = &_gf_out_pFile_time"));
    assert!(main.contains("stamp_time(pFile_time)"));
}

#[test]
fn attempt_builds_and_fuzzes_c_void_pointer_output_slot() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-void-pointer-slot") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("heap_api.h"),
        "#include <stddef.h>\n\
         int finalize_heap_archive(void **ppBuf, size_t *pSize);\n",
    )
    .unwrap();
    fs::write(
        src.join("heap_api.c"),
        "#include \"heap_api.h\"\n\
         int finalize_heap_archive(void **ppBuf, size_t *pSize) { if (!ppBuf || !pSize) return 0; *ppBuf = 0; *pSize = 0; return 1; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CVOIDPP-AUTO".to_owned(),
        lang: Lang::C,
        source_path: src.join("heap_api.c"),
        line: 2,
        name: "finalize_heap_archive".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "void** output slot target should run the empty pass"
            );
        }
        other => panic!("expected void** output slot target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(main.contains("void * _gf_out_ppBuf = NULL"));
    assert!(main.contains("void * * ppBuf = &_gf_out_ppBuf"));
    assert!(main.contains("size_t *pSize = &_gf_out_pSize"));
    assert!(main.contains("finalize_heap_archive(ppBuf, pSize)"));
}

#[test]
fn attempt_builds_and_fuzzes_c_void_output_capacity_and_input_pair() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-c-void-output-capacity") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("compress_mem.h"),
        "#include <stddef.h>\n\
         size_t compress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len);\n",
    )
    .unwrap();
    fs::write(
        src.join("compress_mem.c"),
        "#include \"compress_mem.h\"\n\
         size_t compress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len) {\n\
           unsigned char *out = (unsigned char *)pOut_buf;\n\
           const unsigned char *src = (const unsigned char *)pSrc_buf;\n\
           unsigned int checksum = 0;\n\
           if (!out || !src) return 0;\n\
           for (size_t i = 0; i < src_buf_len; ++i) { checksum += src[i]; if (i < out_buf_len) out[i] = (unsigned char)(src[i] ^ 0x5a); }\n\
           return (size_t)checksum;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CVOID-CAP-AUTO".to_owned(),
        lang: Lang::C,
        source_path: src.join("compress_mem.c"),
        line: 2,
        name: "compress_mem_to_mem".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert!(
                !passes.is_empty(),
                "void output-capacity target should complete at least one fuzz pass"
            );
            assert!(
                passes[0].executions > 0,
                "void output-capacity target should run the first pass"
            );
        }
        other => panic!("expected void output-capacity target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(main.contains("void * pOut_buf = (void *)malloc"));
    assert!(main.contains("size_t out_buf_len = (size_t)_gf_cap_pOut_buf"));
    assert!(main.contains("const void * pSrc_buf = (const void *)Data"));
    assert!(main.contains("size_t src_buf_len = (size_t)Size"));
    assert!(
        !main.contains("src_buf_len = gf_bounded_length"),
        "input length must stay coherent with Data:\n{main}"
    );
    assert!(main.contains("free(pOut_buf)"));
}

#[test]
fn attempt_builds_and_fuzzes_cpp_void_output_capacity_and_input_pair() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-void-output-capacity") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include <cstddef>\n\
         namespace gov {\n\
         std::size_t compress_mem_to_mem(void *pOut_buf, std::size_t out_buf_len, const void *pSrc_buf, std::size_t src_buf_len) {\n\
           auto *out = static_cast<unsigned char *>(pOut_buf);\n\
           auto *src = static_cast<const unsigned char *>(pSrc_buf);\n\
           unsigned int checksum = 0;\n\
           if (!out || !src) return 0;\n\
           for (std::size_t i = 0; i < src_buf_len; ++i) { checksum += src[i]; if (i < out_buf_len) out[i] = static_cast<unsigned char>(src[i] ^ 0x5a); }\n\
           return static_cast<std::size_t>(checksum);\n\
         }\n\
         }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XVOID-CAP-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api,
        line: 3,
        name: "gov::compress_mem_to_mem".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert!(
                !passes.is_empty(),
                "C++ void output-capacity target should complete at least one fuzz pass"
            );
            assert!(
                passes[0].executions > 0,
                "C++ void output-capacity target should run the first pass"
            );
        }
        other => panic!("expected C++ void output-capacity target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(main.contains("void * pOut_buf = (void *)malloc"));
    assert!(main.contains("std::size_t out_buf_len = (std::size_t)_gf_cap_pOut_buf"));
    assert!(main.contains("const void * pSrc_buf = (const void *)Data"));
    assert!(main.contains("std::size_t src_buf_len = (std::size_t)Size"));
    assert!(
        !main.contains("src_buf_len = gf_bounded_length"),
        "input length must stay coherent with Data:\n{main}"
    );
    assert!(main.contains("free(pOut_buf)"));
}

#[test]
fn attempt_builds_and_fuzzes_cpp_void_output_length_pointer_and_input_pair() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-void-output-length") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include <cstddef>\n\
         namespace gov {\n\
         bool compress_mem_to_heap(void *pOut_buf, std::size_t *pOut_len, const void *pSrc_buf, std::size_t src_buf_len) {\n\
           auto *out = static_cast<unsigned char *>(pOut_buf);\n\
           auto *src = static_cast<const unsigned char *>(pSrc_buf);\n\
           if (!out || !pOut_len || !src) return false;\n\
           std::size_t cap = *pOut_len;\n\
           std::size_t copied = 0;\n\
           for (std::size_t i = 0; i < src_buf_len; ++i) { if (i < cap) { out[i] = static_cast<unsigned char>(src[i] ^ 0xa5); ++copied; } }\n\
           *pOut_len = copied;\n\
           return true;\n\
         }\n\
         }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XVOID-LEN-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api,
        line: 3,
        name: "gov::compress_mem_to_heap".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert!(
                !passes.is_empty(),
                "C++ void output-length target should complete at least one fuzz pass"
            );
            assert!(
                passes[0].executions > 0,
                "C++ void output-length target should run the first pass"
            );
        }
        other => panic!("expected C++ void output-length target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(main.contains("void * pOut_buf = (void *)malloc"));
    assert!(main.contains("std::size_t _gf_out_pOut_len = (std::size_t)_gf_cap_pOut_buf"));
    assert!(main.contains("std::size_t *pOut_len = &_gf_out_pOut_len"));
    assert!(main.contains("const void * pSrc_buf = (const void *)Data"));
    assert!(main.contains("std::size_t src_buf_len = (std::size_t)Size"));
    assert!(
        !main.contains("src_buf_len = gf_bounded_length"),
        "input length must stay coherent with Data:\n{main}"
    );
    assert!(main.contains("free(pOut_buf)"));
}

#[test]
fn attempt_builds_and_fuzzes_cpp_standard_scalar_aliases() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-std-scalars") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include <cstddef>\n\
         #include <cstdint>\n\
         namespace gov {\n\
         int tune(std::uint32_t flags, std::size_t count, std::uint16_t code, bool enabled) {\n\
           return static_cast<int>((flags & 0xffu) + (count & 0xffu) + code + (enabled ? 1 : 0));\n\
         }\n\
         }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XSTD-SCALAR-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api,
        line: 4,
        name: "gov::tune".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "C++ std scalar target should run the empty pass"
            );
        }
        other => panic!("expected C++ std scalar target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(main.contains("std::uint32_t flags = (std::uint32_t)gf_bounded_i32"));
    assert!(main.contains("std::size_t count = (std::size_t)gf_bounded_length"));
    assert!(main.contains("std::uint16_t code = (std::uint16_t)gf_bounded_i32"));
    assert!(main.contains("bool enabled = (bool)(gf_u8(&Cur) & 1)"));
    assert!(main.contains("int R = gov::tune(flags, count, code, enabled);"));
    assert!(
        !result.harness_dir.join("build_context_objects.mk").exists(),
        "a target included by main.cpp must not also be linked as a per-TU object"
    );
    let makefile = fs::read_to_string(result.harness_dir.join("Makefile")).unwrap();
    assert!(makefile.contains(".DEFAULT_GOAL := all"));
}

#[test]
fn attempt_builds_and_fuzzes_cpp_struct_by_value_target() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-struct-by-value") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("api.hpp"),
        "#pragma once\n\
         #include <cstddef>\n\
         #include <cstdint>\n\
         namespace gov {\n\
         struct Config {\n\
             int mode;\n\
             bool enabled;\n\
             std::uint16_t code;\n\
         };\n\
         int consume(Config cfg);\n\
         }\n",
    )
    .unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include \"api.hpp\"\n\
         namespace gov {\n\
         int consume(Config cfg) {\n\
             return cfg.mode + (cfg.enabled ? 1 : 0) + static_cast<int>(cfg.code & 0xffu);\n\
         }\n\
         }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -I {} -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            src.display(),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XSTRUCT-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api,
        line: 3,
        name: "gov::consume".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "C++ struct-by-value target should run the empty pass"
            );
        }
        other => panic!("expected C++ struct-by-value target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    // C++ value-initializes the aggregate (`Config cfg{};`) rather than declaring
    // + memset-zeroing it — memset on a non-trivial class is UB (ca4a06e).
    assert!(main.contains("Config cfg{}"));
    assert!(
        !main.contains("memset(&cfg"),
        "C++ struct must be value-initialized, not memset:\n{main}"
    );
    assert!(main.contains("cfg.mode = gf_i32(&Cur)"));
    assert!(main.contains("cfg.enabled = (bool)(gf_u8(&Cur) & 1)"));
    assert!(main.contains("cfg.code = (std::uint16_t)gf_bounded_i32(&Cur, 0, 0xffff)"));
    assert!(main.contains("int R = gov::consume(cfg);"));
}

#[test]
fn attempt_builds_and_fuzzes_cpp_file_pointer_target() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-file-pointer") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include <stdio.h>\n\
         int parse_stream(FILE *stream) { return stream ? fgetc(stream) : 0; }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XFILE-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api,
        line: 2,
        name: "parse_stream".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "C++ FILE* target should run the empty pass"
            );
        }
        other => panic!("expected C++ FILE* target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(main.contains("#include <stdio.h>"));
    assert!(main.contains("FILE * stream = _gf_file_buf_stream ?"));
    assert!(main.contains("fmemopen(_gf_file_buf_stream, Size, \"r+\")"));
    assert!(main.contains("int R = parse_stream(stream);"));
    assert!(main.contains("if (stream) fclose(stream);"));
    assert!(main.contains("free(_gf_file_buf_stream);"));
}

#[test]
fn attempt_builds_and_fuzzes_cpp_callback_typedef_target() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex, pass::Pass};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("attempt-cpp-callback") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("api.hpp"),
        "#pragma once\n\
         typedef int (*visit_cb)(void *opaque, const char *name);\n\
         int visit(visit_cb cb);\n",
    )
    .unwrap();
    let api = src.join("api.cpp");
    fs::write(
        &api,
        "#include \"api.hpp\"\n\
         int visit(visit_cb cb) { return cb ? cb(nullptr, \"name\") : 0; }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -I {} -c {}" }}]"#,
            src.display(),
            api.display(),
            cxx_flags.join(" "),
            src.display(),
            api.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-XCALLBACK-AUTO".to_owned(),
        lang: Lang::Cpp,
        source_path: api,
        line: 2,
        name: "visit".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: vec![Pass::Empty],
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } => {
            assert_eq!(passes.len(), 1);
            assert!(
                passes[0].executions > 0,
                "C++ callback typedef target should run the empty pass"
            );
        }
        other => panic!("expected C++ callback typedef target to build+fuzz, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(main.contains("static int _gf_cb_trampoline(void *opaque, const char *name)"));
    assert!(main.contains("visit_cb cb = (visit_cb)_gf_cb_trampoline;"));
    assert!(main.contains("int R = visit(cb);"));
}

/// Regression for "Ada candidates never reach gprbuild". Before the
/// fix, `try_build` hardcoded the C/C++ make path, so every Ada
/// candidate failed with "no Makefile" and the classifier emitted
/// `Other`. The attempt loop would NEVER classify it as
/// `UnsupportedParams` (that path is reached only when harness
/// generation itself fails), so we'd see a `FailedBuild` outcome
/// full of `Other` errors instead of real GNAT diagnostics. With
/// the dispatch fix in place, we should now see a *real* outcome
/// from the Ada build pipeline - either a successful build, a
/// failed-but-classified build, or an unrecoverable link error.
#[test]
fn attempt_dispatches_ada_candidate_to_gprbuild() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: gprbuild not available");
        return;
    }
    use cli::auto::{
        attempt::*,
        candidate::{Candidate, Lang},
        decl_index::DeclarationIndex,
    };
    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("demo.adb"),
        "with Ada.Text_IO; procedure Demo is begin Ada.Text_IO.Put_Line (\"hi\"); end Demo;\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-A0001".to_owned(),
        lang: Lang::Ada,
        source_path: src.join("demo.adb"),
        line: 1,
        name: "Demo".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(5),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    // The build will fail (no real harness was generated, no .gpr),
    // but the loop must NOT short-circuit on `UnsupportedParams` -
    // that would mean the Ada build path was never reached.
    match result.outcome {
        Outcome::UnsupportedParams { reason } => {
            // generate_harness_for legitimately can fail before we
            // reach try_build; we just need to know the failure
            // wasn't a make-not-found surrogate.
            assert!(
                !reason.contains("Makefile") && !reason.contains("No targets specified"),
                "Ada candidate was routed through the C/C++ make path, not gprbuild: {reason}"
            );
        }
        Outcome::Built { .. }
        | Outcome::BuiltAndFuzzed { .. }
        | Outcome::BuiltNotEntered { .. }
        | Outcome::FailedBuild { .. }
        | Outcome::UnrecoverableLink { .. }
        | Outcome::UnrecoverableRuntime { .. }
        | Outcome::ReportOnly { .. } => {
            // Any of these is fine - the dispatch reached the Ada path.
        }
    }
}

/// Regression for the Ada cross-dir unit recovery lever (adamant's dominant
/// blocker): the target unit `with`s a package whose real source lives in a
/// SIBLING dir outside the scan path. The attempt loop must resolve that unit
/// to its real `.ads` via the tree-wide index and add it to the build
/// (`Repair::AddAdaSource`) — not fabricate a signature-only stub that drops the
/// unit's real enum and cascades.
#[test]
fn attempt_recovers_cross_dir_ada_unit_source() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: gprbuild not available");
        return;
    }
    use cli::auto::{
        attempt::*,
        candidate::{Candidate, Lang},
        decl_index::DeclarationIndex,
    };
    let root = tmpdir();
    let types = root.join("types");
    let core = root.join("core");
    fs::create_dir_all(&types).unwrap();
    fs::create_dir_all(&core).unwrap();
    // Target unit in the scan path; withs a sibling-dir package.
    fs::write(
        types.join("widget.ads"),
        "with Cross_Pkg;\npackage Widget is\n   function Classify (N : Integer) return Cross_Pkg.Status;\nend Widget;\n",
    )
    .unwrap();
    fs::write(
        types.join("widget.adb"),
        "package body Widget is\n   function Classify (N : Integer) return Cross_Pkg.Status is\n   begin\n      if N > 0 then return Cross_Pkg.Positive_Status; else return Cross_Pkg.Zero_Status; end if;\n   end Classify;\nend Widget;\n",
    )
    .unwrap();
    // Real source for the with'd unit, in a SIBLING dir outside the scan path.
    fs::write(
        core.join("cross_pkg.ads"),
        "package Cross_Pkg is\n   type Status is (Zero_Status, Positive_Status);\nend Cross_Pkg;\n",
    )
    .unwrap();

    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-A0CRS".to_owned(),
        lang: Lang::Ada,
        source_path: types.join("widget.ads"),
        line: 3,
        name: "Classify".to_owned(),
        score: 70,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    // Index parses the scan path but indexes Ada unit->source across the whole
    // project root (where `core/` lives) — the cross-tree lever.
    let idx = DeclarationIndex::build_indexed(&types, &root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(10),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(types.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    let repairs = match &result.outcome {
        Outcome::Built { repairs, .. } | Outcome::BuiltAndFuzzed { repairs, .. } => repairs.clone(),
        other => panic!("expected cross-dir Ada unit to build, got {other:?}"),
    };
    assert!(
        repairs.iter().any(|r| matches!(
            r,
            cli::auto::repair::Repair::AddAdaSource { unit, .. }
                if unit.eq_ignore_ascii_case("Cross_Pkg")
        )),
        "expected AddAdaSource for Cross_Pkg (real source), got {repairs:?}"
    );
    // The real enum must be on the build path — assert it was copied into the
    // harness's repair source dir (`work/harnesses/<id>/repairs/ada_stubs/`, where
    // `apply_repair` writes AddAdaSource, on the build's Source_Dirs).
    let added = work
        .join("harnesses")
        .join("H-A0CRS")
        .join("repairs")
        .join("ada_stubs")
        .join("cross_pkg.ads");
    assert!(
        added.is_file(),
        "real cross_pkg.ads must be on the build path"
    );
    assert!(
        fs::read_to_string(&added)
            .unwrap()
            .contains("Positive_Status"),
        "the REAL enum (not a stub) must be added"
    );
}

#[test]
fn static_c_direct_targets_build_through_included_source() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("static-c-direct") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("lib.c"),
        "static int helper(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0001".to_owned(),
        lang: Lang::C,
        source_path: src.join("lib.c"),
        line: 1,
        name: "helper".to_owned(),
        score: 60,
        is_static: true,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = cli::auto::attempt::AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(1),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: Vec::new(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!("expected static C target to build through direct harness, got {other:?}"),
    }
    let main = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(
        main.contains("#include \"lib.c\""),
        "auto-generated harness should include static target source:\n{main}"
    );
}

#[test]
fn static_cpp_direct_targets_build_through_included_source() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    let Some(cxx_flags) = clangxx_libfuzzer_flags("static-cpp-direct") else {
        eprintln!("skipping: clang++ -fsanitize=fuzzer toolchain incomplete");
        return;
    };

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let source = src.join("lib.cpp");
    fs::write(
        &source,
        "#include <cstddef>\n\
         #include <cstdint>\n\
         static int helper(const std::uint8_t *d, std::size_t n) { return d && n ? d[0] : 0; }\n",
    )
    .unwrap();
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{"directory":"{}","file":"{}","command":"clang++ {} -std=c++17 -c {}" }}]"#,
            src.display(),
            source.display(),
            cxx_flags.join(" "),
            source.display()
        ),
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-X0001".to_owned(),
        lang: Lang::Cpp,
        source_path: source,
        line: 3,
        name: "helper".to_owned(),
        score: 60,
        is_static: true,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = cli::auto::attempt::AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(1),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: Vec::new(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => {
            panic!("expected static C++ target to build through direct harness, got {other:?}")
        }
    }
    let main = fs::read_to_string(result.harness_dir.join("main.cpp")).unwrap();
    assert!(
        main.contains("#include \"lib.cpp\""),
        "auto-generated harness should include static C++ target source:\n{main}"
    );
}

#[test]
fn foreign_platform_guarded_target_builds_via_cross_or_platform_stub() {
    // A Windows (`_WIN32`) OS-platform-guarded target is NO LONGER pre-skipped.
    // With mingw + wine present it CROSS-COMPILES to a real PE and fuzzes under
    // wine (the higher-fidelity #b path) — no platform stub. Without that toolchain
    // it falls back to the native `_WIN32`-defined + fake-`windows.h` build (#c
    // StubIsolated, a windows PlatformStub repair). Either way `attempt()` returns
    // BuiltAndFuzzed, not an UnsupportedParams pre-skip.
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("win.c"),
        "#ifdef _WIN32\nint win_decode(const unsigned char *d, unsigned long n) { return (int)n; }\n#endif\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0002".to_owned(),
        lang: Lang::C,
        source_path: src.join("win.c"),
        line: 2,
        name: "win_decode".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: Some("_WIN32".to_owned()),
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = cli::auto::attempt::AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(1),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    let cross_available =
        which::which("x86_64-w64-mingw32-gcc").is_ok() && which::which("wine").is_ok();
    match &result.outcome {
        Outcome::BuiltAndFuzzed { .. } => {
            // Match on the Debug form to avoid importing the Repair type.
            let dbg = format!("{:?}", result.outcome);
            if cross_available {
                // Cross path: a real PE under wine, no platform stub.
                assert!(
                    !dbg.contains("PlatformStub"),
                    "with mingw+wine a _WIN32 target cross-compiles to a PE (no stub): {dbg}"
                );
            } else {
                // Fallback: native build with the windows PlatformStub repair.
                assert!(
                    dbg.contains("PlatformStub") && dbg.contains("windows"),
                    "without mingw+wine a _WIN32 target builds via a windows PlatformStub repair: {dbg}"
                );
            }
        }
        other => panic!("expected BuiltAndFuzzed (cross or platform stub), got {other:?}"),
    }
}

#[test]
fn attempt_reports_phase_progression_through_progress_sink() {
    use cli::auto::progress::{Phase, ProgressSink, ProgressUpdate};
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    struct RecordingSink(std::cell::RefCell<Vec<Phase>>);
    impl ProgressSink for RecordingSink {
        fn update(&self, u: &ProgressUpdate) {
            self.0.borrow_mut().push(u.phase.clone());
        }
    }

    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("skipping: clang/make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("progress") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("good.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0001".to_owned(),
        lang: Lang::C,
        source_path: src.join("good.c"),
        line: 1,
        name: "parse_input".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = cli::auto::attempt::AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(2),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let sink = RecordingSink(std::cell::RefCell::new(Vec::new()));
    let result = attempt_with_progress(&candidate, &work, &idx, options, &sink).unwrap();
    assert!(
        matches!(result.outcome, Outcome::BuiltAndFuzzed { .. }),
        "fixture should build+fuzz, got {:?}",
        result.outcome
    );
    let phases = sink.0.borrow();
    assert_eq!(phases.first(), Some(&Phase::Generate), "{phases:?}");
    assert!(
        phases.iter().any(|p| matches!(p, Phase::Build { .. })),
        "{phases:?}"
    );
    assert!(
        phases.iter().any(|p| matches!(p, Phase::Fuzz { .. })),
        "{phases:?}"
    );
}

/// Regression for the expat `XML_Parser` gap: an opaque handle hidden behind a
/// typedef'd pointer (`typedef struct widget_s *widget_t;`) whose constructor
/// returns the handle and takes a pointer config arg. The harness must
/// construct it via `widget_create(NULL)` and free with `widget_free(w)` rather
/// than skipping the target or zero-filling an incomplete struct.
#[test]
fn attempt_constructs_typedef_hidden_opaque_handle_via_returning_ctor() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // Public header: the struct is opaque (forward-declared only) and the
    // handle is a typedef'd pointer — the harness's TU sees only this.
    fs::write(
        src.join("widget.h"),
        "#ifndef WIDGET_H\n\
         #define WIDGET_H\n\
         struct widget_s;\n\
         typedef struct widget_s *widget_t;\n\
         widget_t widget_create(const char *name);\n\
         void widget_free(widget_t w);\n\
         int widget_parse(widget_t w, const unsigned char *data, unsigned long n);\n\
         #endif\n",
    )
    .unwrap();
    fs::write(
        src.join("widget.c"),
        "#include \"widget.h\"\n\
         #include <stdlib.h>\n\
         struct widget_s { int state; unsigned long total; };\n\
         widget_t widget_create(const char *name) {\n\
         struct widget_s *w = (struct widget_s *)calloc(1, sizeof *w);\n\
         (void)name;\n\
         return w;\n\
         }\n\
         void widget_free(widget_t w) { free(w); }\n\
         int widget_parse(widget_t w, const unsigned char *data, unsigned long n) {\n\
         if (!w) return -1;\n\
         for (unsigned long i = 0; i < n; i++) w->total += data[i];\n\
         w->state = (int)(n & 0x7f);\n\
         return w->state;\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-C0WID".to_owned(),
        lang: Lang::C,
        source_path: src.join("widget.c"),
        line: 10,
        name: "widget_parse".to_owned(),
        score: 80,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(10),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    let result = attempt(&candidate, &work, &idx, options).unwrap();

    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!("expected opaque-handle target to build, got {other:?}"),
    }

    // The harness must drive the handle through its lifecycle, not zero-fill it.
    let main_c = fs::read_to_string(result.harness_dir.join("main.c")).unwrap();
    assert!(
        main_c.contains("widget_create(NULL)"),
        "harness should construct via the returning ctor: {main_c}"
    );
    assert!(
        main_c.contains("widget_free("),
        "harness should free the handle: {main_c}"
    );
}

#[test]
fn attempt_synthesises_corba_stub_for_missing_idl_header_but_empty_for_internal() {
    // Issue #368: a missing CORBA/IDL-generated stub header (`MessageC.h`) must be
    // synthesised with curated CORBA scaffolding typedefs (not an empty
    // #pragma-once placeholder that leaves IDL types undefined and cascades). A
    // missing internal/proprietary header stays an empty placeholder (tight gate).
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    if which::which("clang").is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    if which::which("make").is_err() {
        eprintln!("skipping: make not on PATH");
        return;
    }
    if !support::libfuzzer_toolchain_available("attempt-idl") {
        eprintln!("skipping: clang -fsanitize=fuzzer toolchain incomplete");
        return;
    }

    let root = tmpdir();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // The target pulls in both a CORBA/IDL stub header and an internal header,
    // neither present in the tree.
    fs::write(
        src.join("svc.c"),
        "#include \"src/idl/MessageC.h\"\n\
         #include \"internal/proprietary_alloc.h\"\n\
         int svc_parse(const unsigned char *d, unsigned long n) { return (int)n; }\n",
    )
    .unwrap();
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let candidate = Candidate {
        harness_id: "H-CIDL1".to_owned(),
        lang: Lang::C,
        source_path: src.join("svc.c"),
        line: 3,
        name: "svc_parse".to_owned(),
        score: 60,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&root).unwrap();
    let options = AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 48,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(10),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(src.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };
    let result = attempt(&candidate, &work, &idx, options).unwrap();
    match &result.outcome {
        Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. } => {}
        other => panic!("expected IDL-stub target to build, got {other:?}"),
    }

    let includes = result
        .harness_dir
        .join("repairs")
        .join(cli::auto::repair::AUTO_INCLUDES_DIR);
    let idl_hdr = fs::read_to_string(includes.join("src/idl/MessageC.h")).unwrap();
    assert!(
        idl_hdr.contains("typedef") && idl_hdr.contains("CORBA_Object"),
        "IDL header must carry CORBA stub typedefs: {idl_hdr}"
    );
    let internal_hdr = fs::read_to_string(includes.join("internal/proprietary_alloc.h")).unwrap();
    assert!(
        internal_hdr.contains("#pragma once") && !internal_hdr.contains("typedef"),
        "internal header must stay an empty placeholder: {internal_hdr}"
    );
}

/// F2: a C++ method whose owning class is DEFINED only in a `.cpp` translation
/// unit and never declared in any header is unreachable from a generated harness
/// (which `#include`s the project header). The attempt must report an honest skip
/// naming the class — never an opaque `failed_build` — while a method of a class
/// DECLARED in a header (defined out-of-line in the `.cpp`, the normal case) is
/// NOT over-filtered by this rule. Mirrors json11's real `JsonParser` pattern.
#[test]
fn attempt_skips_cpp_method_of_class_defined_only_in_translation_unit() {
    use cli::auto::{attempt::*, candidate::*, decl_index::DeclarationIndex};

    let root = tmpdir();
    fs::write(
        root.join("json11.hpp"),
        "#pragma once\n\
         #include <string>\n\
         namespace json11 {\n\
         class JsonValue;\n\
         class Json final {\n\
         public:\n\
           Json();\n\
           static Json parse(const std::string &in);\n\
         };\n\
         }\n",
    )
    .unwrap();
    fs::write(
        root.join("json11.cpp"),
        "#include \"json11.hpp\"\n\
         namespace json11 {\n\
         Json::Json() {}\n\
         Json Json::parse(const std::string &in) { (void)in; return Json(); }\n\
         struct JsonParser final {\n\
           bool expect(const std::string &s) { return s.empty(); }\n\
         };\n\
         }\n",
    )
    .unwrap();

    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    let work = fs::canonicalize(&work).unwrap();
    let idx = DeclarationIndex::build(&root).unwrap();
    let make_options = || AttemptOptions {
        decoder_limits: Default::default(),
        force: false,
        engines: vec![cli::auto::attempt::FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
        dir_filter: Default::default(),
        comparison_progress: false,
        max_repair_rounds: 8,
        sanitizers: Default::default(),
        per_target_time: std::time::Duration::from_secs(3),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(root.clone()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: None,
        rss_limit_mb: 2048,
    };

    // The .cpp-only class member: pre-skipped (no toolchain needed — the skip is
    // decided before harness generation / build).
    let cpp_only = Candidate {
        harness_id: "H-X0001".to_owned(),
        lang: Lang::Cpp,
        source_path: root.join("json11.cpp"),
        line: 5,
        name: "json11::JsonParser::expect".to_owned(),
        score: 80,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let result = attempt(&cpp_only, &work, &idx, make_options()).unwrap();
    match &result.outcome {
        Outcome::UnsupportedParams { reason } => {
            assert!(
                reason.contains("JsonParser"),
                "must name the class: {reason}"
            );
            assert!(
                reason.contains("defined only in a .cpp translation unit")
                    && reason.contains("not reachable from an external harness"),
                "must explain the .cpp-only / unreachable cause: {reason}"
            );
        }
        other => panic!("expected an honest skip (UnsupportedParams), got {other:?}"),
    }

    // A header-declared class (methods defined out-of-line) must NOT be filtered by
    // this rule. Assert the negative regardless of toolchain: its outcome is never
    // the .cpp-only skip. When the C++ toolchain is present, also assert it builds.
    let header_declared = Candidate {
        harness_id: "H-X0002".to_owned(),
        lang: Lang::Cpp,
        source_path: root.join("json11.cpp"),
        line: 4,
        name: "json11::Json::parse".to_owned(),
        score: 80,
        // A static *member* is externally linkable; discovery records is_static
        // only for static *free* functions (`is_static && !api.is_method`).
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let result = attempt(&header_declared, &work, &idx, make_options()).unwrap();
    if let Outcome::UnsupportedParams { reason } = &result.outcome {
        assert!(
            !reason.contains("defined only in a .cpp translation unit"),
            "header-declared class must not hit the .cpp-only skip: {reason}"
        );
    }
    let toolchain = which::which("clang").is_ok()
        && which::which("make").is_ok()
        && support::libfuzzer_toolchain_available("attempt_f2");
    if toolchain {
        assert!(
            matches!(
                result.outcome,
                Outcome::Built { .. } | Outcome::BuiltAndFuzzed { .. }
            ),
            "header-declared class must remain harnessable: {:?}",
            result.outcome
        );
    }
}
