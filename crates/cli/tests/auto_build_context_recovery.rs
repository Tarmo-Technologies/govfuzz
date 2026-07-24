// SPDX-License-Identifier: Apache-2.0

//! End-to-end build-context-recovery regressions for ROADMAP §26.1 and §26.8,
//! driven through the real `auto` attempt loop against fixtures created here.
//!
//! * §26.1 — a harness for a multi-TU library links only `main` + the target's
//!   own source and fails with undefined externals; govfuzz must link the
//!   project's already-built static archive to close the link.
//! * §26.8 — a CMake-generated export/config header that lands in the probe/build
//!   dir must be on the harness include path so the build finds it (instead of
//!   stubbing it with an empty placeholder).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod support;

use cli::auto::attempt::{attempt, AttemptOptions, FuzzEngine, Outcome};
use cli::auto::candidate::{Candidate, Lang};
use cli::auto::decl_index::DeclarationIndex;
use cli::auto::repair::Repair;

fn tmpdir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-bcr-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn toolchains_ready(prefix: &str) -> bool {
    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("skipping: clang/make not on PATH");
        return false;
    }
    if !support::libfuzzer_toolchain_available(prefix) {
        eprintln!("skipping: clang sanitizer/coverage toolchain incomplete");
        return false;
    }
    true
}

fn options(source_root: &Path) -> AttemptOptions {
    AttemptOptions {
        project: None,
        decoder_limits: Default::default(),
        force: false,
        per_target_time: Duration::from_secs(2),
        total_time: None,
        per_target_finding_count: None,
        no_stubs: false,
        passes: cli::auto::pass::Pass::ALL.to_vec(),
        source_root: Some(source_root.to_path_buf()),
        ada_dep_dirs: Vec::new(),
        mode: actionability::RunMode::Reporting,
        user_seeds: Vec::new(),
        extra_include_dirs: Vec::new(),
        extra_sources: Vec::new(),
        iterations: Some(64),
        rss_limit_mb: 2048,
        max_repair_rounds: 48,
        comparison_progress: false,
        sanitizers: Default::default(),
        dir_filter: Default::default(),
        engines: vec![FuzzEngine::Builtin],
        ada_main_sources: Default::default(),
    }
}

fn repairs_of(outcome: &Outcome) -> &[Repair] {
    match outcome {
        Outcome::Built { repairs, .. } | Outcome::BuiltAndFuzzed { repairs, .. } => repairs,
        other => panic!("expected a built outcome, got {other:?}"),
    }
}

/// §26.1: the target calls a helper whose DEFINITION lives only in a prebuilt
/// `*.a` in the build dir (its `.c` is never shipped in the swept tree). The
/// harness link fails with `undefined reference to gf_helper`; govfuzz must link
/// the recovered archive to close the link — proving the whole-library fallback,
/// not a blind stub.
#[test]
fn undefined_external_links_recovered_static_library() {
    if !toolchains_ready("bcr-lib") {
        return;
    }
    if which::which("ar").is_err() {
        eprintln!("skipping: ar not on PATH");
        return;
    }

    let root = tmpdir();
    let tree = root.join("tree");
    let inc = tree.join("include");
    let src = tree.join("src");
    let build = tree.join("build");
    fs::create_dir_all(&inc).unwrap();
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&build).unwrap();

    // Public header (declaration only — no body in the swept tree).
    fs::write(inc.join("helper.h"), "int gf_helper(int x);\n").unwrap();
    // The target the harness will exercise; references gf_helper so its object
    // carries an undefined reference the link must resolve.
    fs::write(
        src.join("target.c"),
        "#include \"helper.h\"\n\
         int gf_target(const unsigned char *data, unsigned long len) {\n\
         \x20   int acc = 0;\n\
         \x20   for (unsigned long i = 0; i < len; i++) acc = gf_helper(acc + data[i]);\n\
         \x20   return acc;\n\
         }\n",
    )
    .unwrap();

    // Build the helper's definition OUTSIDE the swept tree, then archive it into
    // the project's build dir — so decl_index never sees gf_helper's body and the
    // ONLY way to resolve it is to link the recovered archive.
    let ext = root.join("external");
    fs::create_dir_all(&ext).unwrap();
    fs::write(
        ext.join("helper.c"),
        "int gf_helper(int x){ return x + 1; }\n",
    )
    .unwrap();
    let obj = ext.join("helper.o");
    assert!(
        Command::new("clang")
            .args(["-fPIC", "-O1", "-c"])
            .arg(ext.join("helper.c"))
            .arg("-o")
            .arg(&obj)
            .status()
            .unwrap()
            .success(),
        "compile helper.o"
    );
    let archive = build.join("libhelper.a");
    assert!(
        Command::new("ar")
            .arg("crs")
            .arg(&archive)
            .arg(&obj)
            .status()
            .unwrap()
            .success(),
        "archive libhelper.a"
    );

    let work = fs::canonicalize({
        let w = root.join("work");
        fs::create_dir_all(&w).unwrap();
        w
    })
    .unwrap();

    let candidate = Candidate {
        harness_id: "H-C26-1".to_owned(),
        lang: Lang::C,
        source_path: src.join("target.c"),
        line: 2,
        name: "gf_target".to_owned(),
        score: 80,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&tree).unwrap();
    // Sanity: gf_helper has NO definition source in the swept tree (only a decl).
    assert!(
        idx.lookup_c_definition_source("gf_helper").is_none(),
        "fixture invalid: gf_helper body must not be in the tree"
    );

    // `source_root` is the project root govfuzz was pointed at — where the build
    // dir (and its recovered archive) lives, as in a real `govfuzz auto <tree>`.
    let result = attempt(&candidate, &work, &idx, options(&tree)).unwrap();
    let repairs = repairs_of(&result.outcome);

    // The recovered archive must have been linked (whole-library fallback).
    assert!(
        repairs.iter().any(|r| matches!(r,
            Repair::AddSource { source_path, .. } if source_path == &archive)),
        "expected the recovered libhelper.a to be linked; repairs = {repairs:?}"
    );
    // And gf_helper must NOT have been blind/declared-stubbed — the real library
    // was linked, not faked.
    assert!(
        !repairs.iter().any(|r| matches!(r,
            Repair::StubBlind { symbol } | Repair::StubDeclared { symbol, .. }
                if symbol == "gf_helper")),
        "gf_helper must be resolved from the archive, not stubbed; repairs = {repairs:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// §26.8: a CMake-`generate_export_header`-style header (`gf_export.h`) is dropped
/// into the probe build dir, not the source tree. The harness build must find it
/// via the build dir on the include path — NOT synthesize an empty placeholder.
#[test]
fn generated_export_header_resolves_from_probe_dir() {
    if !toolchains_ready("bcr-hdr") {
        return;
    }

    let root = tmpdir();
    let tree = root.join("tree");
    let src = tree.join("src");
    // The configure-only probe drops generated headers here (mirrors
    // `build_probe::PROBE_DIR`).
    let probe = tree.join(".govfuzz-build");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&probe).unwrap();

    // Generated export header: defines the export macro AND a value macro the
    // target body uses — an empty placeholder could not supply GF_MAGIC, so a
    // clean build proves the REAL generated header was on the include path.
    fs::write(
        probe.join("gf_export.h"),
        "#ifndef GF_EXPORT_H\n#define GF_EXPORT_H\n\
         #define GF_EXPORT\n\
         #define GF_MAGIC 0x5a\n\
         #endif\n",
    )
    .unwrap();
    fs::write(
        src.join("codec.c"),
        "#include \"gf_export.h\"\n\
         GF_EXPORT int gf_decode(const unsigned char *data, unsigned long len) {\n\
         \x20   return len ? (data[0] ^ GF_MAGIC) : GF_MAGIC;\n\
         }\n",
    )
    .unwrap();

    let work = fs::canonicalize({
        let w = root.join("work");
        fs::create_dir_all(&w).unwrap();
        w
    })
    .unwrap();

    let candidate = Candidate {
        harness_id: "H-C26-8".to_owned(),
        lang: Lang::C,
        source_path: src.join("codec.c"),
        line: 2,
        name: "gf_decode".to_owned(),
        score: 80,
        is_static: false,
        foreign_guard: None,
        input_reachability: None,
        dialect: None,
    };
    let idx = DeclarationIndex::build(&tree).unwrap();

    let result = attempt(&candidate, &work, &idx, options(&src)).unwrap();
    let repairs = repairs_of(&result.outcome);

    // The generated header must NOT have been stubbed with an empty placeholder /
    // synthesized config header — it was resolved from the probe build dir.
    assert!(
        !repairs.iter().any(|r| matches!(r,
            Repair::HeaderPlaceholder { virtual_path }
            | Repair::ConfigHeaderSynth { virtual_path }
                if virtual_path.contains("gf_export.h"))),
        "gf_export.h must resolve from the probe dir, not be placeholdered; repairs = {repairs:?}"
    );

    let _ = fs::remove_dir_all(&root);
}
