// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
struct IdlRecoveryContext {
    files_seen: usize,
    files_parsed: usize,
    defines_applied: usize,
}

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct FakeCorbaArgs {
    /// Path to govfuzz_work directory.
    pub work_dir: PathBuf,

    /// Source directory to scan. Defaults to <work-dir>/src_instrumented.
    #[arg(long)]
    pub source_dir: Option<PathBuf>,

    /// Optional IDL file to parse and emit Helper/Skel/Stub Ada mapping packages for.
    #[arg(long)]
    pub idl: Option<PathBuf>,

    /// ROS .msg/.srv/.action interface file to translate through the IDL mapping pipeline.
    #[arg(long = "ros-interface")]
    pub ros_interfaces: Vec<PathBuf>,

    /// Predefine an IDL preprocessor symbol, as NAME or NAME=VALUE. Repeatable.
    #[arg(long = "idl-define")]
    pub idl_defines: Vec<String>,

    /// Directory to search for IDL #include files.
    #[arg(long = "idl-include-dir")]
    pub idl_include_dirs: Vec<PathBuf>,
}

pub fn run(args: FakeCorbaArgs) -> i32 {
    let work_dir = absolutize(&args.work_dir);
    let source_dir = args
        .source_dir
        .as_deref()
        .map(absolutize)
        .unwrap_or_else(|| work_dir.join("src_instrumented"));
    let output_dir = work_dir.join("fake_corba");

    if let Err(error) = std::fs::create_dir_all(&work_dir) {
        eprintln!("create work directory '{}': {error}", work_dir.display());
        return 1;
    }

    if !source_dir.is_dir() {
        if (args.idl.is_some() || !args.ros_interfaces.is_empty()) && args.source_dir.is_none() {
            if let Err(error) = std::fs::create_dir_all(&source_dir) {
                eprintln!(
                    "create default source directory '{}': {error}",
                    source_dir.display()
                );
                return 1;
            }
        } else {
            eprintln!(
                "source directory '{}' does not exist; run instrumentation first or pass --source-dir",
                source_dir.display()
            );
            return 1;
        }
    }

    match ::fake_corba::generate_fake_corba(&source_dir, &output_dir) {
        Ok(output) => {
            match write_idl_mapping(
                args.idl.as_deref(),
                &args.ros_interfaces,
                &args.idl_defines,
                &args.idl_include_dirs,
                &output_dir,
            ) {
                Ok(idl_count) => {
                    if idl_count == 0 {
                        println!(
                            "generated {} fake CORBA files under {}",
                            output.written_files.len(),
                            output_dir.display()
                        );
                    } else {
                        println!(
                            "generated {} fake CORBA files and {} IDL mapping files under {}",
                            output.written_files.len(),
                            idl_count,
                            output_dir.display()
                        );
                    }
                    0
                }
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        Err(error) => {
            eprintln!(
                "generate fake CORBA under '{}': {error}",
                output_dir.display()
            );
            1
        }
    }
}

/// Auto-generate CORBA/IDL scaffolding from a source tree during `auto`, so an
/// Ada CORBA project's harnesses can build without a manual `fake-corba` step:
/// the base fake-CORBA packages (from detected CORBA usage in the tree) plus the
/// Ada mapping packages for every `.idl` found under `source_root`, all written
/// to `<work>/fake_corba/` (which the Ada build adds as a Source_Dir). This is
/// govfuzz's own IDL parser — it executes no project code — so it runs by default
/// when `.idl` files are present. Returns the number of `.idl` files mapped.
/// Best-effort: a per-file parse failure is logged and skipped.
pub fn auto_generate_from_tree(source_root: &Path, work_dir: &Path, force: bool) -> usize {
    let idls = find_idl_files(source_root);
    // Legacy deliveries often contain only checked-in Ada servant/stub output;
    // the original IDL is no longer shipped.  The base fake-CORBA surface is
    // still useful (and necessary) for those trees, so gate it on CORBA source
    // evidence rather than on the presence of an `.idl` file.  Previously the
    // early return made the source scanner in `fake_corba` unreachable for the
    // exact old-code case it was designed to support.
    let corba_like = ::fake_corba::detect_source_tree(source_root)
        .map(|report| report.is_corba_like())
        .unwrap_or(false);
    if idls.is_empty() && !corba_like {
        return 0;
    }
    let output_dir = work_dir.join("fake_corba");
    if std::fs::create_dir_all(&output_dir).is_err() {
        return 0;
    }
    // Base fake-CORBA packages from CORBA usage detected in the tree. Under
    // --force the Ada external-stub model owns missing application-library
    // packages (reconstructing their full used API), so skip fake-corba's flat
    // `Pkg.Exception` guesses to avoid a duplicate/conflicting unit definition.
    if let Err(error) = ::fake_corba::generate_fake_corba_with(source_root, &output_dir, force) {
        eprintln!("govfuzz auto: fake-corba base generation: {error}");
    }
    // Resolve cross-directory `#include "other.idl"` against EVERY directory that
    // holds an .idl in the tree, not just the current file's own dir (see
    // [`idl_include_dirs`]).
    let include_dirs = idl_include_dirs(&idls)
        .into_iter()
        .map(|path| absolutize(&path))
        .collect::<Vec<_>>();
    let (project_defines, project_include_dirs) = project_idl_options(source_root);
    let mut include_dirs = include_dirs;
    for directory in project_include_dirs {
        let directory = absolutize(&directory);
        if !include_dirs.contains(&directory) {
            include_dirs.push(directory);
        }
    }
    let mut ast = idl_parser::IdlFile {
        declarations: Vec::new(),
        pragmas: Vec::new(),
        warnings: Vec::new(),
    };
    let mut mapped = 0usize;
    for idl in &idls {
        let idl = absolutize(idl);
        match idl_parser::parse_idl_file_recovering_with_options(
            &idl,
            &project_defines,
            &include_dirs,
        ) {
            Ok(parsed) => {
                ast.declarations.extend(parsed.declarations);
                ast.pragmas.extend(parsed.pragmas);
                ast.warnings.extend(parsed.warnings);
                mapped += 1;
            }
            Err(error) => eprintln!("govfuzz auto: skipping {}: {error}", idl.display()),
        }
    }
    // Emit the entire tree in one pass. The emitter merges reopened modules;
    // per-file emission wrote identical package paths repeatedly, making the
    // last IDL silently erase declarations from every earlier one.
    if mapped > 0 {
        if let Err(error) = write_idl_ast(
            &ast,
            &output_dir,
            IdlRecoveryContext {
                files_seen: idls.len(),
                files_parsed: mapped,
                defines_applied: project_defines.len(),
            },
        ) {
            eprintln!("govfuzz auto: write aggregate IDL mapping: {error}");
            return 0;
        }
    }
    // A checked-in binding is authoritative.  Keeping a generated spec/body for
    // the same declared unit makes gprbuild reject the whole flattened source set
    // as a duplicate unit (and an arbitrary project filename makes basename-only
    // collision checks miss it).  Prune only the matching spec/body; generated
    // child/helper units that are genuinely absent remain available.
    match prune_generated_real_unit_collisions(source_root, &output_dir, Some(work_dir)) {
        Ok(removed) => {
            if let Err(error) = checkpoint_real_fake_collisions(&output_dir, removed) {
                eprintln!("govfuzz auto: fake-corba collision checkpoint: {error}");
            }
        }
        Err(error) => {
            eprintln!("govfuzz auto: fake-corba collision pruning: {error}");
        }
    }
    mapped
}

fn ada_declared_unit_key(path: &Path) -> Option<(String, String)> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    if extension != "ads" && extension != "adb" {
        return None;
    }
    let source = crate::source_text::read_source_text(path).ok()?;
    let ast = ada_parser::reconcile::build_structural_ast(&source, None, path).ok()?;
    let unit = ast
        .packages
        .first()
        .map(|package| package.name.to_ascii_lowercase())
        .or_else(|| {
            ast.subprograms
                .iter()
                .find(|subprogram| {
                    matches!(
                        subprogram.owner,
                        ada_parser::ast::SubprogramOwner::LibraryLevel
                    )
                })
                .map(|subprogram| subprogram.name.to_ascii_lowercase())
        })?;
    Some((unit, extension))
}

fn find_ada_unit_keys(
    root: &Path,
    excluded_root: Option<&Path>,
) -> std::collections::BTreeSet<(String, String)> {
    let mut keys = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries = entries.flatten().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            seen += 1;
            if seen > 200_000 {
                return keys;
            }
            let path = entry.path();
            if excluded_root.is_some_and(|excluded| path.starts_with(excluded)) {
                continue;
            }
            if path.is_dir() {
                let skip = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        matches!(
                            name,
                            ".git"
                                | "target"
                                | "build"
                                | "node_modules"
                                | "fake_corba"
                                | "src_instrumented"
                                | "generated_harnesses"
                        )
                    });
                if !skip {
                    stack.push(path);
                }
            } else if let Some(key) = ada_declared_unit_key(&path) {
                keys.insert(key);
            }
        }
    }
    keys
}

/// Remove generated Ada files whose exact declared unit and source kind already
/// exist in the real source tree. Returns the number of collisions removed.
fn prune_generated_real_unit_collisions(
    source_root: &Path,
    output_dir: &Path,
    excluded_root: Option<&Path>,
) -> Result<usize, String> {
    let real = find_ada_unit_keys(source_root, excluded_root.or(Some(output_dir)));
    let mut removed = 0usize;
    let entries = std::fs::read_dir(output_dir)
        .map_err(|error| format!("read '{}': {error}", output_dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && ada_declared_unit_key(&path).is_some_and(|key| real.contains(&key)) {
            std::fs::remove_file(&path).map_err(|error| {
                format!("remove generated collision '{}': {error}", path.display())
            })?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The IDL `#include` search path for a whole tree: every distinct directory that
/// contains an `.idl` (in first-seen order). A CORBA project routinely
/// `#include`s a shared/sibling types IDL — e.g. `ss_smc_common_types.idl` under
/// `idl/common/` from `idl/smc/*.idl`. Passing only each file's OWN parent left
/// those cross-directory includes unresolved, so the preprocessor emitted a
/// `#pragma govfuzz_warning "include ... not found"` breadcrumb and the mapping
/// silently dropped the included types (cascading into unbuildable servant
/// harnesses). The quoted-include current-file-parent still takes precedence in
/// the preprocessor's `resolve_include`, so a same-named local file wins.
fn idl_include_dirs(idls: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for idl in idls {
        if let Some(parent) = idl.parent() {
            let parent = parent.to_path_buf();
            if !dirs.contains(&parent) {
                dirs.push(parent);
            }
        }
    }
    dirs
}

/// Recursively collect `.idl` files under `root` (bounded; skips VCS/build dirs).
fn find_idl_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 200_000 {
                return out;
            }
            let path = entry.path();
            if path.is_dir() {
                let skip = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    matches!(
                        n,
                        ".git" | "govfuzz_work" | "target" | "build" | "node_modules"
                    )
                });
                if !skip {
                    stack.push(path);
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("idl") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Recover IDL preprocessor configuration from checked-in build metadata. This
/// is deliberately evidence-based: only lines that name an IDL tool/IDL flags
/// variable contribute `-D`/`-I` options, so unrelated C compiler feature
/// defines are never unioned into the IDL world.
fn project_idl_options(root: &Path) -> (Vec<(String, String)>, Vec<PathBuf>) {
    fn is_build_metadata(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        matches!(
            name.as_str(),
            "makefile" | "gnumakefile" | "cmakelists.txt" | "meson.build"
        ) || matches!(
            path.extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("mk") | Some("cmake") | Some("gpr")
        )
    }

    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        let mut entries = entries.flatten().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            seen += 1;
            if seen > 50_000 {
                break;
            }
            let path = entry.path();
            if path.is_dir() {
                let skip = entry.file_name().to_string_lossy().starts_with('.')
                    || matches!(
                        entry.file_name().to_string_lossy().as_ref(),
                        "target" | "build" | "node_modules" | "govfuzz_work"
                    );
                if !skip {
                    stack.push(path);
                }
            } else if is_build_metadata(&path) {
                files.push(path);
            }
        }
    }
    files.sort();

    let mut defines = std::collections::BTreeMap::<String, String>::new();
    let mut include_dirs = Vec::new();
    for file in files {
        let Ok(text) = crate::source_text::read_source_text(&file) else {
            continue;
        };
        let base = file.parent().unwrap_or(root);
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if ![
                "idlflags",
                "idl_flags",
                "tao_idl",
                "omniidl",
                "opendds_idl",
                "ridlc",
                " idlj",
                ".idl",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                continue;
            }
            let tokens = line
                .split_whitespace()
                .map(|token| {
                    token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | '(' | ')' | ',' | ';'))
                })
                .filter(|token| !token.is_empty())
                .collect::<Vec<_>>();
            let mut index = 0usize;
            while let Some(token) = tokens.get(index).copied() {
                let define = if token == "-D" {
                    index += 1;
                    tokens.get(index).copied()
                } else {
                    token.strip_prefix("-D")
                };
                if let Some(define) = define.filter(|value| !value.is_empty()) {
                    let (name, value) = define.split_once('=').unwrap_or((define, "1"));
                    if is_idl_identifier(name) && !value.contains('$') && !value.contains('@') {
                        defines.entry(name.to_owned()).or_insert(value.to_owned());
                    }
                }
                let include = if token == "-I" {
                    index += 1;
                    tokens.get(index).copied()
                } else {
                    token.strip_prefix("-I")
                };
                if let Some(include) = include.filter(|value| !value.is_empty()) {
                    if !include.contains('$') && !include.contains('@') {
                        let path = Path::new(include);
                        let resolved = if path.is_absolute() {
                            path.to_path_buf()
                        } else {
                            base.join(path)
                        };
                        if !include_dirs.contains(&resolved) {
                            include_dirs.push(resolved);
                        }
                    }
                }
                index += 1;
            }
        }
    }
    (defines.into_iter().collect(), include_dirs)
}

fn write_idl_mapping(
    idl_path: Option<&Path>,
    ros_interfaces: &[PathBuf],
    idl_defines: &[String],
    idl_include_dirs: &[PathBuf],
    output_dir: &Path,
) -> Result<usize, String> {
    if idl_path.is_none() && ros_interfaces.is_empty() {
        return Ok(0);
    }
    let mut ast = idl_parser::IdlFile {
        declarations: Vec::new(),
        pragmas: Vec::new(),
        warnings: Vec::new(),
    };
    let defines = parse_idl_defines(idl_defines)?;
    let include_dirs = idl_include_dirs
        .iter()
        .map(|path| absolutize(path))
        .collect::<Vec<_>>();

    if let Some(idl_path) = idl_path {
        let idl_path = absolutize(idl_path);
        let idl_ast =
            idl_parser::parse_idl_file_recovering_with_options(&idl_path, &defines, &include_dirs)
                .map_err(|error| format!("parse IDL '{}': {error}", idl_path.display()))?;
        ast.declarations.extend(idl_ast.declarations);
        ast.pragmas.extend(idl_ast.pragmas);
        ast.warnings.extend(idl_ast.warnings);
    }
    for ros_interface in ros_interfaces {
        let ros_interface = absolutize(ros_interface);
        let ros_ast = idl_parser::parse_ros_interface_file(&ros_interface).map_err(|error| {
            format!("parse ROS interface '{}': {error}", ros_interface.display())
        })?;
        ast.declarations.extend(ros_ast.declarations);
        ast.pragmas.extend(ros_ast.pragmas);
        ast.warnings.extend(ros_ast.warnings);
    }

    write_idl_ast(
        &ast,
        output_dir,
        IdlRecoveryContext {
            files_seen: usize::from(idl_path.is_some()) + ros_interfaces.len(),
            files_parsed: usize::from(idl_path.is_some()) + ros_interfaces.len(),
            defines_applied: defines.len(),
        },
    )
}

fn write_idl_ast(
    ast: &idl_parser::IdlFile,
    output_dir: &Path,
    recovery: IdlRecoveryContext,
) -> Result<usize, String> {
    let dictionary_tokens = idl_parser::extract_idl_dictionary_tokens_from_ast(ast);
    let output = idl_parser::emit_ada_packages(ast);
    let reopened_modules = count_reopened_idl_modules(&ast.declarations);
    let generated_unit_collisions = output
        .units
        .iter()
        .map(|unit| unit.relative_path.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let generated_unit_collisions = output.units.len().saturating_sub(generated_unit_collisions);
    if !output_dir.join("corba-any.ads").is_file() {
        let files = [::fake_corba::render_corba_any_file()];
        ::fake_corba::write_generated_files(output_dir, &files).map_err(|error| {
            format!(
                "write CORBA Any support under '{}': {error}",
                output_dir.display()
            )
        })?;
    }
    for warning in &output.warnings {
        eprintln!("IDL mapping warning: {warning}");
    }
    write_idl_recovery_report(
        output_dir,
        &output.warnings,
        recovery,
        reopened_modules,
        generated_unit_collisions,
    )?;
    let written =
        idl_parser::write_generated_ada_units(output_dir, &output.units).map_err(|error| {
            format!(
                "write IDL mapping under '{}': {error}",
                output_dir.display()
            )
        })?;
    write_idl_dictionary(output_dir, &dictionary_tokens)?;
    Ok(written.len())
}

fn write_idl_recovery_report(
    output_dir: &Path,
    warnings: &[String],
    recovery: IdlRecoveryContext,
    reopened_modules: usize,
    generated_unit_collisions: usize,
) -> Result<(), String> {
    let mut categories = std::collections::BTreeMap::<String, usize>::new();
    let mut blocking_warnings = 0usize;
    for warning in warnings {
        let lower = warning.to_ascii_lowercase();
        let (category, blocks_completeness) =
            if lower.contains("include") && lower.contains("not found") {
                ("missing_include", true)
            } else if lower.contains("function-like macro")
                || lower.contains("unsupported macro definition")
            {
                ("unsupported_macro", true)
            } else if lower.contains("unsupported #if expression") {
                ("unsupported_conditional", true)
            } else if lower.contains("unsupported directive") {
                ("unsupported_directive", true)
            } else if lower.contains("unknown idl pragma") {
                // Vendor pragmas can affect an ORB's code-generation policy, but
                // recording one does not remove the declaration that follows it.
                ("vendor_pragma", false)
            } else if lower.contains("unsupported idl constant expression")
                || lower.contains("nonliteral idl bound")
            {
                ("lossy_expression", true)
            } else if lower.contains("unsupported") {
                ("unsupported_mapping", true)
            } else {
                ("other_warning", true)
            };
        *categories.entry(category.to_owned()).or_default() += 1;
        if blocks_completeness {
            blocking_warnings += 1;
        }
    }
    let parse_failures = recovery.files_seen.saturating_sub(recovery.files_parsed);
    if parse_failures > 0 {
        categories.insert("parse_failure".to_owned(), parse_failures);
    }
    let complete = parse_failures == 0 && blocking_warnings == 0;
    let report = serde_json::json!({
        "schema_version": 2,
        "status": if complete { "complete" } else { "partial" },
        "complete": complete,
        "files_seen": recovery.files_seen,
        "files_parsed": recovery.files_parsed,
        "defines_applied": recovery.defines_applied,
        "warnings_total": warnings.len(),
        "blocking_warnings": blocking_warnings + parse_failures,
        "warning_categories": categories,
        "reopened_modules": reopened_modules,
        "generated_unit_collisions": generated_unit_collisions,
        "real_fake_collisions_pruned": 0,
    });
    std::fs::write(
        output_dir.join("idl_recovery_report.json"),
        serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write IDL recovery report: {error}"))?;
    if !complete {
        eprintln!(
            "IDL mapping is partial: {} blocking recovery warning(s); see idl_recovery_report.json",
            blocking_warnings + parse_failures
        );
    }
    Ok(())
}

fn count_reopened_idl_modules(declarations: &[idl_parser::Declaration]) -> usize {
    fn walk(
        declarations: &[idl_parser::Declaration],
        prefix: &str,
        counts: &mut std::collections::BTreeMap<String, usize>,
    ) {
        for declaration in declarations {
            if let idl_parser::Declaration::Module(module) = declaration {
                let qualified = if prefix.is_empty() {
                    module.name.clone()
                } else {
                    format!("{prefix}::{}", module.name)
                };
                *counts.entry(qualified.clone()).or_default() += 1;
                walk(&module.declarations, &qualified, counts);
            }
        }
    }
    let mut counts = std::collections::BTreeMap::new();
    walk(declarations, "", &mut counts);
    counts.values().map(|count| count.saturating_sub(1)).sum()
}

fn checkpoint_real_fake_collisions(output_dir: &Path, removed: usize) -> Result<(), String> {
    let path = output_dir.join("idl_recovery_report.json");
    if !path.is_file() {
        return Ok(());
    }
    let mut report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    report["real_fake_collisions_pruned"] = serde_json::json!(removed);
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn write_idl_dictionary(output_dir: &Path, tokens: &[String]) -> Result<(), String> {
    if tokens.is_empty() {
        return Ok(());
    }
    let mut out = String::new();
    for token in tokens {
        out.push('"');
        out.push_str(&escape_afl_dictionary_token(token.as_bytes()));
        out.push_str("\"\n");
    }
    std::fs::write(output_dir.join("dictionary.txt"), out).map_err(|error| {
        format!(
            "write IDL dictionary under '{}': {error}",
            output_dir.display()
        )
    })
}

fn escape_afl_dictionary_token(token: &[u8]) -> String {
    let mut out = String::new();
    for byte in token {
        match *byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(*byte)),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out
}

fn parse_idl_defines(values: &[String]) -> Result<Vec<(String, String)>, String> {
    values
        .iter()
        .map(|value| {
            let (name, replacement) = value
                .split_once('=')
                .map_or((value.as_str(), ""), |(name, replacement)| {
                    (name, replacement)
                });
            if !is_idl_identifier(name) {
                return Err(format!(
                    "invalid --idl-define '{}': expected NAME or NAME=VALUE",
                    value
                ));
            }
            Ok((name.to_owned(), replacement.to_owned()))
        })
        .collect()
}

fn is_idl_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::{auto_generate_from_tree, find_idl_files, idl_include_dirs, write_idl_mapping};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn auto_generate_maps_in_tree_idl_into_fake_corba() {
        let root = temp_dir("idl-auto");
        let src = root.join("src");
        fs::create_dir_all(src.join("ignored.git")).unwrap();
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("bank.idl"),
            "module Bank { struct Account { long id; }; interface Teller { long balance(in Account a); }; };\n",
        )
        .unwrap();
        // A .git dir's .idl must be skipped by the walk.
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git").join("stale.idl"), "module X {};\n").unwrap();
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();

        let mapped = auto_generate_from_tree(&root, &work, false);
        assert_eq!(mapped, 1, "only the real .idl is mapped (.git skipped)");
        let out = work.join("fake_corba");
        assert!(out.join("bank.ads").is_file(), "module package generated");
        assert!(
            out.join("bank-teller-stub.ads").is_file(),
            "interface stub generated"
        );
        // No .idl anywhere -> no work, returns 0.
        let empty = temp_dir("idl-none");
        fs::create_dir_all(empty.join("a")).unwrap();
        assert_eq!(auto_generate_from_tree(&empty, &empty.join("w"), false), 0);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn auto_generate_writes_base_corba_for_generated_ada_without_idl() {
        // Customer/source archives commonly retain generated Ada bindings but
        // omit their IDL.  CORBA.Object.Ref must still be supplied to the Ada
        // build and type-analysis paths.
        let root = temp_dir("corba-no-idl");
        fs::write(
            root.join("servant.ads"),
            "with CORBA.Object; package Servant is procedure Touch (R : CORBA.Object.Ref); end Servant;\n",
        )
        .unwrap();
        let work = root.join("work");

        assert_eq!(auto_generate_from_tree(&root, &work, false), 0);
        let out = work.join("fake_corba");
        assert!(out.join("corba.ads").is_file());
        let object = fs::read_to_string(out.join("corba-object.ads")).unwrap();
        assert!(object.contains("type Ref is tagged record"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn checked_in_unit_wins_over_generated_mapping_even_with_custom_filename() {
        let root = temp_dir("real-unit-collision");
        fs::write(
            root.join("vendor_binding_name.ads"),
            "package Bank is type Existing is new Integer; end Bank;\n",
        )
        .unwrap();
        fs::write(
            root.join("bank.idl"),
            "module Bank { interface Teller { long balance(); }; };\n",
        )
        .unwrap();
        let work = root.join("work");

        assert_eq!(auto_generate_from_tree(&root, &work, false), 1);
        let out = work.join("fake_corba");
        assert!(
            !out.join("bank.ads").exists(),
            "generated module spec must not collide with the checked-in Bank spec"
        );
        assert!(
            out.join("bank-teller-stub.ads").is_file(),
            "non-colliding generated helper units remain available"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn idl_include_dirs_unions_all_idl_directories_deduped() {
        // Every directory holding an .idl becomes a search dir (first-seen order,
        // deduped) so a cross-directory `#include "common.idl"` resolves.
        let base = PathBuf::from("/tree");
        let idls = vec![
            base.join("idl/smc/ss_smc.idl"),
            base.join("idl/common/ss_smc_common_types.idl"),
            base.join("idl/smc/other.idl"), // same dir as the first -> deduped
        ];
        let dirs = idl_include_dirs(&idls);
        assert_eq!(
            dirs,
            vec![base.join("idl/smc"), base.join("idl/common")],
            "sibling idl/common/ must be on the include path, idl/smc/ deduped"
        );
    }

    #[test]
    fn auto_generate_resolves_cross_directory_idl_include() {
        // A servant IDL that `#include`s a sibling-directory types IDL must map
        // WITHOUT the "include not found" fallback: the included struct's package
        // is generated and the servant's operation references it.
        let root = temp_dir("idl-crossdir");
        let common = root.join("idl/common");
        let smc = root.join("idl/smc");
        fs::create_dir_all(&common).unwrap();
        fs::create_dir_all(&smc).unwrap();
        fs::write(
            common.join("ss_smc_common_types.idl"),
            "module SS_Smc { struct SmcHeader { long id; }; };\n",
        )
        .unwrap();
        fs::write(
            smc.join("ss_smc.idl"),
            "#include \"ss_smc_common_types.idl\"\nmodule SS_Smc { interface SmcService { boolean handle(in SmcHeader h); }; };\n",
        )
        .unwrap();
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();

        let mapped = auto_generate_from_tree(&root, &work, false);
        assert_eq!(mapped, 2, "both .idl files map");
        let out = work.join("fake_corba");
        // The common types package is generated (mapped from its own file), and the
        // servant interface stub is generated — proving the cross-dir include
        // resolved rather than dropping SmcHeader.
        assert!(
            out.join("ss_smc.ads").is_file(),
            "SS_Smc module package generated"
        );
        assert!(
            out.join("ss_smc-smcservice-stub.ads").is_file(),
            "servant interface stub generated (include resolved): {:?}",
            fs::read_dir(&out).map(|d| d
                .filter_map(|e| e.ok().map(|e| e.file_name()))
                .collect::<Vec<_>>())
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn auto_idl_uses_project_defines_and_records_complete_mapping() {
        let root = temp_dir("idl-project-defines");
        fs::write(
            root.join("Makefile"),
            "IDLFLAGS += -DENABLE_ACTIVE=1\ngenerate-idl: service.idl\n\t@echo $(IDLFLAGS)\n",
        )
        .unwrap();
        fs::write(
            root.join("service.idl"),
            "#if ENABLE_ACTIVE\nmodule Active { interface Service { long parse(); }; };\n#else\nmodule Wrong { interface Service {}; };\n#endif\n",
        )
        .unwrap();
        let work = root.join("work");
        assert_eq!(auto_generate_from_tree(&root, &work, false), 1);
        let out = work.join("fake_corba");
        assert!(out.join("active.ads").is_file());
        assert!(!out.join("wrong.ads").is_file());
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("idl_recovery_report.json")).unwrap())
                .unwrap();
        assert_eq!(report["complete"], true);
        assert_eq!(report["defines_applied"], 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn function_like_macro_and_unsupported_if_make_idl_mapping_explicitly_partial() {
        let root = temp_dir("idl-partial-function-macro");
        fs::write(
            root.join("service.idl"),
            "#define ENABLE(x) x\n#if ENABLE(1)\nmodule MaybeActive { interface Hidden {}; };\n#endif\nmodule Visible { interface Service { long parse(); }; };\n",
        )
        .unwrap();
        let work = root.join("work");
        assert_eq!(auto_generate_from_tree(&root, &work, false), 1);
        let out = work.join("fake_corba");
        assert!(out.join("visible.ads").is_file());
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("idl_recovery_report.json")).unwrap())
                .unwrap();
        assert_eq!(report["status"], "partial");
        assert!(
            report["warning_categories"]["unsupported_macro"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        assert!(
            report["warning_categories"]["unsupported_conditional"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn vendor_pragma_is_checkpointed_without_claiming_declarations_were_omitted() {
        let root = temp_dir("idl-vendor-pragma-report");
        fs::write(
            root.join("service.idl"),
            "#pragma vendor optimize on\nmodule Vendor { const long Derived = Unknown + 1; interface Service {}; };\n",
        )
        .unwrap();
        let work = root.join("work");
        assert_eq!(auto_generate_from_tree(&root, &work, false), 1);
        let report: serde_json::Value = serde_json::from_slice(
            &fs::read(work.join("fake_corba/idl_recovery_report.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(report["status"], "partial");
        assert_eq!(report["warning_categories"]["vendor_pragma"], 1);
        assert_eq!(report["warning_categories"]["lossy_expression"], 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn auto_generate_merges_reopened_modules_and_duplicate_includes_once() {
        let root = temp_dir("idl-reopened-modules");
        let idl = root.join("idl");
        fs::create_dir_all(&idl).unwrap();
        fs::write(
            idl.join("common.idl"),
            "module Shared { struct Common { long id; }; const string COMMON_TOKEN = \"COMMON\"; };\n",
        )
        .unwrap();
        fs::write(
            idl.join("first.idl"),
            "#include \"common.idl\"\nmodule Shared { struct First { long first_value; }; const string FIRST_TOKEN = \"FIRST\"; };\n",
        )
        .unwrap();
        fs::write(
            idl.join("second.idl"),
            "#include \"common.idl\"\nmodule Shared { struct Second { long second_value; }; const string SECOND_TOKEN = \"SECOND\"; };\n",
        )
        .unwrap();

        let work_a = root.join("work-a");
        let work_b = root.join("work-b");
        assert_eq!(auto_generate_from_tree(&root, &work_a, false), 3);
        assert_eq!(auto_generate_from_tree(&root, &work_b, false), 3);
        let spec_a = fs::read_to_string(work_a.join("fake_corba/shared.ads")).unwrap();
        let spec_b = fs::read_to_string(work_b.join("fake_corba/shared.ads")).unwrap();
        assert_eq!(spec_a, spec_b, "aggregate emission must be deterministic");
        for declaration in [
            "type Common is record",
            "type First is record",
            "type Second is record",
        ] {
            assert!(
                spec_a.contains(declaration),
                "missing {declaration}:\n{spec_a}"
            );
        }
        assert_eq!(
            spec_a.matches("type Common is record").count(),
            1,
            "a multiply-included declaration must be emitted once:\n{spec_a}"
        );
        let dictionary = fs::read_to_string(work_a.join("fake_corba/dictionary.txt")).unwrap();
        for token in ["COMMON", "FIRST", "SECOND"] {
            assert!(
                dictionary.contains(token),
                "missing dictionary token {token}: {dictionary}"
            );
        }
        ada_parser::reconcile::build_structural_ast(
            &spec_a,
            None,
            &work_a.join("fake_corba/shared.ads"),
        )
        .expect("merged generated package must remain parseable Ada");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn find_idl_files_skips_vcs_and_build_dirs() {
        let root = temp_dir("idl-find");
        for d in ["src", ".git", "target", "build", "node_modules"] {
            fs::create_dir_all(root.join(d)).unwrap();
            fs::write(root.join(d).join("x.idl"), "module M {};\n").unwrap();
        }
        let found = find_idl_files(&root);
        let dirs: Vec<String> = found
            .iter()
            .filter_map(|p| p.parent()?.file_name()?.to_str().map(str::to_owned))
            .collect();
        assert_eq!(
            dirs,
            vec!["src".to_owned()],
            "only src/ .idl found: {dirs:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn idl_mapping_writes_dictionary_from_constants_and_enums() {
        let root = temp_dir("idl-dictionary");
        let idl = root.join("demo.idl");
        fs::write(
            &idl,
            r#"
            module Demo {
              enum Mode { MODE_FAST, MODE_SAFE };
              const string Ready = "READY";
              const unsigned long Magic = 0x42;
              interface Service {};
            };
            "#,
        )
        .unwrap();
        let out = root.join("fake_corba");
        fs::create_dir_all(&out).unwrap();

        let written = write_idl_mapping(Some(&idl), &[], &[], &[], &out).unwrap();

        assert!(written > 0);
        let dictionary = fs::read_to_string(out.join("dictionary.txt")).unwrap();
        assert!(dictionary.contains("\"MODE_FAST\""));
        assert!(dictionary.contains("\"MODE_SAFE\""));
        assert!(dictionary.contains("\"READY\""));
        assert!(dictionary.contains("\"66\""));
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-fake-corba-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
