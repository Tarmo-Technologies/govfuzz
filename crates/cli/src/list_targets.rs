// SPDX-License-Identifier: Apache-2.0

use crate::target_filter::{path_matches_exclusion, ExcludeCategory};
use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use rayon::prelude::*;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use target_rank::{ScoreBreakdown, Target};

#[derive(Debug, clap::Args)]
pub struct ListTargetsArgs {
    /// Path to scan: an Ada/C/C++/Java/Rust file or a directory tree.
    pub path: PathBuf,

    /// Show only the top N targets.
    #[arg(long, default_value_t = 20)]
    pub top: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Exclude paths whose normalized relative path contains this text. Repeatable.
    #[arg(long = "exclude-path")]
    pub exclude_paths: Vec<String>,

    /// Exclude common project areas. Accepts comma-separated values: tests, tools, examples.
    #[arg(long = "exclude", value_enum, value_delimiter = ',')]
    pub exclude: Vec<ExcludeCategory>,

    /// Keep only targets in files modified between `<ref>` and HEAD.
    /// Runs `git diff --name-only <ref>..HEAD` from the git repo
    /// root containing the current working directory. Empty diff
    /// yields empty output — intended CI behaviour for unchanged
    /// commits.
    #[arg(long, value_name = "GIT_REF")]
    pub changed_since: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
}

/// The five lanes this command parses and ranks ITSELF, plus `Other` for the
/// eleven it defers to `auto`'s discovery for.
///
/// The split is historical, not principled: this surface was written when there
/// were five lanes and never revisited, so `list targets` reported NOTHING on a
/// Go, Python, JS/TS, C#, Ruby, PHP, Perl, Lua, Fortran or COBOL tree — 11 of 16
/// languages, silently, on the one command whose job is to answer "what can this
/// tool see here?". Across the 500-project sweep it listed 2.0M targets and every
/// one of them was in these five.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum SourceLanguage {
    Ada,
    C,
    Cpp,
    Java,
    Rust,
    /// A lane discovered by `auto` and rendered here under its own tag.
    #[serde(untagged)]
    Other(&'static str),
}

impl SourceLanguage {
    fn as_str(&self) -> &'static str {
        match self {
            SourceLanguage::Ada => "ada",
            SourceLanguage::C => "c",
            SourceLanguage::Cpp => "cpp",
            SourceLanguage::Java => "java",
            SourceLanguage::Rust => "rust",
            SourceLanguage::Other(tag) => tag,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ListedTarget {
    harness_id: String,
    name: String,
    score: i32,
    language: SourceLanguage,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    breakdown: Option<ScoreBreakdown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

pub fn run(args: ListTargetsArgs) -> Result<()> {
    let format = args.format;
    let all_targets = ranked_targets(args)?;

    match format {
        OutputFormat::Json => {
            let json = json_output(&all_targets)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            print_table(&mut handle, &all_targets)?;
        }
    }

    Ok(())
}

fn ranked_targets(args: ListTargetsArgs) -> Result<Vec<(PathBuf, ListedTarget)>> {
    let changed_set = match args.changed_since.as_deref() {
        Some(reference) => Some(compute_changed_set(reference)?),
        None => None,
    };

    let mut all_targets = Vec::new();
    // Parsing every file in a large tree and holding every target in memory can
    // exhaust RAM: carbon-language/carbon-lang was SIGKILLed (exit -9) here in
    // the 500-project sweep, so `list targets` produced nothing at all. Past the
    // RSS ceiling, stop parsing and report a partial list — the same graceful
    // degradation the static scan and `auto`'s discovery walk use.
    let memory_guard = static_analysis::MemoryGuard::start();
    // Enumerate first, then parse in parallel: parsing is the whole cost on a
    // large tree, and this loop was single threaded. `par_iter().collect()`
    // preserves input order and `walk_targetable_files` sorts, so the listing is
    // byte-identical to the sequential one.
    let skipped = std::sync::atomic::AtomicUsize::new(0);
    let files = walk_targetable_files(&args.path)?;
    let per_file: Vec<Result<Vec<(PathBuf, ListedTarget)>>> = listing_pool().install(|| {
        files
            .par_iter()
            .map(|path| {
                let path = path.clone();
                let mut out: Vec<(PathBuf, ListedTarget)> = Vec::new();
                if memory_guard.under_pressure() {
                    skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(out);
                }
                if path_is_excluded(&path, &args) {
                    return Ok(out);
                }
                if let Some(changed) = changed_set.as_ref() {
                    if !path_in_changed_set(&path, changed) {
                        return Ok(out);
                    }
                }
                let Some(language) = detect_language(&path) else {
                    return Ok(out);
                };
                // Latin-1 fallback: non-UTF-8 legacy sources are transcoded rather than
                // skipped, so real targets in older Ada/C/C++ still get ranked.
                let source = crate::source_text::read_source_text(&path)
                    .with_context(|| format!("read source {}", path.display()))?;
                match language {
                    SourceLanguage::Ada => {
                        let ast = ada_parser::reconcile::build_structural_ast(&source, None, &path)
                            .with_context(|| format!("scan Ada source {}", path.display()))?;
                        let metadata = ada_metadata(&path, &source, &ast);
                        // Same one-time index as the C++ arm below, for the same
                        // reason: a per-target linear scan over every subprogram is
                        // quadratic on a large unit.
                        let ada_lines: std::collections::HashMap<_, _> = ast
                            .subprograms
                            .iter()
                            .map(|subprogram| (subprogram.id, subprogram.decl_span.start_line))
                            .collect();
                        for target in target_rank::rank_targets(&ast) {
                            let line = ada_lines.get(&target.subprogram_id).copied().unwrap_or(0);
                            out.push((
                                path.clone(),
                                ada_listed_target(&path, target, line, metadata.clone()),
                            ));
                        }
                    }
                    SourceLanguage::C => {
                        let mut functions = c_parser::parse_c_functions(&source)
                            .with_context(|| format!("scan C source {}", path.display()))?;
                        // #11 (offline-legacy audit): tree-sitter parses an old-style K&R
                        // definition as a ZERO-parameter function, hiding its real
                        // `(char*, int)` signature — so the listing disagrees with the
                        // K&R-aware `auto` discovery about the same legacy function. Recover
                        // the true K&R signatures and prefer them, matching discovery.
                        let knr = c_parser::parse_knr_functions(&source);
                        if !knr.is_empty() {
                            let knr_names: std::collections::HashSet<String> =
                                knr.iter().map(|function| function.name.clone()).collect();
                            functions.retain(|function| !knr_names.contains(&function.name));
                            functions.splice(0..0, knr);
                        }
                        warn_if_parser_recovered(&path, functions.is_empty(), || {
                            c_parser::count_parse_errors(&source)
                        });
                        for target in target_rank::rank_c_targets(&functions) {
                            out.push((
                                path.clone(),
                                c_family_listed_target(&path, target, SourceLanguage::C, None),
                            ));
                        }
                    }
                    SourceLanguage::Cpp => {
                        let functions = cpp_parser::parse_cpp_functions(&source)
                            .with_context(|| format!("scan C++ source {}", path.display()))?;
                        warn_if_parser_recovered(&path, functions.is_empty(), || {
                            cpp_parser::count_parse_errors(&source)
                        });
                        // Index once, look up per target. Scanning `functions` for each
                        // ranked target is quadratic AND allocates a name string per
                        // comparison, which is what made a single amalgamated header
                        // unlistable: simdjson's 187k-line `singleheader/simdjson.h`
                        // yields 8,613 targets over a similar number of functions, so the
                        // linear search ran ~74M times and cost **50 seconds for one
                        // file** — the whole reason `list targets` timed out on simdjson,
                        // sumatrapdf, Proton and emscripten in the 500-project sweep.
                        // `auto`'s discovery already indexed this and does the same file
                        // in 0.16s.
                        //
                        // First insertion wins, matching the `.find` this replaces.
                        let mut by_identity: std::collections::HashMap<
                            (String, u32),
                            &cpp_parser::CppFunction,
                        > = std::collections::HashMap::with_capacity(functions.len());
                        for function in &functions {
                            by_identity
                                .entry((cpp_listed_target_name(function), function.line))
                                .or_insert(function);
                        }
                        for target in target_rank::rank_cpp_targets(&functions) {
                            let metadata = by_identity
                                .get(&(target.name.clone(), target.line))
                                .and_then(|function| serde_json::to_value(&function.api).ok());
                            out.push((
                                path.clone(),
                                c_family_listed_target(
                                    &path,
                                    target,
                                    SourceLanguage::Cpp,
                                    metadata,
                                ),
                            ));
                        }
                    }
                    SourceLanguage::Java => {
                        let methods = java_parser::parse_java_methods(&source)
                            .with_context(|| format!("scan Java source {}", path.display()))?;
                        for target in target_rank::rank_java_targets(&methods) {
                            out.push((
                                path.clone(),
                                non_c_listed_target(
                                    "H-J",
                                    &path,
                                    &target.name,
                                    target.line,
                                    target.score,
                                    SourceLanguage::Java,
                                ),
                            ));
                        }
                    }
                    SourceLanguage::Rust => {
                        let fns = rust_parser::parse_rust_functions(&source)
                            .with_context(|| format!("scan Rust source {}", path.display()))?;
                        for target in target_rank::rank_rust_targets(&fns) {
                            out.push((
                                path.clone(),
                                non_c_listed_target(
                                    "H-R",
                                    &path,
                                    &target.name,
                                    target.line,
                                    target.score,
                                    SourceLanguage::Rust,
                                ),
                            ));
                        }
                    }
                    // `detect_language` never yields this: it is the tag the deferred pass
                    // below attaches to a candidate `auto` discovered.
                    SourceLanguage::Other(_) => {}
                }
                Ok(out)
            })
            .collect()
    });
    for result in per_file {
        all_targets.extend(result?);
    }
    let skipped_for_memory = skipped.load(std::sync::atomic::Ordering::Relaxed);

    if skipped_for_memory > 0 {
        let ceiling = static_analysis::MemoryGuard::ceiling_kb()
            .map(|kb| format!("{} MiB", kb / 1024))
            .unwrap_or_else(|| "the configured ceiling".to_owned());
        eprintln!(
            "govfuzz: discovery reached its memory ceiling ({ceiling}) and skipped \
             {skipped_for_memory} file(s); this target list is PARTIAL. Raise it with \
             GOVFUZZ_MAX_MEMORY_KB, or list a subdirectory."
        );
    }

    // The eleven lanes this command does not parse itself. `auto`'s discovery
    // already covers all sixteen, so defer to it rather than growing a second
    // copy that drifts — the two surfaces disagreeing about the same tree is the
    // failure mode worth designing out. Gated on a cheap extension scan, so a
    // C/C++/Ada/Java/Rust-only tree pays exactly what it paid before.
    if !memory_guard.under_pressure() && tree_has_deferred_lane_sources(&args.path) {
        for candidate in deferred_lane_targets(&args.path) {
            if path_is_excluded(&candidate.source_path, &args) {
                continue;
            }
            if let Some(changed) = changed_set.as_ref() {
                if !path_in_changed_set(&candidate.source_path, changed) {
                    continue;
                }
            }
            all_targets.push((
                candidate.source_path.clone(),
                ListedTarget {
                    harness_id: candidate.harness_id,
                    name: candidate.name,
                    score: candidate.score,
                    language: SourceLanguage::Other(crate::auto::candidate::lang_tag(
                        candidate.lang,
                    )),
                    line: Some(candidate.line),
                    breakdown: None,
                    metadata: None,
                },
            ));
        }
    }

    all_targets.sort_by(|left, right| {
        right
            .1
            .score
            .cmp(&left.1.score)
            .then_with(|| left.1.name.cmp(&right.1.name))
            .then_with(|| left.0.cmp(&right.0))
    });
    all_targets.truncate(args.top);
    Ok(all_targets)
}

/// Extensions belonging to a lane this command defers to `auto` for. Matching one
/// is the only thing that makes the deferred pass run at all, so a tree without
/// any keeps this command exactly as cheap as it was.
const DEFERRED_LANE_EXTENSIONS: &[&str] = &[
    "go", "py", "pl", "pm", "cs", "js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "rb",
    "php", "lua", "f", "for", "f77", "f90", "f95", "f03", "f08", "cob", "cbl", "cpy",
];

fn tree_has_deferred_lane_sources(root: &Path) -> bool {
    fn is_deferred(path: &Path) -> bool {
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .is_some_and(|extension| DEFERRED_LANE_EXTENSIONS.contains(&extension.as_str()))
    }
    if root.is_file() {
        return is_deferred(root);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => {
                    // A dot-directory is never library source, and `.git` alone
                    // would dominate the walk.
                    let hidden = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with('.'));
                    if !hidden {
                        stack.push(path);
                    }
                }
                Ok(_) if is_deferred(&path) => return true,
                _ => {}
            }
        }
    }
    false
}

/// Candidates from `auto`'s discovery for the lanes this command does not parse
/// itself. A discovery failure yields nothing rather than failing the listing:
/// the five native lanes above have already produced their rows, and a listing
/// that errors out is worse than one that is short.
fn deferred_lane_targets(root: &Path) -> Vec<crate::auto::candidate::Candidate> {
    let Ok(candidates) = crate::auto::discovery::discover(root) else {
        return Vec::new();
    };
    candidates
        .into_iter()
        .filter(|candidate| {
            !matches!(
                candidate.lang,
                crate::auto::candidate::Lang::Ada
                    | crate::auto::candidate::Lang::C
                    | crate::auto::candidate::Lang::Cpp
                    | crate::auto::candidate::Lang::Java
                    | crate::auto::candidate::Lang::Rust
            )
        })
        .collect()
}

fn cpp_listed_target_name(function: &cpp_parser::CppFunction) -> String {
    let qualified = if function.qualifier_path.is_empty() {
        function.name.clone()
    } else {
        format!("{}::{}", function.qualifier_path.join("::"), function.name)
    };
    if function
        .api
        .unsupported
        .iter()
        .any(|item| item == "overload_set")
    {
        format!(
            "{}({})",
            qualified,
            function
                .params
                .iter()
                .map(|param| param.cpp_type.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        qualified
    }
}

/// Stderr-warn when the parser returned no functions but the
/// underlying tree-sitter tree contained ERROR/MISSING nodes. Users
/// scanning a real-world source file hit this when macro-heavy code
/// or a non-C/C++ dialect confuses the parser past recovery;
/// surfacing the signal stops the silent "no targets found" outcome.
///
/// Headers (.h/.hpp) almost always have zero function definitions
/// AND some macro/typedef gymnastics that tree-sitter flags as
/// errors, so the warning would fire on every header. Suppress it
/// for header files - they're not the missing-target signal we care
/// about.
fn warn_if_parser_recovered<F: FnOnce() -> usize>(path: &Path, found_none: bool, count_errors: F) {
    if !found_none {
        return;
    }
    if is_c_header_file(path) {
        return;
    }
    let errors = count_errors();
    if errors == 0 {
        return;
    }
    eprintln!(
        "warning: {}: parser found 0 targets and {errors} tree-sitter ERROR/MISSING node(s). \
         Macro-heavy code or a non-standard dialect can confuse tree-sitter; consider \
         preprocessing with `cpp -E` before passing to govfuzz.",
        path.display()
    );
}

fn ada_listed_target(
    source_path: &Path,
    mut target: Target,
    line: u32,
    metadata: Value,
) -> ListedTarget {
    let harness_id =
        crate::auto::discovery::stable_harness_id("H-A", source_path, line, &target.name);
    if ada_metadata_has_concurrency(&metadata) && target.breakdown.protected_or_task == 0 {
        target.breakdown.protected_or_task = 2;
        target.breakdown.total += 2;
        target.score += 2;
    }
    ListedTarget {
        harness_id,
        name: target.name,
        score: target.score,
        language: SourceLanguage::Ada,
        line: Some(line),
        breakdown: Some(target.breakdown),
        metadata: Some(metadata),
    }
}

fn ada_metadata(source_path: &Path, source: &str, ast: &ada_parser::ast::StructuralAst) -> Value {
    let local_features = AdaSourceFeatures::from_source(source);
    let related_source = related_ada_source(source_path, source, &local_features);
    let features = AdaSourceFeatures::from_source(&related_source);
    let ada_standard = detect_ada_standard_hint(&related_source).unwrap_or_else(|| {
        ast.units
            .first()
            .map(|unit| unit.ada_standard.to_string())
            .unwrap_or_else(|| "unknown".to_owned())
    });
    json!({
        "ada_standard": ada_standard,
        "unit_kind": ast.units.first().map(|unit| format!("{:?}", unit.kind).to_ascii_lowercase()).unwrap_or_else(|| "unknown".to_owned()),
        "subunit_parent": local_features.subunit_parent,
        "generic_context": {
            "declarations": features.generic_declarations,
            "instantiations": features.generic_instantiations,
        },
        "concurrency": {
            "tasks": features.tasks,
            "protected_objects": features.protected_objects,
            "entries": features.entries,
            "selects": features.selects,
            "delays": features.delays,
            "rendezvous_calls": features.rendezvous_calls,
        },
        "type_model": {
            "private_types": features.private_types,
            "tagged_types": features.tagged_types,
            "access_types": features.access_types,
            "limited_types": features.limited_types,
            "controlled_types": features.controlled_types,
            "representation_clauses": features.representation_clauses,
        }
    })
}

fn ada_metadata_has_concurrency(metadata: &Value) -> bool {
    metadata["concurrency"]["tasks"].as_u64().unwrap_or(0) > 0
        || metadata["concurrency"]["protected_objects"]
            .as_u64()
            .unwrap_or(0)
            > 0
        || metadata["concurrency"]["entries"].as_u64().unwrap_or(0) > 0
}

fn related_ada_source(source_path: &Path, source: &str, features: &AdaSourceFeatures) -> String {
    let mut combined = source.to_owned();
    let Some(parent) = &features.subunit_parent else {
        return combined;
    };
    let Some(dir) = source_path.parent() else {
        return combined;
    };
    let parent_prefix = parent.to_ascii_lowercase().replace('.', "-");
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path == source_path || !is_ada_source_file(&path) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if !stem.to_ascii_lowercase().starts_with(&parent_prefix) {
                continue;
            }
            if let Ok(text) = crate::source_text::read_source_text(&path) {
                combined.push('\n');
                combined.push_str(&text);
            }
        }
    }
    combined
}

fn is_ada_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "adb" | "ads"))
}

#[derive(Debug, Clone, Default)]
struct AdaSourceFeatures {
    subunit_parent: Option<String>,
    generic_declarations: usize,
    generic_instantiations: usize,
    tasks: usize,
    protected_objects: usize,
    entries: usize,
    selects: usize,
    delays: usize,
    rendezvous_calls: usize,
    private_types: usize,
    tagged_types: usize,
    access_types: usize,
    limited_types: usize,
    controlled_types: usize,
    representation_clauses: usize,
}

impl AdaSourceFeatures {
    fn from_source(source: &str) -> Self {
        let mut features = Self {
            subunit_parent: subunit_parent(source),
            ..Self::default()
        };
        let mut in_generic_formals = false;
        for line in source.lines() {
            let folded = strip_ada_comment(line).trim().to_ascii_lowercase();
            if folded.is_empty() {
                continue;
            }
            if folded == "generic" {
                features.generic_declarations += 1;
                in_generic_formals = true;
                continue;
            }
            if in_generic_formals
                && (folded.starts_with("package ")
                    || folded.starts_with("procedure ")
                    || folded.starts_with("function "))
            {
                in_generic_formals = false;
            }
            if folded.contains(" is new ") {
                features.generic_instantiations += 1;
            }
            if folded.starts_with("task type ") || folded.starts_with("task ") {
                features.tasks += 1;
            }
            if folded.starts_with("protected type ") || folded.starts_with("protected ") {
                features.protected_objects += 1;
            }
            if folded.starts_with("entry ") {
                features.entries += 1;
            }
            if folded.starts_with("select") {
                features.selects += 1;
            }
            if folded.starts_with("delay ") || folded.starts_with("delay until ") {
                features.delays += 1;
            }
            if folded.contains(".start") || folded.contains(" accept ") {
                features.rendezvous_calls += 1;
            }
            if !in_generic_formals && folded.starts_with("type ") && folded.contains(" is private")
            {
                features.private_types += 1;
            }
            if folded.starts_with("type ")
                && (folded.contains(" is tagged")
                    || folded.contains(" is abstract tagged")
                    || (folded.contains(" is new ") && folded.contains(" with record")))
            {
                features.tagged_types += 1;
            }
            if folded.starts_with("type ") && folded.contains(" access ") {
                features.access_types += 1;
            }
            if folded.starts_with("type ") && folded.contains("limited") {
                features.limited_types += 1;
            }
            if folded.contains("ada.finalization.controlled")
                || folded.contains("limited_controlled")
                || folded.contains("controlled")
            {
                features.controlled_types += 1;
            }
            if folded.starts_with("for ") && folded.contains(" use ") {
                features.representation_clauses += 1;
            }
        }
        features
    }
}

fn strip_ada_comment(line: &str) -> &str {
    line.split_once("--").map_or(line, |(code, _)| code)
}

fn subunit_parent(source: &str) -> Option<String> {
    let folded = source.to_ascii_lowercase();
    let separate = folded.find("separate")?;
    let after = &source[separate..];
    let open = after.find('(')?;
    let close = after[open + 1..].find(')')?;
    let parent = after[open + 1..open + 1 + close].trim();
    if parent.is_empty() {
        None
    } else {
        Some(parent.to_owned())
    }
}

fn detect_ada_standard_hint(source: &str) -> Option<String> {
    let folded = source.to_ascii_lowercase();
    if folded.contains("pragma ada_95") || folded.contains("pragma ada95") {
        Some("ada_95".to_owned())
    } else if folded.contains("pragma ada_2005")
        || folded.contains("pragma ada_05")
        || folded.contains("pragma ada2005")
        || folded.contains("pragma ada05")
    {
        Some("ada_2005".to_owned())
    } else if folded.contains("pragma ada_2012")
        || folded.contains("pragma ada_12")
        || folded.contains("pragma ada2012")
        || folded.contains("pragma ada12")
    {
        Some("ada_2012".to_owned())
    } else if folded.contains("pragma ada_2022") || folded.contains("pragma ada2022") {
        Some("ada_2022".to_owned())
    } else {
        None
    }
}

fn c_family_listed_target(
    source_path: &Path,
    target: target_rank::CTarget,
    language: SourceLanguage,
    metadata: Option<Value>,
) -> ListedTarget {
    let prefix = match language {
        SourceLanguage::Ada => "H-A",
        SourceLanguage::C => "H-C",
        SourceLanguage::Cpp => "H-X",
        // Java/Rust use the dedicated `non_c_listed_target` path (their targets are
        // not `CTarget`), so this arm is never reached; keep the correct prefixes.
        SourceLanguage::Java => "H-J",
        SourceLanguage::Rust => "H-R",
        // Deferred lanes arrive as ready-made `Candidate`s carrying their own
        // harness id, so they never reach a `CTarget` renderer.
        SourceLanguage::Other(_) => "H-?",
    };
    let harness_id =
        crate::auto::discovery::stable_harness_id(prefix, source_path, target.line, &target.name);
    ListedTarget {
        harness_id,
        name: target.name,
        score: target.score,
        language,
        line: Some(target.line),
        breakdown: None,
        metadata,
    }
}

/// Build a `ListedTarget` for a Java/Rust target (whose ranked target types are
/// not the C-family `CTarget`). Mirrors `c_family_listed_target` so the standalone
/// `list`/`scan` commands list Java (`H-J`) and Rust (`H-R`) targets with the same
/// stable harness ids `auto` assigns.
fn non_c_listed_target(
    prefix: &str,
    source_path: &Path,
    name: &str,
    line: u32,
    score: i32,
    language: SourceLanguage,
) -> ListedTarget {
    let harness_id = crate::auto::discovery::stable_harness_id(prefix, source_path, line, name);
    ListedTarget {
        harness_id,
        name: name.to_owned(),
        score,
        language,
        line: Some(line),
        breakdown: None,
        metadata: None,
    }
}

use crate::git_diff::{compute_changed_set, path_in_changed_set};

fn path_is_excluded(path: &Path, args: &ListTargetsArgs) -> bool {
    path_matches_exclusion(path, &args.path, &args.exclude_paths, &args.exclude)
}

/// `list targets`' worker pool. Same shape as discovery's: `cores - 1` workers
/// with big stacks, because parsing recurses over the syntax tree and a rayon
/// worker's default 2 MiB is not enough for real source.
fn listing_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::env::var("GOVFUZZ_DISCOVERY_JOBS")
            .ok()
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get().saturating_sub(1).max(1))
                    .unwrap_or(1)
            });
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(256 * 1024 * 1024)
            .build()
            .expect("build listing thread pool")
    })
}

fn walk_targetable_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!("path is neither file nor directory: {}", path.display());
    }

    let mut files = Vec::new();
    collect_targetable_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_targetable_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read directory {}", path.display()))? {
        let entry = entry.with_context(|| format!("read directory entry in {}", path.display()))?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("read file type for {}", entry_path.display()))?;

        if file_type.is_dir() {
            collect_targetable_files(&entry_path, files)?;
        } else if file_type.is_file() && detect_language(&entry_path).is_some() {
            files.push(entry_path);
        }
    }

    Ok(())
}

fn detect_language(path: &Path) -> Option<SourceLanguage> {
    if is_ada_file(path) {
        return Some(SourceLanguage::Ada);
    }
    // Java (`.java`) and Rust (`.rs`) have unambiguous extensions; check them
    // before the C-family so the standalone `list`/`scan` commands surface the
    // same languages `auto` already discovers (parity across all five lanes).
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("java"))
    {
        return Some(SourceLanguage::Java);
    }
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
    {
        return Some(SourceLanguage::Rust);
    }
    if is_cpp_file(path) {
        return Some(SourceLanguage::Cpp);
    }
    if is_c_source_file(path) {
        return Some(SourceLanguage::C);
    }
    if is_c_header_file(path) {
        return classify_c_header(path);
    }
    None
}

fn classify_c_header(path: &Path) -> Option<SourceLanguage> {
    let source = crate::source_text::read_source_text(path).ok()?;
    let c_count = c_parser::parse_c_functions(&source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    let cpp_count = cpp_parser::parse_cpp_functions(&source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    if cpp_count > c_count || header_looks_like_cpp(&source) {
        Some(SourceLanguage::Cpp)
    } else {
        Some(SourceLanguage::C)
    }
}

fn header_looks_like_cpp(source: &str) -> bool {
    [
        "namespace ",
        "template <",
        "template<",
        "class ",
        "typename ",
        "public:",
        "private:",
        "protected:",
        "constexpr",
        "noexcept",
        "operator",
    ]
    .iter()
    .any(|marker| source.contains(marker))
}

fn is_ada_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ads") || ext.eq_ignore_ascii_case("adb"))
}

fn is_c_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "c")
}

fn is_c_header_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("h"))
}

fn is_cpp_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            if ext == "C" {
                return true;
            }
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx"
            )
        })
}

fn print_table<W: Write>(writer: &mut W, rows: &[(PathBuf, ListedTarget)]) -> Result<()> {
    let file_width = rows
        .iter()
        .map(|(path, _)| path.display().to_string().len())
        .max()
        .unwrap_or("FILE".len())
        .max("FILE".len());
    let target_width = rows
        .iter()
        .map(|(_, target)| target.name.len())
        .max()
        .unwrap_or("TARGET".len())
        .max("TARGET".len());
    let harness_width = rows
        .iter()
        .map(|(_, target)| target.harness_id.len())
        .max()
        .unwrap_or("HARNESS_ID".len())
        .max("HARNESS_ID".len());
    let lang_width = rows
        .iter()
        .map(|(_, target)| target.language.as_str().len())
        .max()
        .unwrap_or("LANG".len())
        .max("LANG".len());
    let score_width = rows
        .iter()
        .map(|(_, target)| target.score.to_string().len())
        .max()
        .unwrap_or("SCORE".len())
        .max("SCORE".len());

    writeln!(
        writer,
        "{:<file_width$}  {:<harness_width$}  {:<lang_width$}  {:<target_width$}  {:>score_width$}",
        "FILE", "HARNESS_ID", "LANG", "TARGET", "SCORE"
    )?;
    writeln!(
        writer,
        "{:-<file_width$}  {:-<harness_width$}  {:-<lang_width$}  {:-<target_width$}  {:-<score_width$}",
        "", "", "", "", ""
    )?;
    for (path, target) in rows {
        writeln!(
            writer,
            "{:<file_width$}  {:<harness_width$}  {:<lang_width$}  {:<target_width$}  {:>score_width$}",
            path.display(),
            target.harness_id,
            target.language.as_str(),
            target.name,
            target.score
        )?;
    }

    Ok(())
}

fn json_output(rows: &[(PathBuf, ListedTarget)]) -> serde_json::Result<String> {
    let rows = rows
        .iter()
        .map(|(path, target)| serde_json::json!({ "file": path, "target": target }))
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&rows)
}

#[cfg(test)]
mod tests {
    use super::{
        deferred_lane_targets, json_output, print_table, ranked_targets,
        tree_has_deferred_lane_sources, walk_targetable_files, ExcludeCategory, ListTargetsArgs,
        ListedTarget, OutputFormat, SourceLanguage,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz_{name}_{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ada_target(name: &str, score: i32) -> ListedTarget {
        ListedTarget {
            harness_id: "H-A0001-12345678".to_owned(),
            name: name.to_owned(),
            score,
            language: SourceLanguage::Ada,
            line: None,
            breakdown: None,
            metadata: None,
        }
    }

    #[test]
    fn walk_targetable_files_finds_ada_and_c_and_cpp() {
        let dir = temp_dir("walk_dir_multi");
        fs::write(dir.join("a.ads"), "package A is end A;").unwrap();
        fs::write(dir.join("b.c"), "int main(void) { return 0; }").unwrap();
        fs::write(dir.join("c.cpp"), "namespace x { int run() { return 0; } }").unwrap();
        fs::write(dir.join("README.md"), "no").unwrap();

        let files = walk_targetable_files(&dir).unwrap();

        assert_eq!(files.len(), 3);
        assert!(files.iter().any(|p| p.ends_with("a.ads")));
        assert!(files.iter().any(|p| p.ends_with("b.c")));
        assert!(files.iter().any(|p| p.ends_with("c.cpp")));
    }

    #[test]
    fn walk_targetable_files_returns_single_file_when_path_is_file() {
        let dir = temp_dir("walk_file");
        let file = dir.join("target.adb");
        fs::write(&file, "procedure Target is begin null; end Target;").unwrap();

        assert_eq!(walk_targetable_files(&file).unwrap(), vec![file]);
    }

    #[test]
    fn ranked_targets_finds_c_functions() {
        let dir = temp_dir("rank_c");
        fs::write(
            dir.join("util.c"),
            "int parse(const char *s) { return 0; }\nint render(int x) { return x; }\n",
        )
        .unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 10,
            format: OutputFormat::Json,
            exclude_paths: Vec::new(),
            exclude: Vec::new(),
            changed_since: None,
        })
        .expect("C scan succeeds");

        let names: Vec<_> = rows.iter().map(|(_, t)| t.name.clone()).collect();
        assert!(names.iter().any(|n| n == "parse"));
        assert!(names.iter().any(|n| n == "render"));
        for (_, target) in &rows {
            assert_eq!(target.language, SourceLanguage::C);
            assert!(target.line.is_some());
        }
    }

    #[test]
    fn ranked_targets_finds_java_and_rust() {
        // The standalone `list`/`scan` walk previously recognised only Ada/C/C++,
        // so a Java/Rust tree listed ZERO targets while `auto` discovered them —
        // an inconsistency in language support. Both lanes must now be listed.
        let dir = temp_dir("rank_java_rust");
        fs::write(
            dir.join("Foo.java"),
            "package com.example;\npublic class Foo {\n  public int add(int a, int b) { return a + b; }\n  public String greet(String n) { return n; }\n}\n",
        )
        .unwrap();
        fs::write(
            dir.join("lib.rs"),
            "pub fn parse(s: &str) -> usize { s.len() }\npub fn render(x: u32) -> u32 { x }\n",
        )
        .unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 50,
            format: OutputFormat::Json,
            exclude_paths: Vec::new(),
            exclude: Vec::new(),
            changed_since: None,
        })
        .expect("Java+Rust scan succeeds");

        let java: Vec<_> = rows
            .iter()
            .filter(|(_, t)| t.language == SourceLanguage::Java)
            .map(|(_, t)| t.name.clone())
            .collect();
        let rust: Vec<_> = rows
            .iter()
            .filter(|(_, t)| t.language == SourceLanguage::Rust)
            .map(|(_, t)| t.name.clone())
            .collect();
        assert!(java.iter().any(|n| n == "greet"), "java targets: {java:?}");
        assert!(rust.iter().any(|n| n == "parse"), "rust targets: {rust:?}");
        // Harness ids carry the lane prefixes `auto` uses (H-J / H-R).
        assert!(rows
            .iter()
            .any(|(_, t)| t.language == SourceLanguage::Java && t.harness_id.starts_with("H-J")));
        assert!(rows
            .iter()
            .any(|(_, t)| t.language == SourceLanguage::Rust && t.harness_id.starts_with("H-R")));
    }

    #[test]
    fn ranked_targets_finds_cpp_functions() {
        let dir = temp_dir("rank_cpp");
        fs::write(
            dir.join("api.cpp"),
            "namespace api { int handle() { return 0; } }",
        )
        .unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 10,
            format: OutputFormat::Json,
            exclude_paths: Vec::new(),
            exclude: Vec::new(),
            changed_since: None,
        })
        .expect("C++ scan succeeds");

        assert!(rows.iter().any(|(_, t)| t.name == "api::handle"));
        assert!(rows.iter().all(|(_, t)| t.language == SourceLanguage::Cpp));
    }

    #[test]
    fn json_output_includes_cpp_api_metadata_and_unsupported_reasons() {
        let dir = temp_dir("rank_cpp_metadata");
        fs::write(
            dir.join("api.cpp"),
            r#"
            namespace gov {
            class Parser {
            public:
                int parse(const std::string &input) { return 0; }
                int parse(const char *input, std::size_t len) { return 0; }
                template <typename T>
                int decode(const T &value) { return 0; }
            };
            }
            "#,
        )
        .unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 10,
            format: OutputFormat::Json,
            exclude_paths: Vec::new(),
            exclude: Vec::new(),
            changed_since: None,
        })
        .expect("C++ scan succeeds");
        let json = json_output(&rows).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let parse = value
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("gov::Parser::parse("))
            })
            .unwrap();

        assert_eq!(parse["target"]["metadata"]["api_kind"], "method");
        assert_eq!(parse["target"]["metadata"]["class_name"], "Parser");
        assert_eq!(parse["target"]["metadata"]["namespace_path"][0], "gov");
        assert!(parse["target"]["metadata"]["unsupported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "overload_set"));
    }

    #[test]
    fn ranked_targets_mixes_ada_and_c_in_one_run() {
        let dir = temp_dir("rank_mixed");
        fs::write(
            dir.join("lib.adb"),
            "procedure Lib (Input : in String) is begin raise Constraint_Error; exception when others => null; end Lib;",
        )
        .unwrap();
        fs::write(dir.join("util.c"), "void render(void) { }\n").unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 10,
            format: OutputFormat::Json,
            exclude_paths: Vec::new(),
            exclude: Vec::new(),
            changed_since: None,
        })
        .expect("mixed scan succeeds");

        let languages: Vec<_> = rows.iter().map(|(_, t)| t.language).collect();
        assert!(languages.contains(&SourceLanguage::Ada));
        assert!(languages.contains(&SourceLanguage::C));
    }

    #[test]
    fn list_targets_transcodes_non_utf8_ada_files_in_directory_scan() {
        let dir = temp_dir("non_utf8_scan");
        fs::write(
            dir.join("good.adb"),
            "procedure Good (Input : in String) is begin raise Constraint_Error; end Good;",
        )
        .unwrap();
        // Latin-1 high byte in a comment: the file must be transcoded and ranked,
        // not dropped from the directory scan.
        fs::write(
            dir.join("legacy_encoding.adb"),
            b"procedure Legacy_Encoding is\n-- \xFF\nbegin\n   null;\nend Legacy_Encoding;\n",
        )
        .unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 20,
            format: OutputFormat::Json,
            exclude_paths: Vec::new(),
            exclude: Vec::new(),
            changed_since: None,
        })
        .expect("directory scan transcodes unsupported-encoding sources");
        assert!(
            rows.iter()
                .any(|(path, _)| path.ends_with("legacy_encoding.adb")),
            "transcoded legacy_encoding.adb should be ranked: {rows:?}"
        );
    }

    #[test]
    fn exclude_path_filters_before_top_limit() {
        let dir = temp_dir("exclude_before_top");
        fs::create_dir(dir.join("src")).unwrap();
        fs::create_dir(dir.join("tests")).unwrap();
        fs::write(
            dir.join("src").join("lib.adb"),
            "procedure Lib (Input : in String) is begin null; end Lib;",
        )
        .unwrap();
        fs::write(
            dir.join("tests").join("high.adb"),
            "procedure High is begin raise Constraint_Error; exception when others => null; end High;",
        )
        .unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 1,
            format: OutputFormat::Json,
            exclude_paths: vec!["tests".to_owned()],
            exclude: Vec::new(),
            changed_since: None,
        })
        .expect("excluded paths are ignored before top-N truncation");

        assert_eq!(rows.len(), 1);
        assert!(rows[0].0.ends_with("src/lib.adb"));
        assert_eq!(rows[0].1.name, "lib");
    }

    #[test]
    fn exclude_category_filters_common_project_areas() {
        let dir = temp_dir("exclude_categories");
        for child in ["src", "tools", "examples"] {
            fs::create_dir(dir.join(child)).unwrap();
        }
        fs::write(
            dir.join("src").join("lib.adb"),
            "procedure Lib (Input : in String) is begin null; end Lib;",
        )
        .unwrap();
        fs::write(
            dir.join("tools").join("tool.adb"),
            "procedure Tool is begin raise Constraint_Error; exception when others => null; end Tool;",
        )
        .unwrap();
        fs::write(
            dir.join("examples").join("demo.adb"),
            "procedure Demo is begin raise Constraint_Error; exception when others => null; end Demo;",
        )
        .unwrap();

        let rows = ranked_targets(ListTargetsArgs {
            path: dir,
            top: 10,
            format: OutputFormat::Json,
            exclude_paths: Vec::new(),
            exclude: vec![ExcludeCategory::Tools, ExcludeCategory::Examples],
            changed_since: None,
        })
        .expect("preset categories are filtered");

        assert_eq!(rows.len(), 1);
        assert!(rows[0].0.ends_with("src/lib.adb"));
    }

    #[test]
    fn print_table_outputs_header_and_rows() {
        let mut output = Vec::new();
        let rows = vec![(PathBuf::from("src.adb"), ada_target("Target", 25))];

        print_table(&mut output, &rows).unwrap();
        let table = String::from_utf8(output).unwrap();

        assert!(table.contains("FILE"));
        assert!(table.contains("HARNESS_ID"));
        assert!(table.contains("LANG"));
        assert!(table.contains("TARGET"));
        assert!(table.contains("SCORE"));
        assert!(table.contains("src.adb"));
        assert!(table.contains("H-A0001-12345678"));
        assert!(table.contains("ada"));
        assert!(table.contains("Target"));
        assert!(table.contains("25"));
    }

    #[test]
    fn json_output_is_valid_json_with_language_field() {
        let rows = vec![(PathBuf::from("src.adb"), ada_target("Target", 25))];

        let json = json_output(&rows).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let first = &value.as_array().unwrap()[0];

        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(first["file"], "src.adb");
        assert_eq!(first["target"]["harness_id"], "H-A0001-12345678");
        assert_eq!(first["target"]["name"], "Target");
        assert_eq!(first["target"]["score"], 25);
        assert_eq!(first["target"]["language"], "ada");
    }

    /// `list targets` reported NOTHING on 11 of the 16 supported lanes: its own
    /// language enum was written when there were five and never revisited, so a
    /// Go, Python, JS/TS, C#, Ruby, PHP, Perl, Lua, Fortran or COBOL tree got an
    /// empty listing from the one command whose job is to say what the tool can
    /// see. The deferred pass hands those lanes to `auto`'s discovery, which
    /// already covers all sixteen.
    #[test]
    fn a_lane_this_command_does_not_parse_is_still_listed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(
            root.join("lib.go"),
            "package lib\n\nfunc ParseRecord(data []byte) int { return len(data) }\n",
        )
        .expect("write go source");

        assert!(
            tree_has_deferred_lane_sources(root),
            "a .go file must arm the deferred pass"
        );
        let listed = deferred_lane_targets(root);
        assert!(
            listed.iter().any(|c| c.name == "ParseRecord"),
            "the Go target must be listed: {:?}",
            listed.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(
            SourceLanguage::Other(crate::auto::candidate::lang_tag(
                crate::auto::candidate::Lang::Go
            ))
            .as_str(),
            "go"
        );
    }

    /// …and a tree with none of them must not pay for the pass. The five native
    /// lanes keep exactly the cost they had.
    #[test]
    fn a_tree_without_a_deferred_lane_never_arms_the_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("a.c"), "int f(const char *s) { return 0; }\n").unwrap();
        std::fs::write(root.join("b.adb"), "procedure B is begin null; end B;\n").unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        // A dot-directory is skipped, so a stray `.git` object cannot arm it.
        std::fs::write(root.join(".git/hook.py"), "def f(): pass\n").unwrap();
        assert!(!tree_has_deferred_lane_sources(root));
    }

    // The git-diff helpers moved to `crate::git_diff`; their unit tests live
    // there now (see `git_diff::tests`).
}
